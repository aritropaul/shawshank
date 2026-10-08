import { DurableObject } from "cloudflare:workers";

// Wire protocol over the client's WebSocket. Every binary message is one frame:
//   u8 type | u32 stream id (big endian) | payload
// OPEN and RES payloads are JSON, DATA/TEXT are raw bytes, WIN is a u32 credit,
// CLOSE is u16 code + utf-8 reason.
const OPEN = 1; // DO → client: new visitor request {m, u, q, h, ip, x, o, ws}
const DATA = 2; // both: body bytes, or a binary websocket message
const END = 3; // both: no more body in this direction
const WIN = 4; // both: receiver consumed n bytes, sender may send n more
const RST = 5; // both: abort the stream
const TEXT = 6; // both: text websocket message
const CLOSE = 7; // both: websocket closed
const RES = 8; // client → DO: response head {s, h}

const CHUNK = 256 * 1024; // max body bytes per frame
const WINDOW = 4 * 1024 * 1024; // per-stream flow-control window, each direction
const MAX_STREAMS = 512; // in-flight requests + visitor websockets per tunnel
const MAX_PER_IP = 256; // of those, from one visitor (a browser loading a dev server can have 100+ in flight)
const MEMORY_BUDGET = 64 * 1024 * 1024; // response bytes held for slow visitors, per tunnel
const OUT_BUDGET = 64 * 1024 * 1024; // bytes sent toward the laptop but not yet delivered, per tunnel
const WS_BACKLOG = 16 * 1024 * 1024; // of those, for one visitor websocket
const AUTH_TTL = 7 * 24 * 3600; // seconds a tunnel login cookie stays valid

const NAME = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const COOKIE = "_tunnel";
const NULL_BODY = new Set([101, 204, 205, 304]);
const HOP = new Set([
	"connection", "keep-alive", "proxy-connection", "transfer-encoding", "te", "upgrade", "host",
	"sec-websocket-key", "sec-websocket-version", "sec-websocket-extensions",
]);
// Response headers a tunneled app may not send: they would act on every
// tunnel, since all tunnels share one origin.
const BLOCKED_RESPONSE = new Set(["service-worker-allowed", "clear-site-data"]);
// Path segments that are almost always secrets when a dev server serves them.
// Mirrored in guard.go.
const SENSITIVE = new Set([
	".git", ".svn", ".hg", ".bzr", ".ssh", ".aws", ".azure", ".gnupg", ".kube", ".docker", ".terraform",
	".terraform.d", ".config", ".password-store", ".vault-token", ".npmrc", ".yarnrc", ".pypirc", ".netrc",
	".pgpass", ".git-credentials", ".htpasswd", ".htaccess", ".ds_store", ".bash_history", ".zsh_history",
	".psql_history", ".mysql_history", "master.key",
]);
const SENSITIVE_SUFFIX = [".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".tfstate", ".sqlite", ".sqlite3"];
// Debug consoles that run code or dump secrets and trust localhost, which
// every tunneled request comes from.
const CONSOLES = ["/__web_console", "/_ignition/", "/_profiler", "/_wdt", "/__debug__/"];

// Liveness seen recently by this isolate, so routing doesn't cost a Durable
// Object call per request. Short-lived and capped; a stale "live" only means
// the object itself answers "offline".
const live = new Map<string, number>();
const offline = new Map<string, number>(); // only for names taken from the path
const LIVE_TTL = 30_000;
const OFFLINE_TTL = 5_000;

function remember(m: Map<string, number>, name: string, ttl: number): void {
	if (m.size > 1000) m.clear();
	m.set(name, Date.now() + ttl);
}

function fresh(m: Map<string, number>, name: string): boolean {
	return (m.get(name) ?? 0) > Date.now();
}

export default {
	async fetch(req, env): Promise<Response> {
		const url = new URL(req.url);
		const ip = clientKey(req);

		if (url.pathname === "/_tunnel/connect") {
			if (!(await allow(env.CONNECTS, ip))) return text("tunnel: too many attempts", 429);
			return connect(req, env, url);
		}
		if (url.pathname.startsWith("/_tunnel/")) return text("tunnel: not found", 404);
		if (!(await allow(env.VISITORS, ip))) return text("tunnel: too many requests", 429);

		// Who is this request for? /<name>/... is explicit. Absolute paths from a
		// tunneled app (/assets/app.js, /src/App.tsx) carry no name, so fall back
		// to the page that asked for it (Referer) and then the last tunnel visited
		// (cookie). A name that isn't the cookie's must prove it's live, since
		// /src/... and /assets/... look like names too.
		const seg = url.pathname.split("/")[1] ?? "";
		const name = NAME.test(seg) ? seg : "";
		const ref = refererName(req, url);
		const cookie = cookieName(req);
		if (name && name === cookie) return route(req, env, ip, name, true);

		const candidates = [...new Set([name, ref, cookie].filter(Boolean))];
		if (candidates.length === 0) return url.pathname === "/" ? text("tunnel") : text("tunnel: not found", 404);
		for (const [i, c] of candidates.entries()) {
			if (i === candidates.length - 1) return route(req, env, ip, c, c === name);
			const r = await isLive(env, ip, c, c === name);
			if (r === "slow") return text("tunnel: too many requests", 429);
			if (r) return route(req, env, ip, c, c === name);
		}
		return text("tunnel: not found", 404);
	},
} satisfies ExportedHandler<Env>;

// Rate-limit key for a visitor: the IP, or its /64 for IPv6, since anyone
// holding one IPv6 address usually holds the whole /64.
function clientKey(req: Request): string {
	const ip = req.headers.get("cf-connecting-ip") ?? "local";
	if (!ip.includes(":")) return ip;
	const [head, tail] = ip.toLowerCase().split("::");
	const h = head ? head.split(":") : [];
	const t = tail ? tail.split(":") : [];
	const groups = tail === undefined ? h : [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill("0"), ...t];
	return groups.slice(0, 4).map((g) => g.replace(/^0+(?=.)/, "")).join(":") + "::/64";
}

async function allow(limiter: RateLimit | undefined, key: string): Promise<boolean> {
	if (!limiter) return true;
	return (await limiter.limit({ key })).success;
}

async function connect(req: Request, env: Env, url: URL): Promise<Response> {
	if (req.headers.get("Upgrade")?.toLowerCase() !== "websocket") return text("tunnel: expected websocket", 426);
	if (!(await tokenOK(req.headers.get("Authorization") ?? "", env.TOKEN))) return text("tunnel: bad token", 401);
	const name = url.searchParams.get("name") ?? "";
	if (!NAME.test(name)) return text("tunnel: invalid name (a-z, 0-9, -)", 400);
	offline.delete(name);
	remember(live, name, LIVE_TTL);
	return env.TUNNEL.getByName(name).fetch(req);
}

// route forwards to a tunnel, rate-limiting lookups of names this isolate
// hasn't seen live (scanners guessing names cost a Durable Object call each).
async function route(req: Request, env: Env, ip: string, name: string, strip: boolean): Promise<Response> {
	if (!fresh(live, name) && !(await allow(env.PROBES, ip))) return text("tunnel: too many requests", 429);
	const res = await forward(req, env, name, strip);
	if (res.headers.get("x-tunnel-offline") === "1") {
		live.delete(name);
		if (strip) remember(offline, name, OFFLINE_TTL);
	} else remember(live, name, LIVE_TTL);
	return res;
}

function forward(req: Request, env: Env, name: string, strip: boolean): Promise<Response> {
	const r = new Request(req);
	for (const k of [...r.headers.keys()]) if (k.startsWith("x-tunnel-")) r.headers.delete(k);
	r.headers.set("x-tunnel-name", name);
	r.headers.set("x-tunnel-prefix", strip ? "/" + name : "");
	const ae = req.cf?.clientAcceptEncoding;
	if (typeof ae === "string") r.headers.set("x-tunnel-ae", ae);
	return env.TUNNEL.getByName(name).fetch(r);
}

// isLive asks a tunnel's object whether a client is connected. Only names
// taken from the URL path are cached as offline: a Referer or cookie name is a
// tunnel the visitor really used, and skipping it on stale data would send
// their request to a different tunnel.
async function isLive(env: Env, ip: string, name: string, fromPath: boolean): Promise<boolean | "slow"> {
	if (fresh(live, name)) return true;
	if (fromPath && fresh(offline, name)) return false;
	if (!(await allow(env.PROBES, ip))) return "slow";
	const up = await env.TUNNEL.getByName(name).live();
	if (up) {
		offline.delete(name);
		remember(live, name, LIVE_TTL);
	} else {
		live.delete(name);
		if (fromPath) remember(offline, name, OFFLINE_TTL);
	}
	return up;
}

function refererName(req: Request, url: URL): string {
	const ref = req.headers.get("Referer");
	if (!ref) return "";
	try {
		const r = new URL(ref);
		if (r.host !== publicHost(req, url)) return "";
		const seg = r.pathname.split("/")[1] ?? "";
		return NAME.test(seg) ? seg : "";
	} catch {
		return "";
	}
}

function cookieValue(req: Request, key: string): string {
	for (const part of (req.headers.get("Cookie") ?? "").split(";")) {
		const i = part.indexOf("=");
		if (i > 0 && part.slice(0, i).trim() === key) return part.slice(i + 1).trim();
	}
	return "";
}

// cookieName is the routing cookie, ignored if there's more than one (page
// script in the shared origin could have planted a second).
function cookieName(req: Request): string {
	const all = (req.headers.get("Cookie") ?? "").split(";").filter((p) => p.trim().startsWith(COOKIE + "="));
	if (all.length !== 1) return "";
	const v = cookieValue(req, COOKIE);
	return NAME.test(v) ? v : "";
}

async function tokenOK(header: string, token: string | undefined): Promise<boolean> {
	if (!token) return false;
	const [a, b] = await Promise.all([sha256(header), sha256("Bearer " + token)]);
	return crypto.subtle.timingSafeEqual(a, b);
}

// True for secrets (/.env, /.git/config, /.ssh/..., *.pem) and debug consoles,
// checked after percent-decoding and case-folding (macOS paths are case-insensitive).
function blocked(path: string, search: string): boolean {
	let p: string, q: string;
	try {
		// Upper then lower folds the way case-insensitive filesystems do
		// (long s to s, Kelvin sign to k), so ".ſsh" can't slip past.
		p = decodeURIComponent(path).toUpperCase().toLowerCase();
		q = decodeURIComponent(search).toUpperCase().toLowerCase();
	} catch {
		return true;
	}
	const secret = p.split(/[/\\]/).some(
		(s) => SENSITIVE.has(s) || s.startsWith(".env") || /^id_(rsa|dsa|ecdsa|ed25519)/.test(s) || SENSITIVE_SUFFIX.some((x) => s.endsWith(x)),
	);
	return secret || CONSOLES.some((c) => p.startsWith(c)) || q.includes("__debugger__");
}

interface Stream {
	id: number;
	ip: string; // clientKey of the visitor
	ws: boolean;
	head: boolean; // HEAD request: response has no body
	resolve: (r: Response) => void;
	cookies: string[]; // Set-Cookie headers the worker adds to the response
	absolute: boolean; // reached without the /<name>/ prefix
	writer?: WritableStreamDefaultWriter<Uint8Array>;
	credit: number; // request-body bytes we may still send
	inflight: number; // request-body bytes sent but not yet delivered
	wake?: () => void;
	closed: boolean; // no more frames expected
	dropped: boolean; // aborted; its buffered bytes are already released
	buffered: number; // response bytes written but not yet read by the visitor
}

interface Ctl {
	name: string;
	origin: string; // public origin, for the ready message
	login: boolean; // the client asked for a password; it arrives as the first message
	auth: string; // hex HMAC of the password (keyed by TOKEN), once received; "" for an open tunnel
}

export class Tunnel extends DurableObject<Env> {
	// In-flight HTTP streams. Memory only: a pending request keeps the object
	// awake, and visitor websockets are found again through their tags.
	streams = new Map<number, Stream>();
	perIP = new Map<string, number>(); // open HTTP streams per visitor
	buffered = 0;
	outbound = 0; // bytes on their way to the laptop
	wsInflight = new Map<number, number>(); // per visitor websocket
	waiters = new Set<() => void>(); // pumps waiting for outbound room
	hmacKey?: CryptoKey;

	live(): boolean {
		return this.ctl() !== undefined;
	}

	async fetch(req: Request): Promise<Response> {
		const url = new URL(req.url);
		if (url.pathname === "/_tunnel/connect") return this.accept(req, url);
		return this.proxy(req, url);
	}

	accept(req: Request, url: URL): Response {
		const name = url.searchParams.get("name") ?? "";
		const login = req.headers.get("x-tunnel-login") === "1";
		// Last client wins: the old one is told it was replaced and exits.
		for (const old of this.ctx.getWebSockets("ctl")) safeClose(old, 4001, "replaced");
		this.closeAll("tunnel client reconnected");
		const { 0: client, 1: server } = new WebSocketPair();
		this.ctx.acceptWebSocket(server, ["ctl"]);
		server.serializeAttachment({ name, origin: origin(req, url), login, auth: "" } satisfies Ctl);
		// A password-protected tunnel is announced only once its password has arrived.
		if (!login) server.send(JSON.stringify({ t: "ready", url: `${origin(req, url)}/${name}/`, auth: false }));
		return new Response(null, { status: 101, webSocket: client });
	}

	async login(ws: WebSocket, msg: string): Promise<void> {
		const ctl = ws.deserializeAttachment() as Ctl;
		let creds = "";
		try {
			const m = JSON.parse(msg);
			if (m.t === "auth" && typeof m.creds === "string") creds = m.creds;
		} catch {
			// ignore
		}
		if (!ctl.login || ctl.auth || !creds.includes(":")) return safeClose(ws, 4002, "bad login message");
		const auth = await this.sign(`auth|${ctl.name}|${creds}`);
		ws.serializeAttachment({ ...ctl, auth } satisfies Ctl);
		ws.send(JSON.stringify({ t: "ready", url: `${ctl.origin}/${ctl.name}/`, auth: true }));
	}

	async proxy(req: Request, url: URL): Promise<Response> {
		const name = req.headers.get("x-tunnel-name") ?? "";
		const ctl = this.ctl();
		if (!ctl) {
			const r = text(`tunnel: ${name} is offline`, 502);
			r.headers.set("x-tunnel-offline", "1");
			return r;
		}

		const prefix = req.headers.get("x-tunnel-prefix") ?? "";
		const path = url.pathname.slice(prefix.length) || "/";
		if (blocked(path, url.search)) return text("tunnel: not found", 404);
		// A service worker registered from an absolute path would control every
		// tunnel on this origin. Keep them under /<name>/.
		if (req.headers.get("service-worker") === "script" && prefix === "") {
			return text("tunnel: service workers must live under /" + name + "/", 403);
		}
		const ip = clientKey(req);
		if (
			this.streams.size + this.ctx.getWebSockets("v").length >= MAX_STREAMS ||
			(this.perIP.get(ip) ?? 0) + this.ctx.getWebSockets(`ip:${ip}`).length >= MAX_PER_IP
		) {
			return text("tunnel: too many open requests", 503);
		}

		const cookies: string[] = [];
		const { auth, login } = ctl.deserializeAttachment() as Ctl;
		if (login && !auth) return text("tunnel: starting", 503);
		let usedBasic = false;
		if (auth) {
			const r = await this.authorize(req, name, auth);
			if (r === "deny") {
				return new Response("tunnel: login required\n", {
					status: 401,
					headers: { "WWW-Authenticate": `Basic realm="${name}", charset="UTF-8"` },
				});
			}
			if (r === "slow") return text("tunnel: too many login attempts", 429);
			if (r !== "cookie") {
				usedBasic = true;
				cookies.push(r);
			}
		}
		if (prefix !== "" && cookieName(req) !== name) {
			cookies.push(`${COOKIE}=${name}; Path=/; Secure; HttpOnly; SameSite=Lax`);
		}

		const ws = req.headers.get("Upgrade")?.toLowerCase() === "websocket";
		const h: [string, string][] = [];
		for (const [k, v] of req.headers) {
			if (HOP.has(k) || k.startsWith("x-tunnel-")) continue;
			if (k === "authorization" && usedBasic) continue; // the tunnel's password, not the app's
			if (k === "cookie") {
				const rest = withoutTunnelCookies(v);
				if (rest) h.push([k, rest]);
				continue;
			}
			h.push([k, k === "accept-encoding" ? (req.headers.get("x-tunnel-ae") ?? v) : v]);
		}
		const id = this.newId();
		const open = {
			m: req.method,
			u: path,
			q: url.search,
			h,
			ip: req.headers.get("cf-connecting-ip") ?? "",
			x: prefix,
			o: origin(req, url),
			ws,
		};
		const head = new Promise<Response>((resolve) => {
			this.add({
				id, ip, ws, head: req.method === "HEAD", resolve, cookies, absolute: prefix === "",
				credit: WINDOW, inflight: 0, closed: false, dropped: false, buffered: 0,
			});
		});
		send(ctl, OPEN, id, enc.encode(JSON.stringify(open)));
		if (req.body && !ws) {
			this.pump(id, req.body).catch(() => this.reset(id, "request body failed"));
		} else if (!ws) {
			send(ctl, END, id);
		}
		req.signal.addEventListener("abort", () => this.reset(id, "visitor went away"));
		return head;
	}

	// Returns "cookie" for a valid session cookie, a Set-Cookie string for a
	// correct password, "slow" when rate limited, or "deny".
	async authorize(req: Request, name: string, auth: string): Promise<string> {
		const now = Math.floor(Date.now() / 1000);
		const [exp, sig] = cookieValue(req, `${COOKIE}_auth_${name}`).split(".");
		if (exp && sig && Number(exp) > now && (await this.verify(`${name}|${auth}|${exp}`, sig))) return "cookie";

		const basic = req.headers.get("Authorization") ?? "";
		if (!basic.toLowerCase().startsWith("basic ")) return "deny";
		const ip = clientKey(req);
		if (!(await allow(this.env.LOGINS, `${ip}|${name}`))) return "slow";
		let creds: string;
		try {
			creds = new TextDecoder().decode(Uint8Array.from(atob(basic.slice(6).trim()), (c) => c.charCodeAt(0)));
		} catch {
			return "deny";
		}
		const [got, want] = await Promise.all([sha256(await this.sign(`auth|${name}|${creds}`)), sha256(auth)]);
		if (!crypto.subtle.timingSafeEqual(got, want)) return "deny";
		const until = now + AUTH_TTL;
		return `${COOKIE}_auth_${name}=${until}.${await this.sign(`${name}|${auth}|${until}`)}; Path=/; Max-Age=${AUTH_TTL}; Secure; HttpOnly; SameSite=Lax`;
	}

	async key(): Promise<CryptoKey> {
		this.hmacKey ??= await crypto.subtle.importKey("raw", enc.encode(this.env.TOKEN), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
		return this.hmacKey;
	}

	async sign(msg: string): Promise<string> {
		const sig = await crypto.subtle.sign("HMAC", await this.key(), enc.encode(msg));
		return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
	}

	async verify(msg: string, sig: string): Promise<boolean> {
		let raw: Uint8Array;
		try {
			raw = Uint8Array.from(atob(sig.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
		} catch {
			return false;
		}
		return crypto.subtle.verify("HMAC", await this.key(), raw, enc.encode(msg));
	}

	async pump(id: number, body: ReadableStream<Uint8Array>): Promise<void> {
		const reader = body.getReader();
		for (;;) {
			const { done, value } = await reader.read();
			const st = this.streams.get(id);
			if (!st || st.closed) {
				await reader.cancel();
				return;
			}
			const ctl = this.ctl();
			if (!ctl) return;
			if (done) {
				send(ctl, END, id);
				return;
			}
			for (let off = 0; off < value.length; off += CHUNK) {
				const chunk = value.subarray(off, off + CHUNK);
				// Wait for this stream's window and for room in the tunnel-wide budget.
				while (!st.closed && (st.credit < chunk.length || this.outbound + chunk.length > OUT_BUDGET)) {
					await new Promise<void>((r) => {
						st.wake = r;
						this.waiters.add(r);
					});
				}
				if (st.closed) {
					await reader.cancel();
					return;
				}
				st.credit -= chunk.length;
				st.inflight += chunk.length;
				this.outbound += chunk.length;
				send(ctl, DATA, id, chunk);
			}
		}
	}

	async webSocketMessage(ws: WebSocket, msg: string | ArrayBuffer): Promise<void> {
		const tags = this.ctx.getTags(ws);
		if (tags.includes("ctl")) {
			if (typeof msg === "string") await this.login(ws, msg);
			else this.onFrame(new Uint8Array(msg));
			return;
		}
		const id = visitorId(tags);
		const ctl = this.ctl();
		if (!ctl) return safeClose(ws, 1001, "tunnel offline");
		const bytes = typeof msg === "string" ? enc.encode(msg) : new Uint8Array(msg);
		// The client acks each delivered message; a visitor that outpaces the
		// local app (or the laptop's link) gets cut off instead of piling up here.
		// One message on its own always goes; the caps limit what piles up behind it.
		const prev = this.wsInflight.get(id) ?? 0;
		const pending = prev + bytes.length;
		if ((prev > 0 && pending > WS_BACKLOG) || (this.outbound > 0 && this.outbound + bytes.length > OUT_BUDGET)) {
			this.releaseWS(id);
			safeClose(ws, 1008, "sending faster than the tunnel can deliver");
			send(ctl, CLOSE, id, closePayload(1001, "visitor cut off"));
			return;
		}
		this.wsInflight.set(id, pending);
		this.outbound += bytes.length;
		send(ctl, typeof msg === "string" ? TEXT : DATA, id, bytes);
	}

	releaseWS(id: number): void {
		this.outbound -= this.wsInflight.get(id) ?? 0;
		this.wsInflight.delete(id);
		this.wakeAll();
	}

	wakeAll(): void {
		const ws = [...this.waiters];
		this.waiters.clear();
		for (const w of ws) w();
	}

	async webSocketClose(ws: WebSocket, code: number, reason: string): Promise<void> {
		this.closed(ws, code, reason);
	}

	async webSocketError(ws: WebSocket): Promise<void> {
		this.closed(ws, 1011, "error");
	}

	closed(ws: WebSocket, code: number, reason: string): void {
		const tags = this.ctx.getTags(ws);
		if (tags.includes("ctl")) {
			// Only tear down if this was the active client, not one we just replaced.
			if (!this.ctl(ws)) this.closeAll("tunnel client disconnected");
			return;
		}
		const id = visitorId(tags);
		this.releaseWS(id);
		const ctl = this.ctl();
		if (ctl) send(ctl, CLOSE, id, closePayload(code, reason));
	}

	onFrame(b: Uint8Array): void {
		if (b.length < 5) return;
		const type = b[0];
		const id = new DataView(b.buffer, b.byteOffset).getUint32(1);
		const payload = b.subarray(5);
		const st = this.streams.get(id);

		if (!st) {
			// Visitor websocket (possibly from before hibernation).
			const v = this.ctx.getWebSockets(`v:${id}`)[0];
			if (!v) {
				if (type !== RST && type !== CLOSE) this.sendCtl(RST, id);
				return;
			}
			try {
				if (type === WIN) {
					const n = new DataView(payload.buffer, payload.byteOffset).getUint32(0);
					const left = Math.max(0, (this.wsInflight.get(id) ?? 0) - n);
					this.outbound -= (this.wsInflight.get(id) ?? 0) - left;
					this.wsInflight.set(id, left);
					this.wakeAll();
				} else if (type === DATA) v.send(payload);
				else if (type === TEXT) v.send(dec.decode(payload));
				else if (type === CLOSE || type === RST) {
					this.releaseWS(id);
					const [code, reason] = type === CLOSE ? parseClose(payload) : [1011, "tunnel reset"];
					safeClose(v, code, reason);
				}
			} catch {
				safeClose(v, 1011, "tunnel error");
			}
			return;
		}

		try {
			switch (type) {
				case RES:
					this.respond(st, JSON.parse(dec.decode(payload)));
					break;
				case DATA: {
					const n = payload.length;
					if (!st.writer) throw new Error("body before head");
					st.buffered += n;
					this.buffered += n;
					st.writer
						.write(payload)
						.then(() => {
							if (st.dropped) return;
							st.buffered -= n;
							this.buffered -= n;
							this.sendCtl(WIN, id, u32(n));
						})
						.catch(() => this.reset(id, "visitor went away"));
					if (this.buffered > MEMORY_BUDGET) this.shed();
					break;
				}
				case END:
					this.remove(st);
					st.closed = true;
					this.outbound -= st.inflight; // request body the app never read
					st.inflight = 0;
					this.wakeAll();
					st.writer?.close().catch(() => {});
					break;
				case WIN: {
					const n = Math.min(new DataView(payload.buffer, payload.byteOffset).getUint32(0), st.inflight);
					st.credit += n;
					st.inflight -= n;
					this.outbound -= n;
					this.wakeAll();
					break;
				}
				case RST:
					this.drop(st, "the local app reset the connection");
					break;
			}
		} catch {
			this.reset(id, "bad response from the tunnel client");
		}
	}

	// Over the memory budget: cut off the visitor that is reading slowest.
	shed(): void {
		let worst: Stream | undefined;
		for (const st of this.streams.values()) if (!worst || st.buffered > worst.buffered) worst = st;
		if (worst) this.reset(worst.id, "visitor is reading too slowly");
	}

	respond(st: Stream, res: { s: number; h: [string, string][] }): void {
		const headers = new Headers();
		for (const [k, v] of res.h) {
			const lk = String(k).toLowerCase();
			if (BLOCKED_RESPONSE.has(lk)) continue;
			if (lk === "set-cookie" && /^\s*_tunnel/i.test(String(v))) continue; // reserved for routing and login
			try {
				headers.append(k, v);
			} catch {
				// header the runtime won't accept; drop it
			}
		}
		for (const c of st.cookies) headers.append("Set-Cookie", c);
		// /assets/app.js means a different file for every tunnel. If the browser
		// cached one tunnel's copy, another tunnel's page would load it.
		if (st.absolute) {
			headers.set("Cache-Control", "no-store");
			headers.delete("ETag");
			headers.delete("Last-Modified");
		}

		if (st.ws) {
			this.remove(st);
			if (res.s !== 101) {
				st.resolve(text(`tunnel: local websocket refused (${okStatus(res.s)})`, okStatus(res.s)));
				return;
			}
			const { 0: client, 1: server } = new WebSocketPair();
			this.ctx.acceptWebSocket(server, ["v", `v:${st.id}`, `ip:${st.ip}`]);
			st.resolve(new Response(null, { status: 101, webSocket: client, headers }));
			return;
		}

		const status = okStatus(res.s);
		if (NULL_BODY.has(status) || st.head) {
			st.resolve(new Response(null, { status, headers }));
			return; // the client still sends END, which cleans up
		}
		const len = Number(headers.get("content-length"));
		const { readable, writable } =
			headers.has("content-length") && Number.isSafeInteger(len) && len >= 0 ? new FixedLengthStream(len) : new IdentityTransformStream();
		st.writer = writable.getWriter();
		// Bytes are passed through exactly as the local app encoded them.
		const encodeBody = headers.has("content-encoding") ? "manual" : "automatic";
		st.resolve(new Response(readable, { status, headers, encodeBody }));
	}

	reset(id: number, why: string): void {
		const st = this.streams.get(id);
		if (!st) return;
		this.drop(st, why);
		this.sendCtl(RST, id);
	}

	drop(st: Stream, why: string): void {
		this.remove(st);
		st.closed = true;
		if (!st.dropped) {
			st.dropped = true;
			this.buffered -= st.buffered;
			st.buffered = 0;
		}
		this.outbound -= st.inflight;
		st.inflight = 0;
		this.wakeAll();
		st.resolve(text(`tunnel: ${why}`, 502));
		st.writer?.abort(why).catch(() => {});
	}

	closeAll(why: string): void {
		for (const st of [...this.streams.values()]) this.drop(st, why);
		for (const v of this.ctx.getWebSockets("v")) safeClose(v, 1001, "tunnel closed");
		this.wsInflight.clear();
		this.outbound = 0;
	}

	add(st: Stream): void {
		this.streams.set(st.id, st);
		this.perIP.set(st.ip, (this.perIP.get(st.ip) ?? 0) + 1);
	}

	remove(st: Stream): void {
		if (!this.streams.delete(st.id)) return;
		const n = (this.perIP.get(st.ip) ?? 1) - 1;
		if (n > 0) this.perIP.set(st.ip, n);
		else this.perIP.delete(st.ip);
	}

	// The open client socket, ignoring `except` (a socket that is closing).
	ctl(except?: WebSocket): WebSocket | undefined {
		return this.ctx.getWebSockets("ctl").find((w) => w !== except && w.readyState === WebSocket.OPEN);
	}

	sendCtl(type: number, id: number, payload?: Uint8Array): void {
		const ctl = this.ctl();
		if (ctl) send(ctl, type, id, payload);
	}

	newId(): number {
		for (;;) {
			const id = crypto.getRandomValues(new Uint32Array(1))[0];
			if (id !== 0 && !this.streams.has(id) && this.ctx.getWebSockets(`v:${id}`).length === 0) return id;
		}
	}
}

const enc = new TextEncoder();
const dec = new TextDecoder();

function text(body: string, status = 200): Response {
	return new Response(body + "\n", {
		status,
		headers: { "Content-Type": "text/plain; charset=utf-8", "X-Content-Type-Options": "nosniff" },
	});
}

function sha256(s: string): Promise<ArrayBuffer> {
	return crypto.subtle.digest("SHA-256", enc.encode(s));
}

function withoutTunnelCookies(header: string): string {
	return header
		.split(";")
		.map((p) => p.trim())
		.filter((p) => p && !p.startsWith(COOKIE))
		.join("; ");
}

function send(ws: WebSocket, type: number, id: number, payload?: Uint8Array): void {
	const b = new Uint8Array(5 + (payload?.length ?? 0));
	b[0] = type;
	new DataView(b.buffer).setUint32(1, id);
	if (payload) b.set(payload, 5);
	try {
		ws.send(b);
	} catch {
		// socket already closed; the close handler cleans up
	}
}

function safeClose(ws: WebSocket, code: number, reason: string): void {
	try {
		ws.close(code, reason);
	} catch {
		// already closed
	}
}

// The public origin. X-Forwarded-Proto is set by Cloudflare's edge, so the
// scheme the visitor used wins. X-Forwarded-Host is only trusted when the
// worker itself is served from loopback, i.e. behind a local dev proxy.
function origin(req: Request, url: URL): string {
	const proto = req.headers.get("x-forwarded-proto");
	const scheme = proto === "https" || proto === "http" ? proto : url.protocol.slice(0, -1);
	return `${scheme}://${publicHost(req, url)}`;
}

function publicHost(req: Request, url: URL): string {
	const fwd = req.headers.get("x-forwarded-host");
	const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
	return loopback && fwd ? fwd : url.host;
}

function u32(n: number): Uint8Array {
	const b = new Uint8Array(4);
	new DataView(b.buffer).setUint32(0, n);
	return b;
}

function visitorId(tags: string[]): number {
	const t = tags.find((t) => t.startsWith("v:"));
	return t ? Number(t.slice(2)) : 0;
}

function okStatus(s: number): number {
	return Number.isInteger(s) && s >= 200 && s <= 599 ? s : 502;
}

// Codes a peer may not send (1004-1006, 1015, out of range) become 1000.
function closeCode(code: number): number {
	return code === 1000 || (code >= 3000 && code <= 4999) || (code >= 1001 && code <= 1014 && code !== 1004 && code !== 1005 && code !== 1006)
		? code
		: 1000;
}

// Close reasons are capped at 123 bytes of UTF-8; cut on a character boundary.
function reason123(s: string): string {
	while (enc.encode(s).length > 123) s = s.slice(0, -1);
	return s;
}

function closePayload(code: number, reason: string): Uint8Array {
	const r = enc.encode(reason123(reason));
	const b = new Uint8Array(2 + r.length);
	new DataView(b.buffer).setUint16(0, closeCode(code));
	b.set(r, 2);
	return b;
}

function parseClose(b: Uint8Array): [number, string] {
	if (b.length < 2) return [1000, ""];
	return [closeCode(new DataView(b.buffer, b.byteOffset).getUint16(0)), reason123(dec.decode(b.subarray(2)))];
}
