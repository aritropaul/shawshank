import { DurableObject } from "cloudflare:workers";

// Wire protocol over the client's WebSocket. Every binary message is one frame:
//   u8 type | u32 stream id (big endian) | payload
// OPEN and RES payloads are JSON, DATA/TEXT are raw bytes, WIN is a u32 credit,
// CLOSE is u16 code + utf-8 reason.
const OPEN = 1; // DO → client: new visitor request {m, u, h, ip, x, o, ws}
const DATA = 2; // both: body bytes, or a binary websocket message
const END = 3; // both: no more body in this direction
const WIN = 4; // both: receiver consumed n bytes, sender may send n more
const RST = 5; // both: abort the stream
const TEXT = 6; // both: text websocket message
const CLOSE = 7; // both: websocket closed
const RES = 8; // client → DO: response head {s, h}

const CHUNK = 256 * 1024; // max body bytes per frame
const WINDOW = 4 * 1024 * 1024; // per-stream flow-control window, each direction

const NAME = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const COOKIE = "_tunnel";
const NULL_BODY = new Set([101, 204, 205, 304]);
const HOP = new Set([
	"connection", "keep-alive", "proxy-connection", "transfer-encoding", "te", "upgrade", "host",
	"sec-websocket-key", "sec-websocket-version", "sec-websocket-extensions",
]);

// Names recently found offline, so absolute-path assets (/src/x.ts, /assets/y.js)
// don't cost a liveness check on every request. Isolate-local and short-lived.
const offline = new Map<string, number>();

export default {
	async fetch(req, env): Promise<Response> {
		const url = new URL(req.url);
		if (url.pathname === "/_tunnel/connect") return connect(req, env, url);

		// Who is this request for? /<name>/... is explicit. Absolute paths from a
		// tunneled app (/assets/app.js, /src/App.tsx) carry no name, so fall back
		// to the page that asked for it (Referer) and then the last tunnel visited
		// (cookie). A name that isn't the cookie's must prove it's live, since
		// /src/... and /assets/... look like names too.
		const seg = url.pathname.split("/")[1] ?? "";
		const name = NAME.test(seg) ? seg : "";
		const ref = refererName(req, url);
		const cookie = cookieName(req);
		if (name && name === cookie) return forward(req, env, name, true);

		const candidates = [...new Set([name, ref, cookie].filter(Boolean))];
		if (candidates.length === 0) {
			return url.pathname === "/"
				? new Response("tunnel\n")
				: new Response("tunnel: not found\n", { status: 404 });
		}
		for (const [i, c] of candidates.entries()) {
			if (i === candidates.length - 1 || (await isLive(env, c))) return forward(req, env, c, c === name);
		}
		return new Response("tunnel: not found\n", { status: 404 });
	},
} satisfies ExportedHandler<Env>;

async function connect(req: Request, env: Env, url: URL): Promise<Response> {
	if (req.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
		return new Response("tunnel: expected websocket\n", { status: 426 });
	}
	if (!(await tokenOK(req.headers.get("Authorization") ?? "", env.TOKEN))) {
		return new Response("tunnel: bad token\n", { status: 401 });
	}
	const name = url.searchParams.get("name") ?? "";
	if (!NAME.test(name)) return new Response("tunnel: invalid name (a-z, 0-9, -)\n", { status: 400 });
	offline.delete(name);
	return env.TUNNEL.getByName(name).fetch(req);
}

function forward(req: Request, env: Env, name: string, strip: boolean): Promise<Response> {
	const r = new Request(req);
	r.headers.set("x-tunnel-name", name);
	r.headers.set("x-tunnel-prefix", strip ? "/" + name : "");
	const ae = req.cf?.clientAcceptEncoding;
	if (typeof ae === "string") r.headers.set("x-tunnel-ae", ae);
	return env.TUNNEL.getByName(name).fetch(r);
}

async function isLive(env: Env, name: string): Promise<boolean> {
	const until = offline.get(name);
	if (until && until > Date.now()) return false;
	const live = await env.TUNNEL.getByName(name).live();
	if (live) offline.delete(name);
	else offline.set(name, Date.now() + 5000);
	return live;
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

function cookieName(req: Request): string {
	for (const part of (req.headers.get("Cookie") ?? "").split(";")) {
		const [k, v] = part.trim().split("=", 2);
		if (k === COOKIE && v && NAME.test(v)) return v;
	}
	return "";
}

async function tokenOK(header: string, token: string | undefined): Promise<boolean> {
	if (!token) return false;
	const enc = new TextEncoder();
	const [a, b] = await Promise.all([
		crypto.subtle.digest("SHA-256", enc.encode(header)),
		crypto.subtle.digest("SHA-256", enc.encode("Bearer " + token)),
	]);
	return crypto.subtle.timingSafeEqual(a, b);
}

interface Stream {
	id: number;
	ws: boolean;
	head: boolean; // HEAD request: response has no body
	resolve: (r: Response) => void;
	writer?: WritableStreamDefaultWriter<Uint8Array>;
	credit: number; // request-body bytes we may still send
	wake?: () => void;
	closed: boolean;
}

export class Tunnel extends DurableObject<Env> {
	// In-flight HTTP streams. Memory only: a pending request keeps the object
	// awake, and visitor websockets are found again through their tags.
	streams = new Map<number, Stream>();

	live(): boolean {
		return this.ctl() !== undefined;
	}

	async fetch(req: Request): Promise<Response> {
		const url = new URL(req.url);
		if (url.pathname === "/_tunnel/connect") return this.accept(req, url);
		return this.proxy(req, url);
	}

	accept(req: Request, url: URL): Response {
		// Last client wins: the old one is told it was replaced and exits.
		for (const old of this.ctx.getWebSockets("ctl")) old.close(4001, "replaced");
		this.closeAll("tunnel client reconnected");
		const { 0: client, 1: server } = new WebSocketPair();
		this.ctx.acceptWebSocket(server, ["ctl"]);
		const name = url.searchParams.get("name");
		server.send(JSON.stringify({ t: "ready", url: `${origin(req, url)}/${name}/` }));
		return new Response(null, { status: 101, webSocket: client });
	}

	async proxy(req: Request, url: URL): Promise<Response> {
		const name = req.headers.get("x-tunnel-name") ?? "";
		const ctl = this.ctl();
		if (!ctl) return new Response(`tunnel: ${name} is offline\n`, { status: 502 });

		const prefix = req.headers.get("x-tunnel-prefix") ?? "";
		const ws = req.headers.get("Upgrade")?.toLowerCase() === "websocket";
		const h: [string, string][] = [];
		for (const [k, v] of req.headers) {
			if (HOP.has(k) || k.startsWith("x-tunnel-")) continue;
			h.push([k, k === "accept-encoding" ? (req.headers.get("x-tunnel-ae") ?? v) : v]);
		}
		const id = this.newId();
		const open = {
			m: req.method,
			u: url.pathname.slice(prefix.length) || "/",
			q: url.search,
			h,
			ip: req.headers.get("cf-connecting-ip") ?? "",
			x: prefix,
			o: origin(req, url),
			ws,
			c: prefix !== "" && cookieName(req) !== name ? name : "", // ask the client to set the routing cookie
		};
		const head = new Promise<Response>((resolve) => {
			this.streams.set(id, { id, ws, head: req.method === "HEAD", resolve, credit: WINDOW, closed: false });
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
				while (st.credit < chunk.length && !st.closed) await new Promise<void>((r) => (st.wake = r));
				if (st.closed) {
					await reader.cancel();
					return;
				}
				st.credit -= chunk.length;
				send(ctl, DATA, id, chunk);
			}
		}
	}

	async webSocketMessage(ws: WebSocket, msg: string | ArrayBuffer): Promise<void> {
		const tags = this.ctx.getTags(ws);
		if (tags.includes("ctl")) {
			if (typeof msg !== "string") this.onFrame(new Uint8Array(msg));
			return;
		}
		const id = visitorId(tags);
		const ctl = this.ctl();
		if (!ctl) return ws.close(1001, "tunnel offline");
		if (typeof msg === "string") send(ctl, TEXT, id, enc.encode(msg));
		else send(ctl, DATA, id, new Uint8Array(msg));
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
		const ctl = this.ctl();
		if (ctl) send(ctl, CLOSE, visitorId(tags), closePayload(code, reason));
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
			if (type === DATA) v.send(payload);
			else if (type === TEXT) v.send(dec.decode(payload));
			else if (type === CLOSE || type === RST) {
				const [code, reason] = type === CLOSE ? parseClose(payload) : [1011, "tunnel reset"];
				v.close(code, reason);
			}
			return;
		}

		switch (type) {
			case RES:
				this.respond(st, JSON.parse(dec.decode(payload)));
				break;
			case DATA: {
				const n = payload.length;
				st.writer
					?.write(payload)
					.then(() => this.sendCtl(WIN, id, u32(n)))
					.catch(() => this.reset(id, "visitor went away"));
				break;
			}
			case END:
				this.streams.delete(id);
				st.closed = true;
				st.wake?.();
				st.writer?.close().catch(() => {});
				break;
			case WIN:
				st.credit += new DataView(payload.buffer, payload.byteOffset).getUint32(0);
				st.wake?.();
				break;
			case RST:
				this.drop(st, dec.decode(payload) || "local app reset the connection");
				break;
		}
	}

	respond(st: Stream, res: { s: number; h: [string, string][] }): void {
		const headers = new Headers();
		for (const [k, v] of res.h) headers.append(k, v);

		if (st.ws) {
			this.streams.delete(st.id);
			if (res.s !== 101) {
				st.resolve(new Response(`tunnel: local websocket refused (${res.s})\n`, { status: okStatus(res.s) }));
				return;
			}
			const { 0: client, 1: server } = new WebSocketPair();
			this.ctx.acceptWebSocket(server, ["v", `v:${st.id}`]);
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
			headers.has("content-length") && Number.isSafeInteger(len) ? new FixedLengthStream(len) : new IdentityTransformStream();
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
		this.streams.delete(st.id);
		st.closed = true;
		st.wake?.();
		st.resolve(new Response(`tunnel: ${why}\n`, { status: 502 }));
		st.writer?.abort(why).catch(() => {});
	}

	closeAll(why: string): void {
		for (const st of [...this.streams.values()]) this.drop(st, why);
		for (const v of this.ctx.getWebSockets("v")) v.close(1001, "tunnel closed");
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
	return s >= 200 && s <= 599 ? s : 502;
}

// Codes a peer may not send (1005, 1006, 1015) become 1000.
function closeCode(code: number): number {
	return code === 1000 || (code >= 3000 && code <= 4999) || (code >= 1001 && code <= 1014 && code !== 1004 && code !== 1005 && code !== 1006)
		? code
		: 1000;
}

function closePayload(code: number, reason: string): Uint8Array {
	const r = enc.encode(reason).subarray(0, 123);
	const b = new Uint8Array(2 + r.length);
	new DataView(b.buffer).setUint16(0, closeCode(code));
	b.set(r, 2);
	return b;
}

function parseClose(b: Uint8Array): [number, string] {
	if (b.length < 2) return [1000, ""];
	return [closeCode(new DataView(b.buffer, b.byteOffset).getUint16(0)), dec.decode(b.subarray(2, 125))];
}

