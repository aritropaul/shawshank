// Error pages for browsers. Everything else (curl, fetch, scripts) keeps
// getting the one-line plain-text message, so nothing that parses errors
// changes. The look follows portless: Geist, a pixel-font status code,
// light and dark from the system setting.

import geist400 from "../assets/geist-400.woff2";
import geist500 from "../assets/geist-500.woff2";
import geistMono from "../assets/geist-mono-400.woff2";
import geistPixel from "../assets/geist-pixel.woff2";

export type Kind = "not-found" | "offline" | "local-down" | "login" | "slow" | "busy" | "starting" | "forbidden" | "bad-request";

const FONTS: Record<string, ArrayBuffer> = {
	"geist-400.woff2": geist400,
	"geist-500.woff2": geist500,
	"geist-mono-400.woff2": geistMono,
	"geist-pixel.woff2": geistPixel,
};

// Served at /_tunnel/assets/<file>. The files never change, so browsers keep them.
export function font(file: string): Response | undefined {
	const body = FONTS[file];
	if (!body) return undefined;
	return new Response(body, {
		headers: {
			"Content-Type": "font/woff2",
			"Cache-Control": "public, max-age=31536000, immutable",
			"X-Content-Type-Options": "nosniff",
		},
	});
}

export function wantsHTML(req: Request): boolean {
	return (req.headers.get("Accept") ?? "").includes("text/html");
}

interface Page {
	status: number;
	title: string;
	desc: string; // HTML, built from escaped parts
	command?: string; // shown in a terminal block, escaped
}

// What each error says. `name` and `path` come from the request and are escaped.
function content(kind: Kind, name: string, path: string): Page {
	const n = `<strong>${esc(name)}</strong>`;
	switch (kind) {
		case "offline":
			return {
				status: 502,
				title: "Offline",
				desc: `${n} isn't connected right now. If it's yours, start it again:`,
				command: `tunnel 3000 -n ${name}`,
			};
		case "local-down":
			return {
				status: 502,
				title: "Bad gateway",
				desc: `The tunnel is up, but the app behind it isn't answering.<br>If it's yours, the terminal running <code>tunnel</code> says why.`,
			};
		case "login":
			return { status: 401, title: "Password required", desc: `${n} is password protected. Reload the page to sign in.` };
		case "slow":
			return { status: 429, title: "Too many requests", desc: "Your network sent too many requests in a short time. Wait a few seconds, then reload." };
		case "busy":
			return { status: 503, title: "Busy", desc: `${n} has too many open requests right now. Try again in a moment.` };
		case "starting":
			return { status: 503, title: "Starting", desc: `${n} is still starting up. Reload in a second.` };
		case "forbidden":
			return { status: 403, title: "Forbidden", desc: `Service workers for ${n} have to live under <strong>/${esc(name)}/</strong>.` };
		case "bad-request":
			return { status: 400, title: "Bad request", desc: "This request couldn't be passed on to the app." };
		case "not-found":
		default:
			return { status: 404, title: "Not found", desc: `There's nothing at <strong>${esc(path)}</strong>.` };
	}
}

export function page(kind: Kind, name: string, path: string, status?: number): Response {
	const p = content(kind, name, path);
	const code = status ?? p.status;
	return render(code, `${code} - ${p.title}`, esc(String(code)), p.title, p.desc, p.command, "tunnel");
}

// home is the page at the root: what this is, and how to start a tunnel.
// It never lists tunnels; their names are the only thing keeping them private.
export function home(host: string): Response {
	return render(
		200,
		"tunnel",
		"tunnel",
		"Expose a local port",
		"Every tunnel here lives at its own path, like <strong>/your-app/</strong>. Start one from your machine:",
		"tunnel 3000",
		host,
		true,
	);
}

function render(status: number, title: string, hero: string, sub: string, desc: string, command: string | undefined, footer: string, cursor = false): Response {
	const cmd = command
		? `<div class="section"><div class="terminal"><span class="prompt">$ </span>${esc(command)}${cursor ? '<span class="cursor" aria-hidden="true"></span>' : ""}</div></div>`
		: "";
	const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="robots" content="noindex">
<title>${esc(title)}</title>
<link rel="preload" href="/_tunnel/assets/geist-pixel.woff2" as="font" type="font/woff2" crossorigin>
<style>${STYLES}</style>
</head>
<body>
<main class="page">
<div class="hero"><h1>${hero}</h1><h2>${esc(sub)}</h2></div>
<div class="content"><p class="desc">${desc}</p>${cmd}</div>
<p class="footer">${esc(footer)}</p>
</main>
</body>
</html>`;
	return new Response(html, {
		status,
		headers: {
			"Content-Type": "text/html; charset=utf-8",
			"Cache-Control": "no-store",
			"X-Content-Type-Options": "nosniff",
			"Referrer-Policy": "no-referrer",
			"Content-Security-Policy":
				"default-src 'none'; style-src 'unsafe-inline'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
		},
	});
}

function esc(s: string): string {
	return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

const STYLES = `
@font-face { font-family: 'Geist'; src: url('/_tunnel/assets/geist-400.woff2') format('woff2'); font-weight: 400; font-display: swap; }
@font-face { font-family: 'Geist'; src: url('/_tunnel/assets/geist-500.woff2') format('woff2'); font-weight: 500; font-display: swap; }
@font-face { font-family: 'Geist Mono'; src: url('/_tunnel/assets/geist-mono-400.woff2') format('woff2'); font-weight: 400; font-display: swap; }
@font-face { font-family: 'Geist Pixel'; src: url('/_tunnel/assets/geist-pixel.woff2') format('woff2'); font-weight: 400; font-display: block; }
*, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
:root {
  --bg: #fff;
  --fg: #171717;
  --border: #eaeaea;
  --surface: #fafafa;
  --text-2: #666;
  --text-3: #737373;
  --font-sans: 'Geist', system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
  --font-mono: 'Geist Mono', ui-monospace, 'SFMono-Regular', Menlo, Monaco, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #000;
    --fg: #ededed;
    --border: rgba(255,255,255,0.1);
    --surface: #111;
    --text-2: #888;
    --text-3: #7d7d7d;
  }
}
html { height: 100%; }
body {
  font-family: var(--font-sans);
  background: var(--bg);
  color: var(--fg);
  min-height: 100%;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}
.page {
  min-height: 100vh;
  min-height: 100dvh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 32px 24px;
}
.hero { display: flex; flex-direction: column; align-items: center; }
.hero h1 {
  font-family: 'Geist Pixel', var(--font-mono);
  font-size: clamp(80px, 15vw, 144px);
  font-weight: 400;
  line-height: 1;
  letter-spacing: -0.04em;
  font-variant-numeric: tabular-nums;
}
.hero h2 {
  font-size: 13px;
  font-weight: 400;
  color: var(--text-3);
  margin-top: 16px;
  text-transform: uppercase;
  letter-spacing: 0.15em;
}
.content { margin-top: 56px; width: 100%; max-width: 480px; }
.desc {
  font-size: 14px;
  color: var(--text-2);
  text-align: center;
  line-height: 1.7;
  text-wrap: balance;
}
.desc strong { color: var(--fg); font-weight: 500; overflow-wrap: anywhere; }
.desc code { font-family: var(--font-mono); font-size: 13px; color: var(--fg); }
.section { margin-top: 32px; }
.terminal {
  font-family: var(--font-mono);
  font-size: 13px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 14px 20px;
  line-height: 1.7;
  color: var(--fg);
  overflow-wrap: anywhere;
}
.terminal .prompt { color: var(--text-3); user-select: none; }
.cursor {
  display: inline-block;
  width: 0.6em;
  height: 1.2em;
  margin-left: 0.15em;
  vertical-align: -0.25em;
  background: var(--fg);
  opacity: 0.8;
  animation: blink 1.1s steps(1) infinite;
}
@keyframes blink { 50% { opacity: 0; } }
@media (prefers-reduced-motion: reduce) { .cursor { animation: none; } }
.footer {
  margin-top: 64px;
  font-size: 11px;
  color: var(--text-3);
  font-family: var(--font-mono);
  letter-spacing: 0.08em;
}
`;
