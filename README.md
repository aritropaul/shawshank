# shawshank

Expose a local port to the internet through your own Cloudflare Worker. It works like ngrok, except the server is yours and it runs on the Workers free plan.

```
$ tunnel 3000

  tunnel  https://tunnel.you.workers.dev/k3j9x2ab/  →  http://localhost:3000

  21:31:27  GET    200      4ms  /k3j9x2ab/
  21:31:28  GET    200      1ms  /src/App.tsx
  21:31:28  WS     101      1ms  /?token=GKKx95ilQdTD
```

There are two parts: a Cloudflare Worker (`worker/`) that visitors hit, and a Go CLI called `tunnel` that runs on your machine and keeps one WebSocket open to the Worker.

## Setup

You need a Cloudflare account (free is fine), Go 1.26.8 or newer, and Bun or Node.

### 1. Deploy the Worker

```sh
git clone https://github.com/aritropaul/shawshank
cd shawshank/worker
bun install                      # or: npm install
bunx wrangler login              # or: npx wrangler login
bunx wrangler deploy
```

`deploy` prints your Worker's URL, something like `https://tunnel.<your-subdomain>.workers.dev`. To call the Worker something other than `tunnel`, change `name` in `wrangler.jsonc` first.

Now give it a token. Only clients with this token can open tunnels:

```sh
openssl rand -hex 24             # copy the output, this is your token
bunx wrangler secret put TOKEN   # paste it when asked
```

### 2. Install the CLI

From the repo root:

```sh
go build -o ~/.local/bin/tunnel .    # any directory on your PATH works
tunnel login https://tunnel.<your-subdomain>.workers.dev
```

`login` asks for the token (or reads it from stdin) and saves both to `~/.config/tunnel/config`, readable only by you.

### 3. Expose something

```sh
tunnel 3000
```

Open the URL it prints. Press Ctrl-C to stop.

## Usage

```
tunnel 3000                      https://tunnel.<you>.workers.dev/<name>/ → localhost:3000
tunnel 3000 -n myapp             https://tunnel.<you>.workers.dev/myapp/
TUNNEL_AUTH=me:secret tunnel 3000   visitors have to log in first
tunnel localhost:8080            host:port works too
tunnel https://localhost:8443    the local app speaks HTTPS (self-signed is fine on localhost)
```

| Flag | Meaning |
|---|---|
| `-n name` | Path name. Default: random, but the same every time for this machine and port. |
| `-auth user:pass` | Make visitors log in (HTTP Basic). Prefer `$TUNNEL_AUTH`, which other users can't see in `ps`. |
| `-s url` | Worker URL. Overrides the saved login and `$TUNNEL_SERVER`. |
| `-t token` | Token. Overrides the saved login and `$TUNNEL_TOKEN`. |

Flags can go before or after the port. If the connection drops, the CLI reconnects with backoff. If another client starts with the same name, the newer one takes over and the older one exits.

## How paths work

Each tunnel lives at `/<name>/` on your Worker, and the name is stripped before the request reaches your app: `/<name>/foo` arrives as `/foo`.

Apps built for `/` also request absolute paths like `/assets/app.js` or `/src/App.tsx`, which have no name in them. The Worker routes those using the page that requested them (`Referer`) and a `_tunnel` cookie it sets on your first visit. A Vite dev server, hot reload included, works this way.

Your app sees the request as if it were local:

- `Host` is `localhost:<port>`, so dev servers that check it (such as Vite's `allowedHosts`) accept it.
- `Origin` and `Referer` are rewritten to the local address, so CSRF checks pass.
- `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host` and `X-Forwarded-Prefix: /<name>` describe the public request.
- A redirect to `/login` comes back as `/<name>/login`, and `http://localhost:3000/x` becomes the public URL.

Streaming bodies, server-sent events, WebSockets, compressed responses, `Content-Length`, multiple `Set-Cookie` headers, 204, 304 and HEAD all pass through.

## Security

**Who can open tunnels.** Only clients with the token. The Worker compares it in constant time, and Cloudflare redacts the `Authorization` header in its logs. The saved token is only ever sent to the saved server, and only over HTTPS: pointing `-s` somewhere else needs its own `-t`. `tunnel login` reads the token from stdin so it stays out of your shell history. Prefer `$TUNNEL_TOKEN` and `$TUNNEL_AUTH` to flags, since other users on your machine can see flags in `ps`.

**Who can reach your app.** Anyone who has the URL, unless you set a password. Default names are 10 random characters derived from a secret in `~/.config/tunnel/id`, so they can't be guessed even though this code is public. Names you pick with `-n` can be.

With `TUNNEL_AUTH=user:pass` (or `-auth`), visitors log in with HTTP Basic and get a signed session cookie that lasts 7 days. The password reaches the Worker inside the encrypted WebSocket, never in a header or URL, and the Worker keeps only an HMAC of it. Your app never sees it. Each IP gets 60 tries a minute per tunnel. If the Worker can't enforce a password, the CLI refuses to start rather than exposing the app unprotected.

**What never reaches your app.** These get a 404 before they leave Cloudflare, and the CLI checks them again:

- Secret files: `.env*`, `.git`, `.ssh`, `.aws`, `.config`, `.npmrc`, `.netrc`, `.htpasswd`, `id_rsa` and friends, `*.pem`, `*.key`, `*.p12`, `*.tfstate`, `*.sqlite`. Matching ignores case and encoding, including Unicode tricks like `.ſsh` that a case-insensitive disk would still open.
- Debug consoles that run code or dump secrets for anything coming from localhost: Werkzeug's debugger, Rails web-console, Laravel Ignition, the Symfony profiler, and Django's debug toolbar.
- Spoofed proxy headers (`X-Forwarded-*`, `Forwarded`, `X-Real-IP` and similar). The tunnel sets its own.

**Your app thinks visitors are local.** Requests arrive from 127.0.0.1 with `Host: localhost:<port>`, which is what makes dev servers work. It also means anything your app reserves for localhost (admin pages, `INTERNAL_IPS`, debug routes of your own) is open to every visitor. The blocklist only covers the well-known consoles.

**Tunnels share one browser origin.** Apps open in the same browser can read each other's cookies and storage, and can make requests to each other. A password doesn't stop another tunneled app from reading a protected one through your logged-in browser. Treat everything you tunnel at once as one site, and don't tunnel something you don't trust next to something private. The Worker does block the worst of it: apps can't set the tunnel's own cookies, send `Clear-Site-Data` or `Service-Worker-Allowed`, or register a service worker outside `/<name>/`. Responses for un-prefixed paths like `/assets/app.js` are marked `no-store`, so one tunnel can't plant a cached file that another tunnel's page then loads.

**Limits.** Per IP and per Cloudflare location: 1,000 requests per 10 seconds, and 300 lookups a minute of tunnel names not recently seen online. Each tunnel holds at most 512 open requests and websockets, 256 of them from one IP. Each direction has a 64 MB buffer budget, and each visitor websocket can have at most 16 MB in flight; visitors who read or send too slowly get cut off rather than filling memory. On the free plan the 100,000 requests a day are shared by every Worker on your account, and limits counted per location can't stop a distributed flood from using them up. Stop the tunnel and the URL goes dark.

**Other details.** Visitors see generic error pages; details go to your terminal. Query string values are hidden in both the Worker's logs and your terminal. TLS certificates are only skipped for local targets on loopback addresses. When the target is `localhost`, the CLI pins the address family your app actually listens on, so another process can't catch visitors on the other one. Each deploy drops connected clients, and they reconnect on their own.

## Errors

| You see | Meaning |
|---|---|
| `tunnel: the local app isn't responding` (502) | Your local app isn't running. The terminal says why. |
| `tunnel: <name> is offline` (502) | No client is connected under that name. |
| `bad token (401)` | The token doesn't match the Worker's `TOKEN` secret. |
| `tunnel: login required` (401) | The tunnel was started with `-auth`. |
| `tunnel: too many requests` (429) | One IP went over a rate limit (see Security). |
| `tunnel: not found` (404) | A blocked path, or no tunnel by that name. |
| `another client took over <name>, exiting` | The same name was started somewhere else. |

## How it works

```
visitor → Worker → Durable Object (one per name) ⇄ WebSocket ⇄ tunnel CLI → localhost
```

The Worker sends each request to a Durable Object named after the tunnel. The Durable Object relays it over the client's WebSocket as binary frames: `u8 type | u32 stream id | payload`. Request and response heads are JSON, and bodies are raw bytes in chunks of up to 256 KB. Each stream has a 4 MB flow-control window in each direction, so a slow visitor can't fill the Durable Object's memory. The Durable Object uses WebSocket hibernation, so an idle tunnel costs nothing.

On a home connection, one download stream ran at 21–23 MB/s, the full speed of the line's upload. Visiting your own tunnel from the machine running it is slower, because your upload and download then share one link.

## Development

```sh
cd worker
echo "TOKEN=$(openssl rand -hex 24)" > .dev.vars
bunx wrangler dev                # http://localhost:8787
```

`bun run dev` does the same behind portless at `https://tunnel.lcl`. `bun run check` typechecks the Worker.

The tests are end-to-end: they start local apps and send real traffic through a running Worker. They read the token from `worker/.dev.vars`.

```sh
TUNNEL_TEST_SERVER=http://localhost:8787 go test -race ./...

# against your deployed Worker
TUNNEL_TEST_SERVER=https://tunnel.<you>.workers.dev TUNNEL_TEST_TOKEN=<token> go test -race ./...
```
