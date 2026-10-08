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

You need a Cloudflare account (free is fine), Go 1.26 or newer, and Bun or Node.

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
tunnel login https://tunnel.<your-subdomain>.workers.dev <token>
```

`login` saves the server and token to `~/.config/tunnel/config`.

### 3. Expose something

```sh
tunnel 3000
```

Open the URL it prints. Press Ctrl-C to stop.

## Usage

```
tunnel 3000                      https://tunnel.<you>.workers.dev/<name>/ → localhost:3000
tunnel 3000 -n myapp             https://tunnel.<you>.workers.dev/myapp/
tunnel localhost:8080            host:port works too
tunnel https://localhost:8443    the local app speaks HTTPS (its certificate isn't checked)
```

| Flag | Meaning |
|---|---|
| `-n name` | Path name. Default: a hash of your hostname and port, so the same command always gets the same URL. |
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

## Things to know

- Anyone with a tunnel URL can reach your local app while the tunnel is up. The token only controls who can open tunnels.
- All tunnels share one origin, so cookies and localStorage set by one tunneled app are visible to the others.
- The Workers free plan allows 100,000 requests a day, for the Worker and the Durable Objects each.
- Each deploy of the Worker drops connected clients, and they reconnect on their own.

## Errors

| You see | Meaning |
|---|---|
| `tunnel: nothing answered on http://localhost:3000` (502) | Your local app isn't running. |
| `tunnel: <name> is offline` (502) | No client is connected under that name. |
| `bad token (401)` | The token doesn't match the Worker's `TOKEN` secret. |
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
