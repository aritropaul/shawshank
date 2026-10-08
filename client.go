package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

// Frame types, mirrored in worker/src/index.ts. Every binary message is
// u8 type | u32 stream id (big endian) | payload.
const (
	fOpen  = 1 // worker → client: visitor request (JSON)
	fData  = 2 // both: body bytes or binary websocket message
	fEnd   = 3 // both: body finished
	fWin   = 4 // both: u32 credit
	fRst   = 5 // both: abort stream
	fText  = 6 // both: text websocket message
	fClose = 7 // both: u16 code + reason
	fRes   = 8 // client → worker: response head (JSON)

	chunkSize  = 256 << 10 // max body bytes per frame
	window     = 4 << 20   // per-stream flow-control window
	maxStreams = 512       // concurrent visitor requests + websockets
	wsBacklog  = 16 << 20  // visitor websocket bytes queued per socket for a slow local app
	wsBudget   = 128 << 20 // and across all sockets
	wsMaxMsg   = 32<<20 - 64
	maxHead    = 1 << 20 // response head (status + headers) size
)

type client struct {
	server   string // https://tunnel.example.workers.dev
	token    string
	name     string
	target   string // local host:port
	localTLS bool
	auth     string // "user:pass" visitors must send; goes to the worker inside the websocket

	out   io.Writer
	color bool
	onUp  func(url string) // each time the tunnel is (re)established

	tr        *http.Transport // HTTP to the local app
	wsHTTP    *http.Client    // websocket dials to the local app
	localDown atomic.Bool
	wsQueued  atomic.Int64 // visitor websocket bytes waiting for the local app

	pinMu    sync.Mutex
	dialAddr string // where "localhost:port" actually answers, once known
}

type fatalError struct{ msg string }

func (e fatalError) Error() string { return e.msg }

func newClient() *client {
	c := &client{out: io.Discard}
	c.tr = &http.Transport{
		Proxy:                  nil,
		DialContext:            c.dialLocal,
		MaxIdleConnsPerHost:    256,
		IdleConnTimeout:        90 * time.Second,
		DisableCompression:     true, // pass bodies through exactly as the app encoded them
		MaxResponseHeaderBytes: maxHead,
		WriteBufferSize:        64 << 10,
		ReadBufferSize:         64 << 10,
	}
	c.wsHTTP = &http.Client{
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            c.dialLocal,
			DisableKeepAlives:      true,
			MaxResponseHeaderBytes: maxHead,
		},
		// A redirect from the local app must not send the visitor's websocket
		// somewhere else on this machine's network.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return c
}

// setLocalTLS decides certificate checking for an https/wss target:
// self-signed is normal on loopback, anything else gets verified.
func (c *client) setLocalTLS() {
	cfg := &tls.Config{InsecureSkipVerify: isLoopback(c.target)}
	c.tr.TLSClientConfig = cfg
	c.wsHTTP.Transport.(*http.Transport).TLSClientConfig = cfg
}

// dialLocal connects to the target. For "localhost" it pins the address
// family that actually answers, so another local process can't pick up
// visitors by listening on the other one.
func (c *client) dialLocal(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	if addr == c.target && strings.HasPrefix(c.target, "localhost:") {
		c.pinMu.Lock()
		if c.dialAddr == "" {
			c.dialAddr = c.probeLocalhost(ctx)
		}
		pinned := c.dialAddr
		c.pinMu.Unlock()
		if pinned != "" {
			addr = pinned
		}
	}
	return d.DialContext(ctx, network, addr)
}

func (c *client) probeLocalhost(ctx context.Context) string {
	port := c.target[len("localhost:"):]
	try := func(host string) bool {
		conn, err := (&net.Dialer{Timeout: 300 * time.Millisecond}).DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		if err == nil {
			conn.Close()
		}
		return err == nil
	}
	switch {
	case try("127.0.0.1"):
		return net.JoinHostPort("127.0.0.1", port)
	case try("::1"):
		return net.JoinHostPort("::1", port)
	}
	return "" // nothing listening yet; try again on the next request
}

func (c *client) run(ctx context.Context) error {
	backoff := time.Second
	up := false
	for {
		start := time.Now()
		err := c.session(ctx, func(u string) {
			if !up {
				lock := ""
				if c.auth != "" {
					lock = "  " + c.paint("2", "(password required)")
				}
				fmt.Fprintf(c.out, "\n  %s  %s  →  %s%s\n\n", c.paint("1", "tunnel"), c.paint("1;4", printable(u)), c.localURL(), lock)
			} else {
				fmt.Fprintf(c.out, "  %s\n", c.paint("32", "reconnected"))
			}
			up = true
			if c.onUp != nil {
				c.onUp(u)
			}
		})
		var fe fatalError
		if errors.As(err, &fe) {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
		// Only a connection that stayed up resets the backoff, so a server that
		// accepts and immediately drops us doesn't get hammered.
		if time.Since(start) > 30*time.Second {
			backoff = time.Second
		}
		wait := backoff/2 + rand.N(backoff/2+1)
		fmt.Fprintf(c.out, "  %s %s, retrying in %s\n", c.paint("33", "disconnected:"), printable(err.Error()), wait.Round(100*time.Millisecond))
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

type session struct {
	c       *client
	ws      *websocket.Conn
	ctx     context.Context
	mu      sync.Mutex
	streams map[uint32]*stream
}

func (c *client) session(ctx context.Context, onUp func(string)) error {
	u, err := url.Parse(c.server)
	if err != nil || u.Host == "" {
		return fatalError{"bad server address " + c.server}
	}
	switch {
	case u.Scheme == "https":
		u.Scheme = "wss"
	case u.Scheme == "http" && isLoopback(u.Host):
		u.Scheme = "ws"
	default:
		return fatalError{"refusing to send the token to " + c.server + ": use https"}
	}
	u.Path = "/_tunnel/connect"
	u.RawQuery = "name=" + url.QueryEscape(c.name)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	dctx, dcancel := context.WithTimeout(ctx, 15*time.Second)
	hdr := http.Header{"Authorization": {"Bearer " + c.token}}
	if c.auth != "" {
		hdr.Set("X-Tunnel-Login", "1") // the password itself follows inside the websocket
	}
	ws, resp, err := websocket.Dial(dctx, u.String(), &websocket.DialOptions{
		HTTPHeader: hdr,
		HTTPClient: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	})
	dcancel()
	if err != nil {
		if resp != nil && resp.StatusCode != http.StatusSwitchingProtocols {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			msg := strings.TrimSpace(string(body))
			if msg == "" {
				msg = resp.Status
			}
			if resp.StatusCode == http.StatusUnauthorized {
				return fatalError{"bad token (401)"}
			}
			if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
				return fatalError{msg}
			}
			return errors.New(msg)
		}
		return err
	}
	defer ws.CloseNow()
	ws.SetReadLimit(33 << 20) // the worker relays messages of up to 32 MiB plus a frame header
	if c.auth != "" {
		j, _ := json.Marshal(map[string]string{"t": "auth", "creds": c.auth})
		if err := ws.Write(ctx, websocket.MessageText, j); err != nil {
			return err
		}
	}

	s := &session{c: c, ws: ws, ctx: ctx, streams: map[uint32]*stream{}}
	go s.keepalive(cancel)
	defer s.abortAll()

	for {
		typ, msg, err := ws.Read(ctx)
		if err != nil {
			if websocket.CloseStatus(err) == 4001 {
				return fatalError{"another client took over " + c.name + ", exiting"}
			}
			if ctx.Err() != nil {
				return errors.New("connection lost")
			}
			return err
		}
		if typ == websocket.MessageText {
			var m struct {
				T, URL string
				Auth   bool
			}
			if json.Unmarshal(msg, &m) == nil && m.T == "ready" {
				if c.auth != "" && !m.Auth {
					return fatalError{"this worker doesn't support -auth yet; redeploy it before exposing anything"}
				}
				onUp(m.URL)
			}
			continue
		}
		s.dispatch(msg)
	}
}

// keepalive pings so idle tunnels survive Cloudflare's idle timeout and dead
// connections are noticed. Protocol pings don't wake a hibernating object.
func (s *session) keepalive(cancel context.CancelFunc) {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			ctx, done := context.WithTimeout(s.ctx, 15*time.Second)
			err := s.ws.Ping(ctx)
			done()
			if err != nil {
				cancel()
				return
			}
		}
	}
}

func (s *session) dispatch(msg []byte) {
	if len(msg) < 5 {
		return
	}
	typ, id, p := msg[0], binary.BigEndian.Uint32(msg[1:5]), msg[5:]
	if typ == fOpen {
		var o open
		if json.Unmarshal(p, &o) != nil {
			s.send(fRst, id, nil)
			return
		}
		s.mu.Lock()
		_, dup := s.streams[id]
		full := len(s.streams) >= maxStreams || dup
		var st *stream
		if !full {
			st = newStream(s, id, o.WS)
			s.streams[id] = st
		}
		s.mu.Unlock()
		if full {
			s.reject(id, o.WS, http.StatusServiceUnavailable, "tunnel: too many open requests\n")
			return
		}
		go st.serve(o)
		return
	}
	s.mu.Lock()
	st := s.streams[id]
	s.mu.Unlock()
	if st == nil {
		return
	}
	switch typ {
	case fData:
		if st.isWS {
			st.queue(wsMsg{typ: websocket.MessageBinary, data: p})
		} else if !st.body.push(p) {
			st.abort()
			s.send(fRst, id, nil)
		}
	case fText:
		st.queue(wsMsg{typ: websocket.MessageText, data: p})
	case fEnd:
		st.body.finish(nil)
	case fWin:
		if len(p) >= 4 {
			st.addCredit(int(binary.BigEndian.Uint32(p)))
		}
	case fRst:
		st.abort()
	case fClose:
		code, reason := websocket.StatusNormalClosure, ""
		if len(p) >= 2 {
			code, reason = websocket.StatusCode(binary.BigEndian.Uint16(p)), string(p[2:])
		}
		st.toLocal.push(wsMsg{close: true, code: code, reason: reason})
	}
}

func (s *session) send(typ byte, id uint32, payload []byte) error {
	b := make([]byte, 5+len(payload))
	copy(b[5:], payload)
	return s.sendFrame(typ, id, b)
}

// sendFrame writes a frame whose first 5 bytes are reserved for the header.
func (s *session) sendFrame(typ byte, id uint32, b []byte) error {
	b[0] = typ
	binary.BigEndian.PutUint32(b[1:5], id)
	return s.ws.Write(s.ctx, websocket.MessageBinary, b)
}

func (s *session) sendJSON(typ byte, id uint32, v any) error {
	j, _ := json.Marshal(v)
	return s.send(typ, id, j)
}

// reject answers a request without involving the local app.
func (s *session) reject(id uint32, ws bool, code int, msg string) {
	if ws {
		s.sendJSON(fRes, id, map[string]any{"s": code, "h": [][2]string{}})
		return
	}
	s.sendJSON(fRes, id, map[string]any{"s": code, "h": [][2]string{
		{"Content-Type", "text/plain; charset=utf-8"},
		{"Content-Length", strconv.Itoa(len(msg))},
	}})
	s.send(fData, id, []byte(msg))
	s.send(fEnd, id, nil)
}

func (s *session) remove(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

func (s *session) abortAll() {
	s.mu.Lock()
	all := s.streams
	s.streams = map[uint32]*stream{}
	s.mu.Unlock()
	for _, st := range all {
		st.abort()
	}
}

func (c *client) logRequest(method string, code int, d time.Duration, path string) {
	col := "32"
	switch {
	case code == 101:
		col = "35"
	case code >= 500:
		col = "31"
	case code >= 400:
		col = "33"
	case code >= 300:
		col = "36"
	}
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i] + redactQuery(path[i:])
	}
	fmt.Fprintf(c.out, "  %s  %-6s %s %6dms  %s\n",
		c.paint("2", time.Now().Format("15:04:05")), printable(method), c.paint(col, strconv.Itoa(code)), d.Milliseconds(), printable(path))
}

func (c *client) localURL() string {
	if c.localTLS {
		return "https://" + c.target
	}
	return "http://" + c.target
}

func (c *client) paint(code, s string) string {
	if !c.color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// parseTarget turns "3000", "localhost:3000", "http://host:3000/x" into host:port.
func parseTarget(s string) (addr string, https bool, err error) {
	switch {
	case strings.HasPrefix(s, "https://"):
		https, s = true, s[len("https://"):]
	case strings.HasPrefix(s, "http://"):
		s = s[len("http://"):]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return "", false, errors.New("missing local port")
	}
	if _, err := strconv.Atoi(s); err == nil {
		return "localhost:" + s, https, nil
	}
	if _, _, err := net.SplitHostPort(s); err != nil {
		if https {
			return net.JoinHostPort(s, "443"), true, nil
		}
		return net.JoinHostPort(s, "80"), false, nil
	}
	return s, https, nil
}

// defaultName is stable per machine + target, so restarting gives the same
// URL, but unguessable: the salt is random and never leaves this machine.
func defaultName(salt, target string) string {
	sum := sha256.Sum256([]byte(salt + "|" + target))
	return strings.ToLower(base32.StdEncoding.EncodeToString(sum[:])[:10])
}
