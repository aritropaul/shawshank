package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
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

// open is the visitor request as the worker saw it.
type open struct {
	M  string      `json:"m"`  // method
	U  string      `json:"u"`  // path, with the /<name> prefix already removed
	Q  string      `json:"q"`  // ?query
	H  [][2]string `json:"h"`  // headers
	IP string      `json:"ip"` // visitor IP
	X  string      `json:"x"`  // prefix the visitor used: "/<name>" or ""
	O  string      `json:"o"`  // public origin, https://tunnel.example.workers.dev
	WS bool        `json:"ws"` // websocket upgrade
}

var errAborted = errors.New("stream aborted")

var chunkPool = sync.Pool{New: func() any { b := make([]byte, 5+chunkSize); return &b }}

// Response headers that describe the hop, not the content.
var hopHeaders = map[string]bool{
	"connection": true, "keep-alive": true, "proxy-connection": true, "transfer-encoding": true,
	"te": true, "trailer": true, "upgrade": true, "content-length": true,
}

type stream struct {
	s      *session
	id     uint32
	isWS   bool
	ctx    context.Context
	cancel context.CancelFunc

	body    *bodyPipe // visitor request body
	toLocal *msgQueue // visitor websocket messages

	mu     sync.Mutex
	cond   *sync.Cond
	credit int // response bytes we may still send
	dead   bool
}

func newStream(s *session, id uint32, ws bool) *stream {
	ctx, cancel := context.WithCancel(s.ctx)
	st := &stream{s: s, id: id, isWS: ws, ctx: ctx, cancel: cancel, credit: window,
		toLocal: &msgQueue{max: wsBacklog, total: &s.c.wsQueued}}
	st.cond = sync.NewCond(&st.mu)
	st.body = &bodyPipe{st: st}
	st.body.cond = sync.NewCond(&st.body.mu)
	st.toLocal.cond = sync.NewCond(&st.toLocal.mu)
	return st
}

func (st *stream) addCredit(n int) {
	st.mu.Lock()
	st.credit += n
	st.mu.Unlock()
	st.cond.Broadcast()
}

// take blocks until n bytes of window are available; false if the stream died.
func (st *stream) take(n int) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	for st.credit < n && !st.dead {
		st.cond.Wait()
	}
	if st.dead {
		return false
	}
	st.credit -= n
	return true
}

func (st *stream) abort() {
	st.cancel()
	st.mu.Lock()
	st.dead = true
	st.mu.Unlock()
	st.cond.Broadcast()
	st.body.finish(errAborted)
	st.toLocal.finish()
}

// queue hands a visitor websocket message to the local side, closing the
// socket if the local app has fallen too far behind (per socket or overall).
func (st *stream) queue(m wsMsg) {
	if st.toLocal.push(m) {
		return
	}
	st.abort()
	p := make([]byte, 2, 2+32)
	binary.BigEndian.PutUint16(p, uint16(websocket.StatusPolicyViolation))
	st.s.send(fClose, st.id, append(p, "local app too slow"...))
}

// target builds the local URL. The path must start with "/", so nothing the
// visitor (or a compromised server) sends can change which host is dialed.
func (st *stream) target(scheme string, o open) (*url.URL, bool) {
	if !strings.HasPrefix(o.U, "/") || (o.Q != "" && !strings.HasPrefix(o.Q, "?")) {
		return nil, false
	}
	u, err := url.Parse(scheme + "://" + st.s.c.target + o.U + o.Q)
	if err != nil || u.Host != st.s.c.target || u.User != nil {
		return nil, false
	}
	return u, true
}

func (st *stream) serve(o open) {
	defer st.s.remove(st.id)
	defer st.cancel()
	// If the local app answers before reading the whole body, unblock the
	// transport's body reader instead of leaving it waiting forever.
	defer st.body.finish(errAborted)
	if blockedRequest(o.U, o.Q) {
		st.s.reject(st.id, o.WS, http.StatusNotFound, "not-found", "tunnel: not found\n")
		st.s.c.logRequest(o.M, http.StatusNotFound, 0, o.X+o.U+o.Q)
		return
	}
	if o.WS {
		st.serveWS(o)
	} else {
		st.serveHTTP(o)
	}
}

func (st *stream) serveHTTP(o open) {
	c := st.s.c
	start := time.Now()
	shown := o.X + o.U + o.Q

	cl := int64(-1)
	for _, kv := range o.H {
		if strings.EqualFold(kv[0], "content-length") {
			cl, _ = strconv.ParseInt(kv[1], 10, 64)
		}
	}
	var body io.ReadCloser = st.body
	switch {
	case cl == 0, cl < 0 && (o.M == "GET" || o.M == "HEAD" || o.M == "OPTIONS"):
		body, cl = http.NoBody, 0
	}
	scheme := "http"
	if c.localTLS {
		scheme = "https"
	}
	u, ok := st.target(scheme, o)
	if !ok {
		st.respondText(http.StatusBadRequest, "bad-request", "tunnel: bad request\n")
		return
	}
	req, err := http.NewRequestWithContext(st.ctx, o.M, u.String(), body)
	if err != nil {
		st.respondText(http.StatusBadRequest, "bad-request", "tunnel: bad request\n")
		return
	}
	req.ContentLength = cl
	for _, kv := range o.H {
		if !strings.EqualFold(kv[0], "content-length") {
			req.Header.Add(kv[0], kv[1])
		}
	}
	c.forwardHeaders(req.Header, o)

	resp, err := c.tr.RoundTrip(req)
	if err != nil {
		if st.ctx.Err() != nil {
			return
		}
		// Visitors get a generic message; the details stay in this terminal.
		var op *net.OpError
		if errors.As(err, &op) && op.Op == "dial" {
			if !c.localDown.Swap(true) {
				c.warn(c.target + " is not reachable (" + op.Err.Error() + ")")
			}
		} else {
			c.warn(o.M + " " + shown + ": " + err.Error())
		}
		st.respondText(http.StatusBadGateway, "local-down", "tunnel: the local app isn't responding\n")
		c.logRequest(o.M, http.StatusBadGateway, time.Since(start), shown)
		return
	}
	defer resp.Body.Close()
	c.localDown.Store(false)

	noBody := o.M == "HEAD" || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified
	h := make([][2]string, 0, len(resp.Header)+2)
	for k, vs := range resp.Header {
		if hopHeaders[strings.ToLower(k)] {
			continue
		}
		for _, v := range vs {
			if strings.EqualFold(k, "Location") {
				v = c.rewriteLocation(v, o)
			}
			h = append(h, [2]string{k, v})
		}
	}
	if resp.ContentLength >= 0 && !(noBody && o.M != "HEAD") {
		h = append(h, [2]string{"Content-Length", strconv.FormatInt(resp.ContentLength, 10)})
	}
	head, _ := json.Marshal(map[string]any{"s": resp.StatusCode, "h": h})
	if len(head) > maxHead {
		c.warn(o.M + " " + shown + ": response headers too large")
		st.respondText(http.StatusBadGateway, "local-down", "tunnel: the local app isn't responding\n")
		return
	}
	if st.s.send(fRes, st.id, head) != nil {
		return
	}
	c.logRequest(o.M, resp.StatusCode, time.Since(start), shown)

	if noBody {
		st.s.send(fEnd, st.id, nil)
		return
	}
	bp := chunkPool.Get().(*[]byte)
	defer chunkPool.Put(bp)
	buf := *bp
	for {
		n, rerr := resp.Body.Read(buf[5:])
		if n > 0 {
			if !st.take(n) || st.s.sendFrame(fData, st.id, buf[:5+n]) != nil {
				return
			}
		}
		if rerr == io.EOF {
			st.s.send(fEnd, st.id, nil)
			return
		}
		if rerr != nil {
			if st.ctx.Err() == nil {
				st.s.send(fRst, st.id, []byte("local app: "+rerr.Error()))
			}
			return
		}
	}
}

func (st *stream) respondText(code int, kind, msg string) {
	st.s.reject(st.id, false, code, kind, msg)
}

func (st *stream) serveWS(o open) {
	c := st.s.c
	start := time.Now()
	hdr := http.Header{}
	var protos []string
	for _, kv := range o.H {
		switch strings.ToLower(kv[0]) {
		case "sec-websocket-protocol":
			for _, p := range strings.Split(kv[1], ",") {
				if p = strings.TrimSpace(p); p != "" {
					protos = append(protos, p)
				}
			}
		case "content-length":
		default:
			hdr.Add(kv[0], kv[1])
		}
	}
	c.forwardHeaders(hdr, o)
	scheme := "ws"
	if c.localTLS {
		scheme = "wss"
	}
	u, ok := st.target(scheme, o)
	if !ok {
		st.s.sendJSON(fRes, st.id, map[string]any{"s": http.StatusBadRequest, "h": [][2]string{}})
		return
	}
	dctx, dcancel := context.WithTimeout(st.ctx, 10*time.Second)
	lc, resp, err := websocket.Dial(dctx, u.String(), &websocket.DialOptions{
		HTTPHeader:   hdr,
		Subprotocols: protos,
		HTTPClient:   c.wsHTTP,
	})
	dcancel()
	if err != nil {
		code := http.StatusBadGateway
		if resp != nil && resp.StatusCode >= 200 && resp.StatusCode != http.StatusSwitchingProtocols {
			code = resp.StatusCode
		}
		st.s.sendJSON(fRes, st.id, map[string]any{"s": code, "h": [][2]string{}})
		c.logRequest("WS", code, time.Since(start), o.X+o.U+o.Q)
		return
	}
	defer lc.CloseNow()
	lc.SetReadLimit(wsMaxMsg) // larger would exceed what the worker accepts and drop the whole tunnel

	h := [][2]string{}
	if p := lc.Subprotocol(); p != "" {
		h = append(h, [2]string{"Sec-WebSocket-Protocol", p})
	}
	for _, v := range resp.Header.Values("Set-Cookie") {
		h = append(h, [2]string{"Set-Cookie", v})
	}
	if st.s.sendJSON(fRes, st.id, map[string]any{"s": 101, "h": h}) != nil {
		return
	}
	c.logRequest("WS", 101, time.Since(start), o.X+o.U+o.Q)

	// local → visitor
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			typ, data, err := lc.Read(st.ctx)
			if err != nil {
				code, reason := websocket.CloseStatus(err), ""
				var ce websocket.CloseError
				if errors.As(err, &ce) {
					reason = ce.Reason
				}
				if code == -1 {
					code = websocket.StatusInternalError
				}
				p := make([]byte, 2, 2+len(reason))
				binary.BigEndian.PutUint16(p, uint16(code))
				st.s.send(fClose, st.id, append(p, reason...))
				st.toLocal.finish()
				return
			}
			t := byte(fData)
			if typ == websocket.MessageText {
				t = fText
			}
			if st.s.send(t, st.id, data) != nil {
				return
			}
		}
	}()

	// visitor → local
	for {
		m, ok := st.toLocal.pop()
		if !ok {
			break
		}
		if m.close {
			lc.Close(m.code, m.reason)
			break
		}
		if lc.Write(st.ctx, m.typ, m.data) != nil {
			break
		}
		// Tell the worker the bytes are delivered so it can count what's in flight.
		var w [4]byte
		binary.BigEndian.PutUint32(w[:], uint32(len(m.data)))
		st.s.send(fWin, st.id, w[:])
	}
	st.cancel()
	<-done
}

// forwardHeaders makes the request look like it came to the local app
// directly: Host is the local address, and Origin/Referer point at it too so
// CSRF and dev-server host checks pass. The public view is in X-Forwarded-*.
func (c *client) forwardHeaders(h http.Header, o open) {
	// Drop anything a visitor could use to pose as a trusted proxy.
	for k := range h {
		if spoofableHeader(strings.ToLower(k)) {
			delete(h, k)
		}
	}
	pub, _ := url.Parse(o.O)
	local := c.localURL()
	if o.IP != "" {
		h.Set("X-Forwarded-For", o.IP)
	}
	if pub != nil {
		h.Set("X-Forwarded-Proto", pub.Scheme)
		h.Set("X-Forwarded-Host", pub.Host)
	}
	if o.X != "" {
		h.Set("X-Forwarded-Prefix", o.X)
	}
	if v := h.Get("Origin"); v == o.O {
		h.Set("Origin", local)
	}
	if v := h.Get("Referer"); strings.HasPrefix(v, o.O+"/") {
		rest := strings.TrimPrefix(v, o.O)
		if o.X != "" && (rest == o.X || strings.HasPrefix(rest, o.X+"/")) {
			rest = strings.TrimPrefix(rest, o.X)
		}
		if rest == "" {
			rest = "/"
		}
		h.Set("Referer", local+rest)
	}
}

// rewriteLocation keeps redirects inside the tunnel.
func (c *client) rewriteLocation(v string, o open) string {
	if strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "//") {
		return o.X + v
	}
	u, err := url.Parse(v)
	if err != nil || u.Host == "" || !c.isLocalHost(u.Host) {
		return v
	}
	rest := u.EscapedPath()
	if u.RawQuery != "" {
		rest += "?" + u.RawQuery
	}
	if u.Fragment != "" {
		rest += "#" + u.EscapedFragment()
	}
	if rest == "" {
		rest = "/"
	}
	return o.O + o.X + rest
}

func (c *client) isLocalHost(hostport string) bool {
	if hostport == c.target {
		return true
	}
	h, p, err := net.SplitHostPort(hostport)
	_, tp, terr := net.SplitHostPort(c.target)
	if err != nil || terr != nil || p != tp {
		return false
	}
	switch h {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0", stripPort(c.target):
		return true
	}
	return false
}

func (c *client) warn(msg string) {
	io.WriteString(c.out, "  "+c.paint("31", "✗")+" "+printable(msg)+"\n")
}

func stripPort(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// bodyPipe feeds the visitor's request body to the local request. The window
// bounds how much can queue; credit goes back as the local app reads.
type bodyPipe struct {
	st      *stream
	mu      sync.Mutex
	cond    *sync.Cond
	chunks  [][]byte
	queued  int
	done    bool
	err     error
	unacked int
}

// push queues body bytes; false if the sender ignored the window.
func (p *bodyPipe) push(b []byte) bool {
	p.mu.Lock()
	if !p.done {
		p.chunks = append(p.chunks, b)
		p.queued += len(b)
	}
	over := p.queued > window+chunkSize
	p.mu.Unlock()
	p.cond.Signal()
	return !over
}

func (p *bodyPipe) finish(err error) {
	p.mu.Lock()
	if !p.done {
		p.done, p.err = true, err
	}
	if err != nil {
		p.chunks = nil
	}
	p.mu.Unlock()
	p.cond.Broadcast()
}

func (p *bodyPipe) Read(b []byte) (int, error) {
	p.mu.Lock()
	for len(p.chunks) == 0 && !p.done {
		p.cond.Wait()
	}
	if len(p.chunks) == 0 {
		err := p.err
		p.mu.Unlock()
		if err != nil {
			return 0, err
		}
		return 0, io.EOF
	}
	n := copy(b, p.chunks[0])
	p.queued -= n
	if p.chunks[0] = p.chunks[0][n:]; len(p.chunks[0]) == 0 {
		p.chunks = p.chunks[1:]
	}
	p.unacked += n
	ack := 0
	if p.unacked >= 64<<10 || len(p.chunks) == 0 {
		ack, p.unacked = p.unacked, 0
	}
	p.mu.Unlock()
	if ack > 0 {
		var w [4]byte
		binary.BigEndian.PutUint32(w[:], uint32(ack))
		p.st.s.send(fWin, p.st.id, w[:])
	}
	return n, nil
}

func (p *bodyPipe) Close() error {
	p.finish(errAborted) // no-op if the body already ended normally
	return nil
}

type wsMsg struct {
	typ    websocket.MessageType
	data   []byte
	close  bool
	code   websocket.StatusCode
	reason string
}

// msgQueue buffers visitor websocket messages so the session read loop
// never blocks on a slow local app.
type msgQueue struct {
	mu    sync.Mutex
	cond  *sync.Cond
	q     []wsMsg
	size  int
	max   int
	total *atomic.Int64 // shared by every queue in the session
	done  bool
}

// push queues a message; false if the socket's backlog or the session's
// would exceed its budget. One message on its own is always allowed.
func (m *msgQueue) push(x wsMsg) bool {
	n := len(x.data)
	m.mu.Lock()
	defer m.cond.Signal()
	defer m.mu.Unlock()
	if m.done {
		return true
	}
	if !x.close && m.size > 0 && (m.size+n > m.max || m.total.Load()+int64(n) > wsBudget) {
		return false
	}
	m.q = append(m.q, x)
	m.size += n
	m.total.Add(int64(n))
	return true
}

// finish stops the queue and releases whatever was still waiting.
func (m *msgQueue) finish() {
	m.mu.Lock()
	m.done = true
	m.total.Add(-int64(m.size))
	m.q, m.size = nil, 0
	m.mu.Unlock()
	m.cond.Broadcast()
}

func (m *msgQueue) pop() (wsMsg, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for len(m.q) == 0 && !m.done {
		m.cond.Wait()
	}
	if len(m.q) == 0 {
		return wsMsg{}, false
	}
	x := m.q[0]
	m.q = m.q[1:]
	m.size -= len(x.data)
	m.total.Add(-int64(len(x.data)))
	return x, true
}
