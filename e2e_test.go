package main

// End-to-end tests against a real worker. Defaults to https://tunnel.lcl
// (`cd worker && bun run dev`) with the token from worker/.dev.vars; set
// TUNNEL_TEST_SERVER and TUNNEL_TEST_TOKEN to test another one.

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func testServer(t testing.TB) (server, token string) {
	server = first(os.Getenv("TUNNEL_TEST_SERVER"), "https://tunnel.lcl")
	token = os.Getenv("TUNNEL_TEST_TOKEN")
	if token == "" {
		b, _ := os.ReadFile("worker/.dev.vars")
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "TOKEN="); ok {
				token = strings.TrimSpace(v)
			}
		}
	}
	resp, err := http.Get(server + "/")
	if err != nil {
		t.Skipf("no worker at %s (%v): run `cd worker && bun run dev`", server, err)
	}
	resp.Body.Close()
	return
}

var visitor = &http.Client{
	Transport: &http.Transport{DisableCompression: true, MaxIdleConnsPerHost: 200},
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Timeout: 60 * time.Second,
}

var ups sync.Map // *client → chan string (public URL each time it comes up)

func startClient(t testing.TB, c *client) chan error {
	ch := make(chan string, 8)
	ups.Store(c, ch)
	c.onUp = func(u string) {
		select {
		case ch <- u:
		default:
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- c.run(ctx) }()
	return done
}

func waitUp(t testing.TB, c *client, done chan error) string {
	t.Helper()
	v, _ := ups.Load(c)
	select {
	case u := <-v.(chan string):
		return u
	case err := <-done:
		t.Fatalf("client exited: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("tunnel did not come up")
	}
	return ""
}

// tunnelFor exposes h under a fresh name and returns its public URL (ending in /).
func tunnelFor(t testing.TB, h http.Handler) (string, *client, *syncBuf, chan error) {
	t.Helper()
	server, token := testServer(t)
	a := httptest.NewServer(h)
	t.Cleanup(a.Close)
	c := newClient()
	c.server, c.token = server, token
	c.name = fmt.Sprintf("t%d", time.Now().UnixNano()%1e12)
	c.target = strings.TrimPrefix(a.URL, "http://")
	out := &syncBuf{}
	c.out = out
	done := startClient(t, c)
	return waitUp(t, c, done), c, out, done
}

func app() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "host=%s path=%s query=%s xff=%s proto=%s fhost=%s prefix=%s origin=%s referer=%s",
			r.Host, r.URL.Path, r.URL.RawQuery, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Forwarded-Proto"),
			r.Header.Get("X-Forwarded-Host"), r.Header.Get("X-Forwarded-Prefix"), r.Header.Get("Origin"), r.Header.Get("Referer"))
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) { io.Copy(w, r.Body) })
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		w.Header().Set("Content-Length", strconv.Itoa(n))
		buf := bytes.Repeat([]byte("0123456789abcdef"), 4096)
		for n > 0 {
			k := min(n, len(buf))
			w.Write(buf[:k])
			n -= k
		}
	})
	mux.HandleFunc("/gz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		w.Write(gzipped)
	})
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: a\n\n")
		w.(http.Flusher).Flush()
		time.Sleep(600 * time.Millisecond)
		io.WriteString(w, "data: b\n\n")
	})
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("to"), http.StatusFound)
	})
	mux.HandleFunc("/cookies", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "a=1; Path=/")
		w.Header().Add("Set-Cookie", "b=2; Expires=Wed, 21 Oct 2037 07:28:00 GMT; Path=/")
	})
	mux.HandleFunc("/status/{code}", func(w http.ResponseWriter, r *http.Request) {
		code, _ := strconv.Atoi(r.PathValue("code"))
		w.WriteHeader(code)
		if code != 204 && code != 304 {
			io.WriteString(w, "status body")
		}
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"echo.v1"}, InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer c.CloseNow()
		c.SetReadLimit(-1)
		for {
			typ, data, err := c.Read(r.Context())
			if err != nil {
				return
			}
			if string(data) == "bye" {
				c.Close(4000, "see ya")
				return
			}
			c.Write(r.Context(), typ, data)
		}
	})
	mux.HandleFunc("/assets/app.js", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "console.log(1)") })
	return mux
}

var gzipped = func() []byte {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	zw.Write(bytes.Repeat([]byte("compress me please "), 5000))
	zw.Close()
	return b.Bytes()
}()

func get(t testing.TB, url string, hdr ...string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := visitor.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func TestTunnel(t *testing.T) {
	pub, c, out, _ := tunnelFor(t, app())
	origin := strings.TrimSuffix(pub, "/"+c.name+"/")
	scheme, host, _ := strings.Cut(origin, "://")

	t.Run("get with prefix stripped and forwarding headers", func(t *testing.T) {
		resp, body := get(t, pub+"hello?x=1", "Origin", origin, "Referer", pub+"page")
		want := []string{
			"host=" + c.target, "path=/hello", "query=x=1", "proto=" + scheme, "fhost=" + host,
			"prefix=/" + c.name, "origin=http://" + c.target, "referer=http://" + c.target + "/page",
		}
		for _, w := range want {
			if !strings.Contains(body, w) {
				t.Errorf("missing %q in %q", w, body)
			}
		}
		if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Set-Cookie"), "_tunnel="+c.name) {
			t.Errorf("status %d, set-cookie %q", resp.StatusCode, resp.Header.Get("Set-Cookie"))
		}
	})

	t.Run("absolute path via cookie", func(t *testing.T) {
		_, body := get(t, origin+"/assets/app.js", "Cookie", "_tunnel="+c.name, "Sec-Fetch-Site", "same-origin")
		if body != "console.log(1)" {
			t.Fatalf("got %q", body)
		}
	})

	t.Run("absolute path via referer", func(t *testing.T) {
		_, body := get(t, origin+"/assets/app.js", "Referer", pub, "Sec-Fetch-Site", "same-origin")
		if body != "console.log(1)" {
			t.Fatalf("got %q", body)
		}
	})

	t.Run("absolute path imported by an absolute-path module", func(t *testing.T) {
		// /src/App.tsx imported from /src/main.tsx: Referer says "src", which is
		// not a tunnel, so the cookie decides.
		_, body := get(t, origin+"/assets/app.js", "Referer", origin+"/assets/main.js", "Cookie", "_tunnel="+c.name, "Sec-Fetch-Site", "same-origin")
		if body != "console.log(1)" {
			t.Fatalf("got %q", body)
		}
	})

	t.Run("urls you open yourself ignore the cookie and referer", func(t *testing.T) {
		// Typed URLs, bookmarks and reloads send Sec-Fetch-Site: none.
		if _, body := get(t, origin+"/", "Cookie", "_tunnel="+c.name, "Sec-Fetch-Site", "none"); body != "tunnel\n" {
			t.Errorf("base url went to the tunnel: %q", body)
		}
		if _, body := get(t, origin+"/assets/app.js", "Cookie", "_tunnel="+c.name, "Sec-Fetch-Site", "none"); body == "console.log(1)" {
			t.Error("typed absolute path went to the tunnel through the cookie")
		}
		if _, body := get(t, pub+"hello", "Cookie", "_tunnel=someone-else", "Sec-Fetch-Site", "none"); !strings.HasPrefix(body, "host=") {
			t.Errorf("explicit /<name>/ didn't reach its tunnel: %q", body)
		}
	})

	t.Run("echo 8MB upload", func(t *testing.T) {
		data := make([]byte, 8<<20)
		rand.Read(data)
		resp, err := visitor.Post(pub+"echo", "application/octet-stream", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !bytes.Equal(got, data) {
			t.Fatalf("echo mismatch: %d bytes back", len(got))
		}
	})

	t.Run("download 64MB keeps content-length", func(t *testing.T) {
		start := time.Now()
		resp, err := visitor.Get(pub + "big?n=" + strconv.Itoa(64<<20))
		if err != nil {
			t.Fatal(err)
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if n != 64<<20 || resp.ContentLength != 64<<20 {
			t.Fatalf("got %d bytes, content-length %d", n, resp.ContentLength)
		}
		t.Logf("64MB in %s (%.0f MB/s)", time.Since(start).Round(time.Millisecond), 64/time.Since(start).Seconds())
	})

	t.Run("gzip passes through untouched", func(t *testing.T) {
		resp, body := get(t, pub+"gz", "Accept-Encoding", "gzip")
		if resp.Header.Get("Content-Encoding") != "gzip" || sha256.Sum256([]byte(body)) != sha256.Sum256(gzipped) {
			t.Fatalf("encoding %q, %d bytes (want %d identical)", resp.Header.Get("Content-Encoding"), len(body), len(gzipped))
		}
	})

	t.Run("sse streams", func(t *testing.T) {
		start := time.Now()
		resp, err := visitor.Get(pub + "sse")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		br := bufio.NewReader(resp.Body)
		line, _ := br.ReadString('\n')
		first := time.Since(start)
		rest, _ := io.ReadAll(br)
		if line != "data: a\n" || first > 550*time.Millisecond || !strings.Contains(string(rest), "data: b") {
			t.Fatalf("first event %q after %s, rest %q", line, first, rest)
		}
	})

	t.Run("redirects stay in the tunnel", func(t *testing.T) {
		resp, _ := get(t, pub+"redirect?to=/login")
		if loc := resp.Header.Get("Location"); loc != "/"+c.name+"/login" {
			t.Errorf("relative: %q", loc)
		}
		resp, _ = get(t, pub+"redirect?to=http://"+c.target+"/x?y=1")
		if loc := resp.Header.Get("Location"); loc != pub+"x?y=1" {
			t.Errorf("absolute: %q", loc)
		}
		resp, _ = get(t, pub+"redirect?to=https://example.com/")
		if loc := resp.Header.Get("Location"); loc != "https://example.com/" {
			t.Errorf("external: %q", loc)
		}
	})

	t.Run("multiple set-cookie", func(t *testing.T) {
		resp, _ := get(t, pub+"cookies", "Cookie", "_tunnel="+c.name)
		got := resp.Header.Values("Set-Cookie")
		if len(got) != 2 || got[0] != "a=1; Path=/" || !strings.HasPrefix(got[1], "b=2; Expires=Wed, 21 Oct 2037") {
			t.Fatalf("set-cookie %q", got)
		}
	})

	t.Run("statuses", func(t *testing.T) {
		for _, code := range []int{201, 204, 304, 404, 500} {
			resp, body := get(t, pub+"status/"+strconv.Itoa(code))
			wantBody := "status body"
			if code == 204 || code == 304 {
				wantBody = ""
			}
			if resp.StatusCode != code || body != wantBody {
				t.Errorf("%d: got %d %q", code, resp.StatusCode, body)
			}
		}
		req, _ := http.NewRequest("HEAD", pub+"big?n=12345", nil)
		resp, err := visitor.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 || resp.ContentLength != 12345 {
			t.Errorf("HEAD: %d content-length %d", resp.StatusCode, resp.ContentLength)
		}
	})

	t.Run("websocket", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		wsURL := strings.Replace(pub, "http", "ws", 1) + "ws"
		ws, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{Subprotocols: []string{"echo.v1"}})
		if err != nil {
			t.Fatal(err)
		}
		defer ws.CloseNow()
		ws.SetReadLimit(-1)
		if ws.Subprotocol() != "echo.v1" {
			t.Errorf("subprotocol %q", ws.Subprotocol())
		}
		big := make([]byte, 2<<20)
		rand.Read(big)
		for _, m := range []struct {
			typ  websocket.MessageType
			data []byte
		}{{websocket.MessageText, []byte("hello")}, {websocket.MessageBinary, []byte{0, 1, 2, 255}}, {websocket.MessageBinary, big}} {
			if err := ws.Write(ctx, m.typ, m.data); err != nil {
				t.Fatal(err)
			}
			typ, data, err := ws.Read(ctx)
			if err != nil || typ != m.typ || !bytes.Equal(data, m.data) {
				t.Fatalf("echo %v (%d bytes): got %v %d bytes %v", m.typ, len(m.data), typ, len(data), err)
			}
		}
		ws.Write(ctx, websocket.MessageText, []byte("bye"))
		_, _, err = ws.Read(ctx)
		var ce websocket.CloseError
		if !errors.As(err, &ce) || ce.Code != 4000 || ce.Reason != "see ya" {
			t.Fatalf("close: %v", err)
		}
	})

	t.Run("100 concurrent", func(t *testing.T) {
		var wg sync.WaitGroup
		errs := make(chan error, 100)
		for i := range 100 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := visitor.Get(pub + "hello?i=" + strconv.Itoa(i))
				if err != nil {
					errs <- err
					return
				}
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if !strings.Contains(string(b), "query=i="+strconv.Itoa(i)) {
					errs <- fmt.Errorf("%d: %q", i, b)
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
	})

	t.Run("client log", func(t *testing.T) {
		s := out.String()
		for _, w := range []string{"GET    200", "/" + c.name + "/hello", "POST   200", "WS     101"} {
			if !strings.Contains(s, w) {
				t.Errorf("log missing %q:\n%s", w, s)
			}
		}
	})
}

func TestLocalDown(t *testing.T) {
	server, token := testServer(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	c := newClient()
	c.server, c.token, c.name, c.target = server, token, fmt.Sprintf("d%d", time.Now().UnixNano()%1e12), dead
	out := &syncBuf{}
	c.out = out
	done := startClient(t, c)
	pub := waitUp(t, c, done)
	resp, body := get(t, pub)
	if resp.StatusCode != 502 || body != "tunnel: the local app isn't responding\n" || strings.Contains(body, dead) {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
	if !strings.Contains(out.String(), "is not reachable") {
		t.Errorf("no warning:\n%s", out.String())
	}
}

func TestOffline(t *testing.T) {
	server, _ := testServer(t)
	resp, body := get(t, server+"/nobody-here-"+strconv.FormatInt(time.Now().UnixNano(), 36)+"/")
	if resp.StatusCode != 502 || !strings.Contains(body, "offline") {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
}

func TestBadToken(t *testing.T) {
	server, _ := testServer(t)
	c := newClient()
	c.server, c.token, c.name, c.target = server, "wrong", "x", "localhost:1"
	err := c.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "bad token") {
		t.Fatalf("err = %v", err)
	}
}

func TestTakeover(t *testing.T) {
	server, token := testServer(t)
	name := fmt.Sprintf("k%d", time.Now().UnixNano()%1e12)
	mk := func(tag string) (*client, chan error) {
		a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, tag) }))
		t.Cleanup(a.Close)
		c := newClient()
		c.server, c.token, c.name, c.target = server, token, name, strings.TrimPrefix(a.URL, "http://")
		return c, startClient(t, c)
	}
	a, doneA := mk("A")
	pub := waitUp(t, a, doneA)
	if _, body := get(t, pub); body != "A" {
		t.Fatalf("got %q", body)
	}
	b, doneB := mk("B")
	waitUp(t, b, doneB)
	select {
	case err := <-doneA:
		if err == nil || !strings.Contains(err.Error(), "took over") {
			t.Fatalf("A exited with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("replaced client did not exit")
	}
	if _, body := get(t, pub); body != "B" {
		t.Fatalf("got %q", body)
	}
}

func TestParseTarget(t *testing.T) {
	for in, want := range map[string]string{
		"3000":                    "localhost:3000",
		"localhost:8080":          "localhost:8080",
		"http://127.0.0.1:5173/x": "127.0.0.1:5173",
		"https://localhost:8443":  "localhost:8443",
		"myhost":                  "myhost:80",
		"[::1]:3000":              "[::1]:3000",
	} {
		got, _, err := parseTarget(in)
		if err != nil || got != want {
			t.Errorf("parseTarget(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// --- security ---

func securityApp() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", app())
	mux.HandleFunc("/headers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(r.Header)
	})
	mux.HandleFunc("/.well-known/ok", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "well-known") })
	mux.HandleFunc("/evil", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "_tunnel=someone-else; Path=/")
		w.Header().Add("Set-Cookie", "_tunnel_auth_victim=1.forged; Path=/")
		w.Header().Add("Set-Cookie", "ok=1; Path=/")
		w.Header().Set("Service-Worker-Allowed", "/")
		w.Header().Set("Clear-Site-Data", `"cookies"`)
	})
	return mux
}

func TestSecurity(t *testing.T) {
	pub, c, _, _ := tunnelFor(t, securityApp())
	origin := strings.TrimSuffix(pub, "/"+c.name+"/")

	t.Run("secret paths never reach the app", func(t *testing.T) {
		for _, p := range []string{".env", ".env.local", ".ENV", "%2Eenv", ".git/config", "a/.git/HEAD",
			"x%2F.env", ".ssh/id_rsa", "id_ed25519", ".aws/credentials", ".npmrc"} {
			resp, body := get(t, pub+p)
			if resp.StatusCode != 404 || body != "tunnel: not found\n" {
				t.Errorf("/%s: %d %q", p, resp.StatusCode, body)
			}
		}
		if _, body := get(t, pub+".well-known/ok"); body != "well-known" {
			t.Errorf(".well-known blocked: %q", body)
		}
		if _, body := get(t, pub+"node_modules/.vite/deps/x.js"); body != "404 page not found\n" {
			t.Errorf(".vite should reach the app: %q", body)
		}
	})

	t.Run("visitors can't spoof forwarding headers or see tunnel cookies", func(t *testing.T) {
		_, body := get(t, pub+"headers",
			"X-Forwarded-For", "6.6.6.6", "Forwarded", "for=6.6.6.6", "X-Real-IP", "6.6.6.6",
			"X-Forwarded-Host", "evil.com", "X-Forwarded-Prefix", "/evil", "True-Client-IP", "6.6.6.6",
			"Cookie", "_tunnel="+c.name+"; app=1; _tunnel_auth_x=2")
		var h http.Header
		json.Unmarshal([]byte(body), &h)
		// Behind a local dev proxy (worker on loopback) X-Forwarded-Host is
		// trusted on purpose; on Cloudflare it never is.
		devProxy := strings.HasSuffix(strings.TrimSuffix(origin, "/"), ".lcl")
		if strings.Contains(body, "6.6.6.6") || strings.Contains(body, "/evil") || (!devProxy && strings.Contains(body, "evil.com")) {
			t.Errorf("spoofed value reached the app: %s", body)
		}
		if h.Get("Forwarded") != "" || h.Get("X-Real-Ip") != "" || h.Get("Cf-Connecting-Ip") != "" {
			t.Errorf("proxy headers leaked: %s", body)
		}
		if h.Get("Cookie") != "app=1" {
			t.Errorf("cookie = %q, want app=1", h.Get("Cookie"))
		}
		if h.Get("X-Forwarded-For") == "" || h.Get("X-Forwarded-Prefix") != "/"+c.name {
			t.Errorf("forwarding headers missing: %s", body)
		}
	})

	t.Run("an app can't set tunnel cookies or origin-wide headers", func(t *testing.T) {
		resp, _ := get(t, pub+"evil", "Cookie", "_tunnel="+c.name)
		got := resp.Header.Values("Set-Cookie")
		if len(got) != 1 || got[0] != "ok=1; Path=/" {
			t.Errorf("set-cookie %q", got)
		}
		if resp.Header.Get("Service-Worker-Allowed") != "" || resp.Header.Get("Clear-Site-Data") != "" {
			t.Errorf("origin-wide headers passed through: %v", resp.Header)
		}
	})

	t.Run("service workers stay under the tunnel's path", func(t *testing.T) {
		resp, _ := get(t, origin+"/sw.js", "Service-Worker", "script", "Cookie", "_tunnel="+c.name, "Sec-Fetch-Site", "same-origin")
		if resp.StatusCode != 403 {
			t.Errorf("root-scope service worker: %d", resp.StatusCode)
		}
		if _, body := get(t, pub+"sw.js", "Service-Worker", "script"); body != "404 page not found\n" {
			t.Errorf("prefixed service worker should reach the app: %q", body)
		}
	})

	t.Run("absolute-path responses are never cached", func(t *testing.T) {
		// /assets/app.js is a different file for every tunnel on the origin.
		resp, _ := get(t, origin+"/assets/app.js", "Cookie", "_tunnel="+c.name, "Sec-Fetch-Site", "same-origin")
		if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("ETag") != "" {
			t.Errorf("absolute path: cache-control %q etag %q", resp.Header.Get("Cache-Control"), resp.Header.Get("ETag"))
		}
		resp, _ = get(t, pub+"assets/app.js")
		if resp.Header.Get("Cache-Control") == "no-store" {
			t.Error("prefixed path should keep the app's own caching")
		}
	})

	t.Run("unicode case folding can't sneak past the secret filter", func(t *testing.T) {
		for _, p := range []string{".%C5%BFsh/id_rsa", ".%E2%84%AAube/config", ".%C5%BFSH/config"} {
			if resp, body := get(t, pub+p); resp.StatusCode != 404 || body != "tunnel: not found\n" {
				t.Errorf("/%s: %d %q", p, resp.StatusCode, body)
			}
		}
	})

	t.Run("two routing cookies are ignored", func(t *testing.T) {
		_, body := get(t, origin+"/assets/app.js", "Cookie", "_tunnel="+c.name+"; _tunnel=someone-else", "Sec-Fetch-Site", "same-origin")
		if body == "console.log(1)" {
			t.Error("an ambiguous routing cookie still routed the request")
		}
	})

	t.Run("reserved paths", func(t *testing.T) {
		resp, _ := get(t, origin+"/_tunnel/anything", "Cookie", "_tunnel="+c.name)
		if resp.StatusCode != 404 {
			t.Errorf("/_tunnel/anything: %d", resp.StatusCode)
		}
	})
}

func TestPassword(t *testing.T) {
	server, token := testServer(t)
	a := httptest.NewServer(securityApp())
	t.Cleanup(a.Close)
	c := newClient()
	c.server, c.token, c.name, c.target = server, token, fmt.Sprintf("p%d", time.Now().UnixNano()%1e12), strings.TrimPrefix(a.URL, "http://")
	c.auth = "me:hunter2"
	pub := waitUp(t, c, startClient(t, c))
	origin := strings.TrimSuffix(pub, "/"+c.name+"/")
	basic := func(u, p string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+p)) }

	resp, _ := get(t, pub+"headers")
	if resp.StatusCode != 401 || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Basic") {
		t.Fatalf("no creds: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	if resp, _ = get(t, pub+"headers", "Authorization", basic("me", "wrong")); resp.StatusCode != 401 {
		t.Fatalf("wrong password: %d", resp.StatusCode)
	}
	resp, body := get(t, pub+"headers", "Authorization", basic("me", "hunter2"))
	if resp.StatusCode != 200 || strings.Contains(body, "Authorization") {
		t.Fatalf("right password: %d, app saw %s", resp.StatusCode, body)
	}
	var session string
	for _, sc := range resp.Header.Values("Set-Cookie") {
		if strings.HasPrefix(sc, "_tunnel_auth_"+c.name+"=") {
			session = strings.SplitN(sc, ";", 2)[0]
		}
	}
	if session == "" {
		t.Fatalf("no session cookie: %q", resp.Header.Values("Set-Cookie"))
	}
	if resp, _ = get(t, pub+"hello", "Cookie", session); resp.StatusCode != 200 {
		t.Fatalf("session cookie: %d", resp.StatusCode)
	}
	if resp, _ = get(t, origin+"/assets/app.js", "Cookie", session+"; _tunnel="+c.name, "Sec-Fetch-Site", "same-origin"); resp.StatusCode != 200 {
		t.Fatalf("absolute path with session: %d", resp.StatusCode)
	}
	exp, _, _ := strings.Cut(strings.TrimPrefix(session, "_tunnel_auth_"+c.name+"="), ".")
	forged := "_tunnel_auth_" + c.name + "=" + exp + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if resp, _ = get(t, pub+"hello", "Cookie", forged); resp.StatusCode != 401 {
		t.Fatalf("forged cookie: %d", resp.StatusCode)
	}
	future := "_tunnel_auth_" + c.name + "=9999999999" + session[strings.Index(session, "."):]
	if resp, _ = get(t, pub+"hello", "Cookie", future); resp.StatusCode != 401 {
		t.Fatalf("extended expiry: %d", resp.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, strings.Replace(pub, "http", "ws", 1)+"ws",
		&websocket.DialOptions{HTTPHeader: http.Header{"Cookie": {session}}, Subprotocols: []string{"echo.v1"}})
	if err != nil {
		t.Fatalf("websocket with session: %v", err)
	}
	ws.Close(websocket.StatusNormalClosure, "")
	if _, _, err := websocket.Dial(ctx, strings.Replace(pub, "http", "ws", 1)+"ws", nil); err == nil {
		t.Fatal("websocket without session was accepted")
	}

	limited := false
	for range 80 {
		if r, _ := get(t, pub+"hello", "Authorization", basic("me", "guess")); r.StatusCode == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Error("80 wrong passwords in a row were never rate limited")
	}
}

func TestTargetURL(t *testing.T) {
	st := &stream{s: &session{c: &client{target: "localhost:3000"}}}
	for _, o := range []open{{U: "@evil.com/x"}, {U: "evil.com"}, {U: ""}, {U: "/x", Q: "#y"}, {U: "/x", Q: "y"}} {
		if u, ok := st.target("http", o); ok {
			t.Errorf("%+v accepted as %s", o, u)
		}
	}
	for _, o := range []open{{U: "/"}, {U: "//evil.com/x"}, {U: "/a@b"}, {U: "/x", Q: "?a=@evil.com"}} {
		u, ok := st.target("http", o)
		if !ok || u.Host != "localhost:3000" {
			t.Errorf("%+v: %v %v", o, u, ok)
		}
	}
}

func TestHelpers(t *testing.T) {
	if a, b := defaultName("salt1", "localhost:3000"), defaultName("salt1", "localhost:3000"); a != b || len(a) != 10 {
		t.Errorf("unstable or wrong length: %q %q", a, b)
	}
	if defaultName("salt1", "localhost:3000") == defaultName("salt2", "localhost:3000") {
		t.Error("salt ignored")
	}
	if got := printable("GET\x1b[2J /x\x07\u009b"); got != "GET[2J /x" {
		t.Errorf("printable = %q", got)
	}
	for h, want := range map[string]bool{"localhost:3000": true, "127.0.0.1:80": true, "[::1]:8443": true,
		"app.localhost:3000": false, "192.168.1.5:80": false, "example.com:443": false} {
		if isLoopback(h) != want {
			t.Errorf("isLoopback(%q) != %v", h, want)
		}
	}
	q := &msgQueue{max: 10, total: new(atomic.Int64)}
	q.cond = sync.NewCond(&q.mu)
	if !q.push(wsMsg{data: make([]byte, 50)}) {
		t.Error("one oversized message on an empty queue should be accepted")
	}
	if q.push(wsMsg{data: []byte{1}}) || !q.push(wsMsg{close: true}) {
		t.Error("msgQueue cap")
	}
	q.finish()
	if q.total.Load() != 0 {
		t.Errorf("finish left %d bytes counted", q.total.Load())
	}
	for _, c := range []struct{ path, query string }{
		{"/.env", ""}, {"/a/.git/config", ""}, {"/%2Eenv", ""}, {"/x%2F.ssh/id_rsa", ""}, {"/certs/server.PEM", ""},
		{"/.config/tunnel/config", ""}, {"/db.sqlite3", ""}, {"/__web_console/repl_sessions/1", ""},
		{"/_ignition/execute-solution", ""}, {"/_profiler/phpinfo", ""}, {"/", "?__debugger__=yes&cmd=1"},
		{"/", "?__DEBUGGER__=yes"}, {"/%zz", ""}, {"/.%C5%BFsh/id_rsa", ""}, {"/.\u212Aube/config", ""}, {"/.ENV", ""},
	} {
		if !blockedRequest(c.path, c.query) {
			t.Errorf("not blocked: %s%s", c.path, c.query)
		}
	}
	for _, p := range []string{"/", "/.well-known/x", "/node_modules/.vite/deps/x.js", "/vite.config.ts", "/keys", "/api/monkey"} {
		if blockedRequest(p, "?x=1") {
			t.Errorf("blocked: %s", p)
		}
	}
	if got := redactQuery("?token=abc&v=2&flag"); got != "?token=…&v=…&flag" {
		t.Errorf("redactQuery = %q", got)
	}
	for _, c := range []struct{ server, token, cfgServer, cfgToken, wantServer, wantToken string }{
		{"", "", "https://t.example.dev", "saved", "https://t.example.dev", "saved"},
		{"t.example.dev", "", "https://t.example.dev", "saved", "https://t.example.dev", "saved"},
		{"https://evil.dev", "", "https://t.example.dev", "saved", "", ""},
		{"https://evil.dev", "mine", "https://t.example.dev", "saved", "https://evil.dev", "mine"},
	} {
		s, tok, err := credentials(c.server, c.token, c.cfgServer, c.cfgToken)
		if s != c.wantServer || tok != c.wantToken || (c.wantToken == "") != (err != nil) {
			t.Errorf("credentials(%q,%q) = %q %q %v", c.server, c.token, s, tok, err)
		}
	}
	p := &bodyPipe{st: &stream{}}
	p.cond = sync.NewCond(&p.mu)
	if !p.push(make([]byte, window)) || p.push(make([]byte, chunkSize+1)) {
		t.Error("bodyPipe should refuse bytes beyond the window")
	}
}

func TestHardening(t *testing.T) {
	// Something on this machine that must never be reachable through a redirect.
	var internalHits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { internalHits.Add(1) }))
	t.Cleanup(internal.Close)

	mux := http.NewServeMux()
	mux.Handle("/", app())
	mux.HandleFunc("/reject", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 401) }) // never reads the body
	mux.HandleFunc("/wsredirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL+"/secret", http.StatusFound)
	})
	pub, _, _, _ := tunnelFor(t, mux)

	t.Run("debug consoles and key files never reach the app", func(t *testing.T) {
		for _, p := range []string{"?__debugger__=yes&cmd=resource", "__web_console/repl_sessions/1", "_ignition/execute-solution",
			"_profiler/phpinfo", "__debug__/sql_select/", "certs/dev.pem", ".config/tunnel/config", "db.sqlite3"} {
			resp, body := get(t, pub+p)
			if resp.StatusCode != 404 || body != "tunnel: not found\n" {
				t.Errorf("/%s: %d %q", p, resp.StatusCode, body)
			}
		}
	})

	t.Run("websocket dials don't follow redirects", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, _, err := websocket.Dial(ctx, strings.Replace(pub, "http", "ws", 1)+"wsredirect", nil); err == nil {
			t.Fatal("websocket upgrade succeeded through a redirect")
		}
		time.Sleep(200 * time.Millisecond)
		if n := internalHits.Load(); n != 0 {
			t.Fatalf("redirect was followed to an internal server (%d hits)", n)
		}
	})

	t.Run("early answers don't leak goroutines", func(t *testing.T) {
		runtime.GC()
		before := runtime.NumGoroutine()
		for range 20 {
			pr, pw := io.Pipe()
			go func() { pw.Write(make([]byte, 64<<10)) }() // part of a 1MB body, then stall
			req, _ := http.NewRequest("POST", pub+"reject", pr)
			req.ContentLength = 1 << 20
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			resp, err := visitor.Do(req.WithContext(ctx))
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			cancel()
			pw.CloseWithError(errors.New("visitor gave up"))
		}
		visitor.CloseIdleConnections()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) && runtime.NumGoroutine() > before+10 {
			time.Sleep(100 * time.Millisecond)
		}
		if after := runtime.NumGoroutine(); after > before+10 {
			t.Fatalf("goroutines grew from %d to %d after 20 early-rejected uploads", before, after)
		}
	})

	t.Run("an 18MB websocket message gets through", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		ws, _, err := websocket.Dial(ctx, strings.Replace(pub, "http", "ws", 1)+"ws", &websocket.DialOptions{Subprotocols: []string{"echo.v1"}})
		if err != nil {
			t.Fatal(err)
		}
		defer ws.CloseNow()
		ws.SetReadLimit(-1)
		big := make([]byte, 18<<20)
		rand.Read(big)
		if err := ws.Write(ctx, websocket.MessageBinary, big); err != nil {
			t.Fatal(err)
		}
		_, got, err := ws.Read(ctx)
		if err != nil || !bytes.Equal(got, big) {
			t.Fatalf("got %d bytes, %v", len(got), err)
		}
	})
}

func TestErrorPages(t *testing.T) {
	server, token := testServer(t)
	html := func(url string) (*http.Response, string) {
		return get(t, url, "Accept", "text/html,application/xhtml+xml")
	}

	t.Run("offline tunnel", func(t *testing.T) {
		name := "gone-" + strconv.FormatInt(time.Now().UnixNano()%1e9, 36)
		resp, body := html(server + "/" + name + "/")
		if resp.StatusCode != 502 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") ||
			!strings.Contains(body, "<title>502 - Offline</title>") || !strings.Contains(body, "tunnel 3000 -n "+name) {
			t.Fatalf("%d %s\n%s", resp.StatusCode, resp.Header.Get("Content-Type"), body)
		}
		if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'none'") || resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("headers: %v", resp.Header)
		}
		// Anything that isn't a browser still gets one line of text.
		if _, body := get(t, server+"/"+name+"/"); body != "tunnel: "+name+" is offline\n" {
			t.Errorf("plain: %q", body)
		}
	})

	t.Run("not found escapes the path", func(t *testing.T) {
		resp, body := html(server + "/robots.txt%3Cscript%3E")
		if resp.StatusCode != 404 || !strings.Contains(body, "404 - Not found") || strings.Contains(body, "<script>") {
			t.Fatalf("%d\n%s", resp.StatusCode, body)
		}
	})

	t.Run("app not responding comes from the client and keeps the port private", func(t *testing.T) {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		dead := ln.Addr().String()
		ln.Close()
		c := newClient()
		c.server, c.token, c.name, c.target = server, token, fmt.Sprintf("e%d", time.Now().UnixNano()%1e12), dead
		pub := waitUp(t, c, startClient(t, c))
		resp, body := html(pub)
		if resp.StatusCode != 502 || !strings.Contains(body, "502 - Bad gateway") || strings.Contains(body, dead) || resp.Header.Get("X-Tunnel-Error") != "" {
			t.Fatalf("%d %v\n%s", resp.StatusCode, resp.Header, body)
		}
		resp, body = html(pub + ".env")
		if resp.StatusCode != 404 || !strings.Contains(body, "404 - Not found") {
			t.Fatalf("blocked path: %d\n%s", resp.StatusCode, body)
		}
	})

	t.Run("home page", func(t *testing.T) {
		resp, body := get(t, server+"/", "Accept", "text/html", "Sec-Fetch-Site", "none")
		if resp.StatusCode != 200 || !strings.Contains(body, "<title>tunnel</title>") || !strings.Contains(body, "Expose a local port") ||
			!strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'none'") {
			t.Fatalf("%d\n%s", resp.StatusCode, body)
		}
		if _, body := get(t, server+"/"); body != "tunnel\n" {
			t.Errorf("plain: %q", body)
		}
	})

	t.Run("fonts", func(t *testing.T) {
		for _, f := range []string{"geist-400", "geist-500", "geist-mono-400", "geist-pixel"} {
			resp, body := get(t, server+"/_tunnel/assets/"+f+".woff2")
			if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "font/woff2" ||
				!strings.Contains(resp.Header.Get("Cache-Control"), "immutable") || !strings.HasPrefix(body, "wOF2") {
				t.Errorf("%s: %d %v", f, resp.StatusCode, resp.Header)
			}
		}
		if resp, _ := get(t, server+"/_tunnel/assets/../secret"); resp.StatusCode != 404 {
			t.Errorf("unknown asset: %d", resp.StatusCode)
		}
	})
}
