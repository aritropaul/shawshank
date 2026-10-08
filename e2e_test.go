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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
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
		_, body := get(t, origin+"/assets/app.js", "Cookie", "_tunnel="+c.name)
		if body != "console.log(1)" {
			t.Fatalf("got %q", body)
		}
	})

	t.Run("absolute path via referer", func(t *testing.T) {
		_, body := get(t, origin+"/assets/app.js", "Referer", pub)
		if body != "console.log(1)" {
			t.Fatalf("got %q", body)
		}
	})

	t.Run("absolute path imported by an absolute-path module", func(t *testing.T) {
		// /src/App.tsx imported from /src/main.tsx: Referer says "src", which is
		// not a tunnel, so the cookie decides.
		_, body := get(t, origin+"/assets/app.js", "Referer", origin+"/assets/main.js", "Cookie", "_tunnel="+c.name)
		if body != "console.log(1)" {
			t.Fatalf("got %q", body)
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
	if resp.StatusCode != 502 || !strings.Contains(body, "nothing answered on http://"+dead) {
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
