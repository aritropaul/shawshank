package main

import (
	"net"
	"net/url"
	"strings"
)

// Requests the client refuses to pass to the local app. The worker applies
// the same rules; checking here too covers older workers.

// Path segments that are almost always secrets when a dev server serves them.
var secretSegments = map[string]bool{
	".git": true, ".svn": true, ".hg": true, ".bzr": true, ".ssh": true, ".aws": true, ".azure": true,
	".gnupg": true, ".kube": true, ".docker": true, ".terraform": true, ".terraform.d": true, ".config": true,
	".password-store": true, ".vault-token": true, ".npmrc": true, ".yarnrc": true, ".pypirc": true,
	".netrc": true, ".pgpass": true, ".git-credentials": true, ".htpasswd": true, ".htaccess": true,
	".ds_store": true, ".bash_history": true, ".zsh_history": true, ".psql_history": true,
	".mysql_history": true, "master.key": true,
}

var secretSuffixes = []string{".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".tfstate", ".sqlite", ".sqlite3"}

// Debug consoles that run code or dump secrets, and that trust a request
// because it comes from localhost, which every tunneled request does.
var consolePrefixes = []string{"/__web_console", "/_ignition/", "/_profiler", "/_wdt", "/__debug__/"}

// blockedRequest reports whether a visitor request for rawPath?rawQuery
// should get a 404 instead of reaching the local app.
func blockedRequest(rawPath, rawQuery string) bool {
	p, err := url.PathUnescape(rawPath)
	if err != nil {
		return true
	}
	// Upper then lower folds the way case-insensitive filesystems do (long s
	// to s, Kelvin sign to k), so "/.ſsh/" can't open ".ssh" on macOS.
	p = strings.ToLower(strings.ToUpper(p))
	for _, seg := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if secretSegments[seg] || strings.HasPrefix(seg, ".env") || strings.HasPrefix(seg, "id_rsa") ||
			strings.HasPrefix(seg, "id_dsa") || strings.HasPrefix(seg, "id_ecdsa") || strings.HasPrefix(seg, "id_ed25519") {
			return true
		}
		for _, s := range secretSuffixes {
			if strings.HasSuffix(seg, s) {
				return true
			}
		}
	}
	for _, c := range consolePrefixes {
		if strings.HasPrefix(p, c) {
			return true
		}
	}
	q, _ := url.QueryUnescape(rawQuery)
	return strings.Contains(strings.ToLower(strings.ToUpper(q)), "__debugger__") // Werkzeug's interactive debugger
}

// Request headers a visitor could use to pose as a trusted proxy. Dropped
// before the tunnel sets its own X-Forwarded-*.
var spoofable = map[string]bool{
	"forwarded": true, "x-real-ip": true, "true-client-ip": true, "x-client-ip": true, "client-ip": true,
	"x-cluster-client-ip": true, "fastly-client-ip": true, "x-original-url": true, "x-rewrite-url": true,
	"x-original-forwarded-for": true, "x-original-host": true, "x-host": true, "x-http-host-override": true,
	"cdn-loop": true,
}

func spoofableHeader(lk string) bool {
	return spoofable[lk] || strings.HasPrefix(lk, "x-forwarded-") || strings.HasPrefix(lk, "cf-")
}

// printable drops control characters so text from visitors, the local app or
// the server can't drive the terminal.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r < 0xa0) {
			return -1
		}
		return r
	}, s)
}

// redactQuery keeps query keys but hides values, so tokens in URLs don't end
// up in terminal scrollback.
func redactQuery(q string) string {
	if q == "" || q == "?" {
		return q
	}
	parts := strings.Split(strings.TrimPrefix(q, "?"), "&")
	for i, p := range parts {
		if k, _, ok := strings.Cut(p, "="); ok {
			parts[i] = k + "=…"
		}
	}
	return "?" + strings.Join(parts, "&")
}

// isLoopback is true only for literal loopback addresses and "localhost".
func isLoopback(hostport string) bool {
	h := strings.Trim(stripPort(hostport), "[]")
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
