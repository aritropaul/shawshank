package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// version is set at release time with -ldflags "-X main.version=v1.2.3".
var version = "dev"

const usage = `tunnel: expose a local port through your Cloudflare worker

  tunnel 3000                       https://tunnel.<you>.workers.dev/<name>/ → localhost:3000
  tunnel 3000 -n myapp              https://tunnel.<you>.workers.dev/myapp/
  TUNNEL_AUTH=me:secret tunnel 3000 visitors must log in (HTTP Basic)
  tunnel https://localhost:8443     local service speaks TLS (cert not verified on loopback)
  tunnel login <server>             save server + token (token is read from stdin)
  tunnel version                    print the version

flags (anywhere on the line):
  -n name     path name (default: random, stable per machine + port)
  -auth u:p   same as $TUNNEL_AUTH
  -s server   worker URL   (default: saved login, or $TUNNEL_SERVER)
  -t token    token for that server (default: saved login, or $TUNNEL_TOKEN)

Flags are visible to other users on this machine (ps), so keep secrets in
the environment or the saved login.
`

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	case "login":
		err = login(args[1:])
	case "version", "-v", "--version":
		fmt.Println("tunnel", version)
		return
	default:
		err = runClient(args)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "tunnel:", printable(err.Error()))
		os.Exit(1)
	}
}

func runClient(args []string) error {
	fs := flag.NewFlagSet("tunnel", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	name := fs.String("n", "", "")
	auth := fs.String("auth", os.Getenv("TUNNEL_AUTH"), "")
	server := fs.String("s", "", "")
	token := fs.String("t", "", "")
	pos := parseInterspersed(fs, args)
	if len(pos) != 1 {
		fs.Usage()
		os.Exit(2)
	}
	target, localTLS, err := parseTarget(pos[0])
	if err != nil {
		return err
	}
	cfgServer, cfgToken := loadConfig()
	*server, *token, err = credentials(first(*server, os.Getenv("TUNNEL_SERVER")), first(*token, os.Getenv("TUNNEL_TOKEN")), cfgServer, cfgToken)
	if err != nil {
		return err
	}
	if *name == "" {
		salt, err := machineSalt()
		if err != nil {
			return err
		}
		*name = defaultName(salt, target)
	}
	if *auth != "" && !strings.Contains(*auth, ":") {
		return fmt.Errorf("-auth wants user:password")
	}
	fi, _ := os.Stdout.Stat()
	c := newClient()
	c.server, c.token, c.name = *server, *token, strings.ToLower(*name)
	c.target, c.localTLS, c.auth = target, localTLS, *auth
	c.setLocalTLS()
	c.out = os.Stdout
	c.color = fi != nil && fi.Mode()&os.ModeCharDevice != 0 && os.Getenv("NO_COLOR") == ""

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return c.run(ctx)
}

// credentials picks the server and token. The saved token is only ever sent
// to the saved server, so pointing -s somewhere else can't leak it.
func credentials(server, token, cfgServer, cfgToken string) (string, string, error) {
	if server == "" {
		server = cfgServer
	}
	if server == "" {
		return "", "", fmt.Errorf("no server: run `tunnel login <server>` or pass -s")
	}
	server = normalizeServer(server)
	if token == "" && cfgServer != "" && server == normalizeServer(cfgServer) {
		token = cfgToken
	}
	if token == "" {
		return "", "", fmt.Errorf("no token for %s: pass -t or set $TUNNEL_TOKEN (the saved token only goes to the saved server)", server)
	}
	return server, token, nil
}

// parseInterspersed lets flags appear before or after the positional args.
func parseInterspersed(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for {
		fs.Parse(args)
		args = fs.Args()
		if len(args) == 0 {
			return pos
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func login(args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return fmt.Errorf("usage: tunnel login <server>   (the token is read from stdin)")
	}
	server := normalizeServer(args[0])
	token := ""
	if len(args) == 2 {
		token = args[1] // still accepted, but it lands in shell history
	} else if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "token: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		token = string(b)
	} else {
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		token = line
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("no token given")
	}
	p := configPath()
	if err := writePrivate(p, "server="+server+"\ntoken="+token+"\n"); err != nil {
		return err
	}
	fmt.Printf("saved %s → %s\n", server, p)
	return nil
}

func loadConfig() (server, token string) {
	f, err := os.Open(configPath())
	if err != nil {
		return "", ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, _ := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		switch k {
		case "server":
			server = v
		case "token":
			token = v
		}
	}
	return
}

// writePrivate writes a file only this user can read, even if it already existed.
func writePrivate(p, data string) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		return err
	}
	return os.Chmod(p, 0o600)
}

// machineSalt is a random secret kept in ~/.config/tunnel/id. It makes default
// names unguessable while keeping them stable on this machine.
func machineSalt() (string, error) {
	p := filepath.Join(filepath.Dir(configPath()), "id")
	if b, err := os.ReadFile(p); err == nil && len(strings.TrimSpace(string(b))) >= 32 {
		return strings.TrimSpace(string(b)), nil
	}
	b := make([]byte, 16)
	rand.Read(b)
	salt := hex.EncodeToString(b)
	return salt, writePrivate(p, salt+"\n")
}

func configPath() string {
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".config", "tunnel", "config")
}

func normalizeServer(s string) string {
	s = strings.TrimSuffix(strings.TrimSpace(s), "/")
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	return s
}

func first(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
