package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

const usage = `tunnel: expose a local port through your Cloudflare worker

  tunnel 3000                       https://tunnel.<you>.workers.dev/<name>/ → localhost:3000
  tunnel 3000 -n myapp              https://tunnel.<you>.workers.dev/myapp/
  tunnel https://localhost:8443     local service speaks TLS (cert not verified)
  tunnel login <server> <token>     save server + token

flags (anywhere on the line):
  -n name     path name (default: stable per machine + port)
  -s server   worker URL   (default: saved login, or $TUNNEL_SERVER)
  -t token    auth token   (default: saved login, or $TUNNEL_TOKEN)
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
	default:
		err = runClient(args)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "tunnel:", err)
		os.Exit(1)
	}
}

func runClient(args []string) error {
	fs := flag.NewFlagSet("tunnel", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	name := fs.String("n", "", "")
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
	*server = first(*server, os.Getenv("TUNNEL_SERVER"), cfgServer)
	*token = first(*token, os.Getenv("TUNNEL_TOKEN"), cfgToken)
	if *server == "" {
		return fmt.Errorf("no server: run `tunnel login <server> <token>` or pass -s")
	}
	if *name == "" {
		*name = defaultName(target)
	}
	fi, _ := os.Stdout.Stat()
	c := newClient()
	c.server, c.token, c.name = normalizeServer(*server), *token, strings.ToLower(*name)
	c.target, c.localTLS = target, localTLS
	c.out = os.Stdout
	c.color = fi != nil && fi.Mode()&os.ModeCharDevice != 0 && os.Getenv("NO_COLOR") == ""

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return c.run(ctx)
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
	if len(args) != 2 {
		return fmt.Errorf("usage: tunnel login <server> <token>")
	}
	p := configPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	server := normalizeServer(args[0])
	if err := os.WriteFile(p, []byte("server="+server+"\ntoken="+args[1]+"\n"), 0o600); err != nil {
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
