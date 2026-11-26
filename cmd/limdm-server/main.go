// limdm-server runs the management server, or creates release signing keys and
// signed agent release manifests.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
	"github.com/maltekiefer/limdm/internal/server"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(log)
	case "keygen":
		err = keygen(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "local-admin":
		err = localAdmin(os.Args[2:])
	case "audit":
		err = auditCmd(os.Args[2:])
	case "keys":
		err = keysCmd(log, os.Args[2:])
	default:
		err = errors.New(`usage: limdm-server [serve | keygen -out FILE | sign -key FILE|-key-env VAR|-pkcs11 LABEL SHA256SUMS
                     | local-admin [-env FILE] [-role admin|auditor] [-out FILE] add|reset|disable|enable|list [NAME]
                     | audit [-ca DIR] [-key HEX -keyed-from ID] verify FILE.jsonl | audit [-ca DIR] key
                     | keys [-env FILE] status | rotate KIND [-name NAME] | finish KIND [-force]]`)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func serve(log *slog.Logger) error {
	cfg, err := server.ConfigFromEnv()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	srv, err := server.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer srv.Close()
	srv.Background(ctx)
	agentTLS, err := srv.AgentTLSConfig()
	if err != nil {
		return err
	}
	newServer := func(addr string, h http.Handler, tc *tls.Config) *http.Server {
		return &http.Server{
			Addr: addr, Handler: h, TLSConfig: tc,
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 5 * time.Minute, IdleTimeout: 120 * time.Second,
		}
	}
	admin := newServer(cfg.Listen, srv.AdminHandler(), &tls.Config{MinVersion: tls.VersionTLS12})
	agent := newServer(cfg.AgentListen, srv.AgentHandler(), agentTLS)

	errc := make(chan error, 2)
	go func() {
		log.Info("admin UI listening", "addr", cfg.Listen, "tls", cfg.TLSCert != "")
		if cfg.TLSCert != "" {
			errc <- admin.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			errc <- admin.ListenAndServe() // loopback only, enforced in config
		}
	}()
	go func() {
		log.Info("agent API listening (mTLS, TLS 1.3)", "addr", cfg.AgentListen)
		errc <- agent.ListenAndServeTLS("", "")
	}()
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err = errors.Join(err, admin.Shutdown(sctx), agent.Shutdown(sctx))
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// localAdmin manages fallback admin accounts. Generated credentials go to
// stdout or, with -out, to a new 0600 file so they do not end up in logs.
// auditCmd verifies a JSON Lines audit export outside the server, or prints
// the audit key for an auditor who verifies on another machine.
func auditCmd(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	def := os.Getenv("LIMDM_CA_DIR")
	if def == "" {
		def = "/var/lib/limdm-server/ca"
	}
	caDir := fs.String("ca", def, "CA directory with command.key")
	keyHex := fs.String("key", "", "audit key (hex) instead of the CA directory; one segment")
	keyedFrom := fs.Int64("keyed-from", 0, "first keyed entry, with -key")
	fs.Parse(args)
	var keys server.AuditKeys
	if *keyHex != "" {
		key, err := hex.DecodeString(*keyHex)
		if err != nil || len(key) != 32 {
			return errors.New("-key must be 64 hex characters")
		}
		keys = server.AuditKeys{{From: *keyedFrom, Key: key}}
	} else {
		var err error
		if keys, err = server.AuditKeysFromDir(*caDir, server.KeyProviderFromEnv()); err != nil {
			return fmt.Errorf("audit key: %w", err)
		}
	}
	switch {
	case fs.Arg(0) == "key":
		// one line per segment: a command key rotation starts a new one
		for _, k := range keys {
			fmt.Printf("key=%s keyed_from=%d\n", hex.EncodeToString(k.Key), k.From)
		}
		return nil
	case fs.Arg(0) == "verify" && fs.NArg() == 2:
		f, err := os.Open(fs.Arg(1))
		if err != nil {
			return err
		}
		defer f.Close()
		n, first, last, broken, err := server.VerifyAuditExport(f, keys)
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("no entries in the file")
		}
		if broken != 0 {
			return fmt.Errorf("chain broken at entry %d (%d entries read)", broken, n)
		}
		fmt.Printf("%d entries, %d to %d: chain intact\n", n, first, last)
		return nil
	}
	return errors.New("usage: limdm-server audit [-ca DIR] [-key HEX -keyed-from ID] verify FILE.jsonl | key")
}

func localAdmin(args []string) error {
	fs := flag.NewFlagSet("local-admin", flag.ExitOnError)
	envFile := fs.String("env", "", "read LIMDM_* settings from this env file (e.g. /etc/limdm-server/server.env)")
	role := fs.String("role", "admin", "admin or auditor")
	out := fs.String("out", "", "write generated credentials to this new file (mode 0600)")
	fs.Parse(args)
	if fs.NArg() < 1 {
		return errors.New("need an operation: add, reset, disable, enable or list")
	}
	if *envFile != "" {
		if err := loadEnvFile(*envFile); err != nil {
			return err
		}
	}
	dsn := os.Getenv("LIMDM_DATABASE_URL")
	if dsn == "" {
		return errors.New("LIMDM_DATABASE_URL not set (use -env)")
	}
	res, err := server.LocalAdmin(context.Background(), dsn, fs.Arg(0), fs.Arg(1), *role)
	if err != nil || res == "" {
		return err
	}
	if *out == "" {
		fmt.Print(res)
		return nil
	}
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(res); err != nil {
		f.Close()
		return err
	}
	fmt.Println("credentials written to", *out)
	return f.Close()
}

// loadEnvFile applies KEY=VALUE lines (systemd EnvironmentFile syntax subset).
func loadEnvFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			if err := os.Setenv(strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"'`)); err != nil {
				return err
			}
		}
	}
	return nil
}

// keygen writes the private release key (keep it offline) and prints the public
// key to compile into the agent.
func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "release.key", "private key file")
	fs.Parse(args)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, []byte(hex.EncodeToString(priv)), 0o600); err != nil {
		return err
	}
	fmt.Printf("private key: %s\npublic key (build agent with UPDATE_PUBKEY=...): %s\n", *out, hex.EncodeToString(pub))
	return nil
}

// sign writes the hex Ed25519 signature of a release's SHA256SUMS file. The
// private key comes from a file or, in CI, from an environment variable.
func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyFile := fs.String("key", "", "private key file (limdm-server keygen)")
	keyEnv := fs.String("key-env", "", "environment variable holding the hex private key")
	label := fs.String("pkcs11", "", "label of an Ed25519 key in the PKCS#11 token (LIMDM_PKCS11_MODULE, LIMDM_PKCS11_TOKEN, LIMDM_PKCS11_PIN)")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: limdm-server sign -key FILE|-key-env VAR|-pkcs11 LABEL SHA256SUMS")
	}
	if *label != "" {
		sums, err := os.ReadFile(fs.Arg(0))
		if err != nil {
			return err
		}
		sig, err := server.SignWithHSM(server.KeyProviderFromEnv(), *label, api.SumsSigned(string(sums)))
		if err != nil {
			return err
		}
		fmt.Println(hex.EncodeToString(sig))
		return nil
	}
	raw := os.Getenv(*keyEnv)
	if *keyFile != "" {
		b, err := os.ReadFile(*keyFile)
		if err != nil {
			return err
		}
		raw = string(b)
	}
	key, err := hex.DecodeString(strings.TrimSpace(raw))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid private key")
	}
	sums, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	fmt.Println(api.SignSums(key, string(sums)))
	return nil
}

// keysCmd shows and rotates the server keys (docs/keys.md). It works on the
// CA directory and the database of the server environment; running servers
// apply a step when they restart.
func keysCmd(log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("keys", flag.ExitOnError)
	envFile := fs.String("env", "", "read LIMDM_* settings from this env file (e.g. /etc/limdm-server/server.env)")
	fs.Parse(args)
	if *envFile != "" {
		if err := loadEnvFile(*envFile); err != nil {
			return err
		}
	}
	op, kind := fs.Arg(0), fs.Arg(1)
	sub := flag.NewFlagSet("keys "+op, flag.ExitOnError)
	name := sub.String("name", "", "name of the new key (required with an HSM: the key labeled limdm-NAME)")
	force := sub.Bool("force", false, "finish although devices still use the old key (they must enroll again)")
	if fs.NArg() > 2 {
		sub.Parse(fs.Args()[2:])
	}
	if op != "status" && (kind == "" || (op != "rotate" && op != "finish")) {
		return errors.New("usage: limdm-server keys [-env FILE] status | rotate ca|network-ca|command|session [-name NAME] | finish KIND [-force]")
	}
	cfg, err := server.ConfigFromEnv()
	if err != nil {
		return err
	}
	ctx := context.Background()
	srv, err := server.OpenKeys(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer srv.Close()
	actor := "cli:" + os.Getenv("USER")
	var msg string
	switch op {
	case "status":
		list, err := srv.KeysStatus(ctx)
		if err != nil {
			return err
		}
		for _, k := range list {
			line := fmt.Sprintf("%-11s active=%s", k.Kind, k.Active)
			if k.Previous != "" {
				line += " retiring=" + k.Previous
				if k.Kind == "session" {
					line += fmt.Sprintf(" left=%d", k.Total)
				} else {
					line += fmt.Sprintf(" moved=%d/%d", k.Done, k.Total)
				}
			}
			fmt.Println(line + " (" + k.Location + ")")
		}
		return nil
	case "rotate":
		msg, err = srv.RotateKey(ctx, actor, kind, *name)
	case "finish":
		msg, err = srv.FinishKey(ctx, actor, kind, *force)
	}
	if err != nil {
		return err
	}
	fmt.Println(msg)
	return nil
}
