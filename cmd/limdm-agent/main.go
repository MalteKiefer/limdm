// limdm-agent is the LiMDM device agent for Debian, Ubuntu and Fedora.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"

	"github.com/maltekiefer/limdm/internal/agent"
)

const usage = `usage:
  limdm-agent enroll --server https://mdm.example.com:8444 --fingerprint SHA256 --token TOKEN [--allow-scripts]
  limdm-agent enroll --config /etc/limdm/enroll.conf
  limdm-agent run                 run the agent (systemd service)
  limdm-agent check [--level 2]   print local compliance report, changes nothing
  limdm-agent recovery-key [--all] create and escrow LUKS recovery keys (asks for the passphrase)
  limdm-agent pam-auth            PAM helper for desktop OIDC login (called by pam_exec)
  limdm-agent version`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if os.Args[1] == "pam-auth" {
		os.Exit(agent.PAMAuth())
	}
	if os.Args[1] == "version" {
		fmt.Println(agent.Version)
		return
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "error: must run as root")
		os.Exit(1)
	}
	var err error
	switch os.Args[1] {
	case "enroll":
		fs := flag.NewFlagSet("enroll", flag.ExitOnError)
		server := fs.String("server", "", "agent API URL")
		token := fs.String("token", "", "enrollment token")
		fp := fs.String("fingerprint", "", "SHA-256 fingerprint of the device CA")
		scripts := fs.Bool("allow-scripts", false, "allow remote shell scripts on this device")
		conf := fs.String("config", "", "enroll with a config file (server, fingerprint, token, allow_scripts)")
		fs.Parse(os.Args[2:])
		if *conf != "" {
			if err = agent.EnrollFromConfig(*conf); err == nil {
				fmt.Println("enrolled. start the agent: systemctl enable --now limdm-agent")
			}
			break
		}
		if *server == "" || *token == "" || *fp == "" {
			err = errors.New("--server, --fingerprint and --token are required")
			break
		}
		if err = agent.Enroll(*server, *token, *fp, *scripts); err == nil {
			fmt.Println("enrolled. start the agent: systemctl enable --now limdm-agent")
		}
	case "run":
		log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
		if !agent.Enrolled() {
			if _, serr := os.Stat(agent.EnrollConfig); serr == nil {
				if err = agent.EnrollFromConfig(agent.EnrollConfig); err != nil {
					break
				}
				log.Info("enrolled from " + agent.EnrollConfig)
			}
		}
		var a *agent.Agent
		if a, err = agent.New(log); err == nil {
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			err = a.Run(ctx)
		}
	case "check":
		fs := flag.NewFlagSet("check", flag.ExitOnError)
		level := fs.Int("level", 0, "override compliance level (1 or 2)")
		fs.Parse(os.Args[2:])
		err = agent.Report(os.Stdout, *level)
	case "recovery-key":
		fs := flag.NewFlagSet("recovery-key", flag.ExitOnError)
		all := fs.Bool("all", false, "also replace keys that are already escrowed")
		fs.Parse(os.Args[2:])
		err = agent.CreateRecoveryKeys(func(prompt string) (string, error) {
			fmt.Fprint(os.Stderr, prompt)
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			return string(b), err
		}, *all)
	default:
		err = errors.New(usage)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
