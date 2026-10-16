// PrimeCloud Agent Daemon CLI Entry Point.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/primecloud/primecloud-agent/internal/agent"
)

var (
	// Version is injected at build time via -ldflags "-X main.Version=...".
	// Defaults to "dev" for unversioned local builds.
	Version = "dev"

	// CommitSHA is injected at build time via -ldflags "-X main.CommitSHA=...".
	// Defaults to "none" for unversioned local builds.
	CommitSHA = "none"
)

const Banner = `
  ___     _              ___ _             _ 
 | _ \_ _(_)_ __  ___  / __| |___ _  _ __| |
 |  _/ '_| | '  \/ -_) | (__| / _ \ || / _` + "`" + ` |
 |_| |_| |_|_|_|_\___|  \___|_\___/\_,_\__,_|
 PrimeCloud Agent Daemon - v%s
`

// formatVersion returns the formatted version string including commit SHA if available.
func formatVersion() string {
	if CommitSHA != "" && CommitSHA != "none" {
		return fmt.Sprintf("primecloud-agent %s (commit: %s)", Version, CommitSHA)
	}
	return fmt.Sprintf("primecloud-agent %s", Version)
}

// run parses command-line arguments and executes the CLI or daemon.
// Extracted from main() for direct, deterministic unit testing.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("primecloud-agent", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var showVersion bool
	fs.BoolVar(&showVersion, "version", false, "Print agent version and commit SHA, then exit")
	fs.BoolVar(&showVersion, "v", false, "Print agent version and commit SHA, then exit (shorthand)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if showVersion {
		fmt.Fprintln(stdout, formatVersion())
		return 0
	}

	displayVersion := strings.TrimPrefix(Version, "v")
	fmt.Fprintf(stdout, Banner, displayVersion)

	cfg, err := agent.LoadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "Fatal error loading configuration: %v\n", err)
		return 1
	}

	logger := agent.SetupLogging(stdout, cfg.LogLevel)
	logger.Info("primecloud_agent_initializing", "version", Version, "commit", CommitSHA)

	ag, err := agent.NewAgent(cfg, logger)
	if err != nil {
		logger.Error("primecloud_agent_init_failed", "error", err)
		return 1
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := ag.Start(ctx); err != nil {
		logger.Error("primecloud_agent_run_failed", "error", err)
		return 1
	}

	logger.Info("primecloud_agent_exited")
	return 0
}

func main() {
	if code := run(os.Args[1:], os.Stdout, os.Stderr); code != 0 {
		os.Exit(code)
	}
}
