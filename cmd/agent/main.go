// PrimeCloud Agent Daemon CLI Entry Point.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/primecloud/primecloud-agent/internal/agent"
)

const (
	Version = "0.3.0"
	Banner  = `
  ___     _              ___ _             _ 
 | _ \_ _(_)_ __  ___  / __| |___ _  _ __| |
 |  _/ '_| | '  \/ -_) | (__| / _ \ || / _` + "`" + ` |
 |_| |_| |_|_|_|_\___|  \___|_\___/\_,_\__,_|
 PrimeCloud Agent Daemon - v%s
`
)

func main() {
	fmt.Printf(Banner, Version)

	cfg, err := agent.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error loading configuration: %v\n", err)
		os.Exit(1)
	}

	logger := agent.SetupLogging(os.Stdout, cfg.LogLevel)
	logger.Info("primecloud_agent_initializing", "version", Version)

	ag, err := agent.NewAgent(cfg, logger)
	if err != nil {
		logger.Error("primecloud_agent_init_failed", "error", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := ag.Start(ctx); err != nil {
		logger.Error("primecloud_agent_run_failed", "error", err)
		os.Exit(1)
	}

	logger.Info("primecloud_agent_exited")
}
