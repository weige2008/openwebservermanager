package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"openwebservermanager/internal/agentrelay"
)

var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	serverURL := flag.String("server", env("OPENWEBSERVERMANAGER_AGENT_SERVER", ""), "manager base URL")
	token := flag.String("token", env("OPENWEBSERVERMANAGER_AGENT_TOKEN", ""), "registration token")
	name := flag.String("name", env("OPENWEBSERVERMANAGER_AGENT_NAME", ""), "agent display name")
	workers := flag.Int("workers", envInt("OPENWEBSERVERMANAGER_AGENT_WORKERS", 4), "concurrent relay workers")
	heartbeat := flag.Duration("heartbeat", envDuration("OPENWEBSERVERMANAGER_AGENT_HEARTBEAT", 30*time.Second), "heartbeat interval")
	insecure := flag.Bool("insecure-skip-verify", envBool("OPENWEBSERVERMANAGER_AGENT_INSECURE_SKIP_VERIFY"), "skip manager TLS certificate verification")
	flag.Parse()

	client, err := agentrelay.NewClient(agentrelay.ClientConfig{
		ServerURL:          *serverURL,
		RegistrationToken:  *token,
		Name:               *name,
		Version:            version + "+" + commit,
		Capabilities:       []string{"tcp", "ssh", "rdp", "vnc", "http", "database"},
		Workers:            *workers,
		HeartbeatInterval:  *heartbeat,
		InsecureSkipVerify: *insecure,
		Logger:             slog.Default(),
	})
	if err != nil {
		slog.Error("agent configuration invalid", "error", err)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := client.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		slog.Error("agent stopped", "error", err)
		os.Exit(1)
	}
}
func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envBool(name string) bool {
	switch strings.ToLower(env(name, "")) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func envInt(name string, fallback int) int {
	value, err := strconv.Atoi(env(name, ""))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func envDuration(name string, fallback time.Duration) time.Duration {
	value, err := time.ParseDuration(env(name, ""))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}
