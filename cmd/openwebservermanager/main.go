package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"openwebservermanager/internal/app"
	"openwebservermanager/internal/guac"
	"openwebservermanager/internal/security"
	sshrunner "openwebservermanager/internal/ssh"
	"openwebservermanager/internal/store"
)

//go:embed static
var staticFS embed.FS

var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	if err := run(); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	addr := env("OPENWEBSERVERMANAGER_ADDR", "127.0.0.1:23876")
	dataDir := env("OPENWEBSERVERMANAGER_DATA_DIR", "data")

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	key, err := security.LoadMasterKey(dataDir)
	if err != nil {
		return err
	}

	cipher, err := security.NewCipher(key)
	if err != nil {
		return err
	}

	storePath, err := migrateStorePath(dataDir)
	if err != nil {
		return err
	}
	st, err := store.Open(storePath, cipher)
	if err != nil {
		return err
	}
	defer st.Close()

	guacd := guac.NewManager(guac.ManagerConfig{
		Host:       env("OPENWEBSERVERMANAGER_GUACD_HOST", ""),
		Port:       env("OPENWEBSERVERMANAGER_GUACD_PORT", "4822"),
		RuntimeDir: env("OPENWEBSERVERMANAGER_GUACD_RUNTIME", "runtime/guacd"),
		Logger:     slog.Default(),
	})
	if err := guacd.Ensure(context.Background()); err != nil {
		slog.Warn("rdp gateway unavailable", "error", err)
	}
	defer guacd.Stop()

	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()
	sshGateway := sshrunner.NewGatewayManager(rootCtx, st, dataDir, env("OPENWEBSERVERMANAGER_SSH_GATEWAY_ADDR", ""), slog.Default())
	if err := sshGateway.Reload(); err != nil {
		slog.Warn("ssh gateway unavailable", "error", err)
	}
	defer sshGateway.Close()
	if sshGateway.Address() != "" {
		slog.Info("ssh gateway ready", "addr", sshGateway.Address())
	}

	appServer := app.NewServer(app.Config{Store: st, Guacd: guacd, SSHGateway: sshGateway, StaticFS: staticFS, DataDir: dataDir, Public: publicConfig(), TrustProxyHeaders: envBool("OPENWEBSERVERMANAGER_TRUST_PROXY_HEADERS")})
	scheduler := appServer.StartScheduler(rootCtx, app.SchedulerConfig{
		PollInterval: schedulerPollInterval(),
		Logger:       slog.Default(),
	})
	defer scheduler.Stop()

	srv := &http.Server{
		Addr:              addr,
		Handler:           appServer,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("openwebservermanager listening", "addr", "http://"+addr)
		errCh <- srv.ListenAndServe()
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-stop:
		slog.Info("shutdown requested", "signal", sig.String())
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rootCancel()
	return srv.Shutdown(ctx)
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	if legacyName := legacyEnvName(name); legacyName != name {
		if value := os.Getenv(legacyName); value != "" {
			return value
		}
	}
	return fallback
}

func envBool(name string) bool {
	value := strings.ToLower(strings.TrimSpace(env(name, "")))
	return value == "1" || value == "true" || value == "yes" || value == "on"
}

func schedulerPollInterval() time.Duration {
	raw := strings.TrimSpace(env("OPENWEBSERVERMANAGER_SCHEDULER_INTERVAL", "30s"))
	if raw == "" {
		return 30 * time.Second
	}
	if duration, err := time.ParseDuration(raw); err == nil && duration > 0 {
		return duration
	}
	if seconds, err := strconv.Atoi(raw); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	slog.Warn("invalid scheduler interval, using default", "value", raw)
	return 30 * time.Second
}

func legacyEnvName(name string) string {
	return strings.Replace(name, "OPENWEBSERVERMANAGER_", "SERVERMANAGER_", 1)
}

func migrateStorePath(dataDir string) (string, error) {
	next := filepath.Join(dataDir, "openwebservermanager.json")
	legacy := filepath.Join(dataDir, "servermanager.json")
	if _, err := os.Stat(next); err == nil {
		return next, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("stat data store: %w", err)
	}
	if _, err := os.Stat(legacy); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return next, nil
		}
		return "", fmt.Errorf("stat legacy data store: %w", err)
	}
	if err := os.Rename(legacy, next); err != nil {
		return "", fmt.Errorf("migrate legacy data store: %w", err)
	}
	return next, nil
}

func publicConfig() app.PublicConfig {
	return app.PublicConfig{
		SiteName:  env("OPENWEBSERVERMANAGER_SITE_NAME", "Open Web Server Manager"),
		Version:   env("OPENWEBSERVERMANAGER_VERSION", version),
		GitHubURL: env("OPENWEBSERVERMANAGER_GITHUB_URL", "https://github.com/weige2008/openwebservermanager"),
		Copyright: env("OPENWEBSERVERMANAGER_COPYRIGHT", "Copyright (c) 2026 weige2008. All rights reserved."),
		NavLinks: []app.PublicNavLink{
			{Title: "product", Href: "/#product"},
			{Title: "connections", Href: "/#connections"},
			{Title: "security", Href: "/#security"},
			{Title: "deploy", Href: "/#deploy"},
			{Title: "about", Href: "/about"},
		},
	}
}
