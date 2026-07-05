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
	"strings"
	"syscall"
	"time"

	"openwebservermanager/internal/app"
	"openwebservermanager/internal/guac"
	"openwebservermanager/internal/security"
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

	srv := &http.Server{
		Addr:              addr,
		Handler:           app.New(app.Config{Store: st, Guacd: guacd, StaticFS: staticFS, DataDir: dataDir, Public: publicConfig(), TrustProxyHeaders: envBool("OPENWEBSERVERMANAGER_TRUST_PROXY_HEADERS")}),
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
