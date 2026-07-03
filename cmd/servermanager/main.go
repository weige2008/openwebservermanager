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
	"syscall"
	"time"

	"servermanager/internal/app"
	"servermanager/internal/guac"
	"servermanager/internal/security"
	"servermanager/internal/store"
)

//go:embed static
var staticFS embed.FS

func main() {
	if err := run(); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	addr := env("SERVERMANAGER_ADDR", "127.0.0.1:23876")
	dataDir := env("SERVERMANAGER_DATA_DIR", "data")

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

	st, err := store.Open(filepath.Join(dataDir, "servermanager.json"), cipher)
	if err != nil {
		return err
	}

	guacd := guac.NewManager(guac.ManagerConfig{
		Host:       os.Getenv("SERVERMANAGER_GUACD_HOST"),
		Port:       env("SERVERMANAGER_GUACD_PORT", "4822"),
		RuntimeDir: env("SERVERMANAGER_GUACD_RUNTIME", "runtime/guacd"),
		Logger:     slog.Default(),
	})
	if err := guacd.Ensure(context.Background()); err != nil {
		slog.Warn("rdp gateway unavailable", "error", err)
	}
	defer guacd.Stop()

	srv := &http.Server{
		Addr:              addr,
		Handler:           app.New(app.Config{Store: st, Guacd: guacd, StaticFS: staticFS, DataDir: dataDir, Public: publicConfig()}),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("servermanager listening", "addr", "http://"+addr)
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
	return fallback
}

func publicConfig() app.PublicConfig {
	return app.PublicConfig{
		SiteName: env("SERVERMANAGER_SITE_NAME", "ServerManager"),
		NavLinks: []app.PublicNavLink{
			{Title: "product", Href: "#product"},
			{Title: "connections", Href: "#connections"},
			{Title: "security", Href: "#security"},
			{Title: "deploy", Href: "#deploy"},
		},
	}
}
