package guac

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

type ManagerConfig struct {
	Host       string
	Port       string
	RuntimeDir string
	Logger     *slog.Logger
}

type Manager struct {
	cfg     ManagerConfig
	cmd     *exec.Cmd
	address string
}

func NewManager(cfg ManagerConfig) *Manager {
	if cfg.Port == "" {
		cfg.Port = "4822"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Manager{cfg: cfg}
}

func (m *Manager) Ensure(ctx context.Context) error {
	if m.cfg.Host != "" {
		m.address = net.JoinHostPort(m.cfg.Host, m.cfg.Port)
		return m.wait(ctx)
	}

	exe, err := m.runtimePath()
	if err != nil {
		return err
	}

	m.address = net.JoinHostPort("127.0.0.1", m.cfg.Port)
	if err := m.waitWithTimeout(300 * time.Millisecond); err == nil {
		return nil
	}

	cmd := exec.CommandContext(ctx, exe, "-b", "127.0.0.1", "-l", m.cfg.Port, "-f")
	cmd.Dir = filepath.Dir(exe)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	m.cmd = cmd

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start guacd %s: %w", exe, err)
	}
	go func() {
		if err := cmd.Wait(); err != nil && m.cfg.Logger != nil {
			m.cfg.Logger.Warn("guacd exited", "error", err)
		}
	}()

	return m.wait(ctx)
}

func (m *Manager) Dial(ctx context.Context) (net.Conn, error) {
	if m.address == "" {
		if err := m.Ensure(ctx); err != nil {
			return nil, err
		}
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", m.address)
}

func (m *Manager) Stop() {
	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
	}
}

func (m *Manager) Address() string {
	return m.address
}

func (m *Manager) runtimePath() (string, error) {
	name := "guacd"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(m.cfg.RuntimeDir, runtime.GOOS, name)
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("guacd not found at %s; set OPENWEBSERVERMANAGER_GUACD_HOST or place bundled guacd runtime: %w", path, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("guacd path is a directory: %s", path)
	}
	return path, nil
}

func (m *Manager) wait(ctx context.Context) error {
	deadline := time.Now().Add(8 * time.Second)
	for {
		err := m.waitWithTimeout(500 * time.Millisecond)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (m *Manager) waitWithTimeout(timeout time.Duration) error {
	if m.address == "" {
		return errors.New("guacd address is empty")
	}
	conn, err := net.DialTimeout("tcp", m.address, timeout)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}
