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
	"strings"
	"sync"
	"time"
)

type ManagerConfig struct {
	Host       string
	Port       string
	RuntimeDir string
	Logger     *slog.Logger
}

type Manager struct {
	cfg       ManagerConfig
	cmd       *exec.Cmd
	mu        sync.RWMutex
	address   string
	lastError string
}

type RuntimeStatus struct {
	Address   string    `json:"address,omitempty"`
	Status    string    `json:"status"`
	LastError string    `json:"last_error,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
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
		m.setAddress(net.JoinHostPort(m.cfg.Host, m.cfg.Port))
		if err := m.wait(ctx); err != nil {
			m.setLastError(err)
			return err
		}
		m.setLastError(nil)
		return nil
	}

	exe, err := m.runtimePath()
	if err != nil {
		m.setLastError(err)
		return err
	}

	m.setAddress(net.JoinHostPort("127.0.0.1", m.cfg.Port))
	if err := m.waitWithTimeout(300 * time.Millisecond); err == nil {
		m.setLastError(nil)
		return nil
	}

	cmd := exec.CommandContext(ctx, exe, "-b", "127.0.0.1", "-l", m.cfg.Port, "-f")
	cmd.Dir = filepath.Dir(exe)
	cmd.Env = m.runtimeEnvironment(exe)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	m.cmd = cmd

	if err := cmd.Start(); err != nil {
		err = fmt.Errorf("start guacd %s: %w", exe, err)
		m.setLastError(err)
		return err
	}
	go func() {
		if err := cmd.Wait(); err != nil && m.cfg.Logger != nil {
			m.cfg.Logger.Warn("guacd exited", "error", err)
		}
	}()

	if err := m.wait(ctx); err != nil {
		m.setLastError(err)
		return err
	}
	m.setLastError(nil)
	return nil
}

func (m *Manager) Dial(ctx context.Context) (net.Conn, error) {
	if m.Address() == "" {
		if err := m.Ensure(ctx); err != nil {
			return nil, err
		}
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", m.Address())
	m.setLastError(err)
	return conn, err
}

func (m *Manager) Stop() {
	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
	}
}

func (m *Manager) Address() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.address
}

func (m *Manager) Status(timeout time.Duration) RuntimeStatus {
	if timeout <= 0 {
		timeout = 300 * time.Millisecond
	}
	status := RuntimeStatus{
		Address:   m.Address(),
		Status:    "unavailable",
		LastError: m.LastError(),
		CheckedAt: time.Now().UTC(),
	}
	if status.Address == "" {
		return status
	}
	if err := m.waitWithTimeout(timeout); err != nil {
		m.setLastError(err)
		status.Status = "error"
		status.LastError = err.Error()
		return status
	}
	m.setLastError(nil)
	status.Status = "running"
	status.LastError = ""
	return status
}

func (m *Manager) LastError() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastError
}

func (m *Manager) setAddress(address string) {
	m.mu.Lock()
	m.address = address
	m.mu.Unlock()
}

func (m *Manager) setLastError(err error) {
	m.mu.Lock()
	if err == nil {
		m.lastError = ""
	} else {
		m.lastError = err.Error()
	}
	m.mu.Unlock()
}

func (m *Manager) runtimePath() (string, error) {
	name := "guacd"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	root := filepath.Join(m.cfg.RuntimeDir, runtime.GOOS)
	candidates := []string{
		filepath.Join(root, name),
		filepath.Join(root, "bin", name),
		filepath.Join(root, "sbin", name),
	}
	for _, path := range candidates {
		info, err := os.Stat(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return "", fmt.Errorf("inspect guacd runtime %s: %w", path, err)
		}
		if info.IsDir() {
			return "", fmt.Errorf("guacd path is a directory: %s", path)
		}
		return path, nil
	}
	return "", fmt.Errorf("guacd not found under %s; set OPENWEBSERVERMANAGER_GUACD_HOST or install a bundled runtime containing %s", root, name)
}

func (m *Manager) runtimeEnvironment(exe string) []string {
	env := os.Environ()
	exeDir := filepath.Dir(exe)
	runtimeRoot := exeDir
	if base := strings.ToLower(filepath.Base(exeDir)); base == "bin" || base == "sbin" {
		runtimeRoot = filepath.Dir(exeDir)
	}
	env = prependEnvironmentPath(env, "PATH", exeDir)
	if runtime.GOOS == "windows" {
		home := filepath.Join(runtimeRoot, "home")
		_ = os.MkdirAll(home, 0o700)
		env = setEnvironmentValue(env, "HOME", home)
	}
	if runtime.GOOS == "linux" {
		env = prependEnvironmentPath(env, "LD_LIBRARY_PATH", filepath.Join(runtimeRoot, "lib"))
		env = setEnvironmentValue(env, "FREERDP_PLUGIN_PATH", filepath.Join(runtimeRoot, "usr", "lib", "freerdp2"))
	}
	return env
}

func prependEnvironmentPath(env []string, key, value string) []string {
	current := environmentValue(env, key)
	if current != "" {
		value += string(os.PathListSeparator) + current
	}
	return setEnvironmentValue(env, key, value)
}

func environmentValue(env []string, key string) string {
	prefix := strings.ToUpper(key) + "="
	for _, item := range env {
		if strings.HasPrefix(strings.ToUpper(item), prefix) {
			return item[len(prefix):]
		}
	}
	return ""
}

func setEnvironmentValue(env []string, key, value string) []string {
	prefix := strings.ToUpper(key) + "="
	next := make([]string, 0, len(env)+1)
	for _, item := range env {
		if !strings.HasPrefix(strings.ToUpper(item), prefix) {
			next = append(next, item)
		}
	}
	return append(next, key+"="+value)
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
	address := m.Address()
	if address == "" {
		return errors.New("guacd address is empty")
	}
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}
