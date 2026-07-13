package guac

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestManagerStatusTracksExternalGatewayHealth(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("split address: %v", err)
	}

	manager := NewManager(ManagerConfig{Host: host, Port: port})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := manager.Ensure(ctx); err == nil {
		t.Fatal("Ensure() succeeded for an unavailable gateway")
	}
	status := manager.Status(50 * time.Millisecond)
	if status.Address != address || status.Status != "error" || status.LastError == "" {
		t.Fatalf("unavailable status = %#v", status)
	}

	listener, err = net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("restore listener: %v", err)
	}
	defer listener.Close()
	status = manager.Status(100 * time.Millisecond)
	if status.Status != "running" || status.LastError != "" {
		t.Fatalf("restored status = %#v", status)
	}
}

func TestManagerRuntimePathSupportsPortableBinLayout(t *testing.T) {
	root := t.TempDir()
	name := "guacd"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	want := filepath.Join(root, runtime.GOOS, "bin", name)
	if err := os.MkdirAll(filepath.Dir(want), 0o755); err != nil {
		t.Fatalf("create runtime bin: %v", err)
	}
	if err := os.WriteFile(want, []byte("runtime"), 0o755); err != nil {
		t.Fatalf("write runtime executable: %v", err)
	}

	manager := NewManager(ManagerConfig{RuntimeDir: root})
	got, err := manager.runtimePath()
	if err != nil {
		t.Fatalf("resolve portable runtime: %v", err)
	}
	if got != want {
		t.Fatalf("runtime path = %q, want %q", got, want)
	}
}

func TestManagerRuntimeEnvironmentPrependsRuntimeDirectories(t *testing.T) {
	root := t.TempDir()
	exe := filepath.Join(root, "bin", "guacd")
	manager := NewManager(ManagerConfig{})
	env := manager.runtimeEnvironment(exe)
	pathValue := environmentValue(env, "PATH")
	if !strings.HasPrefix(pathValue, filepath.Dir(exe)) {
		t.Fatalf("PATH = %q, want runtime bin prefix", pathValue)
	}
	if runtime.GOOS == "linux" {
		if got := environmentValue(env, "LD_LIBRARY_PATH"); !strings.HasPrefix(got, filepath.Join(root, "lib")) {
			t.Fatalf("LD_LIBRARY_PATH = %q", got)
		}
		if got := environmentValue(env, "FREERDP_PLUGIN_PATH"); got != filepath.Join(root, "usr", "lib", "freerdp2") {
			t.Fatalf("FREERDP_PLUGIN_PATH = %q", got)
		}
	}
	if runtime.GOOS == "windows" {
		home := filepath.Join(root, "home")
		if got := environmentValue(env, "HOME"); got != home {
			t.Fatalf("HOME = %q, want %q", got, home)
		}
		if info, err := os.Stat(home); err != nil || !info.IsDir() {
			t.Fatalf("runtime HOME was not created: info=%v err=%v", info, err)
		}
	}
}
