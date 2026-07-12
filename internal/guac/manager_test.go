package guac

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

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
