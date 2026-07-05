package guac

import (
	"testing"

	"openwebservermanager/internal/model"
)

func TestDesktopPolicyArguments(t *testing.T) {
	tunnel := Tunnel{DataDir: t.TempDir()}
	cfg := DesktopConfig{
		Protocol:         model.ProtocolRDP,
		Session:          model.ConnectionSession{ID: "sess_policy"},
		Host:             "127.0.0.1",
		Port:             3390,
		Username:         "Administrator",
		Password:         "secret",
		Width:            1600,
		Height:           1000,
		DPI:              120,
		ColorDepth:       16,
		IgnoreCert:       false,
		EnableDrive:      false,
		ClipboardEnabled: false,
		ReadOnly:         true,
		ResizeMethod:     "reconnect",
	}
	assertArg := func(name, want string) {
		t.Helper()
		if got := tunnel.argValue(name, cfg); got != want {
			t.Fatalf("arg %s = %q, want %q", name, got, want)
		}
	}
	assertArg("port", "3390")
	assertArg("color-depth", "16")
	assertArg("resize-method", "reconnect")
	assertArg("enable-drive", "false")
	assertArg("read-only", "true")
	assertArg("disable-copy", "true")
	assertArg("disable-paste", "true")
	assertArg("ignore-cert", "false")
	assertArg("width", "1600")
	assertArg("height", "1000")
	assertArg("dpi", "120")
}
