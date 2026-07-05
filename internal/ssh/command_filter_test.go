package sshsession

import (
	"path/filepath"
	"strings"
	"testing"

	"openwebservermanager/internal/model"
	"openwebservermanager/internal/security"
	"openwebservermanager/internal/store"
)

func TestCommandInterceptorBlocksDenyFiltersAndLogs(t *testing.T) {
	st := newTestStore(t)
	_, err := st.CreatePlatformItem("command_filters", model.PlatformItemRequest{
		Name:   "dangerous shell",
		Type:   "deny",
		Status: "enabled",
		Metadata: map[string]any{
			"pattern": `rm\s+-rf|shutdown`,
			"risk":    "high",
		},
	})
	if err != nil {
		t.Fatalf("create command filter: %v", err)
	}
	interceptor := newCommandInterceptor(st, model.ConnectionSession{
		ID:           "sess_1",
		Protocol:     model.ProtocolSSH,
		ServerID:     "srv_1",
		CredentialID: "cred_1",
		UserID:       "user_1",
		ClientIP:     "127.0.0.1",
	})

	filtered, events := interceptor.Process([]byte("rm -rf /\r"))
	if string(filtered) != "rm -rf /\x15" {
		t.Fatalf("filtered = %q, want command plus clear-line", string(filtered))
	}
	if len(events) != 1 || !events[0].Blocked {
		t.Fatalf("events = %#v, want one blocked event", events)
	}
	if !strings.Contains(events[0].Notice, "dangerous shell") {
		t.Fatalf("notice = %q, want rule name", events[0].Notice)
	}

	logs, err := st.ListPlatformItems("exec_command_logs")
	if err != nil {
		t.Fatalf("list command logs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("logs len = %d, want 1", len(logs))
	}
	if logs[0].Status != "denied" || logs[0].TargetID != "srv_1" || logs[0].OwnerID != "user_1" {
		t.Fatalf("log = %#v, want denied command log for session user and server", logs[0])
	}
	if logs[0].Metadata["risk"] != "high" || logs[0].Metadata["command"] != "rm -rf /" {
		t.Fatalf("log metadata = %#v, want risk and command", logs[0].Metadata)
	}
}

func TestCommandInterceptorAllowsUnmatchedCommandsAndLogs(t *testing.T) {
	st := newTestStore(t)
	_, err := st.CreatePlatformItem("command_filters", model.PlatformItemRequest{
		Name:     "disabled dangerous shell",
		Type:     "deny",
		Status:   "disabled",
		Metadata: map[string]any{"pattern": `rm\s+-rf`},
	})
	if err != nil {
		t.Fatalf("create command filter: %v", err)
	}
	interceptor := newCommandInterceptor(st, model.ConnectionSession{ID: "sess_2", Protocol: model.ProtocolSSH, ServerID: "srv_2", UserID: "user_2"})

	filtered, events := interceptor.Process([]byte("ls -la\r"))
	if string(filtered) != "ls -la\r" {
		t.Fatalf("filtered = %q, want original command", string(filtered))
	}
	if len(events) != 1 || events[0].Blocked {
		t.Fatalf("events = %#v, want one allowed event", events)
	}

	logs, err := st.ListPlatformItems("exec_command_logs")
	if err != nil {
		t.Fatalf("list command logs: %v", err)
	}
	if len(logs) != 1 || logs[0].Status != "submitted" || logs[0].Name != "ls -la" {
		t.Fatalf("logs = %#v, want submitted command log", logs)
	}
}

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	cipher, err := security.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "store.json"), cipher)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}
