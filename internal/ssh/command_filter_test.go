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

func TestCommandInterceptorRequiresApprovalAndLogs(t *testing.T) {
	st := newTestStore(t)
	_, err := st.CreatePlatformItem("command_filters", model.PlatformItemRequest{
		Name:     "production restart review",
		Type:     "approval",
		Status:   "enabled",
		Protocol: model.ProtocolSSH,
		Metadata: map[string]any{
			"pattern": "systemctl restart",
			"risk":    "medium",
		},
	})
	if err != nil {
		t.Fatalf("create command filter: %v", err)
	}
	interceptor := newCommandInterceptor(st, model.ConnectionSession{ID: "sess_approval", Protocol: model.ProtocolSSH, ServerID: "srv_approval", UserID: "user_approval"})

	filtered, events := interceptor.Process([]byte("systemctl restart nginx\r"))
	if string(filtered) != "systemctl restart nginx\x15" {
		t.Fatalf("filtered = %q, want command plus clear-line", string(filtered))
	}
	if len(events) != 1 || !events[0].Blocked || !strings.Contains(events[0].Notice, "requires approval") {
		t.Fatalf("events = %#v, want approval-required blocked event", events)
	}

	logs, err := st.ListPlatformItems("exec_command_logs")
	if err != nil {
		t.Fatalf("list command logs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("logs len = %d, want 1", len(logs))
	}
	if logs[0].Status != "approval_required" || logs[0].Type != "approval" {
		t.Fatalf("log = %#v, want approval_required log", logs[0])
	}
	if logs[0].Metadata["blocked"] != true || logs[0].Metadata["action"] != "approval" {
		t.Fatalf("log metadata = %#v, want blocked approval metadata", logs[0].Metadata)
	}
}

func TestCommandInterceptorRespectsSessionScope(t *testing.T) {
	st := newTestStore(t)
	_, err := st.CreatePlatformItem("command_filters", model.PlatformItemRequest{
		Name:     "scoped shell",
		Type:     "deny",
		Status:   "enabled",
		Protocol: model.ProtocolSSH,
		TargetID: "srv_match",
		OwnerID:  "user_match",
		Metadata: map[string]any{
			"pattern": "reboot",
			"risk":    "high",
		},
	})
	if err != nil {
		t.Fatalf("create command filter: %v", err)
	}

	other := newCommandInterceptor(st, model.ConnectionSession{ID: "sess_other", Protocol: model.ProtocolSSH, ServerID: "srv_other", UserID: "user_match"})
	filtered, events := other.Process([]byte("reboot\r"))
	if string(filtered) != "reboot\r" || len(events) != 1 || events[0].Blocked {
		t.Fatalf("other session filtered = %q events = %#v, want allowed command", string(filtered), events)
	}

	matching := newCommandInterceptor(st, model.ConnectionSession{ID: "sess_match", Protocol: model.ProtocolSSH, ServerID: "srv_match", UserID: "user_match"})
	filtered, events = matching.Process([]byte("reboot\r"))
	if string(filtered) != "reboot\x15" || len(events) != 1 || !events[0].Blocked {
		t.Fatalf("matching session filtered = %q events = %#v, want blocked command", string(filtered), events)
	}

	logs, err := st.ListPlatformItems("exec_command_logs")
	if err != nil {
		t.Fatalf("list command logs: %v", err)
	}
	if len(logs) != 2 {
		t.Fatalf("logs len = %d, want 2", len(logs))
	}
	if commandLogStatusBySession(logs, "sess_other") != "submitted" || commandLogStatusBySession(logs, "sess_match") != "denied" {
		t.Fatalf("logs = %#v, want submitted other session and denied matching session", logs)
	}
}

func TestCommandInterceptorMatchesUserNameScope(t *testing.T) {
	st := newTestStore(t)
	user, err := st.CreatePlatformItem("users", model.PlatformItemRequest{
		Name:     "operator-name",
		Username: "operator-login",
		Status:   "enabled",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	_, err = st.CreatePlatformItem("command_filters", model.PlatformItemRequest{
		Name:     "operator scoped restart",
		Type:     "deny",
		Status:   "enabled",
		Protocol: model.ProtocolSSH,
		OwnerID:  "operator-login",
		TargetID: "srv_scoped",
		Metadata: map[string]any{
			"pattern": "systemctl restart",
			"risk":    "high",
		},
	})
	if err != nil {
		t.Fatalf("create command filter: %v", err)
	}

	interceptor := newCommandInterceptor(st, model.ConnectionSession{
		ID:       "sess_username_scope",
		Protocol: model.ProtocolSSH,
		ServerID: "srv_scoped",
		UserID:   user.ID,
	})
	filtered, events := interceptor.Process([]byte("systemctl restart nginx\r"))
	if string(filtered) != "systemctl restart nginx\x15" || len(events) != 1 || !events[0].Blocked {
		t.Fatalf("filtered = %q events = %#v, want username-scoped command blocked", string(filtered), events)
	}

	logs, err := st.ListPlatformItems("exec_command_logs")
	if err != nil {
		t.Fatalf("list command logs: %v", err)
	}
	if commandLogStatusBySession(logs, "sess_username_scope") != "denied" {
		t.Fatalf("logs = %#v, want denied username-scoped command", logs)
	}
}

func commandLogStatusBySession(logs []model.PlatformItem, sessionID string) string {
	for _, log := range logs {
		if log.Metadata["session_id"] == sessionID {
			return log.Status
		}
	}
	return ""
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
