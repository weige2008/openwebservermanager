package sshsession

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestCommandInterceptorFailsClosedWhenCommandLogCannotPersist(t *testing.T) {
	st := newTestStore(t)
	unblock := blockPlatformCollectionInsert(t, st, "exec_command_logs")
	defer unblock()
	interceptor := newCommandInterceptor(st, model.ConnectionSession{
		ID:       "sess_audit_failure",
		Protocol: model.ProtocolSSH,
		ServerID: "srv_audit_failure",
		UserID:   "user_audit_failure",
		ClientIP: "192.0.2.50",
	})

	filtered, events := interceptor.Process([]byte("whoami\rprintf skipped\r"))
	if string(filtered) != "whoami\x15" {
		t.Fatalf("filtered = %q, want first command cleared and remaining pasted input dropped", string(filtered))
	}
	if len(events) != 1 || !events[0].Blocked || !events[0].Fatal {
		t.Fatalf("events = %#v, want one fatal blocked event", events)
	}
	if !strings.Contains(strings.ToLower(events[0].Notice), "audit") || !strings.Contains(strings.ToLower(events[0].Notice), "closed") {
		t.Fatalf("notice = %q, want clear audit failure and session closure", events[0].Notice)
	}
	logs, err := st.ListPlatformItems("exec_command_logs")
	if err != nil || len(logs) != 0 {
		t.Fatalf("exec logs = %#v err=%v, want no forged success log", logs, err)
	}
	_, _, _, auditLogs := st.Bootstrap()
	found := false
	for _, item := range auditLogs {
		if item.Action == "exec_command.log.persist_failed" && item.UserID == "user_audit_failure" && item.TargetID == "srv_audit_failure" {
			found = true
		}
	}
	if !found {
		t.Fatalf("core audit logs = %#v, want exec command persistence failure", auditLogs)
	}
}

func TestCommandInterceptorFailsClosedWhenApprovalCannotPersist(t *testing.T) {
	st := newTestStore(t)
	if _, err := st.CreatePlatformItem("command_filters", model.PlatformItemRequest{
		Name:     "restart approval",
		Type:     "approval",
		Status:   "enabled",
		Protocol: model.ProtocolSSH,
		Metadata: map[string]any{"pattern": "systemctl restart", "risk": "critical"},
	}); err != nil {
		t.Fatalf("create approval filter: %v", err)
	}
	unblock := blockPlatformCollectionInsert(t, st, "command_approvals")
	defer unblock()
	interceptor := newCommandInterceptor(st, model.ConnectionSession{ID: "sess_approval_failure", Protocol: model.ProtocolSSH, ServerID: "srv_approval_failure", UserID: "user_approval_failure"})

	filtered, events := interceptor.Process([]byte("systemctl restart nginx\r"))
	if string(filtered) != "systemctl restart nginx\x15" || len(events) != 1 || !events[0].Fatal || !events[0].Blocked {
		t.Fatalf("filtered = %q events = %#v, want fatal approval persistence block", string(filtered), events)
	}
	logs, err := st.ListPlatformItems("exec_command_logs")
	if err != nil || len(logs) != 1 {
		t.Fatalf("exec logs = %#v err=%v, want one approval-required audit record", logs, err)
	}
	if logs[0].Status != "approval_required" || !strings.Contains(firstString(logs[0].Metadata["approval_error"]), "blocked command_approvals insert") {
		t.Fatalf("approval failure log = %#v", logs[0])
	}
	_, _, _, auditLogs := st.Bootstrap()
	found := false
	for _, item := range auditLogs {
		if item.Action == "command_interceptor.persist_failed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("core audit logs = %#v, want approval persistence failure", auditLogs)
	}
}

func TestCommandInterceptorFailsClosedWhenPoliciesCannotLoad(t *testing.T) {
	st := newTestStore(t)
	interceptor := newCommandInterceptor(st, model.ConnectionSession{ID: "sess_policy_failure", Protocol: model.ProtocolSSH, ServerID: "srv_policy_failure", UserID: "user_policy_failure"})
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	filtered, events := interceptor.Process([]byte("id\rnext-command\r"))
	if string(filtered) != "id\x15" || len(events) != 1 || !events[0].Fatal || !events[0].Blocked {
		t.Fatalf("filtered = %q events = %#v, want policy load failure to block and drop remaining input", string(filtered), events)
	}
}

func TestExecCommandFailsClosedWhenPoliciesCannotLoad(t *testing.T) {
	st := newTestStore(t)
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	result, err := (Runner{Store: st}).RunCommand(
		model.ConnectionSession{ID: "sess_exec_policy_failure", Protocol: model.ProtocolSSH, ServerID: "srv_exec_policy_failure", UserID: "user_exec_policy_failure"},
		model.Server{},
		model.Credential{},
		store.CredentialSecret{},
		"whoami",
		time.Second,
	)
	if err == nil {
		t.Fatal("exec command policy load failure was allowed")
	}
	if !result.Blocked || result.Status != "failed" || result.Action != "deny" || !strings.Contains(result.Error, "load command filters") {
		t.Fatalf("exec result = %#v err=%v, want fail-closed policy error", result, err)
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

func blockPlatformCollectionInsert(t *testing.T, st *store.Store, collection string) func() {
	t.Helper()
	db, err := sql.Open("sqlite", st.DatabasePath())
	if err != nil {
		t.Fatalf("open store database: %v", err)
	}
	trigger := "block_" + collection + "_insert"
	statement := `CREATE TRIGGER ` + trigger + ` BEFORE INSERT ON platform_records WHEN NEW.collection = '` + collection + `' BEGIN SELECT RAISE(FAIL, 'blocked ` + collection + ` insert'); END`
	if _, err := db.Exec(statement); err != nil {
		_ = db.Close()
		t.Fatalf("create %s blocker: %v", collection, err)
	}
	return func() {
		_, _ = db.Exec(`DROP TRIGGER IF EXISTS ` + trigger)
		_ = db.Close()
	}
}

func blockPlatformCollectionPayloadInsert(t *testing.T, st *store.Store, collection, fragment string) func() {
	t.Helper()
	db, err := sql.Open("sqlite", st.DatabasePath())
	if err != nil {
		t.Fatalf("open store database: %v", err)
	}
	trigger := "block_" + collection + "_payload_insert"
	statement := `CREATE TRIGGER ` + trigger + ` BEFORE INSERT ON platform_records WHEN NEW.collection = '` + collection + `' AND instr(NEW.payload, '` + fragment + `') > 0 BEGIN SELECT RAISE(FAIL, 'blocked ` + collection + ` payload insert'); END`
	if _, err := db.Exec(statement); err != nil {
		_ = db.Close()
		t.Fatalf("create %s payload blocker: %v", collection, err)
	}
	return func() {
		_, _ = db.Exec(`DROP TRIGGER IF EXISTS ` + trigger)
		_ = db.Close()
	}
}

func firstString(value any) string {
	text, _ := value.(string)
	return text
}

func auditLogActionExists(items []model.AuditLog, action string) bool {
	for _, item := range items {
		if item.Action == action {
			return true
		}
	}
	return false
}
