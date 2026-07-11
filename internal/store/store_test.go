package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"openwebservermanager/internal/model"
	"openwebservermanager/internal/security"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

func TestCoreRecordsSurviveMissingJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openwebservermanager.json")
	cipher := testCipher(t)
	st, err := Open(path, cipher)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	admin, err := st.SetupAdmin("admin", "password123")
	if err != nil {
		t.Fatalf("setup admin: %v", err)
	}
	server, err := st.CreateServer(model.Server{Name: "linux-01", Host: "192.0.2.10", OS: model.ServerOSLinux})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	credential, err := st.CreateCredential(model.Credential{
		ServerID: server.ID,
		Name:     "root password",
		Type:     model.CredentialSSHPassword,
		Username: "root",
	}, CredentialSecret{Password: "secret-password"})
	if err != nil {
		t.Fatalf("create credential: %v", err)
	}
	session, err := st.CreateSession(model.ConnectionSession{
		Protocol:     model.ProtocolSSH,
		ServerID:     server.ID,
		CredentialID: credential.ID,
		UserID:       admin.UserID,
		ClientIP:     "203.0.113.10",
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := st.Audit(model.AuditLog{UserID: admin.UserID, Action: "test.action", TargetID: server.ID, Protocol: model.ProtocolSSH, Detail: "core record audit"}); err != nil {
		t.Fatalf("write audit: %v", err)
	}
	dbPath := st.DatabasePath()
	if got := coreRecordCount(t, dbPath); got < 5 {
		t.Fatalf("core record count = %d, want at least 5", got)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove json mirror: %v", err)
	}

	reopened, err := Open(path, cipher)
	if err != nil {
		t.Fatalf("reopen store from sqlite core records: %v", err)
	}
	defer reopened.Close()
	if _, ok, err := reopened.VerifyAdmin("admin", "password123"); err != nil || !ok {
		t.Fatalf("verify admin after json removal: ok=%v err=%v", ok, err)
	}
	servers, credentials, sessions, logs := reopened.Bootstrap()
	if len(servers) != 1 || servers[0].ID != server.ID {
		t.Fatalf("servers after sqlite reload = %#v", servers)
	}
	if len(credentials) != 1 || credentials[0].ID != credential.ID {
		t.Fatalf("credentials after sqlite reload = %#v", credentials)
	}
	if len(sessions) != 1 || sessions[0].ID != session.ID {
		t.Fatalf("sessions after sqlite reload = %#v", sessions)
	}
	if len(logs) != 1 || logs[0].Action != "test.action" {
		t.Fatalf("audit logs after sqlite reload = %#v", logs)
	}
	_, secret, ok, err := reopened.GetCredential(credential.ID)
	if err != nil || !ok || secret.Password != "secret-password" {
		t.Fatalf("credential secret after sqlite reload: ok=%v secret=%#v err=%v", ok, secret, err)
	}
}

func TestCreateSessionPlatformIndexFailureRollsBackCoreState(t *testing.T) {
	st := newTestStore(t)

	removeBlocker := blockStorePlatformInsert(t, st, "online_sessions")
	_, err := st.CreateSession(model.ConnectionSession{
		Protocol:     model.ProtocolSSH,
		ServerID:     "asset_blocked_online",
		CredentialID: "credential_blocked_online",
		UserID:       "user_blocked_online",
		ClientIP:     "203.0.113.20",
	})
	removeBlocker()
	if err == nil || !strings.Contains(err.Error(), "sync session platform record") {
		t.Fatalf("CreateSession platform index err = %v, want sync session platform record", err)
	}
	_, _, sessions, _ := st.Bootstrap()
	if len(sessions) != 0 {
		t.Fatalf("CreateSession left core sessions after platform index failure: %#v", sessions)
	}
	if got := platformRecordCount(t, st, "online_sessions"); got != 0 {
		t.Fatalf("CreateSession left online session records after platform index failure: %d", got)
	}
}

func TestCloseSessionPlatformIndexFailureRollsBackCoreState(t *testing.T) {
	st := newTestStore(t)
	session, err := st.CreateSession(model.ConnectionSession{
		Protocol:     model.ProtocolRDP,
		ServerID:     "asset_close_insert",
		CredentialID: "credential_close_insert",
		UserID:       "user_close_insert",
		ClientIP:     "203.0.113.21",
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	removeBlocker := blockStorePlatformInsert(t, st, "offline_sessions")
	_, err = st.CloseSession(session.ID, "blocked offline index")
	removeBlocker()
	if err == nil || !strings.Contains(err.Error(), "sync session platform record") {
		t.Fatalf("CloseSession platform index err = %v, want sync session platform record", err)
	}
	stored, ok := st.GetSession(session.ID)
	if !ok {
		t.Fatal("CloseSession platform index failure removed core session")
	}
	if stored.Status != model.SessionPending || stored.EndedAt != nil || stored.Error != "" {
		t.Fatalf("CloseSession platform index failure did not restore core session: %#v", stored)
	}
	if !platformRecordExists(t, st, "online_sessions", session.ID) {
		t.Fatal("CloseSession platform index failure removed online session record")
	}
	if platformRecordExists(t, st, "offline_sessions", session.ID) {
		t.Fatal("CloseSession platform index failure left offline session record")
	}

	closed, err := st.CloseSession(session.ID, "closed after retry")
	if err != nil {
		t.Fatalf("retry close session: %v", err)
	}
	if closed.Status != model.SessionClosed || closed.EndedAt == nil || closed.Error != "closed after retry" {
		t.Fatalf("retry close did not persist closed session: %#v", closed)
	}
	if platformRecordExists(t, st, "online_sessions", session.ID) || !platformRecordExists(t, st, "offline_sessions", session.ID) {
		t.Fatal("retry close did not move session from online to offline platform records")
	}
}

func TestCloseSessionStaleOnlineDeleteFailureRollsBackCoreState(t *testing.T) {
	st := newTestStore(t)
	session, err := st.CreateSession(model.ConnectionSession{
		Protocol:     model.ProtocolVNC,
		ServerID:     "asset_close_delete",
		CredentialID: "credential_close_delete",
		UserID:       "user_close_delete",
		ClientIP:     "203.0.113.22",
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	removeBlocker := blockStorePlatformDelete(t, st, "online_sessions", session.ID)
	_, err = st.CloseSession(session.ID, "blocked online delete")
	removeBlocker()
	if err == nil || !strings.Contains(err.Error(), "remove stale session platform record") {
		t.Fatalf("CloseSession stale online delete err = %v, want remove stale session platform record", err)
	}
	stored, ok := st.GetSession(session.ID)
	if !ok {
		t.Fatal("CloseSession stale online delete failure removed core session")
	}
	if stored.Status != model.SessionPending || stored.EndedAt != nil || stored.Error != "" {
		t.Fatalf("CloseSession stale online delete failure did not restore core session: %#v", stored)
	}
	if !platformRecordExists(t, st, "online_sessions", session.ID) {
		t.Fatal("CloseSession stale online delete failure removed online session record")
	}
	if platformRecordExists(t, st, "offline_sessions", session.ID) {
		t.Fatal("CloseSession stale online delete failure committed offline session record")
	}
}

func TestOpenImportsLegacyJSONStateToCoreRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "openwebservermanager.json")
	now := time.Now().UTC()
	adminHash := mustPasswordHash(t, "password123")
	legacy := state{
		Servers: map[string]model.Server{
			"srv_legacy": {ID: "srv_legacy", Name: "legacy", Host: "192.0.2.20", OS: model.ServerOSLinux, SSHPort: 22, RDPPort: 3389, CreatedAt: now, UpdatedAt: now},
		},
		Credentials: map[string]model.Credential{},
		Sessions:    map[string]model.ConnectionSession{},
		AuditLogs:   []model.AuditLog{{ID: "audit_legacy", UserID: "user_legacy", Action: "legacy.audit", TargetID: "srv_legacy", CreatedAt: now}},
		Admin:       &AdminAuth{UserID: "user_legacy", Username: "admin", PasswordHash: adminHash, CreatedAt: now, UpdatedAt: now},
	}
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("encode legacy state: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write legacy json: %v", err)
	}

	st, err := Open(path, testCipher(t))
	if err != nil {
		t.Fatalf("open legacy json store: %v", err)
	}
	defer st.Close()
	if got := coreRecordCount(t, st.DatabasePath()); got != 3 {
		t.Fatalf("core record count after legacy import = %d, want 3", got)
	}
	if _, ok, err := st.VerifyAdmin("admin", "password123"); err != nil || !ok {
		t.Fatalf("verify imported admin: ok=%v err=%v", ok, err)
	}
	servers, _, _, logs := st.Bootstrap()
	if len(servers) != 1 || servers[0].ID != "srv_legacy" || len(logs) != 1 || logs[0].ID != "audit_legacy" {
		t.Fatalf("bootstrap after legacy import servers=%#v logs=%#v", servers, logs)
	}
}

func TestRestoreSnapshotRestoresSQLiteCoreRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openwebservermanager.json")
	cipher := testCipher(t)
	st, err := Open(path, cipher)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	if _, err := st.SetupAdmin("old-admin", "password123"); err != nil {
		t.Fatalf("setup old admin: %v", err)
	}
	restoreDB := filepath.Join(t.TempDir(), "restore.db")
	now := time.Now().UTC()
	restoredState := state{
		Servers:     map[string]model.Server{},
		Credentials: map[string]model.Credential{},
		Sessions:    map[string]model.ConnectionSession{},
		AuditLogs:   []model.AuditLog{{ID: "audit_restore", UserID: "user_restore", Action: "restore.audit", TargetID: "restore", CreatedAt: now}},
		Admin:       &AdminAuth{UserID: "user_restore", Username: "restored-admin", PasswordHash: mustPasswordHash(t, "new-password123"), CreatedAt: now, UpdatedAt: now},
	}
	writeCoreRestoreDB(t, restoreDB, restoredState)

	summary, err := st.RestoreSnapshot(nil, restoreDB)
	if err != nil {
		t.Fatalf("restore sqlite core records: %v", err)
	}
	if !summary.CoreStateRestored || summary.CoreRecords != 2 {
		t.Fatalf("restore summary = %#v, want sqlite core restore", summary)
	}
	if _, ok, err := st.VerifyAdmin("restored-admin", "new-password123"); err != nil || !ok {
		t.Fatalf("verify restored admin: ok=%v err=%v", ok, err)
	}
	if _, ok, err := st.VerifyAdmin("old-admin", "password123"); err != nil || ok {
		t.Fatalf("old admin still valid after sqlite core restore: ok=%v err=%v", ok, err)
	}
	_, _, _, logs := st.Bootstrap()
	if len(logs) != 1 || logs[0].ID != "audit_restore" {
		t.Fatalf("restored audit logs = %#v", logs)
	}
}

func TestRestoreSnapshotRejectsDuplicatePlatformRecordsWithoutChangingCoreState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openwebservermanager.json")
	st, err := Open(path, testCipher(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	if _, err := st.SetupAdmin("old-admin", "password123"); err != nil {
		t.Fatalf("setup old admin: %v", err)
	}
	existingAsset, err := st.CreatePlatformItem("assets", model.PlatformItemRequest{
		Name:     "existing asset",
		Type:     "linux",
		Status:   "enabled",
		Protocol: model.ProtocolSSH,
		Host:     "192.0.2.10",
		Port:     22,
	})
	if err != nil {
		t.Fatalf("create existing platform asset: %v", err)
	}

	restoreDB := filepath.Join(t.TempDir(), "restore.db")
	now := time.Now().UTC()
	restoredState := state{
		Servers:     map[string]model.Server{},
		Credentials: map[string]model.Credential{},
		Sessions:    map[string]model.ConnectionSession{},
		AuditLogs:   []model.AuditLog{{ID: "audit_restore", UserID: "user_restore", Action: "restore.audit", TargetID: "restore", CreatedAt: now}},
		Admin:       &AdminAuth{UserID: "user_restore", Username: "restored-admin", PasswordHash: mustPasswordHash(t, "new-password123"), CreatedAt: now, UpdatedAt: now},
	}
	writeCoreRestoreDB(t, restoreDB, restoredState)
	writeDuplicatePlatformRestoreRecords(t, restoreDB)

	_, err = st.RestoreSnapshot(nil, restoreDB)
	if err == nil || !strings.Contains(err.Error(), "duplicate platform record") {
		t.Fatalf("restore duplicate platform records err = %v, want duplicate platform record", err)
	}
	if _, ok, err := st.VerifyAdmin("old-admin", "password123"); err != nil || !ok {
		t.Fatalf("old admin should remain valid after failed restore: ok=%v err=%v", ok, err)
	}
	if _, ok, err := st.VerifyAdmin("restored-admin", "new-password123"); err != nil || ok {
		t.Fatalf("restored admin should not become valid after failed restore: ok=%v err=%v", ok, err)
	}
	if _, ok, err := st.GetPlatformItem("assets", existingAsset.ID); err != nil || !ok {
		t.Fatalf("existing platform asset should remain after failed restore: ok=%v err=%v", ok, err)
	}
}

func TestRestoreSnapshotRejectsSQLiteCoreRecordsWithoutAdmin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openwebservermanager.json")
	st, err := Open(path, testCipher(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	if _, err := st.SetupAdmin("old-admin", "password123"); err != nil {
		t.Fatalf("setup old admin: %v", err)
	}

	restoreDB := filepath.Join(t.TempDir(), "restore.db")
	writeCoreRestoreDB(t, restoreDB, state{
		Servers:     map[string]model.Server{},
		Credentials: map[string]model.Credential{},
		Sessions:    map[string]model.ConnectionSession{},
		AuditLogs:   []model.AuditLog{{ID: "audit_restore", UserID: "user_restore", Action: "restore.audit", TargetID: "restore", CreatedAt: time.Now().UTC()}},
	})

	_, err = st.RestoreSnapshot(nil, restoreDB)
	if err == nil || !strings.Contains(err.Error(), "administrator") {
		t.Fatalf("restore core records without admin err = %v, want administrator error", err)
	}
	if _, ok, err := st.VerifyAdmin("old-admin", "password123"); err != nil || !ok {
		t.Fatalf("old admin should remain valid after rejected restore: ok=%v err=%v", ok, err)
	}
}

func testCipher(t *testing.T) *security.Cipher {
	t.Helper()
	key := sha256.Sum256([]byte("store-test-key"))
	cipher, err := security.NewCipher(key[:])
	if err != nil {
		t.Fatalf("create cipher: %v", err)
	}
	return cipher
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "openwebservermanager.json"), testCipher(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func mustPasswordHash(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcryptGenerateFromPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	return hash
}

func bcryptGenerateFromPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func coreRecordCount(t *testing.T, dbPath string) int {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM core_records`).Scan(&count); err != nil {
		t.Fatalf("count core records: %v", err)
	}
	return count
}

func platformRecordCount(t *testing.T, st *Store, collection string) int {
	t.Helper()
	db, err := sql.Open("sqlite", st.DatabasePath())
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM platform_records WHERE collection = ?`, collection).Scan(&count); err != nil {
		t.Fatalf("count platform records: %v", err)
	}
	return count
}

func platformRecordExists(t *testing.T, st *Store, collection, id string) bool {
	t.Helper()
	_, ok, err := st.GetPlatformItem(collection, id)
	if err != nil {
		t.Fatalf("get platform item %s/%s: %v", collection, id, err)
	}
	return ok
}

func blockStorePlatformInsert(t *testing.T, st *Store, collection string) func() {
	t.Helper()
	db, err := sql.Open("sqlite", st.DatabasePath())
	if err != nil {
		t.Fatalf("open sqlite for platform insert blocker: %v", err)
	}
	triggerName := "block_store_platform_insert"
	if _, err := db.Exec(`DROP TRIGGER IF EXISTS ` + triggerName); err != nil {
		_ = db.Close()
		t.Fatalf("drop stale platform insert blocker: %v", err)
	}
	triggerSQL := `CREATE TRIGGER ` + triggerName + ` BEFORE INSERT ON platform_records
WHEN NEW.collection = ` + sqliteTestStringLiteral(collection) + `
BEGIN
  SELECT RAISE(ABORT, 'forced platform insert failure');
END`
	if _, err := db.Exec(triggerSQL); err != nil {
		_ = db.Close()
		t.Fatalf("create platform insert blocker: %v", err)
	}
	return func() {
		_, _ = db.Exec(`DROP TRIGGER IF EXISTS ` + triggerName)
		_ = db.Close()
	}
}

func blockStorePlatformDelete(t *testing.T, st *Store, collection, id string) func() {
	t.Helper()
	db, err := sql.Open("sqlite", st.DatabasePath())
	if err != nil {
		t.Fatalf("open sqlite for platform delete blocker: %v", err)
	}
	triggerName := "block_store_platform_delete"
	if _, err := db.Exec(`DROP TRIGGER IF EXISTS ` + triggerName); err != nil {
		_ = db.Close()
		t.Fatalf("drop stale platform delete blocker: %v", err)
	}
	triggerSQL := `CREATE TRIGGER ` + triggerName + ` BEFORE DELETE ON platform_records
WHEN OLD.collection = ` + sqliteTestStringLiteral(collection) + `
  AND OLD.id = ` + sqliteTestStringLiteral(id) + `
BEGIN
  SELECT RAISE(ABORT, 'forced platform delete failure');
END`
	if _, err := db.Exec(triggerSQL); err != nil {
		_ = db.Close()
		t.Fatalf("create platform delete blocker: %v", err)
	}
	return func() {
		_, _ = db.Exec(`DROP TRIGGER IF EXISTS ` + triggerName)
		_ = db.Close()
	}
}

func sqliteTestStringLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func writeCoreRestoreDB(t *testing.T, dbPath string, source state) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open restore db: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE core_records (
		kind TEXT NOT NULL,
		id TEXT NOT NULL,
		payload TEXT NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		PRIMARY KEY (kind, id)
	)`); err != nil {
		t.Fatalf("create core_records: %v", err)
	}
	insertCoreRecord := func(kind, id string, payload any, createdAt, updatedAt time.Time) {
		t.Helper()
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal core payload: %v", err)
		}
		if _, err := db.Exec(`INSERT INTO core_records(kind, id, payload, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`, kind, id, string(raw), createdAt.Format(time.RFC3339Nano), updatedAt.Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("insert core record: %v", err)
		}
	}
	if source.Admin != nil {
		insertCoreRecord("admin", source.Admin.UserID, source.Admin, source.Admin.CreatedAt, source.Admin.UpdatedAt)
	}
	for _, log := range source.AuditLogs {
		insertCoreRecord("audit_logs", log.ID, log, log.CreatedAt, log.CreatedAt)
	}
}

func writeDuplicatePlatformRestoreRecords(t *testing.T, dbPath string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open restore db for platform records: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE platform_records (
		collection TEXT NOT NULL,
		id TEXT NOT NULL,
		payload TEXT NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`); err != nil {
		t.Fatalf("create platform_records: %v", err)
	}
	now := time.Now().UTC()
	item := model.PlatformItem{
		ID:        "asset_duplicate",
		Module:    "assets",
		Name:      "duplicate restore asset",
		Type:      "linux",
		Status:    "enabled",
		Protocol:  model.ProtocolSSH,
		Host:      "192.0.2.20",
		Port:      22,
		CreatedAt: now,
		UpdatedAt: now,
	}
	raw, err := json.Marshal(item)
	if err != nil {
		t.Fatalf("marshal duplicate platform item: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := db.Exec(`INSERT INTO platform_records(collection, id, payload, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`, "assets", item.ID, string(raw), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("insert duplicate platform record: %v", err)
		}
	}
}
