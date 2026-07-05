package app

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"openwebservermanager/internal/guac"
	"openwebservermanager/internal/model"
	"openwebservermanager/internal/security"
	"openwebservermanager/internal/store"
)

func TestEnsureChildPathRejectsEscape(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "recordings", "sess_1")
	if err := ensureChildPath(root, child); err != nil {
		t.Fatalf("expected child path to pass: %v", err)
	}
	escape := filepath.Join(root, "..", "outside")
	if err := ensureChildPath(root, escape); err == nil {
		t.Fatal("expected escaping path to fail")
	}
}

func TestValidateServer(t *testing.T) {
	if err := validateServer(model.Server{Name: "web", Host: "10.0.0.1", OS: model.ServerOSLinux, SSHPort: 22}); err != nil {
		t.Fatalf("expected valid server: %v", err)
	}
	if err := validateServer(model.Server{Name: "web", Host: "bad/host", OS: model.ServerOSLinux}); err == nil {
		t.Fatal("expected invalid host to fail")
	}
	if err := validateServer(model.Server{Name: "web", Host: "10.0.0.1", OS: model.ServerOSLinux, SSHPort: 70000}); err == nil {
		t.Fatal("expected invalid port to fail")
	}
}

func TestValidateCredentialRequest(t *testing.T) {
	if err := validateCredentialRequest(credentialRequest{Name: "root", Type: model.CredentialSSHPassword, Username: "root", Password: "secret"}); err != nil {
		t.Fatalf("expected valid password credential: %v", err)
	}
	if err := validateCredentialRequest(credentialRequest{Name: "root", Type: model.CredentialSSHPassword, Username: "root"}); err == nil {
		t.Fatal("expected missing password to fail")
	}
	if err := validateCredentialRequest(credentialRequest{Name: "key", Type: model.CredentialSSHKey, Username: "root", PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----"}); err != nil {
		t.Fatalf("expected valid key credential: %v", err)
	}
}

func TestPlatformCollectionEndpoints(t *testing.T) {
	handler, cookie := newTestHandler(t)
	paths := []string{}
	for route := range adminCollectionRoutes {
		paths = append(paths, "/api/admin/"+route)
	}
	for route := range authorizationCollectionRoutes {
		paths = append(paths, "/api/admin/authorizations/"+route)
	}
	for route := range auditCollectionRoutes {
		paths = append(paths, "/api/admin/audit/"+route)
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			assertStatus(t, handler, http.MethodGet, path, nil, cookie, http.StatusOK)

			payload := map[string]any{
				"name":        "test " + filepath.Base(path),
				"type":        "test",
				"status":      "enabled",
				"description": "created by test",
				"metadata":    map[string]any{"case": path},
			}
			if path == "/api/admin/users" {
				payload["password"] = "password123"
				payload["metadata"] = map[string]any{"role": "user"}
			}
			rec := assertStatus(t, handler, http.MethodPost, path, payload, cookie, http.StatusCreated)
			var item model.PlatformItem
			if err := json.Unmarshal(rec.Body.Bytes(), &item); err != nil {
				t.Fatalf("decode created item: %v", err)
			}
			if item.ID == "" {
				t.Fatal("created item missing id")
			}
			if _, ok := item.Metadata["password_hash"]; ok {
				t.Fatal("password hash leaked in response")
			}

			assertStatus(t, handler, http.MethodPatch, path+"/"+item.ID, map[string]any{"name": item.Name + " updated", "status": "disabled"}, cookie, http.StatusOK)
			assertStatus(t, handler, http.MethodDelete, path+"/"+item.ID, nil, cookie, http.StatusOK)
		})
	}
}

func TestPlatformUserLoginAndAccessAuthorization(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "operator",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	if err := json.Unmarshal(userRec.Body.Bytes(), &user); err != nil {
		t.Fatalf("decode user: %v", err)
	}

	assetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "linux-1",
		"type":     "linux",
		"status":   "active",
		"protocol": "ssh",
		"host":     "127.0.0.1",
		"port":     22,
	}, adminCookie, http.StatusCreated)
	var asset model.PlatformItem
	if err := json.Unmarshal(assetRec.Body.Bytes(), &asset); err != nil {
		t.Fatalf("decode asset: %v", err)
	}

	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "operator", "password": "password123"}, nil, http.StatusOK)
	userCookie := loginRec.Result().Cookies()[0]

	assertStatus(t, handler, http.MethodPost, "/api/access/ssh/"+asset.ID, nil, userCookie, http.StatusForbidden)

	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/assets", map[string]any{
		"name":      "operator linux-1",
		"owner_id":  user.ID,
		"target_id": asset.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)

	assertStatus(t, handler, http.MethodGet, "/api/access/assets", nil, userCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/access/ssh/"+asset.ID, nil, userCookie, http.StatusAccepted)
}

func TestRoleBasedAccessControl(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "portal-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)

	allowedRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "allowed-host",
		"type":     "linux",
		"status":   "active",
		"protocol": "ssh",
		"host":     "10.0.0.10",
		"port":     22,
	}, adminCookie, http.StatusCreated)
	var allowedAsset model.PlatformItem
	decodeResponse(t, allowedRec, &allowedAsset)

	deniedRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "denied-host",
		"type":     "linux",
		"status":   "active",
		"protocol": "ssh",
		"host":     "10.0.0.11",
		"port":     22,
	}, adminCookie, http.StatusCreated)
	var deniedAsset model.PlatformItem
	decodeResponse(t, deniedRec, &deniedAsset)

	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/assets", map[string]any{
		"name":      "portal-user allowed-host",
		"owner_id":  user.ID,
		"target_id": allowedAsset.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)

	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "portal-user", "password": "password123"}, nil, http.StatusOK)
	userCookie := loginRec.Result().Cookies()[0]
	assertStatus(t, handler, http.MethodGet, "/api/admin/assets", nil, userCookie, http.StatusForbidden)
	assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{"name": "blocked"}, userCookie, http.StatusForbidden)
	bootstrapRec := assertStatus(t, handler, http.MethodGet, "/api/bootstrap", nil, userCookie, http.StatusOK)
	body := bootstrapRec.Body.String()
	if !strings.Contains(body, allowedAsset.ID) {
		t.Fatal("user bootstrap did not include authorized asset")
	}
	if strings.Contains(body, deniedAsset.ID) {
		t.Fatal("user bootstrap leaked unauthorized asset")
	}
	accessRec := assertStatus(t, handler, http.MethodGet, "/api/access/assets", nil, userCookie, http.StatusOK)
	if strings.Contains(accessRec.Body.String(), deniedAsset.ID) {
		t.Fatal("access asset list leaked unauthorized asset")
	}

	assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "audit-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "auditor"},
	}, adminCookie, http.StatusCreated)
	auditLogin := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "audit-user", "password": "password123"}, nil, http.StatusOK)
	auditCookie := auditLogin.Result().Cookies()[0]
	assertStatus(t, handler, http.MethodGet, "/api/admin/audit/login-logs", nil, auditCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodGet, "/api/system/monitoring", nil, auditCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodGet, "/api/admin/assets", nil, auditCookie, http.StatusForbidden)
	assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{"name": "blocked"}, auditCookie, http.StatusForbidden)

	assertStatus(t, handler, http.MethodPost, "/api/admin/roles", map[string]any{
		"name":   "asset-reader",
		"type":   "custom",
		"status": "enabled",
		"metadata": map[string]any{
			"api_permissions": []string{"GET /api/admin/assets"},
		},
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "asset-reader-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "asset-reader"},
	}, adminCookie, http.StatusCreated)
	readerLogin := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "asset-reader-user", "password": "password123"}, nil, http.StatusOK)
	readerCookie := readerLogin.Result().Cookies()[0]
	assertStatus(t, handler, http.MethodGet, "/api/admin/assets", nil, readerCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{"name": "blocked"}, readerCookie, http.StatusForbidden)
}

func TestLoginSecurityPoliciesAndLocks(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "lock-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	for i := 0; i < 5; i++ {
		assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "lock-user", "password": "wrong-password"}, nil, http.StatusUnauthorized)
	}
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "lock-user", "password": "password123"}, nil, http.StatusTooManyRequests)
	locksRec := assertStatus(t, handler, http.MethodGet, "/api/admin/login-locked", nil, adminCookie, http.StatusOK)
	if !strings.Contains(locksRec.Body.String(), "lock-user") {
		t.Fatal("login lock record was not created after repeated failures")
	}

	assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "policy-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/login-policies", map[string]any{
		"name":        "deny test network",
		"type":        "deny",
		"status":      "enabled",
		"description": "deny httptest default remote address",
		"metadata":    map[string]any{"cidr": "192.0.2.0/24"},
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "policy-user", "password": "password123"}, nil, http.StatusForbidden)
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/login-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), "blocked by login policy") {
		t.Fatal("policy denial was not written to login logs")
	}
}

func TestToolsAndMonitoringEndpoints(t *testing.T) {
	handler, cookie := newTestHandler(t)
	assertStatus(t, handler, http.MethodGet, "/api/system/monitoring", nil, cookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/tools/ping", map[string]any{"target": "localhost", "count": 1}, cookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/tools/ping", map[string]any{"target": "", "count": 1}, cookie, http.StatusBadRequest)
}

func TestResourceOperationEndpoints(t *testing.T) {
	handler, cookie := newTestHandler(t)

	assetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "linux-export",
		"type":     "linux",
		"status":   "active",
		"protocol": "ssh",
		"host":     "127.0.0.1",
		"port":     22,
	}, cookie, http.StatusCreated)
	var asset model.PlatformItem
	decodeResponse(t, assetRec, &asset)
	exportRec := assertStatus(t, handler, http.MethodGet, "/api/admin/assets/export", nil, cookie, http.StatusOK)
	if !strings.Contains(exportRec.Body.String(), asset.ID) {
		t.Fatal("asset export did not include created asset")
	}
	assertStatus(t, handler, http.MethodPost, "/api/admin/assets/import", map[string]any{
		"items": []map[string]any{{
			"name":     "imported-rdp",
			"type":     "windows",
			"status":   "active",
			"protocol": "rdp",
			"host":     "192.0.2.10",
			"port":     3389,
		}},
	}, cookie, http.StatusCreated)

	storageRec := assertStatus(t, handler, http.MethodPost, "/api/admin/storages", map[string]any{
		"name":   "team-drive",
		"type":   "local",
		"status": "enabled",
	}, cookie, http.StatusCreated)
	var storage model.PlatformItem
	decodeResponse(t, storageRec, &storage)
	assertStatus(t, handler, http.MethodGet, "/api/admin/storages/"+storage.ID+"/files", nil, cookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-mkdir", map[string]any{"path": "docs"}, cookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "docs/readme.txt", "content": "hello"}, cookie, http.StatusCreated)
	listRec := assertStatus(t, handler, http.MethodGet, "/api/admin/storages/"+storage.ID+"/files?path=docs", nil, cookie, http.StatusOK)
	if !strings.Contains(listRec.Body.String(), "readme.txt") {
		t.Fatal("storage list did not include written file")
	}
	downloadRec := assertStatus(t, handler, http.MethodGet, "/api/admin/storages/"+storage.ID+"/files-download?path=docs/readme.txt", nil, cookie, http.StatusOK)
	if strings.TrimSpace(downloadRec.Body.String()) != "hello" {
		t.Fatalf("download body = %q, want hello", downloadRec.Body.String())
	}
	assertStatus(t, handler, http.MethodDelete, "/api/admin/storages/"+storage.ID+"/files?path=docs/readme.txt", nil, cookie, http.StatusOK)
	assertStatus(t, handler, http.MethodDelete, "/api/admin/storages/"+storage.ID+"/files", nil, cookie, http.StatusBadRequest)

	certRec := assertStatus(t, handler, http.MethodPost, "/api/admin/certificates/self-signed", map[string]any{
		"name":   "local-cert",
		"domain": "example.test",
		"days":   30,
	}, cookie, http.StatusCreated)
	var cert model.PlatformItem
	decodeResponse(t, certRec, &cert)
	certDownload := assertStatus(t, handler, http.MethodGet, "/api/admin/certificates/"+cert.ID+"/download", nil, cookie, http.StatusOK)
	if !strings.Contains(certDownload.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatal("certificate download did not return pem")
	}

	taskRec := assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks", map[string]any{
		"name":   "Backup now",
		"type":   "backup",
		"status": "enabled",
	}, cookie, http.StatusCreated)
	var task model.PlatformItem
	decodeResponse(t, taskRec, &task)
	assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks/"+task.ID+"/run", nil, cookie, http.StatusAccepted)
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/scheduled-tasks/"+task.ID+"/logs", nil, cookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), task.ID) {
		t.Fatal("scheduled task logs did not include run")
	}

	sqlRec := assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders", map[string]any{
		"name":     "select-one",
		"type":     "query",
		"status":   "approved",
		"metadata": map[string]any{"sql": "SELECT 1 AS answer"},
	}, cookie, http.StatusCreated)
	var order model.PlatformItem
	decodeResponse(t, sqlRec, &order)
	sqlLogRec := assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+order.ID+"/execute", map[string]any{}, cookie, http.StatusOK)
	if !strings.Contains(sqlLogRec.Body.String(), "answer") {
		t.Fatal("sql execution log did not include query result")
	}
}

func TestStorageAuthorizationStrategyPermissions(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	storageRec := assertStatus(t, handler, http.MethodPost, "/api/admin/storages", map[string]any{
		"name":   "strategy-drive",
		"type":   "local",
		"status": "enabled",
	}, adminCookie, http.StatusCreated)
	var storage model.PlatformItem
	decodeResponse(t, storageRec, &storage)

	assertStatus(t, handler, http.MethodPost, "/api/admin/roles", map[string]any{
		"name":   "storage-operator",
		"type":   "custom",
		"status": "enabled",
		"metadata": map[string]any{
			"api_permissions": []string{
				"GET /api/admin/storages/*",
				"POST /api/admin/storages/*",
				"DELETE /api/admin/storages/*",
				"GET /api/admin/audit/file-logs",
			},
		},
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "storage-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "storage-operator"},
	}, adminCookie, http.StatusCreated)
	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "storage-user", "password": "password123"}, nil, http.StatusOK)
	userCookie := loginRec.Result().Cookies()[0]

	assertStatus(t, handler, http.MethodGet, "/api/admin/storages/"+storage.ID+"/files", nil, userCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-mkdir", map[string]any{"path": "docs"}, userCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "docs/a.txt", "content": "alpha"}, userCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-copy", map[string]any{"path": "docs/a.txt", "destination": "docs/b.txt"}, userCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-rename", map[string]any{"path": "docs/b.txt", "destination": "docs/c.txt"}, userCookie, http.StatusOK)
	downloadRec := assertStatus(t, handler, http.MethodGet, "/api/admin/storages/"+storage.ID+"/files-download?path=docs/c.txt", nil, userCookie, http.StatusOK)
	if strings.TrimSpace(downloadRec.Body.String()) != "alpha" {
		t.Fatalf("download body = %q, want alpha", downloadRec.Body.String())
	}
	assertStatus(t, handler, http.MethodDelete, "/api/admin/storages/"+storage.ID+"/files?path=docs/c.txt", nil, userCookie, http.StatusForbidden)
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/file-logs", nil, userCookie, http.StatusOK)
	for _, want := range []string{"copy", "rename", "denied"} {
		if !strings.Contains(logsRec.Body.String(), want) {
			t.Fatalf("file logs did not include %q operation", want)
		}
	}

	assertStatus(t, handler, http.MethodPost, "/api/admin/strategies", map[string]any{
		"name":        "allow strategy-drive delete",
		"type":        "file",
		"status":      "enabled",
		"target_id":   storage.ID,
		"permissions": map[string]bool{"delete": true},
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodDelete, "/api/admin/storages/"+storage.ID+"/files?path=docs/c.txt", nil, userCookie, http.StatusOK)
}

func TestAuditSessionOperations(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	linuxRec := assertStatus(t, handler, http.MethodPost, "/api/servers", map[string]any{
		"name":     "linux-audit",
		"host":     "127.0.0.1",
		"os":       "linux",
		"ssh_port": 22,
	}, adminCookie, http.StatusCreated)
	var linux model.Server
	decodeResponse(t, linuxRec, &linux)
	sshCredRec := assertStatus(t, handler, http.MethodPost, "/api/credentials", map[string]any{
		"name":      "ssh-root",
		"server_id": linux.ID,
		"type":      "ssh_password",
		"username":  "root",
		"password":  "secret",
	}, adminCookie, http.StatusCreated)
	var sshCred model.CredentialPublic
	decodeResponse(t, sshCredRec, &sshCred)
	sshSessionRec := assertStatus(t, handler, http.MethodPost, "/api/connections/ssh", map[string]any{
		"server_id":     linux.ID,
		"credential_id": sshCred.ID,
	}, adminCookie, http.StatusCreated)
	var sshSession model.ConnectionSession
	decodeResponse(t, sshSessionRec, &sshSession)
	closeRec := assertStatus(t, handler, http.MethodPost, "/api/admin/audit/online-sessions/"+sshSession.ID+"/disconnect", nil, adminCookie, http.StatusOK)
	if !strings.Contains(closeRec.Body.String(), string(model.SessionClosed)) {
		t.Fatal("audit disconnect did not close session")
	}
	onlineRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/online-sessions", nil, adminCookie, http.StatusOK)
	if strings.Contains(onlineRec.Body.String(), sshSession.ID) {
		t.Fatal("closed session still appears in online sessions")
	}

	windowsRec := assertStatus(t, handler, http.MethodPost, "/api/servers", map[string]any{
		"name":     "windows-audit",
		"host":     "127.0.0.1",
		"os":       "windows",
		"rdp_port": 3389,
	}, adminCookie, http.StatusCreated)
	var windows model.Server
	decodeResponse(t, windowsRec, &windows)
	rdpCredRec := assertStatus(t, handler, http.MethodPost, "/api/credentials", map[string]any{
		"name":      "rdp-admin",
		"server_id": windows.ID,
		"type":      "rdp_password",
		"username":  "Administrator",
		"password":  "secret",
	}, adminCookie, http.StatusCreated)
	var rdpCred model.CredentialPublic
	decodeResponse(t, rdpCredRec, &rdpCred)
	rdpSessionRec := assertStatus(t, handler, http.MethodPost, "/api/connections/rdp", map[string]any{
		"server_id":         windows.ID,
		"credential_id":     rdpCred.ID,
		"recording_enabled": true,
	}, adminCookie, http.StatusCreated)
	var rdpSession model.ConnectionSession
	decodeResponse(t, rdpSessionRec, &rdpSession)
	if rdpSession.RecordingPath == "" {
		t.Fatal("rdp recording path was not created")
	}
	if err := os.WriteFile(filepath.Join(rdpSession.RecordingPath, "recording.guac"), []byte("frames"), 0o660); err != nil {
		t.Fatalf("write fake recording: %v", err)
	}
	assertStatus(t, handler, http.MethodPost, "/api/connections/"+rdpSession.ID+"/close", nil, adminCookie, http.StatusOK)

	assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "recording-auditor",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "auditor"},
	}, adminCookie, http.StatusCreated)
	auditorLogin := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "recording-auditor", "password": "password123"}, nil, http.StatusOK)
	auditorCookie := auditorLogin.Result().Cookies()[0]
	auditorDownload := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/offline-sessions/"+rdpSession.ID+"/recording", nil, auditorCookie, http.StatusOK)
	assertZipContains(t, auditorDownload.Body.Bytes(), "recording.guac", "frames")
	assertStatus(t, handler, http.MethodPost, "/api/admin/audit/online-sessions/"+rdpSession.ID+"/disconnect", nil, auditorCookie, http.StatusForbidden)

	adminDownload := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/offline-sessions/"+rdpSession.ID+"/recording", nil, adminCookie, http.StatusOK)
	assertZipContains(t, adminDownload.Body.Bytes(), "recording.guac", "frames")
	assertStatus(t, handler, http.MethodDelete, "/api/admin/audit/offline-sessions/"+rdpSession.ID+"/recording", nil, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodGet, "/api/admin/audit/offline-sessions/"+rdpSession.ID+"/recording", nil, adminCookie, http.StatusNotFound)
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), "audit.recording.delete") {
		t.Fatal("recording delete did not write operation log")
	}
}

func newTestHandler(t *testing.T) (http.Handler, *http.Cookie) {
	t.Helper()
	key := make([]byte, 32)
	cipher, err := security.NewCipher(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "store.json"), cipher)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	handler := New(Config{
		Store:    st,
		Guacd:    guac.NewManager(guac.ManagerConfig{}),
		StaticFS: fstest.MapFS{"static/index.html": &fstest.MapFile{Data: []byte("<html></html>")}},
		DataDir:  t.TempDir(),
	})
	rec := assertStatus(t, handler, http.MethodPost, "/api/auth/setup", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusCreated)
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("setup did not set auth cookie")
	}
	return handler, cookies[0]
}

func assertStatus(t *testing.T, handler http.Handler, method, path string, payload any, cookie *http.Cookie, want int) *httptest.ResponseRecorder {
	t.Helper()
	var body *bytes.Reader
	if payload == nil {
		body = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		body = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, body)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("%s %s status = %d, want %d, body: %s", method, path, rec.Code, want, rec.Body.String())
	}
	return rec
}

func decodeResponse(t *testing.T, rec *httptest.ResponseRecorder, out any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

func assertZipContains(t *testing.T, raw []byte, filename, content string) {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	for _, file := range reader.File {
		if file.Name != filename {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			t.Fatalf("open zip entry: %v", err)
		}
		defer rc.Close()
		data, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("read zip entry: %v", err)
		}
		if string(data) != content {
			t.Fatalf("zip entry content = %q, want %q", string(data), content)
		}
		return
	}
	t.Fatalf("zip entry %q not found", filename)
}
