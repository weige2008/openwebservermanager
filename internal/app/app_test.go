package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
