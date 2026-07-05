package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

func TestToolsAndMonitoringEndpoints(t *testing.T) {
	handler, cookie := newTestHandler(t)
	assertStatus(t, handler, http.MethodGet, "/api/system/monitoring", nil, cookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/tools/ping", map[string]any{"target": "localhost", "count": 1}, cookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/tools/ping", map[string]any{"target": "", "count": 1}, cookie, http.StatusBadRequest)
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
