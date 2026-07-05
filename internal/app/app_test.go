package app

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

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
			if path == "/api/admin/audit/access-stats" {
				assertStatus(t, handler, http.MethodPost, path, map[string]any{"name": "manual stats"}, cookie, http.StatusMethodNotAllowed)
				return
			}

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

func TestVNCPlatformAccessCreatesDesktopSession(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "vnc-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)

	assetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "vnc-desktop",
		"type":     "linux-desktop",
		"status":   "active",
		"protocol": "vnc",
		"host":     "127.0.0.1",
		"port":     5901,
	}, adminCookie, http.StatusCreated)
	var asset model.PlatformItem
	decodeResponse(t, assetRec, &asset)

	credentialRec := assertStatus(t, handler, http.MethodPost, "/api/admin/credentials", map[string]any{
		"name":      "vnc-password",
		"type":      "vnc_password",
		"status":    "encrypted",
		"username":  "operator",
		"password":  "secret-vnc",
		"target_id": asset.ID,
	}, adminCookie, http.StatusCreated)
	var credential model.PlatformItem
	decodeResponse(t, credentialRec, &credential)
	for _, leaked := range []string{"password", "plain_password", "encrypted_password"} {
		if _, ok := credential.Metadata[leaked]; ok {
			t.Fatalf("platform credential response leaked %s", leaked)
		}
	}

	badCredentialRec := assertStatus(t, handler, http.MethodPost, "/api/admin/credentials", map[string]any{
		"name":      "rdp-password",
		"type":      "rdp_password",
		"status":    "encrypted",
		"username":  "administrator",
		"password":  "secret-rdp",
		"target_id": asset.ID,
	}, adminCookie, http.StatusCreated)
	var badCredential model.PlatformItem
	decodeResponse(t, badCredentialRec, &badCredential)
	assertStatus(t, handler, http.MethodPost, "/api/connections/vnc", map[string]any{
		"asset_id":      asset.ID,
		"credential_id": badCredential.ID,
	}, adminCookie, http.StatusBadRequest)

	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "vnc-user", "password": "password123"}, nil, http.StatusOK)
	userCookie := loginRec.Result().Cookies()[0]

	assertStatus(t, handler, http.MethodPost, "/api/access/vnc/"+asset.ID, map[string]any{
		"recording_enabled": true,
	}, userCookie, http.StatusForbidden)

	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/assets", map[string]any{
		"name":      "vnc-user desktop",
		"owner_id":  user.ID,
		"target_id": asset.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)

	accessRec := assertStatus(t, handler, http.MethodPost, "/api/access/vnc/"+asset.ID, map[string]any{
		"width":             1280,
		"height":            720,
		"recording_enabled": true,
	}, userCookie, http.StatusAccepted)
	var session model.ConnectionSession
	decodeResponse(t, accessRec, &session)
	if session.Protocol != model.ProtocolVNC || session.ServerID != asset.ID || session.CredentialID != credential.ID {
		t.Fatalf("unexpected vnc session: %#v", session)
	}
	if session.Width != 1280 || session.Height != 720 {
		t.Fatalf("session dimensions = %dx%d, want 1280x720", session.Width, session.Height)
	}
	if session.RecordingPath == "" {
		t.Fatal("vnc recording path was not created")
	}
	if info, err := os.Stat(session.RecordingPath); err != nil || !info.IsDir() {
		t.Fatalf("vnc recording directory missing: %v", err)
	}
	if err := os.WriteFile(filepath.Join(session.RecordingPath, "recording.guac"), []byte("vnc frames"), 0o660); err != nil {
		t.Fatalf("write fake vnc recording: %v", err)
	}
	downloadRec := assertStatus(t, handler, http.MethodGet, "/api/connections/"+session.ID+"/recording.zip", nil, userCookie, http.StatusOK)
	assertZipContains(t, downloadRec.Body.Bytes(), "recording.guac", "vnc frames")
	assertStatus(t, handler, http.MethodPost, "/api/connections/"+session.ID+"/close", nil, userCookie, http.StatusOK)

	directRec := assertStatus(t, handler, http.MethodPost, "/api/connections/vnc", map[string]any{
		"asset_id":          asset.ID,
		"credential_id":     credential.ID,
		"recording_enabled": true,
		"width":             1024,
		"height":            768,
	}, adminCookie, http.StatusCreated)
	var directSession model.ConnectionSession
	decodeResponse(t, directRec, &directSession)
	if directSession.Protocol != model.ProtocolVNC || directSession.CredentialID != credential.ID {
		t.Fatalf("unexpected direct vnc session: %#v", directSession)
	}
}

func TestConnectionAPIsRequireAssetAuthorization(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	linuxRec := assertStatus(t, handler, http.MethodPost, "/api/servers", map[string]any{
		"name":     "ssh-target",
		"host":     "127.0.0.1",
		"os":       "linux",
		"ssh_port": 22,
	}, adminCookie, http.StatusCreated)
	var linuxServer model.Server
	decodeResponse(t, linuxRec, &linuxServer)

	sshCredRec := assertStatus(t, handler, http.MethodPost, "/api/credentials", map[string]any{
		"name":      "ssh-root",
		"server_id": linuxServer.ID,
		"type":      "ssh_password",
		"username":  "root",
		"password":  "password123",
	}, adminCookie, http.StatusCreated)
	var sshCredential model.CredentialPublic
	decodeResponse(t, sshCredRec, &sshCredential)

	windowsRec := assertStatus(t, handler, http.MethodPost, "/api/servers", map[string]any{
		"name":     "rdp-target",
		"host":     "127.0.0.1",
		"os":       "windows",
		"rdp_port": 3389,
	}, adminCookie, http.StatusCreated)
	var windowsServer model.Server
	decodeResponse(t, windowsRec, &windowsServer)

	rdpCredRec := assertStatus(t, handler, http.MethodPost, "/api/credentials", map[string]any{
		"name":      "rdp-admin",
		"server_id": windowsServer.ID,
		"type":      "rdp_password",
		"username":  "administrator",
		"password":  "password123",
	}, adminCookie, http.StatusCreated)
	var rdpCredential model.CredentialPublic
	decodeResponse(t, rdpCredRec, &rdpCredential)

	assertStatus(t, handler, http.MethodPost, "/api/admin/roles", map[string]any{
		"name":   "connection-operator",
		"type":   "custom",
		"status": "enabled",
		"metadata": map[string]any{
			"api_permissions": []string{
				"POST /api/connections/ssh",
				"POST /api/connections/rdp",
			},
		},
	}, adminCookie, http.StatusCreated)
	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "connection-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "connection-operator"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)
	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "connection-user", "password": "password123"}, nil, http.StatusOK)
	userCookie := loginRec.Result().Cookies()[0]

	assertStatus(t, handler, http.MethodPost, "/api/connections/ssh", map[string]any{
		"server_id":     linuxServer.ID,
		"credential_id": sshCredential.ID,
	}, userCookie, http.StatusForbidden)
	assertStatus(t, handler, http.MethodPost, "/api/connections/rdp", map[string]any{
		"server_id":     windowsServer.ID,
		"credential_id": rdpCredential.ID,
	}, userCookie, http.StatusForbidden)

	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/assets", map[string]any{
		"name":      "connection-user ssh-target",
		"owner_id":  user.ID,
		"target_id": linuxServer.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/connections/ssh", map[string]any{
		"server_id":     linuxServer.ID,
		"credential_id": sshCredential.ID,
	}, userCookie, http.StatusCreated)

	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/assets", map[string]any{
		"name":      "connection-user rdp-target",
		"owner_id":  user.ID,
		"target_id": windowsServer.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/connections/rdp", map[string]any{
		"server_id":     windowsServer.ID,
		"credential_id": rdpCredential.ID,
	}, userCookie, http.StatusCreated)
}

func TestAccessAuthorizationSupportsDepartmentsGroupsAndExpiry(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	parentDeptRec := assertStatus(t, handler, http.MethodPost, "/api/admin/departments", map[string]any{
		"name":   "Engineering",
		"type":   "department",
		"status": "enabled",
	}, adminCookie, http.StatusCreated)
	var parentDept model.PlatformItem
	decodeResponse(t, parentDeptRec, &parentDept)
	childDeptRec := assertStatus(t, handler, http.MethodPost, "/api/admin/departments", map[string]any{
		"name":      "Platform",
		"type":      "department",
		"status":    "enabled",
		"parent_id": parentDept.ID,
	}, adminCookie, http.StatusCreated)
	var childDept model.PlatformItem
	decodeResponse(t, childDeptRec, &childDept)

	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":      "department-user",
		"type":      "local",
		"status":    "enabled",
		"password":  "password123",
		"parent_id": childDept.ID,
		"metadata":  map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)

	parentGroupRec := assertStatus(t, handler, http.MethodPost, "/api/admin/asset-groups", map[string]any{
		"name":   "Linux Fleet",
		"type":   "ssh",
		"status": "enabled",
	}, adminCookie, http.StatusCreated)
	var parentGroup model.PlatformItem
	decodeResponse(t, parentGroupRec, &parentGroup)
	childGroupRec := assertStatus(t, handler, http.MethodPost, "/api/admin/asset-groups", map[string]any{
		"name":      "Production Linux",
		"type":      "ssh",
		"status":    "enabled",
		"parent_id": parentGroup.ID,
	}, adminCookie, http.StatusCreated)
	var childGroup model.PlatformItem
	decodeResponse(t, childGroupRec, &childGroup)

	groupAssetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "group-host",
		"type":     "linux",
		"status":   "active",
		"protocol": "ssh",
		"host":     "10.10.0.10",
		"port":     22,
		"group":    childGroup.ID,
	}, adminCookie, http.StatusCreated)
	var groupAsset model.PlatformItem
	decodeResponse(t, groupAssetRec, &groupAsset)
	expiredAssetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "expired-host",
		"type":     "linux",
		"status":   "active",
		"protocol": "ssh",
		"host":     "10.10.0.11",
		"port":     22,
	}, adminCookie, http.StatusCreated)
	var expiredAsset model.PlatformItem
	decodeResponse(t, expiredAssetRec, &expiredAsset)

	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/assets", map[string]any{
		"name":      "expired direct grant",
		"owner_id":  user.ID,
		"target_id": expiredAsset.ID,
		"status":    "enabled",
		"metadata":  map[string]any{"expires_at": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)},
	}, adminCookie, http.StatusCreated)

	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "department-user", "password": "password123"}, nil, http.StatusOK)
	userCookie := loginRec.Result().Cookies()[0]
	assertStatus(t, handler, http.MethodPost, "/api/access/ssh/"+groupAsset.ID, nil, userCookie, http.StatusForbidden)

	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/assets", map[string]any{
		"name":      "engineering linux fleet",
		"type":      "department_group",
		"owner_id":  parentDept.ID,
		"target_id": parentGroup.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)

	accessRec := assertStatus(t, handler, http.MethodGet, "/api/access/assets", nil, userCookie, http.StatusOK)
	accessBody := accessRec.Body.String()
	if !strings.Contains(accessBody, groupAsset.ID) {
		t.Fatal("department and asset-group authorization did not include grouped asset")
	}
	if strings.Contains(accessBody, expiredAsset.ID) {
		t.Fatal("expired authorization leaked asset into access portal")
	}
	assertStatus(t, handler, http.MethodPost, "/api/access/ssh/"+groupAsset.ID, nil, userCookie, http.StatusAccepted)
	assertStatus(t, handler, http.MethodPost, "/api/access/ssh/"+expiredAsset.ID, nil, userCookie, http.StatusForbidden)
}

func TestCommandSnippetBootstrapVisibility(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "snippet-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)

	publicRec := assertStatus(t, handler, http.MethodPost, "/api/admin/command-snippets", map[string]any{
		"name":     "public uptime",
		"type":     "public",
		"status":   "enabled",
		"metadata": map[string]any{"command": "uptime"},
	}, adminCookie, http.StatusCreated)
	var publicSnippet model.PlatformItem
	decodeResponse(t, publicRec, &publicSnippet)
	ownedRec := assertStatus(t, handler, http.MethodPost, "/api/admin/command-snippets", map[string]any{
		"name":     "owned disk",
		"type":     "private",
		"status":   "enabled",
		"owner_id": user.ID,
		"metadata": map[string]any{"command": "df -h"},
	}, adminCookie, http.StatusCreated)
	var ownedSnippet model.PlatformItem
	decodeResponse(t, ownedRec, &ownedSnippet)
	privateRec := assertStatus(t, handler, http.MethodPost, "/api/admin/command-snippets", map[string]any{
		"name":     "other private",
		"type":     "private",
		"status":   "enabled",
		"owner_id": "other-user",
		"metadata": map[string]any{"command": "whoami"},
	}, adminCookie, http.StatusCreated)
	var otherSnippet model.PlatformItem
	decodeResponse(t, privateRec, &otherSnippet)
	disabledRec := assertStatus(t, handler, http.MethodPost, "/api/admin/command-snippets", map[string]any{
		"name":     "disabled public",
		"type":     "public",
		"status":   "disabled",
		"metadata": map[string]any{"command": "id"},
	}, adminCookie, http.StatusCreated)
	var disabledSnippet model.PlatformItem
	decodeResponse(t, disabledRec, &disabledSnippet)

	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "snippet-user", "password": "password123"}, nil, http.StatusOK)
	userCookie := loginRec.Result().Cookies()[0]
	bootstrapRec := assertStatus(t, handler, http.MethodGet, "/api/bootstrap", nil, userCookie, http.StatusOK)
	body := bootstrapRec.Body.String()
	if !strings.Contains(body, publicSnippet.ID) || !strings.Contains(body, ownedSnippet.ID) {
		t.Fatal("user bootstrap did not include public and owned command snippets")
	}
	if strings.Contains(body, otherSnippet.ID) || strings.Contains(body, disabledSnippet.ID) {
		t.Fatal("user bootstrap leaked private or disabled command snippets")
	}
}

func TestWebAssetProxyRequiresAuthorizationAndLogs(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-OpenWebServerManager-User") == "" || r.Header.Get("X-OpenWebServerManager-Asset") == "" {
			t.Fatal("upstream did not receive proxy identity headers")
		}
		if r.URL.Query().Get("from") != "asset" {
			t.Fatalf("upstream query missing base query: %q", r.URL.RawQuery)
		}
		switch r.URL.Path {
		case "/root/hello":
			if r.URL.Query().Get("x") != "1" {
				t.Fatalf("upstream hello query = %q, want x=1", r.URL.RawQuery)
			}
			w.Header().Set("X-Upstream", "ok")
			_, _ = w.Write([]byte("proxied ok"))
		case "/root/fail":
			if r.URL.Query().Get("x") != "2" {
				t.Fatalf("upstream fail query = %q, want x=2", r.URL.RawQuery)
			}
			http.Error(w, "upstream failed", http.StatusInternalServerError)
		default:
			t.Fatalf("upstream path = %q, want /root/hello or /root/fail", r.URL.Path)
		}
	}))
	defer upstream.Close()

	handler, adminCookie := newTestHandler(t)
	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "web-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)
	webRec := assertStatus(t, handler, http.MethodPost, "/api/admin/websites", map[string]any{
		"name":     "internal app",
		"type":     "http",
		"status":   "enabled",
		"metadata": map[string]any{"target_url": upstream.URL + "/root?from=asset"},
	}, adminCookie, http.StatusCreated)
	var webAsset model.PlatformItem
	decodeResponse(t, webRec, &webAsset)
	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "web-user", "password": "password123"}, nil, http.StatusOK)
	userCookie := loginRec.Result().Cookies()[0]

	assertStatus(t, handler, http.MethodGet, "/api/access/http/"+webAsset.ID+"/proxy/hello?x=1", nil, userCookie, http.StatusForbidden)
	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/websites", map[string]any{
		"name":      "web-user internal app",
		"owner_id":  user.ID,
		"target_id": webAsset.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)
	proxyRec := assertStatusWithHeaders(t, handler, http.MethodGet, "/api/access/http/"+webAsset.ID+"/proxy/hello?x=1", nil, userCookie, map[string]string{
		"Referer":    "https://docs.example.test/start",
		"User-Agent": "openwebservermanager-test",
	}, http.StatusOK)
	if proxyRec.Body.String() != "proxied ok" || proxyRec.Header().Get("X-Upstream") != "ok" {
		t.Fatalf("proxy response body/header = %q/%q", proxyRec.Body.String(), proxyRec.Header().Get("X-Upstream"))
	}
	assertStatusWithHeaders(t, handler, http.MethodGet, "/api/access/http/"+webAsset.ID+"/proxy/fail?x=2", nil, userCookie, map[string]string{
		"Referer":    "https://docs.example.test/error",
		"User-Agent": "openwebservermanager-test",
	}, http.StatusInternalServerError)
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/access-logs", nil, adminCookie, http.StatusOK)
	logsBody := logsRec.Body.String()
	if !strings.Contains(logsBody, webAsset.ID) || !strings.Contains(logsBody, "200") || !strings.Contains(logsBody, "500") || !strings.Contains(logsBody, "/proxy/hello") || !strings.Contains(logsBody, "docs.example.test") {
		t.Fatal("access logs did not include proxied request details")
	}
	statsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/access-stats", nil, adminCookie, http.StatusOK)
	statsBody := statsRec.Body.String()
	for _, want := range []string{"access-stat-summary", "request_count", "unique_ips", "traffic_bytes", "error_rate", "docs.example.test", "/api/access/http/" + webAsset.ID + "/proxy/hello", "500"} {
		if !strings.Contains(statsBody, want) {
			t.Fatalf("access stats did not include %q", want)
		}
	}
}

func TestDatabaseAssetQueryRequiresAuthorizationAndLogs(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "database-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)

	databaseRec := assertStatus(t, handler, http.MethodPost, "/api/admin/database-assets", map[string]any{
		"name":     "ops-db",
		"type":     "sqlite",
		"status":   "enabled",
		"protocol": "database",
		"metadata": map[string]any{"sqlite_path": "ops.db", "row_limit": 10},
	}, adminCookie, http.StatusCreated)
	var databaseAsset model.PlatformItem
	decodeResponse(t, databaseRec, &databaseAsset)

	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "database-user", "password": "password123"}, nil, http.StatusOK)
	userCookie := loginRec.Result().Cookies()[0]

	assertStatus(t, handler, http.MethodPost, "/api/access/database/"+databaseAsset.ID+"/query", map[string]any{
		"sql": "SELECT 1 AS answer",
	}, userCookie, http.StatusForbidden)

	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/databases", map[string]any{
		"name":      "database-user ops-db",
		"owner_id":  user.ID,
		"target_id": databaseAsset.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)

	accessRec := assertStatus(t, handler, http.MethodGet, "/api/access/assets", nil, userCookie, http.StatusOK)
	if !strings.Contains(accessRec.Body.String(), databaseAsset.ID) {
		t.Fatal("authorized database asset did not appear in access portal")
	}

	assertStatus(t, handler, http.MethodPost, "/api/access/database/"+databaseAsset.ID+"/query", map[string]any{
		"sql": "CREATE TABLE servers(id INTEGER PRIMARY KEY, name TEXT)",
	}, userCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/access/database/"+databaseAsset.ID+"/query", map[string]any{
		"sql": "INSERT INTO servers(name) VALUES ('alpha')",
	}, userCookie, http.StatusOK)
	selectRec := assertStatus(t, handler, http.MethodPost, "/api/access/database/"+databaseAsset.ID+"/query", map[string]any{
		"sql": "SELECT name FROM servers",
	}, userCookie, http.StatusOK)
	if !strings.Contains(selectRec.Body.String(), "alpha") || !strings.Contains(selectRec.Body.String(), "columns") {
		t.Fatal("database query response did not include selected rows")
	}

	assertStatus(t, handler, http.MethodPost, "/api/access/database/"+databaseAsset.ID+"/query", map[string]any{
		"sql": "SELECT * FROM missing_table",
	}, userCookie, http.StatusBadRequest)

	workOrderRec := assertStatus(t, handler, http.MethodPost, "/api/access/database/"+databaseAsset.ID+"/work-orders", map[string]any{
		"sql":    "CREATE TABLE work_order_hosts(name TEXT)",
		"reason": "create host review table",
	}, userCookie, http.StatusCreated)
	var workOrder model.PlatformItem
	decodeResponse(t, workOrderRec, &workOrder)
	if workOrder.Status != "pending" || workOrder.TargetID != databaseAsset.ID || workOrder.OwnerID != user.ID {
		t.Fatalf("work order = status %q target %q owner %q", workOrder.Status, workOrder.TargetID, workOrder.OwnerID)
	}
	assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+workOrder.ID+"/execute", map[string]any{}, adminCookie, http.StatusConflict)
	assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+workOrder.ID+"/approve", map[string]any{"note": "approved for test"}, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+workOrder.ID+"/execute", map[string]any{
		"sql": "DROP TABLE servers",
	}, adminCookie, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+workOrder.ID+"/execute", map[string]any{}, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+workOrder.ID+"/execute", map[string]any{}, adminCookie, http.StatusConflict)

	workOrderQueryRec := assertStatus(t, handler, http.MethodPost, "/api/access/database/"+databaseAsset.ID+"/query", map[string]any{
		"sql": "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'work_order_hosts'",
	}, userCookie, http.StatusOK)
	if !strings.Contains(workOrderQueryRec.Body.String(), "work_order_hosts") {
		t.Fatal("approved work order execution did not create the expected table")
	}

	rejectedRec := assertStatus(t, handler, http.MethodPost, "/api/access/database/"+databaseAsset.ID+"/work-orders", map[string]any{
		"sql":    "CREATE TABLE rejected_table(name TEXT)",
		"reason": "should be rejected",
	}, userCookie, http.StatusCreated)
	var rejectedOrder model.PlatformItem
	decodeResponse(t, rejectedRec, &rejectedOrder)
	assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+rejectedOrder.ID+"/reject", map[string]any{"note": "not allowed"}, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+rejectedOrder.ID+"/execute", map[string]any{}, adminCookie, http.StatusConflict)

	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/sql-logs", nil, adminCookie, http.StatusOK)
	logsBody := logsRec.Body.String()
	for _, want := range []string{databaseAsset.ID, "database_access", "alpha", "missing_table", "failed", "work_order", workOrder.ID, "work_order_hosts"} {
		if !strings.Contains(logsBody, want) {
			t.Fatalf("sql logs did not include %q", want)
		}
	}
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

func TestLoginCaptchaRequirement(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "Login captcha",
		"type":   "security",
		"status": "enabled",
		"metadata": map[string]any{
			"captcha_enabled": true,
		},
	}, adminCookie, http.StatusCreated)

	statusRec := assertStatus(t, handler, http.MethodGet, "/api/auth/status", nil, nil, http.StatusOK)
	if !strings.Contains(statusRec.Body.String(), `"captcha_required":true`) {
		t.Fatal("auth status did not report captcha requirement")
	}
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username": "admin",
		"password": "password123",
	}, nil, http.StatusBadRequest)

	captchaRec := assertStatus(t, handler, http.MethodGet, "/api/auth/captcha", nil, nil, http.StatusOK)
	var captcha map[string]any
	decodeResponse(t, captchaRec, &captcha)
	captchaID, _ := captcha["captcha_id"].(string)
	question, _ := captcha["question"].(string)
	if captchaID == "" || question == "" {
		t.Fatalf("captcha response missing id/question: %v", captcha)
	}
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username":       "admin",
		"password":       "password123",
		"captcha_id":     captchaID,
		"captcha_answer": "wrong",
	}, nil, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username":       "admin",
		"password":       "password123",
		"captcha_id":     captchaID,
		"captcha_answer": captchaAnswerFromQuestion(question),
	}, nil, http.StatusBadRequest)

	nextCaptchaRec := assertStatus(t, handler, http.MethodGet, "/api/auth/captcha", nil, nil, http.StatusOK)
	var nextCaptcha map[string]any
	decodeResponse(t, nextCaptchaRec, &nextCaptcha)
	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username":       "admin",
		"password":       "password123",
		"captcha_id":     nextCaptcha["captcha_id"],
		"captcha_answer": captchaAnswerFromQuestion(stringValueFromAny(nextCaptcha["question"])),
	}, nil, http.StatusOK)
	if len(loginRec.Result().Cookies()) == 0 {
		t.Fatal("captcha-protected login did not set auth cookie")
	}
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/login-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), "invalid captcha") {
		t.Fatal("invalid captcha was not written to login logs")
	}
}

func TestDisablePasswordLoginSetting(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	createRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "Disable password login",
		"type":   "security",
		"status": "enabled",
		"metadata": map[string]any{
			"disable_password_login": true,
		},
	}, adminCookie, http.StatusCreated)
	var setting model.PlatformItem
	decodeResponse(t, createRec, &setting)

	statusRec := assertStatus(t, handler, http.MethodGet, "/api/auth/status", nil, nil, http.StatusOK)
	if !strings.Contains(statusRec.Body.String(), `"password_login_disabled":true`) {
		t.Fatal("auth status did not report disabled password login")
	}
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username": "admin",
		"password": "password123",
	}, nil, http.StatusForbidden)
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/login-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), "password login is disabled") {
		t.Fatal("disabled password login was not written to login logs")
	}
	auditRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(auditRec.Body.String(), "auth.login.password_denied") {
		t.Fatal("disabled password login was not written to audit logs")
	}

	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+setting.ID, map[string]any{
		"name":   "Disable password login",
		"type":   "security",
		"status": "enabled",
		"metadata": map[string]any{
			"disable_password_login": false,
			"password_login":         true,
		},
	}, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username": "admin",
		"password": "password123",
	}, nil, http.StatusOK)
}

func TestTOTPLoginMFASetupChallengeRecoveryAndDisable(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	statusRec := assertStatus(t, handler, http.MethodGet, "/api/auth/mfa/status", nil, adminCookie, http.StatusOK)
	if !strings.Contains(statusRec.Body.String(), `"enabled":false`) {
		t.Fatal("initial MFA status should be disabled")
	}

	setupRec := assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/setup", nil, adminCookie, http.StatusOK)
	var setup map[string]any
	decodeResponse(t, setupRec, &setup)
	secret, _ := setup["secret"].(string)
	if secret == "" || !strings.Contains(setupRec.Body.String(), "otpauth://totp/") {
		t.Fatal("MFA setup did not return secret and otpauth URL")
	}
	enableRec := assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/enable", map[string]any{
		"secret":   secret,
		"mfa_code": totpCode(secret, time.Now().UTC()),
	}, adminCookie, http.StatusOK)
	var enabled map[string]any
	decodeResponse(t, enableRec, &enabled)
	recoveryCodes := stringSliceFromAny(enabled["recovery_codes"])
	if len(recoveryCodes) != 8 {
		t.Fatalf("recovery code count = %d, want 8", len(recoveryCodes))
	}
	usersRec := assertStatus(t, handler, http.MethodGet, "/api/admin/users", nil, adminCookie, http.StatusOK)
	for _, leaked := range []string{secret, "mfa_secret_encrypted", "mfa_recovery_hashes"} {
		if strings.Contains(usersRec.Body.String(), leaked) {
			t.Fatalf("MFA secret material leaked in users response: %s", leaked)
		}
	}

	loginChallengeRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusAccepted)
	var challenge map[string]any
	decodeResponse(t, loginChallengeRec, &challenge)
	token, _ := challenge["mfa_token"].(string)
	if token == "" || challenge["mfa_required"] != true {
		t.Fatalf("login did not return MFA challenge: %v", challenge)
	}
	assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/complete-login", map[string]any{"token": token, "mfa_code": "000000"}, nil, http.StatusUnauthorized)
	completeRec := assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/complete-login", map[string]any{
		"token":    token,
		"mfa_code": totpCode(secret, time.Now().UTC()),
	}, nil, http.StatusOK)
	if len(completeRec.Result().Cookies()) == 0 {
		t.Fatal("MFA completion did not set auth cookie")
	}

	recoveryChallengeRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusAccepted)
	var recoveryChallenge map[string]any
	decodeResponse(t, recoveryChallengeRec, &recoveryChallenge)
	recoveryToken, _ := recoveryChallenge["mfa_token"].(string)
	recoveryLoginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/complete-login", map[string]any{
		"token":         recoveryToken,
		"recovery_code": recoveryCodes[0],
	}, nil, http.StatusOK)
	recoveryCookie := recoveryLoginRec.Result().Cookies()[0]
	reusedChallengeRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusAccepted)
	var reusedChallenge map[string]any
	decodeResponse(t, reusedChallengeRec, &reusedChallenge)
	assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/complete-login", map[string]any{
		"token":         reusedChallenge["mfa_token"],
		"recovery_code": recoveryCodes[0],
	}, nil, http.StatusUnauthorized)

	assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/disable", map[string]any{
		"current_password": "password123",
		"mfa_code":         totpCode(secret, time.Now().UTC()),
	}, recoveryCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusOK)
}

func TestForcedMFAEnrollmentDuringLogin(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "Force MFA",
		"type":   "security",
		"status": "enabled",
		"metadata": map[string]any{
			"force_mfa": true,
		},
	}, adminCookie, http.StatusCreated)

	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusAccepted)
	var challenge map[string]any
	decodeResponse(t, loginRec, &challenge)
	if challenge["mfa_setup_required"] != true {
		t.Fatalf("forced MFA did not require setup: %v", challenge)
	}
	token, _ := challenge["mfa_token"].(string)
	secret, _ := challenge["secret"].(string)
	assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/complete-login", map[string]any{
		"token":    token,
		"mfa_code": totpCode(secret, time.Now().UTC()),
	}, nil, http.StatusOK)

	nextLoginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusAccepted)
	if !strings.Contains(nextLoginRec.Body.String(), `"mfa_required":true`) {
		t.Fatal("enrolled forced MFA account did not require MFA on next login")
	}
}

func TestOIDCProviderAuthorizationCodeFlow(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	clientRec := assertStatus(t, handler, http.MethodPost, "/api/admin/oidc-clients", map[string]any{
		"name":     "openweb-test",
		"type":     "confidential",
		"status":   "enabled",
		"password": "client-secret",
		"metadata": map[string]any{
			"client_id":     "openweb-test",
			"redirect_uris": []string{"https://client.example/callback"},
			"scopes":        []string{"openid", "profile", "email"},
		},
	}, adminCookie, http.StatusCreated)
	if strings.Contains(clientRec.Body.String(), "client_secret") || strings.Contains(clientRec.Body.String(), "client_secret_hash") {
		t.Fatal("oidc client secret leaked in create response")
	}

	discoveryRec := assertStatus(t, handler, http.MethodGet, "/.well-known/openid-configuration", nil, nil, http.StatusOK)
	for _, want := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri", "RS256"} {
		if !strings.Contains(discoveryRec.Body.String(), want) {
			t.Fatalf("discovery did not include %q", want)
		}
	}
	jwksRec := assertStatus(t, handler, http.MethodGet, "/api/oidc/jwks", nil, nil, http.StatusOK)
	if !strings.Contains(jwksRec.Body.String(), `"kty":"RSA"`) || !strings.Contains(jwksRec.Body.String(), `"kid"`) {
		t.Fatal("jwks did not include rsa signing key")
	}

	codeVerifier := "verifier-1234567890"
	challengeRaw := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(challengeRaw[:])
	redirectURI := "https://client.example/callback"
	authorizePath := "/api/oidc/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {"openweb-test"},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid profile"},
		"state":                 {"state-1"},
		"nonce":                 {"nonce-1"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	loginRedirect := assertStatus(t, handler, http.MethodGet, authorizePath, nil, nil, http.StatusFound)
	if location := loginRedirect.Header().Get("Location"); !strings.HasPrefix(location, "/login?next=") {
		t.Fatalf("unauthenticated authorize redirect = %q, want login next", location)
	}
	assertStatus(t, handler, http.MethodGet, "/api/oidc/authorize?response_type=code&client_id=openweb-test&redirect_uri="+url.QueryEscape("https://evil.example/callback")+"&scope=openid", nil, adminCookie, http.StatusBadRequest)

	authorizeRec := assertStatus(t, handler, http.MethodGet, authorizePath, nil, adminCookie, http.StatusFound)
	location, err := url.Parse(authorizeRec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse authorize redirect: %v", err)
	}
	if location.Scheme != "https" || location.Host != "client.example" || location.Query().Get("state") != "state-1" {
		t.Fatalf("authorize redirect = %q", location.String())
	}
	code := location.Query().Get("code")
	if code == "" {
		t.Fatal("authorize redirect did not include code")
	}

	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
	}
	tokenRec := assertFormStatus(t, handler, "/api/oidc/token", tokenForm, nil, map[string]string{
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("openweb-test:client-secret")),
	}, http.StatusOK)
	var tokenResponse map[string]any
	decodeResponse(t, tokenRec, &tokenResponse)
	accessToken, _ := tokenResponse["access_token"].(string)
	idToken, _ := tokenResponse["id_token"].(string)
	if accessToken == "" || len(strings.Split(idToken, ".")) != 3 || tokenResponse["token_type"] != "Bearer" {
		t.Fatalf("token response missing access/id token: %v", tokenResponse)
	}

	assertFormStatus(t, handler, "/api/oidc/token", tokenForm, nil, map[string]string{
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("openweb-test:client-secret")),
	}, http.StatusBadRequest)

	userInfoRec := assertStatusWithHeaders(t, handler, http.MethodGet, "/api/oidc/userinfo", nil, nil, map[string]string{
		"Authorization": "Bearer " + accessToken,
	}, http.StatusOK)
	if !strings.Contains(userInfoRec.Body.String(), `"preferred_username":"admin"`) || !strings.Contains(userInfoRec.Body.String(), `"sub"`) {
		t.Fatal("userinfo did not include signed-in user claims")
	}
	assertStatusWithHeaders(t, handler, http.MethodGet, "/api/oidc/userinfo", nil, nil, map[string]string{
		"Authorization": "Bearer invalid",
	}, http.StatusUnauthorized)
}

func TestToolsAndMonitoringEndpoints(t *testing.T) {
	handler, cookie := newTestHandler(t)
	assertStatus(t, handler, http.MethodGet, "/api/system/monitoring", nil, cookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/tools/ping", map[string]any{"target": "localhost", "count": 1}, cookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/tools/ping", map[string]any{"target": "", "count": 1}, cookie, http.StatusBadRequest)
}

func TestAgentGatewayRegistrationHeartbeatAndTimeout(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	gatewayRec := assertStatus(t, handler, http.MethodPost, "/api/admin/agent-gateways", map[string]any{
		"name":     "edge-gateway",
		"type":     "agent",
		"status":   "offline",
		"metadata": map[string]any{"heartbeat_timeout_seconds": 30},
	}, adminCookie, http.StatusCreated)
	var gateway model.PlatformItem
	decodeResponse(t, gatewayRec, &gateway)

	assertStatus(t, handler, http.MethodPost, "/api/agent/gateways/register", map[string]any{
		"gateway_id": gateway.ID,
		"token":      "missing",
		"hostname":   "edge-01",
	}, nil, http.StatusUnauthorized)

	tokenRec := assertStatus(t, handler, http.MethodPost, "/api/admin/agent-gateways/"+gateway.ID+"/token", nil, adminCookie, http.StatusOK)
	if strings.Contains(tokenRec.Body.String(), "agent_token_hash") {
		t.Fatal("agent token hash leaked in token response")
	}
	var tokenPayload map[string]any
	decodeResponse(t, tokenRec, &tokenPayload)
	registrationToken, _ := tokenPayload["registration_token"].(string)
	if registrationToken == "" || !strings.HasPrefix(registrationToken, gateway.ID+".") {
		t.Fatalf("registration token = %q, want gateway scoped token", registrationToken)
	}

	assertStatus(t, handler, http.MethodPost, "/api/agent/gateways/register", map[string]any{
		"registration_token": gateway.ID + ".wrong-token",
		"hostname":           "edge-01",
	}, nil, http.StatusUnauthorized)

	registerRec := assertStatus(t, handler, http.MethodPost, "/api/agent/gateways/register", map[string]any{
		"registration_token": registrationToken,
		"hostname":           "edge-01",
		"version":            "1.2.3",
		"os":                 "linux",
		"arch":               "amd64",
		"public_address":     "10.0.0.10",
		"ip_addresses":       []string{"10.0.0.10", "fd00::10"},
		"labels":             []string{"prod", "edge"},
		"capabilities":       []string{"ssh", "rdp", "database"},
	}, nil, http.StatusOK)
	if !strings.Contains(registerRec.Body.String(), `"status":"online"`) || !strings.Contains(registerRec.Body.String(), "edge-01") {
		t.Fatal("agent registration did not mark gateway online with identity metadata")
	}
	if strings.Contains(registerRec.Body.String(), "agent_token_hash") {
		t.Fatal("agent token hash leaked in register response")
	}

	heartbeatRec := assertStatusWithHeaders(t, handler, http.MethodPost, "/api/agent/gateways/heartbeat", map[string]any{
		"latency_ms":         18,
		"cpu_percent":        12.5,
		"memory_used_bytes":  512,
		"memory_total_bytes": 1024,
		"disk_used_bytes":    2048,
		"disk_total_bytes":   4096,
		"network_rx_bytes":   1000,
		"network_tx_bytes":   2000,
		"active_sessions":    3,
		"metrics":            map[string]any{"queue_depth": 2},
	}, nil, map[string]string{
		"Authorization": "Bearer " + registrationToken,
	}, http.StatusOK)
	for _, want := range []string{`"latency_ms":18`, `"cpu_percent":12.5`, `"memory_percent":50`, `"active_sessions":3`, "queue_depth"} {
		if !strings.Contains(heartbeatRec.Body.String(), want) {
			t.Fatalf("heartbeat response did not include %q", want)
		}
	}

	listRec := assertStatus(t, handler, http.MethodGet, "/api/admin/agent-gateways", nil, adminCookie, http.StatusOK)
	if !strings.Contains(listRec.Body.String(), `"status":"online"`) || !strings.Contains(listRec.Body.String(), `"latency_ms":18`) {
		t.Fatal("agent gateway list did not include online heartbeat metrics")
	}
	if strings.Contains(listRec.Body.String(), "agent_token_hash") || strings.Contains(listRec.Body.String(), registrationToken) {
		t.Fatal("agent gateway list leaked token material")
	}
	statusRec := assertStatus(t, handler, http.MethodGet, "/api/admin/agent-gateways/status", nil, adminCookie, http.StatusOK)
	if !strings.Contains(statusRec.Body.String(), `"online":1`) {
		t.Fatal("agent gateway status summary did not count online gateway")
	}

	oldHeartbeat := time.Now().Add(-2 * time.Minute).UTC().Format(time.RFC3339Nano)
	assertStatus(t, handler, http.MethodPatch, "/api/admin/agent-gateways/"+gateway.ID, map[string]any{
		"name":   "edge-gateway",
		"status": "online",
		"metadata": map[string]any{
			"last_heartbeat_at":         oldHeartbeat,
			"heartbeat_timeout_seconds": 30,
			"latency_ms":                18,
		},
	}, adminCookie, http.StatusOK)
	offlineRec := assertStatus(t, handler, http.MethodGet, "/api/admin/agent-gateways", nil, adminCookie, http.StatusOK)
	if !strings.Contains(offlineRec.Body.String(), `"status":"offline"`) || !strings.Contains(offlineRec.Body.String(), "heartbeat timeout") {
		t.Fatal("stale heartbeat did not mark agent gateway offline")
	}

	assertStatus(t, handler, http.MethodPost, "/api/agent/gateways/heartbeat", map[string]any{
		"registration_token": registrationToken,
		"latency_ms":         9,
	}, nil, http.StatusOK)
	recoveredRec := assertStatus(t, handler, http.MethodGet, "/api/admin/agent-gateways", nil, adminCookie, http.StatusOK)
	if !strings.Contains(recoveredRec.Body.String(), `"status":"online"`) || !strings.Contains(recoveredRec.Body.String(), `"latency_ms":9`) {
		t.Fatal("valid heartbeat did not recover offline gateway")
	}

	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), "agent.gateway.register") || !strings.Contains(logsRec.Body.String(), "agent_gateway.token") {
		t.Fatal("agent gateway token/register operations were not audited")
	}
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
	assertMultipartStatus(t, handler, "/api/admin/storages/"+storage.ID+"/files-upload", map[string]string{"path": "docs"}, "upload.bin", []byte{0, 1, 2, 3}, cookie, http.StatusCreated)
	listRec := assertStatus(t, handler, http.MethodGet, "/api/admin/storages/"+storage.ID+"/files?path=docs", nil, cookie, http.StatusOK)
	if !strings.Contains(listRec.Body.String(), "readme.txt") || !strings.Contains(listRec.Body.String(), "upload.bin") {
		t.Fatal("storage list did not include written and uploaded files")
	}
	downloadRec := assertStatus(t, handler, http.MethodGet, "/api/admin/storages/"+storage.ID+"/files-download?path=docs/readme.txt", nil, cookie, http.StatusOK)
	if strings.TrimSpace(downloadRec.Body.String()) != "hello" {
		t.Fatalf("download body = %q, want hello", downloadRec.Body.String())
	}
	uploadDownloadRec := assertStatus(t, handler, http.MethodGet, "/api/admin/storages/"+storage.ID+"/files-download?path=docs/upload.bin", nil, cookie, http.StatusOK)
	if !bytes.Equal(uploadDownloadRec.Body.Bytes(), []byte{0, 1, 2, 3}) {
		t.Fatalf("uploaded file body = %v, want binary payload", uploadDownloadRec.Body.Bytes())
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

	databaseRec := assertStatus(t, handler, http.MethodPost, "/api/admin/database-assets", map[string]any{
		"name":     "resource-ops-db",
		"type":     "sqlite",
		"status":   "enabled",
		"protocol": "database",
		"metadata": map[string]any{"sqlite_path": "resource-ops.db"},
	}, cookie, http.StatusCreated)
	var databaseAsset model.PlatformItem
	decodeResponse(t, databaseRec, &databaseAsset)

	sqlRec := assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders", map[string]any{
		"name":      "select-one",
		"type":      "query",
		"status":    "approved",
		"protocol":  "database",
		"target_id": databaseAsset.ID,
		"metadata":  map[string]any{"sql": "SELECT 1 AS answer"},
	}, cookie, http.StatusCreated)
	var order model.PlatformItem
	decodeResponse(t, sqlRec, &order)
	sqlLogRec := assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+order.ID+"/execute", map[string]any{}, cookie, http.StatusOK)
	if !strings.Contains(sqlLogRec.Body.String(), "answer") {
		t.Fatal("sql execution log did not include query result")
	}
}

func TestBackupListDownloadAndRestore(t *testing.T) {
	handler, cookie := newTestHandler(t)

	restoredAssetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "restore-kept",
		"type":     "linux",
		"status":   "active",
		"protocol": "ssh",
		"host":     "127.0.0.1",
		"port":     22,
	}, cookie, http.StatusCreated)
	var restoredAsset model.PlatformItem
	decodeResponse(t, restoredAssetRec, &restoredAsset)

	createBackupRec := assertStatus(t, handler, http.MethodPost, "/api/admin/backups", nil, cookie, http.StatusCreated)
	var backupMetadata map[string]any
	decodeResponse(t, createBackupRec, &backupMetadata)
	backupPath, _ := backupMetadata["backup_path"].(string)
	backupName := filepath.Base(filepath.FromSlash(backupPath))
	if backupName == "." || backupName == "" {
		t.Fatalf("backup path missing from metadata: %v", backupMetadata)
	}

	listRec := assertStatus(t, handler, http.MethodGet, "/api/admin/backups", nil, cookie, http.StatusOK)
	if !strings.Contains(listRec.Body.String(), backupName) || !strings.Contains(listRec.Body.String(), "manifest.json") {
		t.Fatal("backup list did not include created backup and manifest")
	}

	downloadRec := assertStatus(t, handler, http.MethodGet, "/api/admin/backups/"+backupName+"/download", nil, cookie, http.StatusOK)
	if downloadRec.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("backup download content type = %q", downloadRec.Header().Get("Content-Type"))
	}
	downloadZip, err := zip.NewReader(bytes.NewReader(downloadRec.Body.Bytes()), int64(downloadRec.Body.Len()))
	if err != nil {
		t.Fatalf("open downloaded backup zip: %v", err)
	}
	if !zipHasEntry(downloadZip, "manifest.json") {
		t.Fatal("backup download did not include manifest.json")
	}

	transientAssetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "restore-removed",
		"type":     "linux",
		"status":   "active",
		"protocol": "ssh",
		"host":     "127.0.0.2",
		"port":     22,
	}, cookie, http.StatusCreated)
	var transientAsset model.PlatformItem
	decodeResponse(t, transientAssetRec, &transientAsset)

	dryRunRec := assertMultipartStatus(t, handler, "/api/admin/backups/restore?dry_run=1", nil, backupName, downloadRec.Body.Bytes(), cookie, http.StatusOK)
	if !strings.Contains(dryRunRec.Body.String(), `"valid":true`) || !strings.Contains(dryRunRec.Body.String(), "store.db") {
		t.Fatal("backup dry-run restore did not validate archive")
	}
	assertMultipartStatus(t, handler, "/api/admin/backups/restore", nil, "not-a-backup.zip", []byte("not a zip"), cookie, http.StatusBadRequest)

	restoreRec := assertMultipartStatus(t, handler, "/api/admin/backups/restore", nil, backupName, downloadRec.Body.Bytes(), cookie, http.StatusOK)
	if !strings.Contains(restoreRec.Body.String(), `"restored":true`) || !strings.Contains(restoreRec.Body.String(), "pre_restore_backup") {
		t.Fatal("backup restore response did not include restore summary and pre-restore backup")
	}

	assertStatus(t, handler, http.MethodGet, "/api/bootstrap", nil, cookie, http.StatusUnauthorized)
	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusOK)
	newCookie := loginRec.Result().Cookies()[0]
	assetsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/assets", nil, newCookie, http.StatusOK)
	assetsBody := assetsRec.Body.String()
	if !strings.Contains(assetsBody, restoredAsset.ID) {
		t.Fatal("restored backup did not retain pre-backup asset")
	}
	if strings.Contains(assetsBody, transientAsset.ID) {
		t.Fatal("restored backup retained post-backup transient asset")
	}
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, newCookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), "backup.restore") {
		t.Fatal("backup restore did not write operation log")
	}
}

func TestScheduledTaskRunners(t *testing.T) {
	handler, cookie := newTestHandler(t)

	backupTaskRec := assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks", map[string]any{
		"name":   "Backup now",
		"type":   "backup",
		"status": "enabled",
	}, cookie, http.StatusCreated)
	var backupTask model.PlatformItem
	decodeResponse(t, backupTaskRec, &backupTask)
	backupRunRec := assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks/"+backupTask.ID+"/run", nil, cookie, http.StatusAccepted)
	var backupLog model.PlatformItem
	decodeResponse(t, backupRunRec, &backupLog)
	backupPath, _ := backupLog.Metadata["backup_path"].(string)
	if backupPath == "" {
		t.Fatal("backup task did not return backup path")
	}
	if info, err := os.Stat(filepath.FromSlash(backupPath)); err != nil || info.Size() == 0 {
		t.Fatalf("backup file missing or empty: %v", err)
	}

	oldAccessRec := assertStatus(t, handler, http.MethodPost, "/api/admin/audit/access-logs", map[string]any{
		"name":     "old access",
		"type":     "GET",
		"status":   "200",
		"metadata": map[string]any{"uri": "/old"},
	}, cookie, http.StatusCreated)
	var oldAccess model.PlatformItem
	decodeResponse(t, oldAccessRec, &oldAccess)
	oldSQLRec := assertStatus(t, handler, http.MethodPost, "/api/admin/audit/sql-logs", map[string]any{
		"name":     "old sql",
		"type":     "query",
		"status":   "success",
		"metadata": map[string]any{"sql": "SELECT 1"},
	}, cookie, http.StatusCreated)
	var oldSQL model.PlatformItem
	decodeResponse(t, oldSQLRec, &oldSQL)
	cleanupTaskRec := assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks", map[string]any{
		"name":     "Cleanup logs",
		"type":     "log-cleanup",
		"status":   "enabled",
		"metadata": map[string]any{"retention_days": 0},
	}, cookie, http.StatusCreated)
	var cleanupTask model.PlatformItem
	decodeResponse(t, cleanupTaskRec, &cleanupTask)
	cleanupRunRec := assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks/"+cleanupTask.ID+"/run", nil, cookie, http.StatusAccepted)
	if !strings.Contains(cleanupRunRec.Body.String(), "deleted_count") {
		t.Fatal("cleanup task did not report deleted count")
	}
	accessLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/access-logs", nil, cookie, http.StatusOK)
	if strings.Contains(accessLogsRec.Body.String(), oldAccess.ID) {
		t.Fatal("log cleanup did not delete old access log")
	}
	sqlLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/sql-logs", nil, cookie, http.StatusOK)
	if strings.Contains(sqlLogsRec.Body.String(), oldSQL.ID) {
		t.Fatal("log cleanup did not delete old sql log")
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	webRec := assertStatus(t, handler, http.MethodPost, "/api/admin/websites", map[string]any{
		"name":     "status web",
		"type":     "http",
		"status":   "enabled",
		"metadata": map[string]any{"target_url": upstream.URL},
	}, cookie, http.StatusCreated)
	var webAsset model.PlatformItem
	decodeResponse(t, webRec, &webAsset)
	statusTaskRec := assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks", map[string]any{
		"name":     "Asset status",
		"type":     "asset-status",
		"status":   "enabled",
		"metadata": map[string]any{"timeout_ms": 1000},
	}, cookie, http.StatusCreated)
	var statusTask model.PlatformItem
	decodeResponse(t, statusTaskRec, &statusTask)
	statusRunRec := assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks/"+statusTask.ID+"/run", nil, cookie, http.StatusAccepted)
	if !strings.Contains(statusRunRec.Body.String(), "checked") || !strings.Contains(statusRunRec.Body.String(), "active") {
		t.Fatal("asset status task did not report check result")
	}
	webListRec := assertStatus(t, handler, http.MethodGet, "/api/admin/websites", nil, cookie, http.StatusOK)
	if !strings.Contains(webListRec.Body.String(), webAsset.ID) || !strings.Contains(webListRec.Body.String(), "last_check_status") {
		t.Fatal("asset status task did not update web asset check metadata")
	}

	certRec := assertStatus(t, handler, http.MethodPost, "/api/admin/certificates/self-signed", map[string]any{
		"name":   "renew-cert",
		"domain": "renew.example.test",
		"days":   1,
	}, cookie, http.StatusCreated)
	var cert model.PlatformItem
	decodeResponse(t, certRec, &cert)
	cert.Metadata["expires_at"] = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	assertStatus(t, handler, http.MethodPatch, "/api/admin/certificates/"+cert.ID, map[string]any{
		"name":     cert.Name,
		"status":   cert.Status,
		"metadata": cert.Metadata,
	}, cookie, http.StatusOK)
	renewTaskRec := assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks", map[string]any{
		"name":     "Renew certs",
		"type":     "certificate-renewal",
		"status":   "enabled",
		"metadata": map[string]any{"renew_before_days": 30, "validity_days": 90},
	}, cookie, http.StatusCreated)
	var renewTask model.PlatformItem
	decodeResponse(t, renewTaskRec, &renewTask)
	renewRunRec := assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks/"+renewTask.ID+"/run", nil, cookie, http.StatusAccepted)
	if !strings.Contains(renewRunRec.Body.String(), "renewed_count") || !strings.Contains(renewRunRec.Body.String(), cert.ID) {
		t.Fatal("certificate renewal task did not renew due certificate")
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
	assertMultipartStatus(t, handler, "/api/admin/storages/"+storage.ID+"/files-upload", map[string]string{"path": "docs"}, "uploaded.txt", []byte("uploaded"), userCookie, http.StatusCreated)
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

	assertStatus(t, handler, http.MethodPost, "/api/admin/strategies", map[string]any{
		"name":        "deny strategy-drive upload",
		"type":        "file",
		"status":      "enabled",
		"target_id":   storage.ID,
		"permissions": map[string]bool{"upload": false},
	}, adminCookie, http.StatusCreated)
	assertMultipartStatus(t, handler, "/api/admin/storages/"+storage.ID+"/files-upload", map[string]string{"path": "docs"}, "blocked.txt", []byte("blocked"), userCookie, http.StatusForbidden)
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
	return assertStatusWithHeaders(t, handler, method, path, payload, cookie, nil, want)
}

func assertStatusWithHeaders(t *testing.T, handler http.Handler, method, path string, payload any, cookie *http.Cookie, headers map[string]string, want int) *httptest.ResponseRecorder {
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
	for key, value := range headers {
		req.Header.Set(key, value)
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

func assertFormStatus(t *testing.T, handler http.Handler, path string, form url.Values, cookie *http.Cookie, headers map[string]string, want int) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("POST %s form status = %d, want %d, body: %s", path, rec.Code, want, rec.Body.String())
	}
	return rec
}

func assertMultipartStatus(t *testing.T, handler http.Handler, path string, fields map[string]string, fileName string, fileContent []byte, cookie *http.Cookie, want int) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatalf("write multipart field: %v", err)
		}
	}
	part, err := writer.CreateFormFile("file", fileName)
	if err != nil {
		t.Fatalf("create multipart file: %v", err)
	}
	if _, err := part.Write(fileContent); err != nil {
		t.Fatalf("write multipart file: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("POST %s multipart status = %d, want %d, body: %s", path, rec.Code, want, rec.Body.String())
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

func stringSliceFromAny(value any) []string {
	raw, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

func captchaAnswerFromQuestion(question string) string {
	parts := strings.Fields(question)
	if len(parts) < 3 {
		return ""
	}
	left, _ := strconv.Atoi(parts[0])
	right, _ := strconv.Atoi(parts[2])
	return strconv.Itoa(left + right)
}

func stringValueFromAny(value any) string {
	text, _ := value.(string)
	return text
}

func zipHasEntry(reader *zip.Reader, filename string) bool {
	for _, file := range reader.File {
		if file.Name == filename {
			return true
		}
	}
	return false
}
