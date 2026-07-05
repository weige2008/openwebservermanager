package app

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net"
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

	cryptossh "golang.org/x/crypto/ssh"
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
	credentialRec := assertStatus(t, handler, http.MethodPost, "/api/admin/credentials", map[string]any{
		"name":      "linux-1 root",
		"type":      "ssh_password",
		"status":    "encrypted",
		"username":  "root",
		"password":  "target-secret",
		"target_id": asset.ID,
	}, adminCookie, http.StatusCreated)
	var credential model.PlatformItem
	decodeResponse(t, credentialRec, &credential)

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
	sessionRec := assertStatus(t, handler, http.MethodPost, "/api/access/ssh/"+asset.ID, map[string]any{
		"cols": 88,
		"rows": 27,
	}, userCookie, http.StatusAccepted)
	var session model.ConnectionSession
	decodeResponse(t, sessionRec, &session)
	if session.Protocol != model.ProtocolSSH || session.ServerID != asset.ID || session.CredentialID != credential.ID || session.Width != 88 || session.Height != 27 {
		t.Fatalf("unexpected ssh access session: %#v", session)
	}
	srv := handler.(*Server)
	req := httptest.NewRequest(http.MethodGet, "/api/connections/ssh/"+session.ID+"/ws", nil)
	req.AddCookie(userCookie)
	_, resolvedServer, resolvedCredential, secret, ok := srv.connectionParts(httptest.NewRecorder(), req, session.ID, model.ProtocolSSH)
	if !ok {
		t.Fatal("platform ssh session did not resolve for websocket")
	}
	if resolvedServer.Host != asset.Host || resolvedServer.SSHPort != asset.Port || resolvedCredential.Username != "root" || secret.Password != "target-secret" {
		t.Fatalf("unexpected resolved ssh parts: server=%#v credential=%#v secret=%#v", resolvedServer, resolvedCredential, secret)
	}
}

func TestUserImportCreatesSkipsAndUpdatesLoginUsers(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	importRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users/import", map[string]any{
		"items": []map[string]any{
			{
				"name":     "import-user",
				"type":     "local",
				"status":   "enabled",
				"password": "password123",
				"metadata": map[string]any{"role": "user"},
			},
			{
				"name":     "disabled-import-user",
				"type":     "local",
				"status":   "disabled",
				"password": "password123",
				"metadata": map[string]any{"role": "auditor"},
			},
		},
	}, adminCookie, http.StatusCreated)
	importBody := importRec.Body.String()
	if !strings.Contains(importBody, `"created":2`) || strings.Contains(importBody, "password_hash") {
		t.Fatalf("unexpected user import response: %s", importBody)
	}

	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "import-user", "password": "password123"}, nil, http.StatusOK)
	if !strings.Contains(loginRec.Body.String(), `"role":"user"`) {
		t.Fatalf("imported user login did not carry role: %s", loginRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "disabled-import-user", "password": "password123"}, nil, http.StatusUnauthorized)

	skipRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users/import", map[string]any{
		"items": []map[string]any{{
			"name":     "import-user",
			"type":     "local",
			"status":   "enabled",
			"password": "newpassword123",
			"metadata": map[string]any{"role": "admin"},
		}},
	}, adminCookie, http.StatusCreated)
	if !strings.Contains(skipRec.Body.String(), `"skipped":1`) {
		t.Fatalf("duplicate user import was not skipped: %s", skipRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "import-user", "password": "newpassword123"}, nil, http.StatusUnauthorized)

	updateRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users/import", map[string]any{
		"update_existing": true,
		"items": []map[string]any{{
			"name":     "import-user",
			"type":     "local",
			"status":   "enabled",
			"password": "newpassword123",
			"metadata": map[string]any{"role": "admin"},
		}},
	}, adminCookie, http.StatusCreated)
	if !strings.Contains(updateRec.Body.String(), `"updated":1`) || strings.Contains(updateRec.Body.String(), "password_hash") {
		t.Fatalf("unexpected user update import response: %s", updateRec.Body.String())
	}
	updatedLoginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "import-user", "password": "newpassword123"}, nil, http.StatusOK)
	if !strings.Contains(updatedLoginRec.Body.String(), `"role":"admin"`) {
		t.Fatalf("updated imported user did not login with new role: %s", updatedLoginRec.Body.String())
	}

	usersRec := assertStatus(t, handler, http.MethodGet, "/api/admin/users", nil, adminCookie, http.StatusOK)
	if strings.Contains(usersRec.Body.String(), "password_hash") {
		t.Fatalf("user list leaked password hash: %s", usersRec.Body.String())
	}
	operationRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(operationRec.Body.String(), "users.import") {
		t.Fatalf("user import operation audit missing: %s", operationRec.Body.String())
	}
}

func TestSSHExecAccessRunsCommandAndLogs(t *testing.T) {
	targetAddr, closeTarget := startFakeSSHExecServer(t, "root", "target-secret")
	defer closeTarget()
	host, portText, err := net.SplitHostPort(targetAddr)
	if err != nil {
		t.Fatalf("split target addr: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse target port: %v", err)
	}
	handler, adminCookie := newTestHandler(t)

	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "exec-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)

	assetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "exec-host",
		"type":     "linux",
		"status":   "enabled",
		"protocol": "ssh",
		"host":     host,
		"port":     port,
	}, adminCookie, http.StatusCreated)
	var asset model.PlatformItem
	decodeResponse(t, assetRec, &asset)
	credentialRec := assertStatus(t, handler, http.MethodPost, "/api/admin/credentials", map[string]any{
		"name":      "exec-root",
		"type":      "ssh_password",
		"status":    "encrypted",
		"username":  "root",
		"password":  "target-secret",
		"target_id": asset.ID,
	}, adminCookie, http.StatusCreated)
	var credential model.PlatformItem
	decodeResponse(t, credentialRec, &credential)

	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "exec-user", "password": "password123"}, nil, http.StatusOK)
	userCookie := loginRec.Result().Cookies()[0]
	assertStatus(t, handler, http.MethodPost, "/api/access/ssh/"+asset.ID+"/exec", map[string]any{"command": "printf ok"}, userCookie, http.StatusForbidden)

	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/assets", map[string]any{
		"name":      "exec-user host",
		"owner_id":  user.ID,
		"target_id": asset.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)
	execRec := assertStatus(t, handler, http.MethodPost, "/api/access/ssh/"+asset.ID+"/exec", map[string]any{
		"command":         "printf ok",
		"credential_id":   credential.ID,
		"timeout_seconds": 5,
	}, userCookie, http.StatusOK)
	var execResult map[string]any
	decodeResponse(t, execRec, &execResult)
	if execResult["status"] != "success" || execResult["exit_code"].(float64) != 0 || !strings.Contains(execResult["stdout"].(string), "ran: printf ok") {
		t.Fatalf("unexpected ssh exec result: %#v", execResult)
	}

	assertStatus(t, handler, http.MethodPost, "/api/admin/command-filters", map[string]any{
		"name":      "deny destructive exec",
		"type":      "deny",
		"status":    "enabled",
		"protocol":  "ssh",
		"owner_id":  user.ID,
		"target_id": asset.ID,
		"metadata":  map[string]any{"pattern": "rm -rf", "risk": "high"},
	}, adminCookie, http.StatusCreated)
	deniedRec := assertStatus(t, handler, http.MethodPost, "/api/access/ssh/"+asset.ID+"/exec", map[string]any{
		"command": "rm -rf /tmp/test",
	}, userCookie, http.StatusForbidden)
	var deniedResult map[string]any
	decodeResponse(t, deniedRec, &deniedResult)
	if deniedResult["blocked"] != true || deniedResult["status"] != "denied" || deniedResult["risk"] != "high" {
		t.Fatalf("unexpected denied ssh exec result: %#v", deniedResult)
	}

	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/exec-command-logs", nil, adminCookie, http.StatusOK)
	logsBody := logsRec.Body.String()
	for _, want := range []string{"printf ok", "rm -rf /tmp/test", `"exit_code":0`, `"risk":"high"`, `"interactive":false`} {
		if !strings.Contains(logsBody, want) {
			t.Fatalf("exec command logs missing %s in %s", want, logsBody)
		}
	}
	operationRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	operationBody := operationRec.Body.String()
	if !strings.Contains(operationBody, "connection.ssh.exec") || !strings.Contains(operationBody, "connection.ssh.exec.denied") {
		t.Fatalf("operation logs missing ssh exec audit: %s", operationBody)
	}
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

func TestDesktopAccessSettingsApplyToRDPAndVNC(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "desktop access policy",
		"type":   "access",
		"status": "enabled",
		"metadata": map[string]any{
			"desktop_width":             1600,
			"desktop_height":            1000,
			"desktop_dpi":               120,
			"desktop_color_depth":       16,
			"desktop_resize_method":     "reconnect",
			"desktop_recording_enabled": true,
			"desktop_clipboard_enabled": false,
			"desktop_ignore_cert":       false,
			"desktop_read_only":         true,
			"rdp_file_transfer_enabled": false,
			"watermark_enabled":         true,
			"watermark_text":            "AUDIT",
			"watermark_color":           "rgba(255,0,0,0.2)",
			"watermark_font_size":       36,
		},
	}, adminCookie, http.StatusCreated)

	windowsRec := assertStatus(t, handler, http.MethodPost, "/api/servers", map[string]any{
		"name":     "windows-policy",
		"host":     "127.0.0.1",
		"os":       "windows",
		"rdp_port": 3389,
	}, adminCookie, http.StatusCreated)
	var windows model.Server
	decodeResponse(t, windowsRec, &windows)
	rdpCredRec := assertStatus(t, handler, http.MethodPost, "/api/credentials", map[string]any{
		"name":      "rdp-policy",
		"server_id": windows.ID,
		"type":      "rdp_password",
		"username":  "Administrator",
		"password":  "secret",
	}, adminCookie, http.StatusCreated)
	var rdpCred model.CredentialPublic
	decodeResponse(t, rdpCredRec, &rdpCred)
	rdpRec := assertStatus(t, handler, http.MethodPost, "/api/connections/rdp", map[string]any{
		"server_id":     windows.ID,
		"credential_id": rdpCred.ID,
	}, adminCookie, http.StatusCreated)
	var rdpSession model.ConnectionSession
	decodeResponse(t, rdpRec, &rdpSession)
	assertDesktopPolicySession(t, rdpSession, 1600, 1000, 120, 16, false, false, false, true)

	onlineRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/online-sessions", nil, adminCookie, http.StatusOK)
	body := onlineRec.Body.String()
	for _, expected := range []string{`"workspace_dpi":120`, `"color_depth":16`, `"clipboard_enabled":false`, `"file_transfer_enabled":false`, `"watermark_text":"AUDIT"`} {
		if !strings.Contains(body, expected) {
			t.Fatalf("online session metadata missing %s in %s", expected, body)
		}
	}

	assetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "vnc-policy",
		"protocol": "vnc",
		"host":     "127.0.0.1",
		"port":     5900,
		"status":   "enabled",
	}, adminCookie, http.StatusCreated)
	var asset model.PlatformItem
	decodeResponse(t, assetRec, &asset)
	vncCredRec := assertStatus(t, handler, http.MethodPost, "/api/admin/credentials", map[string]any{
		"name":      "vnc-policy",
		"type":      "vnc_password",
		"status":    "encrypted",
		"username":  "vnc",
		"password":  "secret",
		"target_id": asset.ID,
	}, adminCookie, http.StatusCreated)
	var vncCred model.PlatformItem
	decodeResponse(t, vncCredRec, &vncCred)
	vncRec := assertStatus(t, handler, http.MethodPost, "/api/connections/vnc", map[string]any{
		"asset_id":      asset.ID,
		"credential_id": vncCred.ID,
	}, adminCookie, http.StatusCreated)
	var vncSession model.ConnectionSession
	decodeResponse(t, vncRec, &vncSession)
	assertDesktopPolicySession(t, vncSession, 1600, 1000, 120, 16, false, false, false, true)
}

func assertDesktopPolicySession(t *testing.T, session model.ConnectionSession, width, height, dpi, colorDepth int, clipboard, fileTransfer, ignoreCert, readOnly bool) {
	t.Helper()
	if session.Width != width || session.Height != height || session.DPI != dpi || session.ColorDepth != colorDepth {
		t.Fatalf("desktop policy dimensions = %dx%d dpi=%d color=%d", session.Width, session.Height, session.DPI, session.ColorDepth)
	}
	if session.RecordingPath == "" {
		t.Fatal("default desktop recording path was not created")
	}
	if session.ResizeMethod != "reconnect" {
		t.Fatalf("resize method = %q, want reconnect", session.ResizeMethod)
	}
	if boolPtrValue(session.ClipboardEnabled, !clipboard) != clipboard {
		t.Fatalf("clipboard_enabled = %v, want %v", session.ClipboardEnabled, clipboard)
	}
	if boolPtrValue(session.FileTransferEnabled, !fileTransfer) != fileTransfer {
		t.Fatalf("file_transfer_enabled = %v, want %v", session.FileTransferEnabled, fileTransfer)
	}
	if boolPtrValue(session.IgnoreCert, !ignoreCert) != ignoreCert {
		t.Fatalf("ignore_cert = %v, want %v", session.IgnoreCert, ignoreCert)
	}
	if boolPtrValue(session.ReadOnly, !readOnly) != readOnly {
		t.Fatalf("read_only = %v, want %v", session.ReadOnly, readOnly)
	}
	if boolPtrValue(session.WatermarkEnabled, false) != true || session.WatermarkText != "AUDIT" || session.WatermarkFontSize != 36 {
		t.Fatalf("watermark policy not applied: %#v", session)
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
	groupCredentialRec := assertStatus(t, handler, http.MethodPost, "/api/admin/credentials", map[string]any{
		"name":      "group-host root",
		"type":      "ssh_password",
		"status":    "encrypted",
		"username":  "root",
		"password":  "target-secret",
		"target_id": groupAsset.ID,
	}, adminCookie, http.StatusCreated)
	var groupCredential model.PlatformItem
	decodeResponse(t, groupCredentialRec, &groupCredential)
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
	groupSessionRec := assertStatus(t, handler, http.MethodPost, "/api/access/ssh/"+groupAsset.ID, nil, userCookie, http.StatusAccepted)
	var groupSession model.ConnectionSession
	decodeResponse(t, groupSessionRec, &groupSession)
	if groupSession.Protocol != model.ProtocolSSH || groupSession.ServerID != groupAsset.ID || groupSession.CredentialID != groupCredential.ID {
		t.Fatalf("unexpected group ssh session: %#v", groupSession)
	}
	assertStatus(t, handler, http.MethodPost, "/api/access/ssh/"+expiredAsset.ID, nil, userCookie, http.StatusForbidden)
}

func TestBulkAuthorizationGrantsAccessAcrossResourceTypes(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "bulk-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)

	assetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "bulk-ssh",
		"type":     "linux",
		"status":   "active",
		"protocol": "ssh",
		"host":     "10.20.0.10",
		"port":     22,
	}, adminCookie, http.StatusCreated)
	var asset model.PlatformItem
	decodeResponse(t, assetRec, &asset)
	expiredAssetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "bulk-expired-ssh",
		"type":     "linux",
		"status":   "active",
		"protocol": "ssh",
		"host":     "10.20.0.11",
		"port":     22,
	}, adminCookie, http.StatusCreated)
	var expiredAsset model.PlatformItem
	decodeResponse(t, expiredAssetRec, &expiredAsset)
	webRec := assertStatus(t, handler, http.MethodPost, "/api/admin/websites", map[string]any{
		"name":     "bulk-web",
		"type":     "http",
		"status":   "enabled",
		"protocol": "http",
		"host":     "https://example.test",
	}, adminCookie, http.StatusCreated)
	var webAsset model.PlatformItem
	decodeResponse(t, webRec, &webAsset)
	dbRec := assertStatus(t, handler, http.MethodPost, "/api/admin/database-assets", map[string]any{
		"name":     "bulk-db",
		"type":     "sqlite",
		"status":   "enabled",
		"protocol": "database",
		"metadata": map[string]any{"sqlite_path": "bulk.db"},
	}, adminCookie, http.StatusCreated)
	var databaseAsset model.PlatformItem
	decodeResponse(t, dbRec, &databaseAsset)

	bulkRec := assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/assets/bulk", map[string]any{
		"subject_ids": []string{user.ID},
		"target_ids":  []string{asset.ID},
		"expires_at":  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}, adminCookie, http.StatusCreated)
	if !strings.Contains(bulkRec.Body.String(), `"created":1`) {
		t.Fatalf("bulk asset authorization did not create record: %s", bulkRec.Body.String())
	}
	skipRec := assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/assets/bulk", map[string]any{
		"subject_ids": []string{user.ID},
		"target_ids":  []string{asset.ID},
	}, adminCookie, http.StatusCreated)
	if !strings.Contains(skipRec.Body.String(), `"skipped":1`) {
		t.Fatalf("duplicate bulk authorization was not skipped: %s", skipRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/assets/bulk", map[string]any{
		"subject_ids": []string{user.ID},
		"target_ids":  []string{expiredAsset.ID},
		"expires_at":  time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/websites/bulk", map[string]any{
		"subject_ids": []string{user.ID},
		"target_ids":  []string{webAsset.ID},
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/databases/bulk", map[string]any{
		"subject_ids": []string{user.ID},
		"target_ids":  []string{databaseAsset.ID},
	}, adminCookie, http.StatusCreated)

	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "bulk-user", "password": "password123"}, nil, http.StatusOK)
	userCookie := loginRec.Result().Cookies()[0]
	accessRec := assertStatus(t, handler, http.MethodGet, "/api/access/assets", nil, userCookie, http.StatusOK)
	accessBody := accessRec.Body.String()
	for _, want := range []string{asset.ID, webAsset.ID, databaseAsset.ID} {
		if !strings.Contains(accessBody, want) {
			t.Fatalf("bulk authorization did not expose %s in access portal: %s", want, accessBody)
		}
	}
	if strings.Contains(accessBody, expiredAsset.ID) {
		t.Fatalf("expired bulk authorization exposed asset: %s", accessBody)
	}
	operationRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	operationBody := operationRec.Body.String()
	for _, want := range []string{"authorized_assets.bulk_create", "authorized_web_assets.bulk_create", "authorized_database_assets.bulk_create"} {
		if !strings.Contains(operationBody, want) {
			t.Fatalf("bulk authorization audit missing %s: %s", want, operationBody)
		}
	}
}

func TestDepartmentTreeMetadataAndMemberCounts(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	parentRec := assertStatus(t, handler, http.MethodPost, "/api/admin/departments", map[string]any{
		"name":   "Engineering",
		"type":   "department",
		"status": "enabled",
		"port":   10,
	}, adminCookie, http.StatusCreated)
	var parent model.PlatformItem
	decodeResponse(t, parentRec, &parent)
	platformRec := assertStatus(t, handler, http.MethodPost, "/api/admin/departments", map[string]any{
		"name":      "Platform",
		"type":      "department",
		"status":    "enabled",
		"parent_id": parent.ID,
		"metadata":  map[string]any{"sort": 20},
	}, adminCookie, http.StatusCreated)
	var platform model.PlatformItem
	decodeResponse(t, platformRec, &platform)
	designRec := assertStatus(t, handler, http.MethodPost, "/api/admin/departments", map[string]any{
		"name":      "Design",
		"type":      "department",
		"status":    "enabled",
		"parent_id": parent.ID,
		"metadata":  map[string]any{"sort": 10},
	}, adminCookie, http.StatusCreated)
	var design model.PlatformItem
	decodeResponse(t, designRec, &design)

	assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "engineering-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user", "department_id": parent.ID},
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":      "platform-user",
		"type":      "local",
		"status":    "enabled",
		"password":  "password123",
		"parent_id": platform.ID,
		"metadata":  map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)

	departmentRec := assertStatus(t, handler, http.MethodGet, "/api/admin/departments", nil, adminCookie, http.StatusOK)
	var list struct {
		Items []model.PlatformItem `json:"items"`
	}
	decodeResponse(t, departmentRec, &list)
	if len(list.Items) < 3 {
		t.Fatalf("department list returned %d items, want at least 3", len(list.Items))
	}
	createdDepartments := filterPlatformItemsByIDs(list.Items, parent.ID, design.ID, platform.ID)
	if len(createdDepartments) != 3 {
		t.Fatalf("department list did not include all created departments: %v", createdDepartments)
	}
	if createdDepartments[0].ID != parent.ID || createdDepartments[1].ID != design.ID || createdDepartments[2].ID != platform.ID {
		t.Fatalf("department tree order = %s, %s, %s", createdDepartments[0].Name, createdDepartments[1].Name, createdDepartments[2].Name)
	}
	assertDepartmentMetadata(t, createdDepartments[0], 0, "Engineering", 1, 2, 2)
	assertDepartmentMetadata(t, createdDepartments[1], 1, "Engineering / Design", 0, 0, 0)
	assertDepartmentMetadata(t, createdDepartments[2], 1, "Engineering / Platform", 1, 1, 0)

	bootstrapRec := assertStatus(t, handler, http.MethodGet, "/api/bootstrap", nil, adminCookie, http.StatusOK)
	var bootstrap struct {
		Platform map[string][]model.PlatformItem `json:"platform"`
	}
	decodeResponse(t, bootstrapRec, &bootstrap)
	bootstrapDepartments := filterPlatformItemsByIDs(bootstrap.Platform["departments"], parent.ID, design.ID, platform.ID)
	if len(bootstrapDepartments) != 3 || bootstrapDepartments[2].Metadata["path"] != "Engineering / Platform" {
		t.Fatal("bootstrap did not include enriched department tree data")
	}
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

func TestDatabaseAssetConnectionBuildsExternalDriverDSN(t *testing.T) {
	mysqlAsset := model.PlatformItem{
		ID:       "db_mysql",
		Name:     "mysql ops",
		Type:     "mysql",
		Host:     "mysql.internal",
		Port:     3307,
		Username: "asset_user",
		Metadata: map[string]any{"database": "ops", "charset": "utf8mb4"},
	}
	driver, dsn, err := databaseAssetDriverAndDSN(t.TempDir(), mysqlAsset, databaseAssetSecret{Password: "asset-secret"})
	if err != nil {
		t.Fatalf("mysql dsn: %v", err)
	}
	if driver != "mysql" || !strings.Contains(dsn, "asset_user:asset-secret@tcp(mysql.internal:3307)/ops") || !strings.Contains(dsn, "parseTime=true") {
		t.Fatalf("mysql driver/dsn = %q %q", driver, dsn)
	}

	postgresAsset := model.PlatformItem{
		ID:       "db_postgres",
		Name:     "postgres ops",
		Type:     "postgres",
		Host:     "postgres.internal:5433",
		Username: "pg_asset",
		Metadata: map[string]any{"database": "app", "sslmode": "require"},
	}
	driver, dsn, err = databaseAssetDriverAndDSN(t.TempDir(), postgresAsset, databaseAssetSecret{Password: "pg-secret"})
	if err != nil {
		t.Fatalf("postgres dsn: %v", err)
	}
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse postgres dsn: %v", err)
	}
	if driver != "pgx" || parsed.Scheme != "postgres" || parsed.Host != "postgres.internal:5433" || parsed.Path != "/app" || parsed.Query().Get("sslmode") != "require" {
		t.Fatalf("postgres driver/dsn = %q %q", driver, dsn)
	}
	if user := parsed.User.Username(); user != "pg_asset" {
		t.Fatalf("postgres dsn username = %q, want pg_asset", user)
	}
	password, _ := parsed.User.Password()
	if password != "pg-secret" {
		t.Fatalf("postgres dsn password = %q, want pg-secret", password)
	}

	handler, adminCookie := newTestHandler(t)
	server := handler.(*Server)
	credentialRec := assertStatus(t, handler, http.MethodPost, "/api/admin/credentials", map[string]any{
		"name":     "postgres credential",
		"type":     "database_password",
		"status":   "enabled",
		"username": "pg_credential",
		"password": "credential-secret",
	}, adminCookie, http.StatusCreated)
	var credential model.PlatformItem
	decodeResponse(t, credentialRec, &credential)
	if strings.Contains(credentialRec.Body.String(), "credential-secret") {
		t.Fatal("credential secret leaked in API response")
	}
	assetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/database-assets", map[string]any{
		"name":     "credential-backed postgres",
		"type":     "postgres",
		"status":   "enabled",
		"protocol": "database",
		"host":     "postgres.internal",
		"port":     5432,
		"username": "asset-user",
		"metadata": map[string]any{"database": "app", "credential_id": credential.ID, "sslmode": "disable"},
	}, adminCookie, http.StatusCreated)
	var asset model.PlatformItem
	decodeResponse(t, assetRec, &asset)
	connection, err := server.databaseAssetConnection(asset)
	if err != nil {
		t.Fatalf("database asset connection: %v", err)
	}
	parsed, err = url.Parse(connection.DSN)
	if err != nil {
		t.Fatalf("parse credential postgres dsn: %v", err)
	}
	if connection.Driver != "pgx" || connection.Username != "pg_credential" || parsed.User.Username() != "pg_credential" {
		t.Fatalf("credential-backed connection = %#v dsn=%q", connection, connection.DSN)
	}
	password, _ = parsed.User.Password()
	if password != "credential-secret" {
		t.Fatalf("credential-backed dsn password = %q, want credential-secret", password)
	}
	if strings.Contains(assetRec.Body.String(), "credential-secret") {
		t.Fatal("database asset response leaked credential secret")
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

func TestCustomRoleAPIAndMenuPermissions(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	roleRec := assertStatus(t, handler, http.MethodPost, "/api/admin/roles", map[string]any{
		"name":   "asset-menu-reader",
		"type":   "custom",
		"status": "enabled",
		"metadata": map[string]any{
			"api_permissions":  []string{"GET /api/admin/assets"},
			"menu_permissions": []string{"assets", "/app/assets"},
		},
	}, adminCookie, http.StatusCreated)
	var role model.PlatformItem
	decodeResponse(t, roleRec, &role)
	assetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "custom-role-asset",
		"type":     "linux",
		"status":   "active",
		"protocol": "ssh",
		"host":     "10.20.30.40",
		"port":     22,
	}, adminCookie, http.StatusCreated)
	var asset model.PlatformItem
	decodeResponse(t, assetRec, &asset)

	assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "custom-role-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "asset-menu-reader"},
	}, adminCookie, http.StatusCreated)
	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username": "custom-role-user",
		"password": "password123",
	}, nil, http.StatusOK)
	var loginPayload struct {
		User authUserPayload `json:"user"`
	}
	decodeResponse(t, loginRec, &loginPayload)
	if !stringSliceContains(loginPayload.User.APIPermissions, "GET /api/admin/assets") {
		t.Fatalf("login response api permissions = %v", loginPayload.User.APIPermissions)
	}
	if !stringSliceContains(loginPayload.User.MenuPermissions, "assets") || !stringSliceContains(loginPayload.User.MenuPermissions, "/app/assets") {
		t.Fatalf("login response menu permissions = %v", loginPayload.User.MenuPermissions)
	}
	userCookie := loginRec.Result().Cookies()[0]

	meRec := assertStatus(t, handler, http.MethodGet, "/api/auth/me", nil, userCookie, http.StatusOK)
	if !strings.Contains(meRec.Body.String(), "menu_permissions") || !strings.Contains(meRec.Body.String(), "GET /api/admin/assets") {
		t.Fatal("auth me did not include custom role permissions")
	}
	assertStatus(t, handler, http.MethodGet, "/api/admin/assets", nil, userCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{"name": "blocked"}, userCookie, http.StatusForbidden)
	assertStatus(t, handler, http.MethodGet, "/api/admin/users", nil, userCookie, http.StatusForbidden)
	bootstrapRec := assertStatus(t, handler, http.MethodGet, "/api/bootstrap", nil, userCookie, http.StatusOK)
	if !strings.Contains(bootstrapRec.Body.String(), asset.ID) {
		t.Fatal("custom role bootstrap did not include API-permitted assets collection")
	}

	assertStatus(t, handler, http.MethodPatch, "/api/admin/roles/"+role.ID, map[string]any{
		"name":   "asset-menu-reader",
		"type":   "custom",
		"status": "disabled",
	}, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodGet, "/api/admin/assets", nil, userCookie, http.StatusForbidden)
}

func TestPlatformUserLoginPresenceAndDisable(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "presence-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var created model.PlatformItem
	decodeResponse(t, userRec, &created)

	loginRec := assertStatusWithHeaders(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username": "presence-user",
		"password": "password123",
	}, nil, map[string]string{"User-Agent": "presence-test-browser"}, http.StatusOK)
	userCookie := loginRec.Result().Cookies()[0]

	loggedIn := platformUserFromList(t, handler, adminCookie, created.ID)
	if loggedIn.Metadata["online"] != true {
		t.Fatalf("user online metadata = %v, want true", loggedIn.Metadata["online"])
	}
	if strings.TrimSpace(stringValueFromAny(loggedIn.Metadata["last_login_at"])) == "" {
		t.Fatal("last_login_at was not recorded")
	}
	if strings.TrimSpace(stringValueFromAny(loggedIn.Metadata["last_login_ip"])) == "" {
		t.Fatal("last_login_ip was not recorded")
	}
	if stringValueFromAny(loggedIn.Metadata["last_user_agent"]) != "presence-test-browser" {
		t.Fatalf("last_user_agent = %v", loggedIn.Metadata["last_user_agent"])
	}
	if loginCountFromAny(loggedIn.Metadata["login_count"]) != 1 {
		t.Fatalf("login_count = %v, want 1", loggedIn.Metadata["login_count"])
	}

	secondLoginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username": "presence-user",
		"password": "password123",
	}, nil, http.StatusOK)
	secondUserCookie := secondLoginRec.Result().Cookies()[0]

	assertStatus(t, handler, http.MethodPost, "/api/auth/logout", nil, userCookie, http.StatusOK)
	stillOnline := platformUserFromList(t, handler, adminCookie, created.ID)
	if stillOnline.Metadata["online"] != true {
		t.Fatalf("user online metadata after closing one of two sessions = %v, want true", stillOnline.Metadata["online"])
	}

	assertStatus(t, handler, http.MethodPost, "/api/auth/logout", nil, secondUserCookie, http.StatusOK)
	loggedOut := platformUserFromList(t, handler, adminCookie, created.ID)
	if loggedOut.Metadata["online"] != false {
		t.Fatalf("user online metadata after logout = %v, want false", loggedOut.Metadata["online"])
	}
	if strings.TrimSpace(stringValueFromAny(loggedOut.Metadata["last_logout_at"])) == "" {
		t.Fatal("last_logout_at was not recorded")
	}

	assertStatus(t, handler, http.MethodPatch, "/api/admin/users/"+created.ID, map[string]any{
		"name":   "presence-user",
		"status": "Disabled",
	}, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username": "presence-user",
		"password": "password123",
	}, nil, http.StatusUnauthorized)
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

func TestExternalOIDCLoginCreatesUserAndSession(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	var authorizeState string
	var authorizeNonce string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			query := r.URL.Query()
			if query.Get("client_id") != "openweb-client" || query.Get("response_type") != "code" || query.Get("redirect_uri") == "" {
				http.Error(w, "bad authorize request", http.StatusBadRequest)
				return
			}
			authorizeState = query.Get("state")
			authorizeNonce = query.Get("nonce")
			callback, _ := url.Parse(query.Get("redirect_uri"))
			values := callback.Query()
			values.Set("code", "external-code")
			values.Set("state", authorizeState)
			callback.RawQuery = values.Encode()
			http.Redirect(w, r, callback.String(), http.StatusFound)
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			clientID, clientSecret, _ := r.BasicAuth()
			if clientID != "openweb-client" || clientSecret != "openweb-secret" || r.PostForm.Get("code") != "external-code" {
				http.Error(w, "bad token request", http.StatusUnauthorized)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"access_token": "external-access", "token_type": "Bearer", "expires_in": 300})
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer external-access" {
				http.Error(w, "bad bearer", http.StatusUnauthorized)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"sub":                "external-subject-1",
				"preferred_username": "oidc-operator",
				"name":               "OIDC Operator",
				"nonce":              authorizeNonce,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "External OIDC",
		"type":   "identity",
		"status": "enabled",
		"metadata": map[string]any{
			"oidc_login_enabled":          true,
			"oidc_provider_id":            "fake-sso",
			"oidc_provider_name":          "Fake SSO",
			"oidc_authorization_endpoint": provider.URL + "/authorize",
			"oidc_token_endpoint":         provider.URL + "/token",
			"oidc_userinfo_endpoint":      provider.URL + "/userinfo",
			"oidc_client_id":              "openweb-client",
			"oidc_client_secret":          "openweb-secret",
			"oidc_scopes":                 []string{"openid", "profile", "email"},
			"oidc_role":                   "user",
			"oidc_providers": []any{
				map[string]any{
					"id":                     "disabled-sso",
					"enabled":                false,
					"authorization_endpoint": provider.URL + "/disabled-authorize",
					"token_endpoint":         provider.URL + "/disabled-token",
					"client_id":              "disabled-client",
					"client_secret":          "disabled-secret",
				},
			},
		},
	}, adminCookie, http.StatusCreated)
	systemSettingsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/system-settings", nil, adminCookie, http.StatusOK)
	for _, leaked := range []string{"openweb-secret", "disabled-secret", "oidc_client_secret_encrypted", "client_secret_encrypted"} {
		if strings.Contains(systemSettingsRec.Body.String(), leaked) {
			t.Fatalf("external oidc settings leaked sensitive value %q: %s", leaked, systemSettingsRec.Body.String())
		}
	}

	providersRec := assertStatus(t, handler, http.MethodGet, "/api/auth/oidc/providers", nil, nil, http.StatusOK)
	if !strings.Contains(providersRec.Body.String(), "fake-sso") || !strings.Contains(providersRec.Body.String(), "Fake SSO") || strings.Contains(providersRec.Body.String(), "openweb-secret") {
		t.Fatalf("external oidc providers response invalid: %s", providersRec.Body.String())
	}

	startRec := assertStatus(t, handler, http.MethodGet, "/api/auth/oidc/start?provider=fake-sso&next=/app/access", nil, nil, http.StatusFound)
	providerLocation := startRec.Header().Get("Location")
	if !strings.HasPrefix(providerLocation, provider.URL+"/authorize?") {
		t.Fatalf("start did not redirect to provider: %s", providerLocation)
	}
	noRedirectClient := provider.Client()
	noRedirectClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	providerResp, err := noRedirectClient.Get(providerLocation)
	if err != nil {
		t.Fatalf("call fake provider authorize: %v", err)
	}
	_ = providerResp.Body.Close()
	if providerResp.StatusCode != http.StatusFound {
		t.Fatalf("fake provider authorize status = %d", providerResp.StatusCode)
	}
	callbackLocation := providerResp.Header.Get("Location")
	callbackURL, err := url.Parse(callbackLocation)
	if err != nil {
		t.Fatalf("parse callback location: %v", err)
	}
	if callbackURL.Path != "/api/auth/oidc/callback" || callbackURL.Query().Get("state") != authorizeState || callbackURL.Query().Get("code") == "" {
		t.Fatalf("bad callback location: %s", callbackLocation)
	}

	callbackRec := assertStatus(t, handler, http.MethodGet, callbackURL.RequestURI(), nil, nil, http.StatusFound)
	if callbackRec.Header().Get("Location") != "/app/access" {
		t.Fatalf("callback did not redirect to requested next path: %s", callbackRec.Header().Get("Location"))
	}
	cookies := callbackRec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("callback did not set auth cookie")
	}
	meRec := assertStatus(t, handler, http.MethodGet, "/api/auth/me", nil, cookies[0], http.StatusOK)
	if !strings.Contains(meRec.Body.String(), `"username":"oidc-operator"`) || !strings.Contains(meRec.Body.String(), `"role":"user"`) {
		t.Fatalf("oidc login did not create authenticated user: %s", meRec.Body.String())
	}
	usersRec := assertStatus(t, handler, http.MethodGet, "/api/admin/users", nil, adminCookie, http.StatusOK)
	if !strings.Contains(usersRec.Body.String(), "external-subject-1") || strings.Contains(usersRec.Body.String(), "openweb-secret") || strings.Contains(usersRec.Body.String(), "password_hash") {
		t.Fatalf("external oidc user list invalid: %s", usersRec.Body.String())
	}
	loginLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/login-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(loginLogsRec.Body.String(), `"type":"oidc"`) || !strings.Contains(loginLogsRec.Body.String(), "fake-sso") {
		t.Fatalf("oidc login log missing: %s", loginLogsRec.Body.String())
	}
}

func TestExternalLDAPLoginCreatesUserAndSession(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)
	fakeLDAP := &fakeLDAPAuthenticator{
		users: map[string]fakeLDAPUser{
			"ldap-operator": {
				password: "directory-password",
				claims: externalLDAPClaims{
					Subject:     "uid=ldap-operator,ou=people,dc=example,dc=test",
					DN:          "uid=ldap-operator,ou=people,dc=example,dc=test",
					Username:    "ldap-operator",
					DisplayName: "LDAP Operator",
					Email:       "ldap-operator@example.test",
				},
			},
		},
	}
	srv.ldap = fakeLDAP

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "LDAP identity",
		"type":   "identity",
		"status": "enabled",
		"metadata": map[string]any{
			"disable_password_login":      true,
			"ldap_enabled":                true,
			"ldap_provider_id":            "corp-ldap",
			"ldap_provider_name":          "Corp LDAP",
			"ldap_url":                    "ldap://directory.example.test:389",
			"ldap_bind_dn":                "cn=reader,dc=example,dc=test",
			"ldap_bind_password":          "directory-secret",
			"ldap_base_dn":                "ou=people,dc=example,dc=test",
			"ldap_user_filter":            "(uid={username})",
			"ldap_username_attribute":     "uid",
			"ldap_display_name_attribute": "cn",
			"ldap_email_attribute":        "mail",
			"ldap_role":                   "user",
			"ldap_auto_create":            true,
			"ldap_providers": []any{
				map[string]any{
					"id":                 "disabled-ldap",
					"enabled":            false,
					"url":                "ldap://disabled.example.test:389",
					"base_dn":            "dc=disabled,dc=test",
					"ldap_bind_password": "disabled-secret",
				},
			},
		},
	}, adminCookie, http.StatusCreated)

	statusRec := assertStatus(t, handler, http.MethodGet, "/api/auth/status", nil, nil, http.StatusOK)
	if !strings.Contains(statusRec.Body.String(), `"password_login_disabled":true`) {
		t.Fatalf("auth status did not report disabled local password login: %s", statusRec.Body.String())
	}
	settingsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/system-settings", nil, adminCookie, http.StatusOK)
	for _, leaked := range []string{"directory-secret", "disabled-secret", "ldap_bind_password_encrypted", "bind_password_encrypted"} {
		if strings.Contains(settingsRec.Body.String(), leaked) {
			t.Fatalf("ldap settings leaked sensitive value %q: %s", leaked, settingsRec.Body.String())
		}
	}

	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username": "ldap-operator",
		"password": "wrong-password",
	}, nil, http.StatusUnauthorized)
	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username": "ldap-operator",
		"password": "directory-password",
	}, nil, http.StatusOK)
	if fakeLDAP.calls != 2 {
		t.Fatalf("ldap authenticator calls = %d, want 2", fakeLDAP.calls)
	}
	if fakeLDAP.lastProvider.ID != "corp-ldap" || fakeLDAP.lastProvider.BindPassword != "directory-secret" || fakeLDAP.lastProvider.BaseDN != "ou=people,dc=example,dc=test" {
		t.Fatalf("ldap provider was not parsed/decrypted correctly: %#v", fakeLDAP.lastProvider)
	}
	cookies := loginRec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("ldap login did not set auth cookie")
	}
	meRec := assertStatus(t, handler, http.MethodGet, "/api/auth/me", nil, cookies[0], http.StatusOK)
	if !strings.Contains(meRec.Body.String(), `"username":"ldap-operator"`) || !strings.Contains(meRec.Body.String(), `"role":"user"`) {
		t.Fatalf("ldap login did not authenticate synced user: %s", meRec.Body.String())
	}
	usersRec := assertStatus(t, handler, http.MethodGet, "/api/admin/users", nil, adminCookie, http.StatusOK)
	for _, expected := range []string{"ldap-operator", "uid=ldap-operator,ou=people,dc=example,dc=test", `"type":"ldap"`} {
		if !strings.Contains(usersRec.Body.String(), expected) {
			t.Fatalf("ldap user list missing %q: %s", expected, usersRec.Body.String())
		}
	}
	if strings.Contains(usersRec.Body.String(), "directory-password") || strings.Contains(usersRec.Body.String(), "password_hash") {
		t.Fatalf("ldap user list leaked secret material: %s", usersRec.Body.String())
	}
	loginLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/login-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(loginLogsRec.Body.String(), `"type":"ldap"`) || !strings.Contains(loginLogsRec.Body.String(), "signed in") {
		t.Fatalf("ldap login log missing: %s", loginLogsRec.Body.String())
	}
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
	uploadCertPEM, uploadKeyPEM, err := makeSelfSignedCertificate(certificateRequest{Domain: "uploaded.example.test", Days: 90})
	if err != nil {
		t.Fatalf("make upload certificate: %v", err)
	}
	mismatchCertPEM, _, err := makeSelfSignedCertificate(certificateRequest{Domain: "mismatch.example.test", Days: 90})
	if err != nil {
		t.Fatalf("make mismatch certificate: %v", err)
	}
	assertMultipartFilesStatus(t, handler, "/api/admin/certificates/upload", map[string]string{"name": "uploaded-cert"}, map[string]multipartFile{
		"certificate": {Name: "uploaded.crt", Content: uploadCertPEM},
		"private_key": {Name: "uploaded.key", Content: uploadKeyPEM},
	}, cookie, http.StatusCreated)
	uploadRec := assertMultipartFilesStatus(t, handler, "/api/admin/certificates/upload", map[string]string{"name": "bad-cert"}, map[string]multipartFile{
		"certificate": {Name: "bad.crt", Content: mismatchCertPEM},
		"private_key": {Name: "uploaded.key", Content: uploadKeyPEM},
	}, cookie, http.StatusBadRequest)
	if !strings.Contains(uploadRec.Body.String(), "private key does not match certificate") {
		t.Fatal("mismatched certificate upload did not explain key mismatch")
	}
	certificatesRec := assertStatus(t, handler, http.MethodGet, "/api/admin/certificates", nil, cookie, http.StatusOK)
	certificatesBody := certificatesRec.Body.String()
	if !strings.Contains(certificatesBody, "uploaded-cert") || !strings.Contains(certificatesBody, "uploaded.example.test") || !strings.Contains(certificatesBody, "expires_at") {
		t.Fatal("uploaded certificate metadata did not appear in certificate list")
	}
	if strings.Contains(certificatesBody, "PRIVATE KEY") {
		t.Fatal("certificate list leaked uploaded private key")
	}
	logsAfterUpload := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, cookie, http.StatusOK)
	if !strings.Contains(logsAfterUpload.Body.String(), "certificate.upload") {
		t.Fatal("certificate upload did not write operation log")
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

func TestSMTPIntegrationTestEmail(t *testing.T) {
	handler, cookie := newTestHandler(t)
	smtpServer := newFakeSMTPServer(t)
	host, portText, err := net.SplitHostPort(smtpServer.addr)
	if err != nil {
		t.Fatalf("split smtp address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse smtp port: %v", err)
	}
	settingRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":     "Notification integrations",
		"type":     "integration",
		"status":   "enabled",
		"host":     host,
		"port":     port,
		"username": "smtp-user",
		"password": "smtp-secret",
		"metadata": map[string]any{
			"smtp_host":     host,
			"smtp_port":     port,
			"smtp_from":     "sender@example.test",
			"smtp_to":       "receiver@example.test",
			"llm_provider":  "openai-compatible",
			"llm_api_key":   "llm-secret",
			"llm_base_url":  "https://api.example.test/v1",
			"llm_model":     "test-model",
			"smtp_username": "smtp-user",
		},
	}, cookie, http.StatusCreated)
	var setting model.PlatformItem
	decodeResponse(t, settingRec, &setting)
	settingsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/system-settings", nil, cookie, http.StatusOK)
	settingsBody := settingsRec.Body.String()
	for _, leaked := range []string{"smtp-secret", "llm-secret", "smtp_password_encrypted", "llm_api_key_encrypted"} {
		if strings.Contains(settingsBody, leaked) {
			t.Fatalf("system settings leaked sensitive value %q", leaked)
		}
	}
	if !strings.Contains(settingsBody, "smtp_password_set") || !strings.Contains(settingsBody, "llm_api_key_set") {
		t.Fatal("system settings did not expose secret presence flags")
	}
	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/smtp/test", map[string]any{
		"setting_id": setting.ID,
		"to":         "receiver@example.test",
		"subject":    "SMTP probe",
		"body":       "delivery works",
	}, cookie, http.StatusOK)
	select {
	case message := <-smtpServer.messages:
		if !strings.Contains(message, "Subject: SMTP probe") || !strings.Contains(message, "delivery works") || !strings.Contains(message, "receiver@example.test") {
			t.Fatalf("SMTP message missing expected content:\n%s", message)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SMTP server did not receive test email")
	}
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, cookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), "system_settings.smtp_test") {
		t.Fatal("SMTP test did not write operation log")
	}
	smtpServer.close()
	failedRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/smtp/test", map[string]any{
		"setting_id": setting.ID,
		"to":         "receiver@example.test",
	}, cookie, http.StatusBadGateway)
	if !strings.Contains(failedRec.Body.String(), "send SMTP test email") {
		t.Fatal("failed SMTP test did not return a clear send error")
	}
	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/smtp/test", map[string]any{
		"setting_id": "missing",
	}, cookie, http.StatusNotFound)
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
		"metadata":    map[string]any{"path_prefix": ""},
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

func TestStorageAuthorizationStrategySubjectAndPathScope(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	storageRec := assertStatus(t, handler, http.MethodPost, "/api/admin/storages", map[string]any{
		"name":   "scoped-drive",
		"type":   "local",
		"status": "enabled",
	}, adminCookie, http.StatusCreated)
	var storage model.PlatformItem
	decodeResponse(t, storageRec, &storage)

	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "safe/blocked.txt", "content": "blocked"}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "safe/other.txt", "content": "other"}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "open/allowed.txt", "content": "allowed"}, adminCookie, http.StatusCreated)

	assertStatus(t, handler, http.MethodPost, "/api/admin/roles", map[string]any{
		"name":   "storage-scoped-operator",
		"type":   "custom",
		"status": "enabled",
		"metadata": map[string]any{
			"api_permissions": []string{
				"DELETE /api/admin/storages/*",
				"GET /api/admin/audit/file-logs",
			},
		},
	}, adminCookie, http.StatusCreated)
	scopedUserRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "storage-scoped-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "storage-scoped-operator"},
	}, adminCookie, http.StatusCreated)
	var scopedUser model.PlatformItem
	decodeResponse(t, scopedUserRec, &scopedUser)
	assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "storage-other-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "storage-scoped-operator"},
	}, adminCookie, http.StatusCreated)

	assertStatus(t, handler, http.MethodPost, "/api/admin/strategies", map[string]any{
		"name":        "allow scoped-drive delete",
		"type":        "file",
		"status":      "enabled",
		"target_id":   storage.ID,
		"permissions": map[string]bool{"delete": true},
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/strategies", map[string]any{
		"name":        "deny scoped user safe delete",
		"type":        "file",
		"status":      "enabled",
		"target_id":   storage.ID,
		"owner_id":    scopedUser.ID,
		"permissions": map[string]bool{"delete": false},
		"metadata":    map[string]any{"path_prefix": "safe"},
	}, adminCookie, http.StatusCreated)

	scopedLoginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "storage-scoped-user", "password": "password123"}, nil, http.StatusOK)
	scopedCookie := scopedLoginRec.Result().Cookies()[0]
	otherLoginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "storage-other-user", "password": "password123"}, nil, http.StatusOK)
	otherCookie := otherLoginRec.Result().Cookies()[0]

	assertStatus(t, handler, http.MethodDelete, "/api/admin/storages/"+storage.ID+"/files?path=safe/blocked.txt", nil, scopedCookie, http.StatusForbidden)
	assertStatus(t, handler, http.MethodDelete, "/api/admin/storages/"+storage.ID+"/files?path=open/allowed.txt", nil, scopedCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodDelete, "/api/admin/storages/"+storage.ID+"/files?path=safe/other.txt", nil, otherCookie, http.StatusOK)

	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/file-logs", nil, scopedCookie, http.StatusOK)
	logsBody := logsRec.Body.String()
	if !strings.Contains(logsBody, "safe/blocked.txt") || !strings.Contains(logsBody, "denied") {
		t.Fatal("scoped path denial did not write file log")
	}
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

func startFakeSSHExecServer(t *testing.T, username, password string) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake ssh exec server: %v", err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ssh host key: %v", err)
	}
	signer, err := cryptossh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("create ssh signer: %v", err)
	}
	config := &cryptossh.ServerConfig{
		PasswordCallback: func(meta cryptossh.ConnMetadata, payload []byte) (*cryptossh.Permissions, error) {
			if meta.User() == username && string(payload) == password {
				return nil, nil
			}
			return nil, os.ErrPermission
		},
	}
	config.AddHostKey(signer)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleFakeSSHExecConnection(conn, config)
		}
	}()
	return listener.Addr().String(), func() {
		_ = listener.Close()
		<-done
	}
}

func handleFakeSSHExecConnection(conn net.Conn, config *cryptossh.ServerConfig) {
	sshConn, channels, requests, err := cryptossh.NewServerConn(conn, config)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer sshConn.Close()
	go cryptossh.DiscardRequests(requests)
	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(cryptossh.UnknownChannelType, "session only")
			continue
		}
		channel, reqs, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go handleFakeSSHExecChannel(channel, reqs)
	}
}

func handleFakeSSHExecChannel(channel cryptossh.Channel, requests <-chan *cryptossh.Request) {
	defer channel.Close()
	for req := range requests {
		if req.Type != "exec" {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
		var payload struct {
			Command string
		}
		if err := cryptossh.Unmarshal(req.Payload, &payload); err != nil {
			_ = req.Reply(false, nil)
			return
		}
		_ = req.Reply(true, nil)
		status := uint32(0)
		if strings.Contains(payload.Command, "fail") {
			status = 7
			_, _ = channel.Stderr().Write([]byte("failed: " + payload.Command + "\n"))
		} else {
			_, _ = channel.Write([]byte("ran: " + payload.Command + "\n"))
		}
		_, _ = channel.SendRequest("exit-status", false, cryptossh.Marshal(struct{ Status uint32 }{Status: status}))
		return
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

type fakeLDAPUser struct {
	password string
	claims   externalLDAPClaims
}

type fakeLDAPAuthenticator struct {
	users        map[string]fakeLDAPUser
	calls        int
	lastProvider externalLDAPProvider
}

func (f *fakeLDAPAuthenticator) Authenticate(ctx context.Context, provider externalLDAPProvider, username, password string) (externalLDAPClaims, bool, error) {
	if err := ctx.Err(); err != nil {
		return externalLDAPClaims{}, false, err
	}
	f.calls++
	f.lastProvider = provider
	if provider.BindDN == "" || provider.BindPassword == "" || provider.BaseDN == "" {
		return externalLDAPClaims{}, false, errors.New("ldap provider missing required bind/search settings")
	}
	user, ok := f.users[username]
	if !ok || user.password != password {
		return externalLDAPClaims{}, false, nil
	}
	return user.claims, true, nil
}

type fakeSMTPServer struct {
	addr     string
	messages chan string
	close    func()
}

func newFakeSMTPServer(t *testing.T) fakeSMTPServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake smtp: %v", err)
	}
	server := fakeSMTPServer{
		addr:     listener.Addr().String(),
		messages: make(chan string, 4),
		close: func() {
			_ = listener.Close()
		},
	}
	t.Cleanup(server.close)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleFakeSMTPConnection(conn, server.messages)
		}
	}()
	return server
}

func handleFakeSMTPConnection(conn net.Conn, messages chan<- string) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	writeLine := func(value string) bool {
		if _, err := writer.WriteString(value + "\r\n"); err != nil {
			return false
		}
		return writer.Flush() == nil
	}
	if !writeLine("220 fake.smtp.local ESMTP") {
		return
	}
	var data strings.Builder
	inData := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if inData {
			if trimmed == "." {
				select {
				case messages <- data.String():
				default:
				}
				data.Reset()
				inData = false
				if !writeLine("250 queued") {
					return
				}
				continue
			}
			data.WriteString(line)
			continue
		}
		command := strings.ToUpper(trimmed)
		switch {
		case strings.HasPrefix(command, "EHLO"):
			if !writeLine("250-fake.smtp.local") || !writeLine("250 AUTH PLAIN") {
				return
			}
		case strings.HasPrefix(command, "HELO"):
			if !writeLine("250 fake.smtp.local") {
				return
			}
		case strings.HasPrefix(command, "AUTH "):
			if !writeLine("235 authenticated") {
				return
			}
		case strings.HasPrefix(command, "MAIL FROM:"), strings.HasPrefix(command, "RCPT TO:"):
			if !writeLine("250 ok") {
				return
			}
		case strings.HasPrefix(command, "DATA"):
			inData = true
			if !writeLine("354 end data with <CR><LF>.<CR><LF>") {
				return
			}
		case strings.HasPrefix(command, "QUIT"):
			_ = writeLine("221 bye")
			return
		default:
			if !writeLine("250 ok") {
				return
			}
		}
	}
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

type multipartFile struct {
	Name    string
	Content []byte
}

func assertMultipartFilesStatus(t *testing.T, handler http.Handler, path string, fields map[string]string, files map[string]multipartFile, cookie *http.Cookie, want int) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatalf("write multipart field: %v", err)
		}
	}
	for field, file := range files {
		part, err := writer.CreateFormFile(field, file.Name)
		if err != nil {
			t.Fatalf("create multipart file: %v", err)
		}
		if _, err := part.Write(file.Content); err != nil {
			t.Fatalf("write multipart file: %v", err)
		}
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

func platformUserFromList(t *testing.T, handler http.Handler, adminCookie *http.Cookie, userID string) model.PlatformItem {
	t.Helper()
	rec := assertStatus(t, handler, http.MethodGet, "/api/admin/users", nil, adminCookie, http.StatusOK)
	var response struct {
		Items []model.PlatformItem `json:"items"`
	}
	decodeResponse(t, rec, &response)
	for _, item := range response.Items {
		if item.ID == userID {
			return item
		}
	}
	t.Fatalf("user %s not found in user list", userID)
	return model.PlatformItem{}
}

func filterPlatformItemsByIDs(items []model.PlatformItem, ids ...string) []model.PlatformItem {
	wanted := map[string]bool{}
	for _, id := range ids {
		wanted[id] = true
	}
	result := []model.PlatformItem{}
	for _, item := range items {
		if wanted[item.ID] {
			result = append(result, item)
		}
	}
	return result
}

func stringSliceContains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func loginCountFromAny(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case float64:
		return int(typed)
	case string:
		parsed, _ := strconv.Atoi(strings.TrimSpace(typed))
		return parsed
	default:
		return 0
	}
}

func assertDepartmentMetadata(t *testing.T, item model.PlatformItem, level int, path string, memberCount, totalMemberCount, childCount int) {
	t.Helper()
	if loginCountFromAny(item.Metadata["level"]) != level {
		t.Fatalf("%s level = %v, want %d", item.Name, item.Metadata["level"], level)
	}
	if stringValueFromAny(item.Metadata["path"]) != path {
		t.Fatalf("%s path = %v, want %q", item.Name, item.Metadata["path"], path)
	}
	if loginCountFromAny(item.Metadata["member_count"]) != memberCount {
		t.Fatalf("%s member_count = %v, want %d", item.Name, item.Metadata["member_count"], memberCount)
	}
	if loginCountFromAny(item.Metadata["total_member_count"]) != totalMemberCount {
		t.Fatalf("%s total_member_count = %v, want %d", item.Name, item.Metadata["total_member_count"], totalMemberCount)
	}
	if loginCountFromAny(item.Metadata["direct_child_count"]) != childCount {
		t.Fatalf("%s direct_child_count = %v, want %d", item.Name, item.Metadata["direct_child_count"], childCount)
	}
}

func zipHasEntry(reader *zip.Reader, filename string) bool {
	for _, file := range reader.File {
		if file.Name == filename {
			return true
		}
	}
	return false
}
