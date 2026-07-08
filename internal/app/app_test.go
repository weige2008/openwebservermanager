package app

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
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

	"github.com/fxamacker/cbor/v2"
	cryptossh "golang.org/x/crypto/ssh"
	_ "modernc.org/sqlite"
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

func TestInitialAdminRoleIsCanonicalSuperAdmin(t *testing.T) {
	handler := newUnconfiguredTestServer(t, nil)
	setupRec := assertStatus(t, handler, http.MethodPost, "/api/auth/setup", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusCreated)
	var setupPayload struct {
		User authUserPayload `json:"user"`
	}
	decodeResponse(t, setupRec, &setupPayload)
	if setupPayload.User.Role != string(roleSuperAdmin) {
		t.Fatalf("setup role = %q, want %q", setupPayload.User.Role, roleSuperAdmin)
	}
	cookies := setupRec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("setup did not set auth cookie")
	}

	meRec := assertStatus(t, handler, http.MethodGet, "/api/auth/me", nil, cookies[0], http.StatusOK)
	var mePayload struct {
		User authUserPayload `json:"user"`
	}
	decodeResponse(t, meRec, &mePayload)
	if mePayload.User.Role != string(roleSuperAdmin) {
		t.Fatalf("auth/me role = %q, want %q", mePayload.User.Role, roleSuperAdmin)
	}

	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusOK)
	var loginPayload struct {
		User authUserPayload `json:"user"`
	}
	decodeResponse(t, loginRec, &loginPayload)
	if loginPayload.User.Role != string(roleSuperAdmin) {
		t.Fatalf("login role = %q, want %q", loginPayload.User.Role, roleSuperAdmin)
	}
}

func TestSetupLoginLogFailureRollsBackAdminInitialization(t *testing.T) {
	srv := newUnconfiguredTestServer(t, nil)
	handler := http.Handler(srv)

	removeBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "login_logs")
	failedRec := assertStatus(t, handler, http.MethodPost, "/api/auth/setup", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusInternalServerError)
	removeBlocker()
	if !strings.Contains(failedRec.Body.String(), "persist login log failed") {
		t.Fatalf("setup login log failure was not reported: %s", failedRec.Body.String())
	}
	if srv.cfg.Store.AdminConfigured() {
		t.Fatal("admin remained configured after setup login log failure")
	}
	users, err := srv.cfg.Store.ListPlatformItems("users")
	if err != nil {
		t.Fatalf("list users after setup login log failure: %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("setup login log failure left users behind: %#v", users)
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "auth.login.log.persist_failed") {
		t.Fatal("setup login log persistence failure was not written to core audit logs")
	}

	retryRec := assertStatus(t, handler, http.MethodPost, "/api/auth/setup", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusCreated)
	if len(retryRec.Result().Cookies()) == 0 {
		t.Fatal("setup retry after login log failure did not set auth cookie")
	}
}

func TestSetupLoginStatePersistenceFailureRollsBackAdminInitialization(t *testing.T) {
	srv := newUnconfiguredTestServer(t, nil)
	handler := http.Handler(srv)

	removeBlocker := blockPlatformCollectionSavePayloadFragment(t, srv.cfg.Store, "users", `"online":true`)
	failedRec := assertStatus(t, handler, http.MethodPost, "/api/auth/setup", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusInternalServerError)
	removeBlocker()
	if !strings.Contains(failedRec.Body.String(), "persist user login state failed") {
		t.Fatalf("setup login state persistence failure was not reported: %s", failedRec.Body.String())
	}
	if cookies := failedRec.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("setup issued cookies even though login state persistence failed: %#v", cookies)
	}
	if srv.cfg.Store.AdminConfigured() {
		t.Fatal("admin remained configured after setup login state persistence failure")
	}
	users, err := srv.cfg.Store.ListPlatformItems("users")
	if err != nil {
		t.Fatalf("list users after setup login state failure: %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("setup login state failure left users behind: %#v", users)
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "auth.login.state.persist_failed") {
		t.Fatal("setup login state persistence failure was not written to core audit logs")
	}

	retryRec := assertStatus(t, handler, http.MethodPost, "/api/auth/setup", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusCreated)
	if len(retryRec.Result().Cookies()) == 0 {
		t.Fatal("setup retry after login state failure did not set auth cookie")
	}
}

func TestSetupUserCreateFailureRollsBackAdminInitialization(t *testing.T) {
	srv := newUnconfiguredTestServer(t, nil)
	handler := http.Handler(srv)

	removeBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "users")
	failedRec := assertStatus(t, handler, http.MethodPost, "/api/auth/setup", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusInternalServerError)
	removeBlocker()
	if !strings.Contains(failedRec.Body.String(), "forced platform item create failure") {
		t.Fatalf("setup user create failure was not reported: %s", failedRec.Body.String())
	}
	if srv.cfg.Store.AdminConfigured() {
		t.Fatal("admin remained configured after setup user create failure")
	}

	retryRec := assertStatus(t, handler, http.MethodPost, "/api/auth/setup", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusCreated)
	if len(retryRec.Result().Cookies()) == 0 {
		t.Fatal("setup retry after user create failure did not set auth cookie")
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

			detailRec := assertStatus(t, handler, http.MethodGet, path+"/"+item.ID, nil, cookie, http.StatusOK)
			if !strings.Contains(detailRec.Body.String(), item.ID) {
				t.Fatalf("detail response did not include created id: %s", detailRec.Body.String())
			}
			if strings.Contains(detailRec.Body.String(), "password_hash") {
				t.Fatalf("detail response leaked password hash: %s", detailRec.Body.String())
			}
			assertStatus(t, handler, http.MethodPatch, path+"/"+item.ID, map[string]any{"name": item.Name + " updated", "status": "disabled"}, cookie, http.StatusOK)
			assertStatus(t, handler, http.MethodDelete, path+"/"+item.ID, nil, cookie, http.StatusOK)
		})
	}
}

func TestPlatformCollectionOperationLogFailureRollsBackMutations(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)

	removeCreateBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	createRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "no-audit-create",
		"type":     "ssh",
		"status":   "enabled",
		"protocol": "ssh",
		"host":     "127.0.0.1",
		"port":     22,
	}, adminCookie, http.StatusInternalServerError)
	removeCreateBlocker()
	if !strings.Contains(createRec.Body.String(), "persist operation log failed") {
		t.Fatalf("create operation log failure was not reported: %s", createRec.Body.String())
	}
	assetsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/assets", nil, adminCookie, http.StatusOK)
	if strings.Contains(assetsRec.Body.String(), "no-audit-create") {
		t.Fatalf("asset create was not rolled back after operation log failure: %s", assetsRec.Body.String())
	}

	assetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "audited-asset",
		"type":     "ssh",
		"status":   "enabled",
		"protocol": "ssh",
		"host":     "127.0.0.1",
		"port":     22,
	}, adminCookie, http.StatusCreated)
	var asset model.PlatformItem
	decodeResponse(t, assetRec, &asset)

	removeUpdateBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	updateRec := assertStatus(t, handler, http.MethodPatch, "/api/admin/assets/"+asset.ID, map[string]any{
		"name":   "no-audit-update",
		"status": "disabled",
	}, adminCookie, http.StatusInternalServerError)
	removeUpdateBlocker()
	if !strings.Contains(updateRec.Body.String(), "persist operation log failed") {
		t.Fatalf("update operation log failure was not reported: %s", updateRec.Body.String())
	}
	detailRec := assertStatus(t, handler, http.MethodGet, "/api/admin/assets/"+asset.ID, nil, adminCookie, http.StatusOK)
	var restoredAsset model.PlatformItem
	decodeResponse(t, detailRec, &restoredAsset)
	if restoredAsset.Name != "audited-asset" || restoredAsset.Status != "enabled" {
		t.Fatalf("asset update was not rolled back after operation log failure: %#v", restoredAsset)
	}

	removeDeleteBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	deleteRec := assertStatus(t, handler, http.MethodDelete, "/api/admin/assets/"+asset.ID, nil, adminCookie, http.StatusInternalServerError)
	removeDeleteBlocker()
	if !strings.Contains(deleteRec.Body.String(), "persist operation log failed") {
		t.Fatalf("delete operation log failure was not reported: %s", deleteRec.Body.String())
	}
	afterDeleteRec := assertStatus(t, handler, http.MethodGet, "/api/admin/assets/"+asset.ID, nil, adminCookie, http.StatusOK)
	if !strings.Contains(afterDeleteRec.Body.String(), "audited-asset") {
		t.Fatalf("asset delete was not rolled back after operation log failure: %s", afterDeleteRec.Body.String())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "operation.log.persist_failed") {
		t.Fatal("platform mutation operation log failure was not written to core audit logs")
	}
}

func TestLegacyServerCredentialOperationLogFailuresRollBackMutations(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)

	removeServerBlocker := blockOperationLogName(t, srv.cfg.Store, "server.create")
	serverFailureRec := assertStatus(t, handler, http.MethodPost, "/api/servers", map[string]any{
		"name":     "no-audit-legacy-server",
		"host":     "192.0.2.55",
		"os":       "linux",
		"ssh_port": 22,
	}, adminCookie, http.StatusInternalServerError)
	removeServerBlocker()
	if !strings.Contains(serverFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("legacy server create operation log failure was not reported: %s", serverFailureRec.Body.String())
	}
	servers, _, _, _ := srv.cfg.Store.Bootstrap()
	for _, server := range servers {
		if server.Name == "no-audit-legacy-server" {
			t.Fatalf("legacy server create was not rolled back after operation log failure: %#v", server)
		}
	}

	serverRec := assertStatus(t, handler, http.MethodPost, "/api/servers", map[string]any{
		"name":     "audited-legacy-server",
		"host":     "192.0.2.56",
		"os":       "linux",
		"ssh_port": 22,
	}, adminCookie, http.StatusCreated)
	var server model.Server
	decodeResponse(t, serverRec, &server)

	removeCredentialBlocker := blockOperationLogName(t, srv.cfg.Store, "credential.create")
	credentialFailureRec := assertStatus(t, handler, http.MethodPost, "/api/credentials", map[string]any{
		"name":        "no-audit-legacy-credential",
		"server_id":   server.ID,
		"type":        "ssh_key",
		"username":    "root",
		"private_key": "blocked-private-key",
		"passphrase":  "blocked-passphrase",
	}, adminCookie, http.StatusInternalServerError)
	removeCredentialBlocker()
	if !strings.Contains(credentialFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("legacy credential create operation log failure was not reported: %s", credentialFailureRec.Body.String())
	}
	if strings.Contains(credentialFailureRec.Body.String(), "blocked-private-key") || strings.Contains(credentialFailureRec.Body.String(), "blocked-passphrase") {
		t.Fatalf("legacy credential failure response leaked secret material: %s", credentialFailureRec.Body.String())
	}
	_, credentials, _, _ := srv.cfg.Store.Bootstrap()
	for _, credential := range credentials {
		if credential.Name == "no-audit-legacy-credential" {
			t.Fatalf("legacy credential create was not rolled back after operation log failure: %#v", credential)
		}
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "operation.log.persist_failed") {
		t.Fatal("legacy server or credential operation log failure was not written to core audit logs")
	}

	credentialRec := assertStatus(t, handler, http.MethodPost, "/api/credentials", map[string]any{
		"name":      "audited-legacy-credential",
		"server_id": server.ID,
		"type":      "ssh_password",
		"username":  "root",
		"password":  "target-secret",
	}, adminCookie, http.StatusCreated)
	if strings.Contains(credentialRec.Body.String(), "target-secret") || strings.Contains(credentialRec.Body.String(), "encrypted_password") {
		t.Fatalf("legacy credential create response leaked secret material: %s", credentialRec.Body.String())
	}
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), "server.create") || !strings.Contains(logsRec.Body.String(), "credential.create") {
		t.Fatalf("legacy server or credential create was not written to operation logs: %s", logsRec.Body.String())
	}
}

func TestAuditLogExportJSONAndCSV(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	logRec := assertStatus(t, handler, http.MethodPost, "/api/admin/audit/login-logs", map[string]any{
		"name":        "operator login",
		"type":        "password",
		"status":      "success",
		"owner_id":    "operator",
		"description": "login accepted",
		"metadata": map[string]any{
			"client_ip":  "192.0.2.10",
			"user_agent": "test-browser",
		},
	}, adminCookie, http.StatusCreated)
	var logItem model.PlatformItem
	decodeResponse(t, logRec, &logItem)

	jsonRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/login-logs/export", nil, adminCookie, http.StatusOK)
	if !strings.Contains(jsonRec.Header().Get("Content-Disposition"), "openwebservermanager-login-logs") {
		t.Fatalf("json export missing attachment filename: %s", jsonRec.Header().Get("Content-Disposition"))
	}
	var payload struct {
		Collection string               `json:"collection"`
		Items      []model.PlatformItem `json:"items"`
		ExportedAt time.Time            `json:"exported_at"`
	}
	decodeResponse(t, jsonRec, &payload)
	if payload.Collection != "login_logs" || payload.ExportedAt.IsZero() || !platformItemsContainID(payload.Items, logItem.ID) {
		t.Fatalf("unexpected json export payload: %#v", payload)
	}

	csvRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/login-logs/export?format=csv", nil, adminCookie, http.StatusOK)
	if !strings.Contains(csvRec.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("csv export content type = %q", csvRec.Header().Get("Content-Type"))
	}
	csvBody := csvRec.Body.String()
	for _, want := range []string{"id,module,name,type,status,protocol", logItem.ID, "operator login", "192.0.2.10", "test-browser"} {
		if !strings.Contains(csvBody, want) {
			t.Fatalf("csv export missing %q: %s", want, csvBody)
		}
	}

	assertStatus(t, handler, http.MethodGet, "/api/admin/audit/login-logs/export?format=xml", nil, adminCookie, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPost, "/api/admin/audit/login-logs/export", nil, adminCookie, http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, "/api/admin/audit/missing/export", nil, adminCookie, http.StatusNotFound)

	operationLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(operationLogsRec.Body.String(), "audit.login_logs.export") {
		t.Fatalf("audit export did not write operation log: %s", operationLogsRec.Body.String())
	}
	removeExportBlocker := blockOperationLogName(t, handler.(*Server).cfg.Store, "audit.login_logs.export")
	blockedExportRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/login-logs/export", nil, adminCookie, http.StatusInternalServerError)
	removeExportBlocker()
	if !strings.Contains(blockedExportRec.Body.String(), "persist operation log failed") {
		t.Fatalf("audit export operation log failure was not reported: %s", blockedExportRec.Body.String())
	}
	if blockedExportRec.Header().Get("Content-Disposition") != "" || strings.Contains(blockedExportRec.Body.String(), logItem.ID) {
		t.Fatalf("audit export returned data after operation log failure: %s", blockedExportRec.Body.String())
	}
	if !coreAuditLogsContainAction(handler.(*Server).cfg.Store, "operation.log.persist_failed") {
		t.Fatal("audit export operation log failure was not written to core audit logs")
	}
}

func platformItemsContainID(items []model.PlatformItem, id string) bool {
	for _, item := range items {
		if item.ID == id {
			return true
		}
	}
	return false
}

func coreAuditLogsContainAction(st *store.Store, action string) bool {
	_, _, _, logs := st.Bootstrap()
	for _, log := range logs {
		if log.Action == action {
			return true
		}
	}
	return false
}

func TestAdminLicenseEndpoint(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	getRec := assertStatus(t, handler, http.MethodGet, "/api/admin/license", nil, adminCookie, http.StatusOK)
	var initial localLicenseInfo
	decodeResponse(t, getRec, &initial)
	if initial.Edition != "Community" || initial.Enforcement != "none" || initial.Status != "active" {
		t.Fatalf("unexpected initial license status: %+v", initial)
	}
	if len(initial.InstallationFingerprint) != 32 {
		t.Fatalf("expected stable 32-char installation fingerprint, got %q", initial.InstallationFingerprint)
	}
	if _, ok := initial.Usage["users"]; initial.Limits["users"] != "unlimited" || !ok {
		t.Fatalf("expected unlimited local license with user usage: %+v", initial)
	}

	putRec := assertStatus(t, handler, http.MethodPut, "/api/admin/license", map[string]any{
		"licensee":   "QA Lab",
		"contact":    "ops@example.test",
		"serial":     "LOCAL-COMMUNITY-001",
		"issued_at":  "2026-07-06",
		"expires_at": "never",
		"notes":      "local validation license",
		"features":   []string{"ssh", "rdp", "audit", "gateway"},
	}, adminCookie, http.StatusOK)
	var updated localLicenseInfo
	decodeResponse(t, putRec, &updated)
	if updated.Licensee != "QA Lab" || updated.Serial != "LOCAL-COMMUNITY-001" || updated.SettingID == "" {
		t.Fatalf("license update did not persist local fields: %+v", updated)
	}
	if updated.Enforcement != "none" || updated.Limits["assets"] != "unlimited" {
		t.Fatalf("local license must not introduce commercial enforcement: %+v", updated)
	}

	logRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(logRec.Body.String(), "license.update") {
		t.Fatalf("license update was not written to operation audit logs: %s", logRec.Body.String())
	}
}

func TestAdminLicenseOperationLogFailureRollsBackSetting(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)

	removeCreateBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	createFailureRec := assertStatus(t, handler, http.MethodPut, "/api/admin/license", map[string]any{
		"licensee": "no-audit-license",
		"serial":   "NO-AUDIT",
	}, adminCookie, http.StatusInternalServerError)
	removeCreateBlocker()
	if !strings.Contains(createFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("license create operation log failure was not reported: %s", createFailureRec.Body.String())
	}
	emptyInfoRec := assertStatus(t, handler, http.MethodGet, "/api/admin/license", nil, adminCookie, http.StatusOK)
	var emptyInfo localLicenseInfo
	decodeResponse(t, emptyInfoRec, &emptyInfo)
	if emptyInfo.SettingID != "" || emptyInfo.Licensee == "no-audit-license" {
		t.Fatalf("license create was not rolled back after operation log failure: %+v", emptyInfo)
	}

	initialRec := assertStatus(t, handler, http.MethodPut, "/api/admin/license", map[string]any{
		"licensee": "Audited License",
		"serial":   "AUDITED-001",
		"features": []string{"ssh", "rdp"},
	}, adminCookie, http.StatusOK)
	var initialInfo localLicenseInfo
	decodeResponse(t, initialRec, &initialInfo)
	if initialInfo.SettingID == "" {
		t.Fatal("initial audited license did not create a setting")
	}

	removeUpdateBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	updateFailureRec := assertStatus(t, handler, http.MethodPatch, "/api/admin/license", map[string]any{
		"licensee": "Changed License",
		"serial":   "CHANGED-001",
		"features": []string{"database"},
	}, adminCookie, http.StatusInternalServerError)
	removeUpdateBlocker()
	if !strings.Contains(updateFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("license update operation log failure was not reported: %s", updateFailureRec.Body.String())
	}
	restoredRec := assertStatus(t, handler, http.MethodGet, "/api/admin/license", nil, adminCookie, http.StatusOK)
	var restoredInfo localLicenseInfo
	decodeResponse(t, restoredRec, &restoredInfo)
	if restoredInfo.SettingID != initialInfo.SettingID || restoredInfo.Licensee != "Audited License" || restoredInfo.Serial != "AUDITED-001" {
		t.Fatalf("license update was not rolled back after operation log failure: %+v", restoredInfo)
	}
	if strings.Join(restoredInfo.Features, ",") != "ssh,rdp" {
		t.Fatalf("license features were not restored after operation log failure: %+v", restoredInfo.Features)
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "operation.log.persist_failed") {
		t.Fatal("license operation log persistence failure was not written to core audit logs")
	}
}

func TestAdminLicenseRequiresAdminPermission(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "license-viewer",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	if !strings.Contains(userRec.Body.String(), "license-viewer") {
		t.Fatalf("expected created user response, got %s", userRec.Body.String())
	}
	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "license-viewer", "password": "password123"}, nil, http.StatusOK)
	userCookie := loginRec.Result().Cookies()[0]

	assertStatus(t, handler, http.MethodGet, "/api/admin/license", nil, userCookie, http.StatusForbidden)
	assertStatus(t, handler, http.MethodPut, "/api/admin/license", map[string]any{"licensee": "denied"}, userCookie, http.StatusForbidden)
}

func TestPublicConfigUsesBrandingSettings(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":        "Custom branding",
		"type":        "branding",
		"status":      "enabled",
		"description": "custom public branding",
		"metadata": map[string]any{
			"site_name":         "Ops Portal",
			"logo_url":          "/brand.svg",
			"asset_logo_url":    "/asset.svg",
			"github_url":        "https://example.test/repo",
			"copyright":         "Copyright 2026 Ops",
			"icp_number":        "Test ICP 0001",
			"about_title":       "About Ops Portal",
			"about_description": "Managed access workspace",
			"about_body":        "Public about copy",
			"footer_text":       "Footer copy",
			"nav_links": []map[string]any{
				{"title": "product", "href": "/#product"},
				{"title": "Docs", "href": "https://docs.example.test", "external": true},
			},
		},
	}, adminCookie, http.StatusCreated)

	rec := assertStatus(t, handler, http.MethodGet, "/api/public/config", nil, nil, http.StatusOK)
	var cfg PublicConfig
	decodeResponse(t, rec, &cfg)
	if cfg.SiteName != "Ops Portal" || cfg.LogoURL != "/brand.svg" || cfg.AssetLogoURL != "/asset.svg" {
		t.Fatalf("public config did not apply logo/name branding: %+v", cfg)
	}
	if cfg.GitHubURL != "https://example.test/repo" || cfg.Copyright != "Copyright 2026 Ops" || cfg.ICPNumber != "Test ICP 0001" {
		t.Fatalf("public config did not apply repository/footer branding: %+v", cfg)
	}
	if cfg.AboutTitle != "About Ops Portal" || cfg.AboutDescription != "Managed access workspace" || cfg.AboutBody != "Public about copy" || cfg.FooterText != "Footer copy" {
		t.Fatalf("public config did not apply about branding: %+v", cfg)
	}
	if len(cfg.NavLinks) != 2 || cfg.NavLinks[1].Title != "Docs" || !cfg.NavLinks[1].External {
		t.Fatalf("public config did not apply nav links: %+v", cfg.NavLinks)
	}
}

func TestPlatformCollectionDetailRedactsSensitiveMetadata(t *testing.T) {
	handler, cookie := newTestHandler(t)

	credentialRec := assertStatus(t, handler, http.MethodPost, "/api/admin/credentials", map[string]any{
		"name":     "detail credential",
		"type":     "database_password",
		"status":   "enabled",
		"username": "db-user",
		"password": "credential-secret",
	}, cookie, http.StatusCreated)
	var credential model.PlatformItem
	decodeResponse(t, credentialRec, &credential)
	credentialDetail := assertStatus(t, handler, http.MethodGet, "/api/admin/credentials/"+credential.ID, nil, cookie, http.StatusOK)
	for _, leaked := range []string{"credential-secret", "encrypted_password", "plain_password", `"password"`} {
		if strings.Contains(credentialDetail.Body.String(), leaked) {
			t.Fatalf("credential detail leaked %q: %s", leaked, credentialDetail.Body.String())
		}
	}

	dsn := "postgres://detail_user:dsn-secret@postgres.internal:5432/app?sslmode=disable"
	databaseRec := assertStatus(t, handler, http.MethodPost, "/api/admin/database-assets", map[string]any{
		"name":     "detail dsn database",
		"type":     "postgres",
		"status":   "enabled",
		"protocol": "database",
		"metadata": map[string]any{"dsn": dsn},
	}, cookie, http.StatusCreated)
	var databaseAsset model.PlatformItem
	decodeResponse(t, databaseRec, &databaseAsset)
	databaseDetail := assertStatus(t, handler, http.MethodGet, "/api/admin/database-assets/"+databaseAsset.ID, nil, cookie, http.StatusOK)
	for _, leaked := range []string{"dsn-secret", "postgres://detail_user", `"dsn":`, "database_dsn_encrypted"} {
		if strings.Contains(databaseDetail.Body.String(), leaked) {
			t.Fatalf("database asset detail leaked %q: %s", leaked, databaseDetail.Body.String())
		}
	}
	if !strings.Contains(databaseDetail.Body.String(), "database_dsn_set") {
		t.Fatalf("database asset detail did not expose dsn presence flag: %s", databaseDetail.Body.String())
	}

	settingRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":     "detail integrations",
		"type":     "integration",
		"status":   "enabled",
		"password": "smtp-secret",
		"metadata": map[string]any{
			"smtp_host":   "smtp.example.test",
			"smtp_from":   "sender@example.test",
			"smtp_to":     "receiver@example.test",
			"llm_api_key": "llm-secret",
		},
	}, cookie, http.StatusCreated)
	var setting model.PlatformItem
	decodeResponse(t, settingRec, &setting)
	settingDetail := assertStatus(t, handler, http.MethodGet, "/api/admin/system-settings/"+setting.ID, nil, cookie, http.StatusOK)
	for _, leaked := range []string{"smtp-secret", "llm-secret", "smtp_password_encrypted", "llm_api_key_encrypted", `"llm_api_key":`} {
		if strings.Contains(settingDetail.Body.String(), leaked) {
			t.Fatalf("system setting detail leaked %q: %s", leaked, settingDetail.Body.String())
		}
	}
	for _, expected := range []string{"smtp_password_set", "llm_api_key_set"} {
		if !strings.Contains(settingDetail.Body.String(), expected) {
			t.Fatalf("system setting detail missing %q presence flag: %s", expected, settingDetail.Body.String())
		}
	}

	assertStatus(t, handler, http.MethodGet, "/api/admin/database-assets/missing-detail", nil, cookie, http.StatusNotFound)
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
	deniedLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(deniedLogsRec.Body.String(), "access.ssh.denied") || !strings.Contains(deniedLogsRec.Body.String(), asset.ID) {
		t.Fatalf("denied access portal attempt was not audited: %s", deniedLogsRec.Body.String())
	}

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

func TestAccessPortalExcludesDisabledAssets(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "disabled-access-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)

	sshRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "disabled-ssh-asset",
		"type":     "linux",
		"status":   "disabled",
		"protocol": "ssh",
		"host":     "127.0.0.1",
		"port":     22,
	}, adminCookie, http.StatusCreated)
	var sshAsset model.PlatformItem
	decodeResponse(t, sshRec, &sshAsset)
	lockedSSHRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "locked-ssh-asset",
		"type":     "linux",
		"status":   "locked",
		"protocol": "ssh",
		"host":     "127.0.0.1",
		"port":     22,
	}, adminCookie, http.StatusCreated)
	var lockedSSHAsset model.PlatformItem
	decodeResponse(t, lockedSSHRec, &lockedSSHAsset)
	webRec := assertStatus(t, handler, http.MethodPost, "/api/admin/websites", map[string]any{
		"name":     "disabled-web-asset",
		"type":     "http",
		"status":   "disabled",
		"protocol": "http",
		"host":     "https://disabled.example.test",
	}, adminCookie, http.StatusCreated)
	var webAsset model.PlatformItem
	decodeResponse(t, webRec, &webAsset)
	lockedWebRec := assertStatus(t, handler, http.MethodPost, "/api/admin/websites", map[string]any{
		"name":     "locked-web-asset",
		"type":     "http",
		"status":   "locked",
		"protocol": "http",
		"host":     "https://locked.example.test",
	}, adminCookie, http.StatusCreated)
	var lockedWebAsset model.PlatformItem
	decodeResponse(t, lockedWebRec, &lockedWebAsset)
	databaseRec := assertStatus(t, handler, http.MethodPost, "/api/admin/database-assets", map[string]any{
		"name":     "disabled-database-asset",
		"type":     "sqlite",
		"status":   "offline",
		"protocol": "database",
		"metadata": map[string]any{"sqlite_path": "disabled-access.db"},
	}, adminCookie, http.StatusCreated)
	var databaseAsset model.PlatformItem
	decodeResponse(t, databaseRec, &databaseAsset)
	lockedDatabaseRec := assertStatus(t, handler, http.MethodPost, "/api/admin/database-assets", map[string]any{
		"name":     "locked-database-asset",
		"type":     "sqlite",
		"status":   "locked",
		"protocol": "database",
		"metadata": map[string]any{"sqlite_path": "locked-access.db"},
	}, adminCookie, http.StatusCreated)
	var lockedDatabaseAsset model.PlatformItem
	decodeResponse(t, lockedDatabaseRec, &lockedDatabaseAsset)

	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/assets", map[string]any{
		"name":      "disabled user ssh",
		"owner_id":  user.ID,
		"target_id": sshAsset.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/assets", map[string]any{
		"name":      "locked user ssh",
		"owner_id":  user.ID,
		"target_id": lockedSSHAsset.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/websites", map[string]any{
		"name":      "disabled user web",
		"owner_id":  user.ID,
		"target_id": webAsset.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/websites", map[string]any{
		"name":      "locked user web",
		"owner_id":  user.ID,
		"target_id": lockedWebAsset.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/databases", map[string]any{
		"name":      "disabled user database",
		"owner_id":  user.ID,
		"target_id": databaseAsset.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/databases", map[string]any{
		"name":      "locked user database",
		"owner_id":  user.ID,
		"target_id": lockedDatabaseAsset.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)

	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "disabled-access-user", "password": "password123"}, nil, http.StatusOK)
	userCookie := loginRec.Result().Cookies()[0]
	accessRec := assertStatus(t, handler, http.MethodGet, "/api/access/assets", nil, userCookie, http.StatusOK)
	accessBody := accessRec.Body.String()
	for _, forbidden := range []string{sshAsset.ID, lockedSSHAsset.ID, webAsset.ID, lockedWebAsset.ID, databaseAsset.ID, lockedDatabaseAsset.ID} {
		if strings.Contains(accessBody, forbidden) {
			t.Fatalf("non-connectable asset leaked into access portal: %s", accessBody)
		}
	}
	adminAccessRec := assertStatus(t, handler, http.MethodGet, "/api/access/assets", nil, adminCookie, http.StatusOK)
	for _, forbidden := range []string{sshAsset.ID, lockedSSHAsset.ID, webAsset.ID, lockedWebAsset.ID, databaseAsset.ID, lockedDatabaseAsset.ID} {
		if strings.Contains(adminAccessRec.Body.String(), forbidden) {
			t.Fatalf("non-connectable asset leaked into admin access portal: %s", adminAccessRec.Body.String())
		}
	}

	assertStatus(t, handler, http.MethodPost, "/api/access/ssh/"+sshAsset.ID, map[string]any{"cols": 120, "rows": 32}, userCookie, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPost, "/api/access/ssh/"+lockedSSHAsset.ID, map[string]any{"cols": 120, "rows": 32}, userCookie, http.StatusNotFound)
	assertStatus(t, handler, http.MethodGet, "/api/access/http/"+webAsset.ID+"/proxy/", nil, userCookie, http.StatusNotFound)
	assertStatus(t, handler, http.MethodGet, "/api/access/http/"+lockedWebAsset.ID+"/proxy/", nil, userCookie, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPost, "/api/access/database/"+databaseAsset.ID+"/query", map[string]any{"sql": "SELECT 1"}, userCookie, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPost, "/api/access/database/"+lockedDatabaseAsset.ID+"/query", map[string]any{"sql": "SELECT 1"}, userCookie, http.StatusNotFound)
}

func TestAuthenticatedPasswordChange(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	assertStatus(t, handler, http.MethodPost, "/api/auth/password", map[string]any{
		"current_password": "password123",
		"new_password":     "new-admin-password",
	}, nil, http.StatusUnauthorized)

	secondAdminLogin := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username": "admin",
		"password": "password123",
	}, nil, http.StatusOK)
	secondAdminCookie := secondAdminLogin.Result().Cookies()[0]

	assertStatus(t, handler, http.MethodPost, "/api/auth/password", map[string]any{
		"current_password": "wrong-password",
		"new_password":     "new-admin-password",
	}, adminCookie, http.StatusUnauthorized)
	assertStatus(t, handler, http.MethodPost, "/api/auth/password", map[string]any{
		"current_password": "password123",
		"new_password":     "short",
	}, adminCookie, http.StatusBadRequest)

	removeAdminPasswordLogBlocker := blockOperationLogName(t, handler.(*Server).cfg.Store, "auth.password.change")
	blockedAdminChangeRec := assertStatus(t, handler, http.MethodPost, "/api/auth/password", map[string]any{
		"current_password": "password123",
		"new_password":     "blocked-admin-password",
	}, adminCookie, http.StatusInternalServerError)
	removeAdminPasswordLogBlocker()
	if !strings.Contains(blockedAdminChangeRec.Body.String(), "persist operation log failed") {
		t.Fatalf("admin password change operation log failure was not reported: %s", blockedAdminChangeRec.Body.String())
	}
	if !coreAuditLogsContainAction(handler.(*Server).cfg.Store, "operation.log.persist_failed") {
		t.Fatal("admin password change operation log failure was not audited")
	}
	assertStatus(t, handler, http.MethodGet, "/api/auth/me", nil, secondAdminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "blocked-admin-password"}, nil, http.StatusUnauthorized)
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusOK)

	changeRec := assertStatus(t, handler, http.MethodPost, "/api/auth/password", map[string]any{
		"current_password": "password123",
		"new_password":     "new-admin-password",
	}, adminCookie, http.StatusOK)
	if strings.Contains(changeRec.Body.String(), "password_hash") || strings.Contains(changeRec.Body.String(), "new-admin-password") {
		t.Fatal("password change response leaked secret material")
	}
	assertStatus(t, handler, http.MethodGet, "/api/auth/me", nil, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodGet, "/api/auth/me", nil, secondAdminCookie, http.StatusUnauthorized)
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusUnauthorized)
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "new-admin-password"}, nil, http.StatusOK)

	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "password-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)
	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "password-user", "password": "password123"}, nil, http.StatusOK)
	userCookie := loginRec.Result().Cookies()[0]

	removeUserPasswordLogBlocker := blockOperationLogName(t, handler.(*Server).cfg.Store, "auth.password.change")
	blockedUserChangeRec := assertStatus(t, handler, http.MethodPost, "/api/auth/password", map[string]any{
		"current_password": "password123",
		"new_password":     "blocked-user-password",
	}, userCookie, http.StatusInternalServerError)
	removeUserPasswordLogBlocker()
	if !strings.Contains(blockedUserChangeRec.Body.String(), "persist operation log failed") {
		t.Fatalf("user password change operation log failure was not reported: %s", blockedUserChangeRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "password-user", "password": "blocked-user-password"}, nil, http.StatusUnauthorized)
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "password-user", "password": "password123"}, nil, http.StatusOK)

	userChangeRec := assertStatus(t, handler, http.MethodPost, "/api/auth/password", map[string]any{
		"current_password": "password123",
		"new_password":     "new-user-password",
	}, userCookie, http.StatusOK)
	if strings.Contains(userChangeRec.Body.String(), "password_hash") || strings.Contains(userChangeRec.Body.String(), "new-user-password") {
		t.Fatal("platform user password change response leaked secret material")
	}
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "password-user", "password": "password123"}, nil, http.StatusUnauthorized)
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "password-user", "password": "new-user-password"}, nil, http.StatusOK)

	usersRec := assertStatus(t, handler, http.MethodGet, "/api/admin/users", nil, adminCookie, http.StatusOK)
	if strings.Contains(usersRec.Body.String(), "password_hash") || strings.Contains(usersRec.Body.String(), "new-user-password") || strings.Contains(usersRec.Body.String(), "new-admin-password") {
		t.Fatal("user list leaked password material")
	}
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), "auth.password.change") || !strings.Contains(logsRec.Body.String(), "auth.password.change.failed") {
		t.Fatal("password change audit logs were not recorded")
	}
}

func TestAccessMFARequiredForPortalConnections(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)

	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "mfa-operator",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)
	secret := "JBSWY3DPEHPK3PXP"
	if _, err := srv.cfg.Store.EnableUserMFA(user.ID, secret, []string{"ABCDE-FGHIJ"}); err != nil {
		t.Fatalf("enable user MFA: %v", err)
	}

	assetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "mfa-linux",
		"type":     "linux",
		"status":   "active",
		"protocol": "ssh",
		"host":     "127.0.0.1",
		"port":     22,
	}, adminCookie, http.StatusCreated)
	var asset model.PlatformItem
	decodeResponse(t, assetRec, &asset)
	assertStatus(t, handler, http.MethodPost, "/api/admin/credentials", map[string]any{
		"name":      "mfa-linux root",
		"type":      "ssh_password",
		"status":    "encrypted",
		"username":  "root",
		"password":  "target-secret",
		"target_id": asset.ID,
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/assets", map[string]any{
		"name":      "mfa-operator linux",
		"owner_id":  user.ID,
		"target_id": asset.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)

	databaseRec := assertStatus(t, handler, http.MethodPost, "/api/admin/database-assets", map[string]any{
		"name":     "mfa-db",
		"type":     "sqlite",
		"status":   "enabled",
		"protocol": "database",
		"metadata": map[string]any{"sqlite_path": "mfa.db", "row_limit": 10},
	}, adminCookie, http.StatusCreated)
	var databaseAsset model.PlatformItem
	decodeResponse(t, databaseRec, &databaseAsset)
	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/databases", map[string]any{
		"name":      "mfa-operator database",
		"owner_id":  user.ID,
		"target_id": databaseAsset.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "Access MFA",
		"type":   "access",
		"status": "enabled",
		"metadata": map[string]any{
			"access_mfa_enabled":       true,
			"access_mfa_valid_minutes": 5,
		},
	}, adminCookie, http.StatusCreated)

	loginWithMFA := func() *http.Cookie {
		t.Helper()
		loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
			"username": "mfa-operator",
			"password": "password123",
		}, nil, http.StatusAccepted)
		var challenge map[string]any
		decodeResponse(t, loginRec, &challenge)
		token, _ := challenge["mfa_token"].(string)
		if token == "" {
			t.Fatalf("login MFA challenge missing token: %v", challenge)
		}
		completeRec := assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/complete-login", map[string]any{
			"token":    token,
			"mfa_code": totpCode(secret, time.Now().UTC()),
		}, nil, http.StatusOK)
		cookies := completeRec.Result().Cookies()
		if len(cookies) == 0 {
			t.Fatal("MFA login did not return auth cookie")
		}
		return cookies[0]
	}

	userCookie := loginWithMFA()
	missingRec := assertStatus(t, handler, http.MethodPost, "/api/access/ssh/"+asset.ID, map[string]any{
		"cols": 120,
		"rows": 32,
	}, userCookie, http.StatusPreconditionRequired)
	if !strings.Contains(missingRec.Body.String(), `"mfa_required":true`) || !strings.Contains(missingRec.Body.String(), `"mfa_scope":"access"`) {
		t.Fatalf("missing access MFA response is not structured: %s", missingRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, "/api/access/ssh/"+asset.ID, map[string]any{
		"cols":     120,
		"rows":     32,
		"mfa_code": "000000",
	}, userCookie, http.StatusUnauthorized)
	sessionRec := assertStatus(t, handler, http.MethodPost, "/api/access/ssh/"+asset.ID, map[string]any{
		"cols":     120,
		"rows":     32,
		"mfa_code": totpCode(secret, time.Now().UTC()),
	}, userCookie, http.StatusAccepted)
	var session model.ConnectionSession
	decodeResponse(t, sessionRec, &session)
	if session.Protocol != model.ProtocolSSH || session.ServerID != asset.ID {
		t.Fatalf("unexpected SSH session after access MFA: %#v", session)
	}
	assertStatus(t, handler, http.MethodPost, "/api/access/ssh/"+asset.ID, map[string]any{
		"cols": 100,
		"rows": 24,
	}, userCookie, http.StatusAccepted)

	databaseCookie := loginWithMFA()
	assertStatus(t, handler, http.MethodPost, "/api/access/database/"+databaseAsset.ID+"/query", map[string]any{
		"sql": "CREATE TABLE access_mfa_check(id INTEGER PRIMARY KEY)",
	}, databaseCookie, http.StatusPreconditionRequired)
	assertStatus(t, handler, http.MethodPost, "/api/access/database/"+databaseAsset.ID+"/query", map[string]any{
		"sql":      "CREATE TABLE access_mfa_check(id INTEGER PRIMARY KEY)",
		"mfa_code": totpCode(secret, time.Now().UTC()),
	}, databaseCookie, http.StatusOK)

	operationRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(operationRec.Body.String(), "access.mfa.verify") || !strings.Contains(operationRec.Body.String(), "access.mfa.failed") {
		t.Fatalf("access MFA audit entries missing: %s", operationRec.Body.String())
	}
}

func TestAccessMFAWebAssetPreflightUnlocksProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("web asset ok"))
	}))
	defer upstream.Close()

	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)
	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "web-mfa-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)
	secret := "JBSWY3DPEHPK3PXP"
	if _, err := srv.cfg.Store.EnableUserMFA(user.ID, secret, []string{"KLMNO-PQRST"}); err != nil {
		t.Fatalf("enable user MFA: %v", err)
	}
	webRec := assertStatus(t, handler, http.MethodPost, "/api/admin/websites", map[string]any{
		"name":     "mfa web app",
		"type":     "http",
		"status":   "enabled",
		"metadata": map[string]any{"target_url": upstream.URL},
	}, adminCookie, http.StatusCreated)
	var webAsset model.PlatformItem
	decodeResponse(t, webRec, &webAsset)
	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/websites", map[string]any{
		"name":      "web-mfa-user app",
		"owner_id":  user.ID,
		"target_id": webAsset.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "Access MFA",
		"type":   "access",
		"status": "enabled",
		"metadata": map[string]any{
			"access_mfa_enabled":       true,
			"access_mfa_valid_minutes": 5,
		},
	}, adminCookie, http.StatusCreated)

	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username": "web-mfa-user",
		"password": "password123",
	}, nil, http.StatusAccepted)
	var challenge map[string]any
	decodeResponse(t, loginRec, &challenge)
	completeRec := assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/complete-login", map[string]any{
		"token":    challenge["mfa_token"],
		"mfa_code": totpCode(secret, time.Now().UTC()),
	}, nil, http.StatusOK)
	userCookie := completeRec.Result().Cookies()[0]

	proxyBlocked := assertStatus(t, handler, http.MethodGet, "/api/access/http/"+webAsset.ID+"/proxy/", nil, userCookie, http.StatusPreconditionRequired)
	if !strings.Contains(proxyBlocked.Body.String(), `"mfa_required":true`) {
		t.Fatalf("web proxy did not require access MFA: %s", proxyBlocked.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, "/api/access/http/"+webAsset.ID+"/mfa", map[string]any{}, userCookie, http.StatusPreconditionRequired)
	assertStatus(t, handler, http.MethodPost, "/api/access/http/"+webAsset.ID+"/mfa", map[string]any{"mfa_code": "000000"}, userCookie, http.StatusUnauthorized)
	preflightRec := assertStatus(t, handler, http.MethodPost, "/api/access/http/"+webAsset.ID+"/mfa", map[string]any{
		"mfa_code": totpCode(secret, time.Now().UTC()),
	}, userCookie, http.StatusOK)
	if !strings.Contains(preflightRec.Body.String(), `"ok":true`) || !strings.Contains(preflightRec.Body.String(), `"mfa_scope":"access"`) {
		t.Fatalf("web access MFA preflight response is not structured: %s", preflightRec.Body.String())
	}
	proxyRec := assertStatus(t, handler, http.MethodGet, "/api/access/http/"+webAsset.ID+"/proxy/", nil, userCookie, http.StatusOK)
	if proxyRec.Body.String() != "web asset ok" {
		t.Fatalf("web proxy after preflight = %q, want web asset ok", proxyRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, "/api/auth/logout", nil, userCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodGet, "/api/access/http/"+webAsset.ID+"/proxy/", nil, userCookie, http.StatusUnauthorized)
}

func TestMFACompleteLoginRejectsDisabledUser(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)

	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "disabled-mfa-login",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)
	secret := "JBSWY3DPEHPK3PXP"
	if _, err := srv.cfg.Store.EnableUserMFA(user.ID, secret, []string{"VWXYZ-ABCDE"}); err != nil {
		t.Fatalf("enable user MFA: %v", err)
	}

	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username": "disabled-mfa-login",
		"password": "password123",
	}, nil, http.StatusAccepted)
	var challenge map[string]any
	decodeResponse(t, loginRec, &challenge)
	token, _ := challenge["mfa_token"].(string)
	if token == "" {
		t.Fatalf("login MFA challenge missing token: %v", challenge)
	}

	assertStatus(t, handler, http.MethodPatch, "/api/admin/users/"+user.ID, map[string]any{
		"status": "disabled",
	}, adminCookie, http.StatusOK)
	completeRec := assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/complete-login", map[string]any{
		"token":    token,
		"mfa_code": totpCode(secret, time.Now().UTC()),
	}, nil, http.StatusUnauthorized)
	if len(completeRec.Result().Cookies()) != 0 {
		t.Fatal("disabled user MFA completion returned an auth cookie")
	}
	if !strings.Contains(completeRec.Body.String(), "MFA account is disabled or no longer exists") {
		t.Fatalf("disabled user MFA response did not explain account state: %s", completeRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/complete-login", map[string]any{
		"token":    token,
		"mfa_code": totpCode(secret, time.Now().UTC()),
	}, nil, http.StatusUnauthorized)
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/login-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), "disabled-mfa-login") || !strings.Contains(logsRec.Body.String(), "MFA account is disabled or no longer exists") {
		t.Fatalf("disabled user MFA failure was not written to login logs: %s", logsRec.Body.String())
	}
}

func TestPasskeyRegistrationAndLogin(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	privateKey, credentialID, passkey := registerTestPasskeyWithCredentialID(t, handler, adminCookie, "admin", []byte("admin-passkey-credential"))

	listRec := assertStatus(t, handler, http.MethodGet, "/api/auth/passkeys", nil, adminCookie, http.StatusOK)
	if strings.Contains(listRec.Body.String(), "public_key_x") || strings.Contains(listRec.Body.String(), "public_key_y") {
		t.Fatalf("passkey list leaked public key internals: %s", listRec.Body.String())
	}

	loginOptions := testPasskeyLoginOptions(t, handler, "admin")
	assertionPayload := testPasskeyAssertionPayload(t, loginOptions.ChallengeID, loginOptions.PublicKey.Challenge, loginOptions.PublicKey.RPID, credentialID, privateKey, 2, false)
	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/login/verify", assertionPayload, nil, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/login/verify", assertionPayload, nil, http.StatusUnauthorized)
	cookies := loginRec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("passkey login did not set auth cookie")
	}
	assertStatus(t, handler, http.MethodGet, "/api/auth/me", nil, cookies[0], http.StatusOK)

	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/login-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), `"type":"passkey"`) || !strings.Contains(logsRec.Body.String(), `"status":"success"`) {
		t.Fatalf("passkey login log missing: %s", logsRec.Body.String())
	}

	badOptions := testPasskeyLoginOptions(t, handler, "admin")
	badPayload := testPasskeyAssertionPayload(t, badOptions.ChallengeID, badOptions.PublicKey.Challenge, badOptions.PublicKey.RPID, credentialID, privateKey, 3, true)
	assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/login/verify", badPayload, nil, http.StatusUnauthorized)
	validAfterBadPayload := testPasskeyAssertionPayload(t, badOptions.ChallengeID, badOptions.PublicKey.Challenge, badOptions.PublicKey.RPID, credentialID, privateKey, 3, false)
	validAfterBadRec := assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/login/verify", validAfterBadPayload, nil, http.StatusUnauthorized)
	if len(validAfterBadRec.Result().Cookies()) > 0 {
		t.Fatal("passkey login challenge was reused after failed verification")
	}

	registerOptionsRec := assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/register/options", map[string]any{}, adminCookie, http.StatusOK)
	var registerOptions testPasskeyCreationOptionsResponse
	decodeResponse(t, registerOptionsRec, &registerOptions)
	extraPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate extra passkey key: %v", err)
	}
	extraCredentialID := []byte("admin-passkey-extra-credential")
	badRegisterPayload := testPasskeyRegistrationPayload(t, registerOptions, "admin", extraCredentialID, extraPrivateKey)
	badRegisterPayload["type"] = "not-public-key"
	assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/register/verify", badRegisterPayload, adminCookie, http.StatusBadRequest)
	validRegisterAfterBad := testPasskeyRegistrationPayload(t, registerOptions, "admin", extraCredentialID, extraPrivateKey)
	assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/register/verify", validRegisterAfterBad, adminCookie, http.StatusUnauthorized)

	assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "passkey-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	otherLoginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "passkey-user", "password": "password123"}, nil, http.StatusOK)
	otherCookie := otherLoginRec.Result().Cookies()[0]
	_, _, otherPasskey := registerTestPasskeyWithCredentialID(t, handler, otherCookie, "passkey-user", []byte("other-passkey-credential"))

	assertStatus(t, handler, http.MethodDelete, "/api/auth/passkeys/"+passkey.ID, nil, otherCookie, http.StatusNotFound)
	assertStatus(t, handler, http.MethodDelete, "/api/auth/passkeys/"+otherPasskey.ID, nil, adminCookie, http.StatusNotFound)
	assertStatus(t, handler, http.MethodDelete, "/api/auth/passkeys/"+passkey.ID, nil, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/login/options", map[string]any{"username": "admin"}, nil, http.StatusUnauthorized)
	assertStatus(t, handler, http.MethodDelete, "/api/auth/passkeys/"+otherPasskey.ID, nil, otherCookie, http.StatusOK)

	disabledUserRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "disabled-passkey-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var disabledUser model.PlatformItem
	decodeResponse(t, disabledUserRec, &disabledUser)
	disabledLoginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "disabled-passkey-user", "password": "password123"}, nil, http.StatusOK)
	disabledCookie := disabledLoginRec.Result().Cookies()[0]
	disabledPrivateKey, disabledCredentialID, _ := registerTestPasskeyWithCredentialID(t, handler, disabledCookie, "disabled-passkey-user", []byte("disabled-passkey-credential"))
	disabledOptions := testPasskeyLoginOptions(t, handler, "disabled-passkey-user")
	assertStatus(t, handler, http.MethodPatch, "/api/admin/users/"+disabledUser.ID, map[string]any{
		"status": "disabled",
	}, adminCookie, http.StatusOK)
	disabledPayload := testPasskeyAssertionPayload(t, disabledOptions.ChallengeID, disabledOptions.PublicKey.Challenge, disabledOptions.PublicKey.RPID, disabledCredentialID, disabledPrivateKey, 2, false)
	disabledVerifyRec := assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/login/verify", disabledPayload, nil, http.StatusUnauthorized)
	if len(disabledVerifyRec.Result().Cookies()) > 0 {
		t.Fatal("disabled passkey user received a session cookie")
	}
	disabledLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/login-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(disabledLogsRec.Body.String(), "passkey account is disabled or no longer exists") {
		t.Fatalf("disabled passkey login was not audited: %s", disabledLogsRec.Body.String())
	}
}

func TestPasskeyOperationLogFailureRollsBackMutations(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)

	optionsRec := assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/register/options", map[string]any{}, adminCookie, http.StatusOK)
	var options testPasskeyCreationOptionsResponse
	decodeResponse(t, optionsRec, &options)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate blocked passkey key: %v", err)
	}
	blockedCredentialID := []byte("blocked-passkey-credential")
	blockedPayload := testPasskeyRegistrationPayload(t, options, "admin", blockedCredentialID, privateKey)

	removeRegisterBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	registerFailureRec := assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/register/verify", blockedPayload, adminCookie, http.StatusInternalServerError)
	removeRegisterBlocker()
	if !strings.Contains(registerFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("passkey register operation log failure was not reported: %s", registerFailureRec.Body.String())
	}
	listAfterRegisterFailure := assertStatus(t, handler, http.MethodGet, "/api/auth/passkeys", nil, adminCookie, http.StatusOK)
	if strings.Contains(listAfterRegisterFailure.Body.String(), passkeyBase64Encode(blockedCredentialID)) {
		t.Fatalf("passkey registration survived failed operation log write: %s", listAfterRegisterFailure.Body.String())
	}

	restoreFailedOptionsRec := assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/register/options", map[string]any{}, adminCookie, http.StatusOK)
	var restoreFailedOptions testPasskeyCreationOptionsResponse
	decodeResponse(t, restoreFailedOptionsRec, &restoreFailedOptions)
	restoreFailedPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate restore-failed passkey key: %v", err)
	}
	restoreFailedCredentialID := []byte("register-restore-failed-passkey")
	restoreFailedPayload := testPasskeyRegistrationPayload(t, restoreFailedOptions, "admin", restoreFailedCredentialID, restoreFailedPrivateKey)
	removeRegisterLogBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	removeRegisterRollbackBlocker := blockPlatformItemDeletePayloadFragment(t, srv.cfg.Store, "passkeys", `"credential_id":"`+passkeyBase64Encode(restoreFailedCredentialID)+`"`)
	registerRestoreFailureRec := assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/register/verify", restoreFailedPayload, adminCookie, http.StatusInternalServerError)
	removeRegisterRollbackBlocker()
	removeRegisterLogBlocker()
	if !strings.Contains(registerRestoreFailureRec.Body.String(), "failed to remove registered passkey after operation log failure") {
		t.Fatalf("passkey register rollback failure was not reported: %s", registerRestoreFailureRec.Body.String())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "auth.passkey.restore_failed") {
		t.Fatal("passkey register rollback failure was not written to core audit logs")
	}

	_, _, passkey := registerTestPasskeyWithCredentialID(t, handler, adminCookie, "admin", []byte("delete-rollback-passkey-credential"))
	removeDeleteBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	deleteFailureRec := assertStatus(t, handler, http.MethodDelete, "/api/auth/passkeys/"+passkey.ID, nil, adminCookie, http.StatusInternalServerError)
	removeDeleteBlocker()
	if !strings.Contains(deleteFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("passkey delete operation log failure was not reported: %s", deleteFailureRec.Body.String())
	}
	listAfterDeleteFailure := assertStatus(t, handler, http.MethodGet, "/api/auth/passkeys", nil, adminCookie, http.StatusOK)
	if !strings.Contains(listAfterDeleteFailure.Body.String(), passkey.ID) || !strings.Contains(listAfterDeleteFailure.Body.String(), passkey.CredentialID) {
		t.Fatalf("passkey delete was not restored after failed operation log write: %s", listAfterDeleteFailure.Body.String())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "operation.log.persist_failed") {
		t.Fatal("passkey operation log persistence failure was not written to core audit logs")
	}

	_, _, unrestoredPasskey := registerTestPasskeyWithCredentialID(t, handler, adminCookie, "admin", []byte("delete-restore-failed-passkey-credential"))
	removeDeleteLogBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	removeRestoreBlocker := blockPlatformItemSave(t, srv.cfg.Store, "passkeys", unrestoredPasskey.ID)
	restoreFailureRec := assertStatus(t, handler, http.MethodDelete, "/api/auth/passkeys/"+unrestoredPasskey.ID, nil, adminCookie, http.StatusInternalServerError)
	removeRestoreBlocker()
	removeDeleteLogBlocker()
	if !strings.Contains(restoreFailureRec.Body.String(), "failed to restore deleted passkey") {
		t.Fatalf("passkey restore failure was not reported: %s", restoreFailureRec.Body.String())
	}
	listAfterRestoreFailure := assertStatus(t, handler, http.MethodGet, "/api/auth/passkeys", nil, adminCookie, http.StatusOK)
	if strings.Contains(listAfterRestoreFailure.Body.String(), unrestoredPasskey.ID) || strings.Contains(listAfterRestoreFailure.Body.String(), unrestoredPasskey.CredentialID) {
		t.Fatalf("passkey unexpectedly survived forced restore failure: %s", listAfterRestoreFailure.Body.String())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "auth.passkey.restore_failed") {
		t.Fatal("passkey restore failure was not written to core audit logs")
	}
}

func TestPasskeyLoginLogFailureRollsBackUsage(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)

	privateKey, credentialID, passkey := registerTestPasskeyWithCredentialID(t, handler, adminCookie, "admin", []byte("login-log-rollback-passkey"))
	before, ok, err := srv.cfg.Store.GetPlatformItem("passkeys", passkey.ID)
	if err != nil || !ok {
		t.Fatalf("load passkey before failed login: ok=%v err=%v", ok, err)
	}
	if got := passkeyMetadataInt(before.Metadata["sign_count"]); got != 1 {
		t.Fatalf("initial passkey sign_count = %d, want 1", got)
	}

	loginOptions := testPasskeyLoginOptions(t, handler, "admin")
	assertionPayload := testPasskeyAssertionPayload(t, loginOptions.ChallengeID, loginOptions.PublicKey.Challenge, loginOptions.PublicKey.RPID, credentialID, privateKey, 2, false)
	removeLoginLogBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "login_logs")
	loginFailureRec := assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/login/verify", assertionPayload, nil, http.StatusInternalServerError)
	removeLoginLogBlocker()
	if !strings.Contains(loginFailureRec.Body.String(), "persist login log failed") {
		t.Fatalf("passkey login log failure was not reported: %s", loginFailureRec.Body.String())
	}
	if len(loginFailureRec.Result().Cookies()) > 0 {
		t.Fatalf("passkey login issued cookies after failed login log write: %#v", loginFailureRec.Result().Cookies())
	}

	after, ok, err := srv.cfg.Store.GetPlatformItem("passkeys", passkey.ID)
	if err != nil || !ok {
		t.Fatalf("load passkey after failed login: ok=%v err=%v", ok, err)
	}
	if got := passkeyMetadataInt(after.Metadata["sign_count"]); got != 1 {
		t.Fatalf("passkey sign_count changed after failed login log write: got %d", got)
	}
	if firstMetadataString(after.Metadata, "last_used_at", "last_used_ip") != "" {
		t.Fatalf("passkey usage metadata survived failed login log write: %#v", after.Metadata)
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "auth.login.log.persist_failed") {
		t.Fatal("passkey login log persistence failure was not written to core audit logs")
	}

	restoreFailureOptions := testPasskeyLoginOptions(t, handler, "admin")
	restoreFailurePayload := testPasskeyAssertionPayload(t, restoreFailureOptions.ChallengeID, restoreFailureOptions.PublicKey.Challenge, restoreFailureOptions.PublicKey.RPID, credentialID, privateKey, 2, false)
	removeLoginLogBlocker = blockPlatformItemCreate(t, srv.cfg.Store, "login_logs")
	removeRestoreBlocker := blockPlatformItemSavePayloadFragment(t, srv.cfg.Store, "passkeys", passkey.ID, `"sign_count":1`)
	restoreFailureRec := assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/login/verify", restoreFailurePayload, nil, http.StatusInternalServerError)
	removeRestoreBlocker()
	removeLoginLogBlocker()
	if !strings.Contains(restoreFailureRec.Body.String(), "failed to restore passkey usage after login log failure") {
		t.Fatalf("passkey usage restore failure was not reported: %s", restoreFailureRec.Body.String())
	}
	if len(restoreFailureRec.Result().Cookies()) > 0 {
		t.Fatalf("passkey login issued cookies after failed usage restore: %#v", restoreFailureRec.Result().Cookies())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "auth.passkey.restore_failed") {
		t.Fatal("passkey usage restore failure was not written to core audit logs")
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
				"metadata": map[string]any{"role": "user", "mfa_secret": "raw-mfa-secret", "mfa_recovery_codes": []string{"raw-recovery-code"}},
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
	csvRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users/import", map[string]any{
		"format": "csv",
		"content": strings.Join([]string{
			"name,type,status,password,role,group,tags",
			`csv-user,local,enabled,password123,auditor,ops,"csv,import"`,
		}, "\n"),
	}, adminCookie, http.StatusCreated)
	if !strings.Contains(csvRec.Body.String(), `"created":1`) {
		t.Fatalf("csv user import did not create user: %s", csvRec.Body.String())
	}
	csvLoginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "csv-user", "password": "password123"}, nil, http.StatusOK)
	if !strings.Contains(csvLoginRec.Body.String(), `"role":"auditor"`) {
		t.Fatalf("csv imported user did not login with role: %s", csvLoginRec.Body.String())
	}
	removeCreateImportBlocker := blockOperationLogName(t, handler.(*Server).cfg.Store, "users.import")
	createImportFailureRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users/import", map[string]any{
		"items": []map[string]any{{
			"name":     "rollback-import-user",
			"type":     "local",
			"status":   "enabled",
			"password": "password123",
			"metadata": map[string]any{"role": "user"},
		}},
	}, adminCookie, http.StatusInternalServerError)
	removeCreateImportBlocker()
	if !strings.Contains(createImportFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("user import create operation log failure was not reported: %s", createImportFailureRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "rollback-import-user", "password": "password123"}, nil, http.StatusUnauthorized)
	removePartialImportBlocker := blockPlatformCollectionSavePayloadFragment(t, handler.(*Server).cfg.Store, "users", `"name":"partial-blocked-user"`)
	partialImportFailureRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users/import", map[string]any{
		"items": []map[string]any{{
			"name":     "partial-created-user",
			"type":     "local",
			"status":   "enabled",
			"password": "password123",
			"metadata": map[string]any{"role": "user"},
		}, {
			"name":     "partial-blocked-user",
			"type":     "local",
			"status":   "enabled",
			"password": "password123",
			"metadata": map[string]any{"role": "user"},
		}},
	}, adminCookie, http.StatusInternalServerError)
	removePartialImportBlocker()
	if !strings.Contains(partialImportFailureRec.Body.String(), "forced platform collection payload save failure") {
		t.Fatalf("partial user import failure was not reported: %s", partialImportFailureRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "partial-created-user", "password": "password123"}, nil, http.StatusUnauthorized)
	removeUpdateImportBlocker := blockOperationLogName(t, handler.(*Server).cfg.Store, "users.import")
	updateImportFailureRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users/import", map[string]any{
		"update_existing": true,
		"items": []map[string]any{{
			"name":     "import-user",
			"type":     "local",
			"status":   "enabled",
			"password": "blockedpassword123",
			"metadata": map[string]any{"role": "auditor"},
		}},
	}, adminCookie, http.StatusInternalServerError)
	removeUpdateImportBlocker()
	if !strings.Contains(updateImportFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("user import update operation log failure was not reported: %s", updateImportFailureRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "import-user", "password": "blockedpassword123"}, nil, http.StatusUnauthorized)
	rolledBackLoginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "import-user", "password": "newpassword123"}, nil, http.StatusOK)
	if !strings.Contains(rolledBackLoginRec.Body.String(), `"role":"admin"`) {
		t.Fatalf("user import update was not rolled back after operation log failure: %s", rolledBackLoginRec.Body.String())
	}
	exportJSONRec := assertStatus(t, handler, http.MethodGet, "/api/admin/users/export", nil, adminCookie, http.StatusOK)
	exportJSONBody := exportJSONRec.Body.String()
	for _, leaked := range []string{"password_hash", "raw-mfa-secret", "raw-recovery-code"} {
		if strings.Contains(exportJSONBody, leaked) {
			t.Fatalf("user json export leaked %q: %s", leaked, exportJSONBody)
		}
	}
	if !strings.Contains(exportJSONBody, "csv-user") || !strings.Contains(exportJSONBody, `"role":"auditor"`) {
		t.Fatalf("user json export missing imported users: %s", exportJSONBody)
	}
	exportCSVRec := assertStatus(t, handler, http.MethodGet, "/api/admin/users/export?format=csv", nil, adminCookie, http.StatusOK)
	if contentType := exportCSVRec.Header().Get("Content-Type"); !strings.Contains(contentType, "text/csv") {
		t.Fatalf("user csv export content type = %q", contentType)
	}
	for _, leaked := range []string{"password_hash", "raw-mfa-secret", "raw-recovery-code"} {
		if strings.Contains(exportCSVRec.Body.String(), leaked) {
			t.Fatalf("user csv export leaked %q: %s", leaked, exportCSVRec.Body.String())
		}
	}
	userRows, err := csv.NewReader(strings.NewReader(exportCSVRec.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("parse user csv export: %v", err)
	}
	if len(userRows) < 2 || strings.Join(userRows[0], ",") != "name,type,status,role,group,owner_id,department_id,tags,online,last_login_at,last_login_ip,description,metadata_json" {
		t.Fatalf("user csv export header/rows invalid: %#v", userRows)
	}
	foundCSVUser := false
	for _, row := range userRows[1:] {
		if len(row) >= 13 && row[0] == "csv-user" {
			foundCSVUser = row[1] == "local" && row[2] == "enabled" && row[3] == "auditor" && row[4] == "ops" && row[7] == "csv,import"
		}
	}
	if !foundCSVUser {
		t.Fatalf("user csv export missing csv-user row: %#v", userRows)
	}
	removeUserExportBlocker := blockOperationLogName(t, handler.(*Server).cfg.Store, "users.export")
	blockedUserExportRec := assertStatus(t, handler, http.MethodGet, "/api/admin/users/export", nil, adminCookie, http.StatusInternalServerError)
	removeUserExportBlocker()
	if !strings.Contains(blockedUserExportRec.Body.String(), "persist operation log failed") {
		t.Fatalf("user export operation log failure was not reported: %s", blockedUserExportRec.Body.String())
	}
	if blockedUserExportRec.Header().Get("Content-Disposition") != "" || strings.Contains(blockedUserExportRec.Body.String(), "csv-user") {
		t.Fatalf("user export returned data after operation log failure: %s", blockedUserExportRec.Body.String())
	}
	if !coreAuditLogsContainAction(handler.(*Server).cfg.Store, "operation.log.persist_failed") {
		t.Fatal("user export operation log failure was not written to core audit logs")
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
	srv := handler.(*Server)

	assertStatus(t, handler, http.MethodPost, "/api/admin/roles", map[string]any{
		"name":   "command-approval-reviewer",
		"type":   "custom",
		"status": "enabled",
		"metadata": map[string]any{
			"api_permissions": []string{
				"POST /api/admin/command-approvals/*",
			},
		},
	}, adminCookie, http.StatusCreated)
	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "exec-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)
	assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "command-limited-approver",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "command-approval-reviewer"},
	}, adminCookie, http.StatusCreated)

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
	limitedLoginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "command-limited-approver", "password": "password123"}, nil, http.StatusOK)
	limitedCookie := limitedLoginRec.Result().Cookies()[0]
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

	removeExecLogBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "exec_command_logs")
	execLogFailureRec := assertStatus(t, handler, http.MethodPost, "/api/access/ssh/"+asset.ID+"/exec", map[string]any{
		"command":         "printf missing-log",
		"credential_id":   credential.ID,
		"timeout_seconds": 5,
	}, userCookie, http.StatusInternalServerError)
	removeExecLogBlocker()
	if !strings.Contains(execLogFailureRec.Body.String(), "persist exec command log failed") {
		t.Fatalf("ssh exec command log failure was not reported: %s", execLogFailureRec.Body.String())
	}
	if strings.Contains(execLogFailureRec.Body.String(), "ran: printf missing-log") {
		t.Fatalf("ssh exec returned command output after command log failure: %s", execLogFailureRec.Body.String())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "exec_command.log.persist_failed") {
		t.Fatal("ssh exec command log persistence failure was not written to core audit logs")
	}
	execLogsAfterFailureRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/exec-command-logs", nil, adminCookie, http.StatusOK)
	if strings.Contains(execLogsAfterFailureRec.Body.String(), "printf missing-log") {
		t.Fatalf("ssh exec command log failure still left an exec command log: %s", execLogsAfterFailureRec.Body.String())
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

	approvalFilterRec := assertStatus(t, handler, http.MethodPost, "/api/admin/command-filters", map[string]any{
		"name":      "approve service restart",
		"type":      "approval",
		"status":    "enabled",
		"protocol":  "ssh",
		"owner_id":  user.ID,
		"target_id": asset.ID,
		"metadata":  map[string]any{"pattern": "systemctl restart", "risk": "critical"},
	}, adminCookie, http.StatusCreated)
	var approvalFilter model.PlatformItem
	decodeResponse(t, approvalFilterRec, &approvalFilter)
	approvalRequiredRec := assertStatus(t, handler, http.MethodPost, "/api/access/ssh/"+asset.ID+"/exec", map[string]any{
		"command":         "systemctl restart nginx",
		"credential_id":   credential.ID,
		"timeout_seconds": 5,
	}, userCookie, http.StatusForbidden)
	var approvalRequiredResult map[string]any
	decodeResponse(t, approvalRequiredRec, &approvalRequiredResult)
	approvalID, _ := approvalRequiredResult["approval_id"].(string)
	if approvalRequiredResult["blocked"] != true || approvalRequiredResult["status"] != "approval_required" || approvalRequiredResult["risk"] != "critical" || approvalID == "" {
		t.Fatalf("unexpected approval-required ssh exec result: %#v", approvalRequiredResult)
	}
	commandApprovalsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/command-approvals", nil, adminCookie, http.StatusOK)
	if !strings.Contains(commandApprovalsRec.Body.String(), approvalID) || !strings.Contains(commandApprovalsRec.Body.String(), "systemctl restart nginx") || !strings.Contains(commandApprovalsRec.Body.String(), `"status":"pending"`) {
		t.Fatalf("command approval was not listed as pending: %s", commandApprovalsRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, "/api/admin/command-approvals/"+approvalID+"/execute", map[string]any{}, adminCookie, http.StatusConflict)
	limitedApproveRec := assertStatus(t, handler, http.MethodPost, "/api/admin/command-approvals/"+approvalID+"/approve", map[string]any{"note": "no asset access"}, limitedCookie, http.StatusForbidden)
	if !strings.Contains(limitedApproveRec.Body.String(), "ssh asset access denied") {
		t.Fatalf("limited command approver denial did not explain asset authorization: %s", limitedApproveRec.Body.String())
	}
	assetDeniedLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(assetDeniedLogsRec.Body.String(), "command_approval.asset_access.denied") || !strings.Contains(assetDeniedLogsRec.Body.String(), approvalID) || !strings.Contains(assetDeniedLogsRec.Body.String(), asset.ID) {
		t.Fatalf("command approval asset denial was not audited: %s", assetDeniedLogsRec.Body.String())
	}
	removeApproveLogBlocker := blockOperationLogName(t, srv.cfg.Store, "command_approval.approved")
	blockedApproveRec := assertStatus(t, handler, http.MethodPost, "/api/admin/command-approvals/"+approvalID+"/approve", map[string]any{"note": "blocked operation log"}, adminCookie, http.StatusInternalServerError)
	removeApproveLogBlocker()
	if !strings.Contains(blockedApproveRec.Body.String(), "persist operation log failed") {
		t.Fatalf("command approval log persistence failure did not explain error: %s", blockedApproveRec.Body.String())
	}
	blockedApproveStatusRec := assertStatus(t, handler, http.MethodGet, "/api/admin/command-approvals/"+approvalID, nil, adminCookie, http.StatusOK)
	if !strings.Contains(blockedApproveStatusRec.Body.String(), `"status":"pending"`) || strings.Contains(blockedApproveStatusRec.Body.String(), "blocked operation log") {
		t.Fatalf("command approval was not restored after approve log failure: %s", blockedApproveStatusRec.Body.String())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "operation.log.persist_failed") {
		t.Fatal("command approval approve operation log failure was not audited")
	}
	rejectRequiredRec := assertStatus(t, handler, http.MethodPost, "/api/access/ssh/"+asset.ID+"/exec", map[string]any{
		"command":         "systemctl restart cron",
		"credential_id":   credential.ID,
		"timeout_seconds": 5,
	}, userCookie, http.StatusForbidden)
	var rejectRequiredResult map[string]any
	decodeResponse(t, rejectRequiredRec, &rejectRequiredResult)
	rejectApprovalID, _ := rejectRequiredResult["approval_id"].(string)
	if rejectApprovalID == "" {
		t.Fatalf("approval-required reject command did not return approval id: %#v", rejectRequiredResult)
	}
	removeRejectLogBlocker := blockOperationLogName(t, srv.cfg.Store, "command_approval.rejected")
	blockedRejectRec := assertStatus(t, handler, http.MethodPost, "/api/admin/command-approvals/"+rejectApprovalID+"/reject", map[string]any{"note": "blocked reject log"}, adminCookie, http.StatusInternalServerError)
	removeRejectLogBlocker()
	if !strings.Contains(blockedRejectRec.Body.String(), "persist operation log failed") {
		t.Fatalf("command reject log persistence failure did not explain error: %s", blockedRejectRec.Body.String())
	}
	blockedRejectStatusRec := assertStatus(t, handler, http.MethodGet, "/api/admin/command-approvals/"+rejectApprovalID, nil, adminCookie, http.StatusOK)
	if !strings.Contains(blockedRejectStatusRec.Body.String(), `"status":"pending"`) || strings.Contains(blockedRejectStatusRec.Body.String(), "blocked reject log") {
		t.Fatalf("command approval was not restored after reject log failure: %s", blockedRejectStatusRec.Body.String())
	}
	rejectDecisionRec := assertStatus(t, handler, http.MethodPost, "/api/admin/command-approvals/"+rejectApprovalID+"/reject", map[string]any{"note": "not this window"}, adminCookie, http.StatusOK)
	if !strings.Contains(rejectDecisionRec.Body.String(), `"status":"rejected"`) || !strings.Contains(rejectDecisionRec.Body.String(), "not this window") {
		t.Fatalf("command approval reject response did not include rejected state: %s", rejectDecisionRec.Body.String())
	}
	approvedRec := assertStatus(t, handler, http.MethodPost, "/api/admin/command-approvals/"+approvalID+"/approve", map[string]any{"note": "maintenance window approved"}, adminCookie, http.StatusOK)
	if !strings.Contains(approvedRec.Body.String(), `"status":"approved"`) || !strings.Contains(approvedRec.Body.String(), "maintenance window approved") {
		t.Fatalf("command approval response did not include approved state: %s", approvedRec.Body.String())
	}
	limitedExecuteRec := assertStatus(t, handler, http.MethodPost, "/api/admin/command-approvals/"+approvalID+"/execute", map[string]any{"timeout_seconds": 5}, limitedCookie, http.StatusForbidden)
	if !strings.Contains(limitedExecuteRec.Body.String(), "ssh asset access denied") {
		t.Fatalf("limited command executor denial did not explain asset authorization: %s", limitedExecuteRec.Body.String())
	}
	removeApprovedExecLogBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "exec_command_logs")
	approvedExecLogFailureRec := assertStatus(t, handler, http.MethodPost, "/api/admin/command-approvals/"+approvalID+"/execute", map[string]any{"timeout_seconds": 5}, adminCookie, http.StatusInternalServerError)
	removeApprovedExecLogBlocker()
	if !strings.Contains(approvedExecLogFailureRec.Body.String(), "persist exec command log failed") {
		t.Fatalf("approved ssh exec command log failure was not reported: %s", approvedExecLogFailureRec.Body.String())
	}
	if strings.Contains(approvedExecLogFailureRec.Body.String(), "ran: systemctl restart nginx") {
		t.Fatalf("approved ssh exec returned command output after command log failure: %s", approvedExecLogFailureRec.Body.String())
	}
	approvedLogFailureStateRec := assertStatus(t, handler, http.MethodGet, "/api/admin/command-approvals/"+approvalID, nil, adminCookie, http.StatusOK)
	if !strings.Contains(approvedLogFailureStateRec.Body.String(), `"status":"approved"`) || strings.Contains(approvedLogFailureStateRec.Body.String(), `"execution_status":"success"`) {
		t.Fatalf("approved command state changed after exec command log failure: %s", approvedLogFailureStateRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPatch, "/api/admin/command-filters/"+approvalFilter.ID, map[string]any{"status": "disabled"}, adminCookie, http.StatusOK)
	approvedExecRec := assertStatus(t, handler, http.MethodPost, "/api/admin/command-approvals/"+approvalID+"/execute", map[string]any{"timeout_seconds": 5}, adminCookie, http.StatusOK)
	var approvedExecResult map[string]any
	decodeResponse(t, approvedExecRec, &approvedExecResult)
	if approvedExecResult["status"] != "success" || approvedExecResult["approved_execution"] != true || approvedExecResult["approval_id"] != approvalID || !strings.Contains(approvedExecResult["stdout"].(string), "ran: systemctl restart nginx") {
		t.Fatalf("unexpected approved command execution result: %#v", approvedExecResult)
	}
	executedApprovalRec := assertStatus(t, handler, http.MethodGet, "/api/admin/command-approvals/"+approvalID, nil, adminCookie, http.StatusOK)
	if !strings.Contains(executedApprovalRec.Body.String(), `"status":"executed"`) || !strings.Contains(executedApprovalRec.Body.String(), `"execution_status":"success"`) {
		t.Fatalf("executed command approval did not persist execution metadata: %s", executedApprovalRec.Body.String())
	}

	assertStatus(t, handler, http.MethodPatch, "/api/admin/command-filters/"+approvalFilter.ID, map[string]any{"status": "enabled"}, adminCookie, http.StatusOK)
	blockedPersistRequiredRec := assertStatus(t, handler, http.MethodPost, "/api/access/ssh/"+asset.ID+"/exec", map[string]any{
		"command":         "systemctl restart api",
		"credential_id":   credential.ID,
		"timeout_seconds": 5,
	}, userCookie, http.StatusForbidden)
	var blockedPersistRequiredResult map[string]any
	decodeResponse(t, blockedPersistRequiredRec, &blockedPersistRequiredResult)
	blockedPersistApprovalID, _ := blockedPersistRequiredResult["approval_id"].(string)
	if blockedPersistApprovalID == "" {
		t.Fatalf("approval-required command did not return approval id: %#v", blockedPersistRequiredResult)
	}
	assertStatus(t, handler, http.MethodPost, "/api/admin/command-approvals/"+blockedPersistApprovalID+"/approve", map[string]any{"note": "approved persistence failure path"}, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, "/api/admin/command-filters/"+approvalFilter.ID, map[string]any{"status": "disabled"}, adminCookie, http.StatusOK)
	removeExecutedBlocker := blockPlatformItemStatusUpdate(t, srv.cfg.Store, "command_approvals", blockedPersistApprovalID, "executed")
	blockedPersistExecuteRec := assertStatus(t, handler, http.MethodPost, "/api/admin/command-approvals/"+blockedPersistApprovalID+"/execute", map[string]any{"timeout_seconds": 5}, adminCookie, http.StatusInternalServerError)
	removeExecutedBlocker()
	if !strings.Contains(blockedPersistExecuteRec.Body.String(), "persist command approval executed state failed") {
		t.Fatalf("command approval persistence failure did not explain executed state error: %s", blockedPersistExecuteRec.Body.String())
	}
	blockedPersistApprovalRec := assertStatus(t, handler, http.MethodGet, "/api/admin/command-approvals/"+blockedPersistApprovalID, nil, adminCookie, http.StatusOK)
	if !strings.Contains(blockedPersistApprovalRec.Body.String(), `"status":"approved"`) {
		t.Fatalf("blocked command approval status update unexpectedly changed state: %s", blockedPersistApprovalRec.Body.String())
	}

	assertStatus(t, handler, http.MethodPatch, "/api/admin/command-filters/"+approvalFilter.ID, map[string]any{"status": "enabled"}, adminCookie, http.StatusOK)
	blockedApprovalRequiredRec := assertStatus(t, handler, http.MethodPost, "/api/access/ssh/"+asset.ID+"/exec", map[string]any{
		"command":         "systemctl restart postgresql",
		"credential_id":   credential.ID,
		"timeout_seconds": 5,
	}, userCookie, http.StatusForbidden)
	var blockedApprovalRequiredResult map[string]any
	decodeResponse(t, blockedApprovalRequiredRec, &blockedApprovalRequiredResult)
	blockedApprovalID, _ := blockedApprovalRequiredResult["approval_id"].(string)
	if blockedApprovalRequiredResult["status"] != "approval_required" || blockedApprovalID == "" {
		t.Fatalf("unexpected second approval-required ssh exec result: %#v", blockedApprovalRequiredResult)
	}
	assertStatus(t, handler, http.MethodPost, "/api/admin/command-approvals/"+blockedApprovalID+"/approve", map[string]any{"note": "approved before deny rule"}, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/admin/command-filters", map[string]any{
		"name":      "deny restarted database",
		"type":      "deny",
		"status":    "enabled",
		"protocol":  "ssh",
		"owner_id":  user.ID,
		"target_id": asset.ID,
		"metadata":  map[string]any{"pattern": "systemctl restart postgresql", "risk": "emergency"},
	}, adminCookie, http.StatusCreated)
	blockedApprovedExecRec := assertStatus(t, handler, http.MethodPost, "/api/admin/command-approvals/"+blockedApprovalID+"/execute", map[string]any{"timeout_seconds": 5}, adminCookie, http.StatusForbidden)
	var blockedApprovedExecResult map[string]any
	decodeResponse(t, blockedApprovedExecRec, &blockedApprovedExecResult)
	if blockedApprovedExecResult["status"] != "denied" || blockedApprovedExecResult["approved_execution"] != true || blockedApprovedExecResult["approval_id"] != blockedApprovalID || blockedApprovedExecResult["blocked"] != true {
		t.Fatalf("approved command was not blocked by later deny rule: %#v", blockedApprovedExecResult)
	}
	blockedApprovalRec := assertStatus(t, handler, http.MethodGet, "/api/admin/command-approvals/"+blockedApprovalID, nil, adminCookie, http.StatusOK)
	if !strings.Contains(blockedApprovalRec.Body.String(), `"status":"denied"`) || !strings.Contains(blockedApprovalRec.Body.String(), `"execution_status":"denied"`) || !strings.Contains(blockedApprovalRec.Body.String(), `"approved_execution":true`) {
		t.Fatalf("denied approved command did not persist execution metadata: %s", blockedApprovalRec.Body.String())
	}

	deniedPersistRequiredRec := assertStatus(t, handler, http.MethodPost, "/api/access/ssh/"+asset.ID+"/exec", map[string]any{
		"command":         "systemctl restart mysql",
		"credential_id":   credential.ID,
		"timeout_seconds": 5,
	}, userCookie, http.StatusForbidden)
	var deniedPersistRequiredResult map[string]any
	decodeResponse(t, deniedPersistRequiredRec, &deniedPersistRequiredResult)
	deniedPersistApprovalID, _ := deniedPersistRequiredResult["approval_id"].(string)
	if deniedPersistApprovalID == "" {
		t.Fatalf("approval-required denied command did not return approval id: %#v", deniedPersistRequiredResult)
	}
	assertStatus(t, handler, http.MethodPost, "/api/admin/command-approvals/"+deniedPersistApprovalID+"/approve", map[string]any{"note": "approved denied persistence failure path"}, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/admin/command-filters", map[string]any{
		"name":      "deny restarted mysql",
		"type":      "deny",
		"status":    "enabled",
		"protocol":  "ssh",
		"owner_id":  user.ID,
		"target_id": asset.ID,
		"metadata":  map[string]any{"pattern": "systemctl restart mysql", "risk": "emergency"},
	}, adminCookie, http.StatusCreated)
	removeDeniedBlocker := blockPlatformItemStatusUpdate(t, srv.cfg.Store, "command_approvals", deniedPersistApprovalID, "denied")
	deniedPersistExecuteRec := assertStatus(t, handler, http.MethodPost, "/api/admin/command-approvals/"+deniedPersistApprovalID+"/execute", map[string]any{"timeout_seconds": 5}, adminCookie, http.StatusInternalServerError)
	removeDeniedBlocker()
	if !strings.Contains(deniedPersistExecuteRec.Body.String(), "persist command approval denied state failed") {
		t.Fatalf("command approval persistence failure did not explain denied state error: %s", deniedPersistExecuteRec.Body.String())
	}
	persistFailureOperationRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(persistFailureOperationRec.Body.String(), "command_approval.execute.persist_failed") {
		t.Fatalf("command approval persistence failure was not audited: %s", persistFailureOperationRec.Body.String())
	}

	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/exec-command-logs", nil, adminCookie, http.StatusOK)
	logsBody := logsRec.Body.String()
	for _, want := range []string{"printf ok", "rm -rf /tmp/test", "systemctl restart nginx", "systemctl restart postgresql", `"exit_code":0`, `"risk":"high"`, `"risk":"critical"`, `"risk":"emergency"`, `"interactive":false`, approvalID, blockedApprovalID, `"approved_execution":true`} {
		if !strings.Contains(logsBody, want) {
			t.Fatalf("exec command logs missing %s in %s", want, logsBody)
		}
	}
	operationRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	operationBody := operationRec.Body.String()
	if !strings.Contains(operationBody, "connection.ssh.exec") || !strings.Contains(operationBody, "connection.ssh.exec.denied") || !strings.Contains(operationBody, "command_approval.approved") || !strings.Contains(operationBody, "command_approval.execute") {
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

func TestConnectionCreateOperationLogFailuresRollbackSessions(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)

	linuxRec := assertStatus(t, handler, http.MethodPost, "/api/servers", map[string]any{
		"name":     "rollback-ssh",
		"host":     "127.0.0.1",
		"os":       "linux",
		"ssh_port": 22,
	}, adminCookie, http.StatusCreated)
	var linux model.Server
	decodeResponse(t, linuxRec, &linux)
	sshCredRec := assertStatus(t, handler, http.MethodPost, "/api/credentials", map[string]any{
		"name":      "rollback-ssh-root",
		"server_id": linux.ID,
		"type":      "ssh_password",
		"username":  "root",
		"password":  "secret",
	}, adminCookie, http.StatusCreated)
	var sshCred model.CredentialPublic
	decodeResponse(t, sshCredRec, &sshCred)

	removeLegacySSHLogBlocker := blockOperationLogName(t, srv.cfg.Store, "connection.ssh.create")
	legacySSHRec := assertStatus(t, handler, http.MethodPost, "/api/connections/ssh", map[string]any{
		"server_id":     linux.ID,
		"credential_id": sshCred.ID,
	}, adminCookie, http.StatusInternalServerError)
	removeLegacySSHLogBlocker()
	if !strings.Contains(legacySSHRec.Body.String(), "persist operation log failed") {
		t.Fatalf("legacy ssh create operation log failure was not reported: %s", legacySSHRec.Body.String())
	}
	if connectionSessionsForTarget(t, srv, linux.ID) != 0 || platformItemsForTarget(t, srv, "online_sessions", linux.ID) != 0 {
		t.Fatal("legacy ssh create left a session after operation log failure")
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "operation.log.persist_failed") {
		t.Fatal("legacy ssh create operation log failure was not audited")
	}
	goodSSHRec := assertStatus(t, handler, http.MethodPost, "/api/connections/ssh", map[string]any{
		"server_id":     linux.ID,
		"credential_id": sshCred.ID,
	}, adminCookie, http.StatusCreated)
	var goodSSH model.ConnectionSession
	decodeResponse(t, goodSSHRec, &goodSSH)
	removeSSHOpenLogBlocker := blockOperationLogName(t, srv.cfg.Store, "connection.ssh.open")
	sshOpenRec := assertStatus(t, handler, http.MethodGet, "/api/connections/ssh/"+goodSSH.ID+"/ws?term=xterm&cols=100&rows=30", nil, adminCookie, http.StatusInternalServerError)
	removeSSHOpenLogBlocker()
	if !strings.Contains(sshOpenRec.Body.String(), "persist operation log failed") {
		t.Fatalf("ssh websocket open operation log failure was not reported: %s", sshOpenRec.Body.String())
	}
	if _, ok := srv.cfg.Store.GetSession(goodSSH.ID); !ok {
		t.Fatal("ssh websocket open operation log failure removed the session")
	}

	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "connection-create-rollback-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)
	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username": "connection-create-rollback-user",
		"password": "password123",
	}, nil, http.StatusOK)
	userCookie := loginRec.Result().Cookies()[0]

	vncAssetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "rollback-vnc",
		"type":     "linux-desktop",
		"status":   "active",
		"protocol": "vnc",
		"host":     "127.0.0.1",
		"port":     5901,
	}, adminCookie, http.StatusCreated)
	var vncAsset model.PlatformItem
	decodeResponse(t, vncAssetRec, &vncAsset)
	assertStatus(t, handler, http.MethodPost, "/api/admin/credentials", map[string]any{
		"name":      "rollback-vnc-password",
		"type":      "vnc_password",
		"status":    "encrypted",
		"username":  "operator",
		"password":  "secret-vnc",
		"target_id": vncAsset.ID,
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/assets", map[string]any{
		"name":      "rollback-user vnc",
		"owner_id":  user.ID,
		"target_id": vncAsset.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)

	recordingDirBefore := recordingDirCountForTest(t, srv)
	removeVNCLogBlocker := blockOperationLogName(t, srv.cfg.Store, "connection.vnc.create")
	vncRec := assertStatus(t, handler, http.MethodPost, "/api/access/vnc/"+vncAsset.ID, map[string]any{
		"recording_enabled": true,
	}, userCookie, http.StatusInternalServerError)
	removeVNCLogBlocker()
	if !strings.Contains(vncRec.Body.String(), "persist operation log failed") {
		t.Fatalf("vnc create operation log failure was not reported: %s", vncRec.Body.String())
	}
	if connectionSessionsForTarget(t, srv, vncAsset.ID) != 0 || platformItemsForTarget(t, srv, "online_sessions", vncAsset.ID) != 0 {
		t.Fatal("vnc create left a session after operation log failure")
	}
	if got := recordingDirCountForTest(t, srv); got != recordingDirBefore {
		t.Fatalf("vnc create left recording directories after operation log failure: got %d want %d", got, recordingDirBefore)
	}
	goodVNCRec := assertStatus(t, handler, http.MethodPost, "/api/access/vnc/"+vncAsset.ID, nil, userCookie, http.StatusAccepted)
	var goodVNC model.ConnectionSession
	decodeResponse(t, goodVNCRec, &goodVNC)
	removeVNCOpenLogBlocker := blockOperationLogName(t, srv.cfg.Store, "connection.vnc.open")
	vncOpenRec := assertStatus(t, handler, http.MethodGet, "/api/connections/vnc/"+goodVNC.ID+"/tunnel?width=1024&height=768&dpi=96", nil, userCookie, http.StatusInternalServerError)
	removeVNCOpenLogBlocker()
	if !strings.Contains(vncOpenRec.Body.String(), "persist operation log failed") {
		t.Fatalf("vnc tunnel open operation log failure was not reported: %s", vncOpenRec.Body.String())
	}
	if _, ok := srv.cfg.Store.GetSession(goodVNC.ID); !ok {
		t.Fatal("vnc tunnel open operation log failure removed the session")
	}

	webAssetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/websites", map[string]any{
		"name":     "rollback-web",
		"type":     "http",
		"status":   "active",
		"protocol": "http",
		"host":     "http://127.0.0.1:8080",
	}, adminCookie, http.StatusCreated)
	var webAsset model.PlatformItem
	decodeResponse(t, webAssetRec, &webAsset)
	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/websites", map[string]any{
		"name":      "rollback-user web",
		"owner_id":  user.ID,
		"target_id": webAsset.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)

	removeWebLogBlocker := blockOperationLogName(t, srv.cfg.Store, "access.http.create")
	webRec := assertStatus(t, handler, http.MethodPost, "/api/access/http/"+webAsset.ID, nil, userCookie, http.StatusInternalServerError)
	removeWebLogBlocker()
	if !strings.Contains(webRec.Body.String(), "persist operation log failed") {
		t.Fatalf("web access create operation log failure was not reported: %s", webRec.Body.String())
	}
	if platformItemsForTarget(t, srv, "online_sessions", webAsset.ID) != 0 {
		t.Fatal("web access create left an online session after operation log failure")
	}
}

func TestPlatformConnectionsRejectDisabledAssetsAndCredentialsAtOpen(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)

	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "connection-toggle-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)

	sshAssetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "toggle-ssh",
		"type":     "linux",
		"status":   "active",
		"protocol": "ssh",
		"host":     "127.0.0.1",
		"port":     22,
	}, adminCookie, http.StatusCreated)
	var sshAsset model.PlatformItem
	decodeResponse(t, sshAssetRec, &sshAsset)
	sshCredentialRec := assertStatus(t, handler, http.MethodPost, "/api/admin/credentials", map[string]any{
		"name":      "toggle-ssh-root",
		"type":      "ssh_password",
		"status":    "encrypted",
		"username":  "root",
		"password":  "secret",
		"target_id": sshAsset.ID,
	}, adminCookie, http.StatusCreated)
	var sshCredential model.PlatformItem
	decodeResponse(t, sshCredentialRec, &sshCredential)
	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/assets", map[string]any{
		"name":      "connection-toggle-user ssh",
		"owner_id":  user.ID,
		"target_id": sshAsset.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)
	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username": "connection-toggle-user",
		"password": "password123",
	}, nil, http.StatusOK)
	userCookie := loginRec.Result().Cookies()[0]
	sshSessionRec := assertStatus(t, handler, http.MethodPost, "/api/access/ssh/"+sshAsset.ID, map[string]any{
		"cols": 100,
		"rows": 30,
	}, userCookie, http.StatusAccepted)
	var sshSession model.ConnectionSession
	decodeResponse(t, sshSessionRec, &sshSession)
	sshReq := httptest.NewRequest(http.MethodGet, "/api/connections/ssh/"+sshSession.ID+"/ws", nil)
	sshReq.AddCookie(userCookie)
	_, _, _, _, ok := srv.connectionParts(httptest.NewRecorder(), sshReq, sshSession.ID, model.ProtocolSSH)
	if !ok {
		t.Fatal("expected ssh session to resolve before disabling asset")
	}
	assertStatus(t, handler, http.MethodPatch, "/api/admin/assets/"+sshAsset.ID, map[string]any{"status": "disabled"}, adminCookie, http.StatusOK)
	disabledAssetRec := httptest.NewRecorder()
	_, _, _, _, ok = srv.connectionParts(disabledAssetRec, sshReq, sshSession.ID, model.ProtocolSSH)
	if ok || disabledAssetRec.Code != http.StatusNotFound {
		t.Fatalf("disabled ssh asset resolved: ok=%v status=%d body=%s", ok, disabledAssetRec.Code, disabledAssetRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPatch, "/api/admin/assets/"+sshAsset.ID, map[string]any{"status": "active"}, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, "/api/admin/assets/"+sshAsset.ID, map[string]any{"status": "locked"}, adminCookie, http.StatusOK)
	lockedAssetRec := httptest.NewRecorder()
	_, _, _, _, ok = srv.connectionParts(lockedAssetRec, sshReq, sshSession.ID, model.ProtocolSSH)
	if ok || lockedAssetRec.Code != http.StatusNotFound {
		t.Fatalf("locked ssh asset resolved: ok=%v status=%d body=%s", ok, lockedAssetRec.Code, lockedAssetRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPatch, "/api/admin/assets/"+sshAsset.ID, map[string]any{"status": "active"}, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, "/api/admin/credentials/"+sshCredential.ID, map[string]any{"status": "disabled"}, adminCookie, http.StatusOK)
	disabledCredentialRec := httptest.NewRecorder()
	_, _, _, _, ok = srv.connectionParts(disabledCredentialRec, sshReq, sshSession.ID, model.ProtocolSSH)
	if ok || disabledCredentialRec.Code != http.StatusNotFound {
		t.Fatalf("disabled ssh credential resolved: ok=%v status=%d body=%s", ok, disabledCredentialRec.Code, disabledCredentialRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPatch, "/api/admin/credentials/"+sshCredential.ID, map[string]any{"status": "encrypted"}, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, "/api/admin/credentials/"+sshCredential.ID, map[string]any{"status": "locked"}, adminCookie, http.StatusOK)
	lockedCredentialRec := httptest.NewRecorder()
	_, _, _, _, ok = srv.connectionParts(lockedCredentialRec, sshReq, sshSession.ID, model.ProtocolSSH)
	if ok || lockedCredentialRec.Code != http.StatusNotFound {
		t.Fatalf("locked ssh credential resolved: ok=%v status=%d body=%s", ok, lockedCredentialRec.Code, lockedCredentialRec.Body.String())
	}

	vncAssetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "toggle-vnc",
		"type":     "linux-desktop",
		"status":   "enabled",
		"protocol": "vnc",
		"host":     "127.0.0.1",
		"port":     5900,
	}, adminCookie, http.StatusCreated)
	var vncAsset model.PlatformItem
	decodeResponse(t, vncAssetRec, &vncAsset)
	disabledVNCRec := assertStatus(t, handler, http.MethodPost, "/api/admin/credentials", map[string]any{
		"name":      "toggle-vnc-disabled",
		"type":      "vnc_password",
		"status":    "disabled",
		"username":  "vnc",
		"password":  "disabled-secret",
		"target_id": vncAsset.ID,
	}, adminCookie, http.StatusCreated)
	var disabledVNC model.PlatformItem
	decodeResponse(t, disabledVNCRec, &disabledVNC)
	lockedVNCRec := assertStatus(t, handler, http.MethodPost, "/api/admin/credentials", map[string]any{
		"name":      "toggle-vnc-locked",
		"type":      "vnc_password",
		"status":    "locked",
		"username":  "vnc",
		"password":  "locked-secret",
		"target_id": vncAsset.ID,
	}, adminCookie, http.StatusCreated)
	var lockedVNC model.PlatformItem
	decodeResponse(t, lockedVNCRec, &lockedVNC)
	enabledVNCRec := assertStatus(t, handler, http.MethodPost, "/api/admin/credentials", map[string]any{
		"name":      "toggle-vnc-enabled",
		"type":      "vnc_password",
		"status":    "encrypted",
		"username":  "vnc",
		"password":  "enabled-secret",
		"target_id": vncAsset.ID,
	}, adminCookie, http.StatusCreated)
	var enabledVNC model.PlatformItem
	decodeResponse(t, enabledVNCRec, &enabledVNC)
	assertStatus(t, handler, http.MethodPost, "/api/connections/vnc", map[string]any{
		"asset_id":      vncAsset.ID,
		"credential_id": disabledVNC.ID,
	}, adminCookie, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPost, "/api/connections/vnc", map[string]any{
		"asset_id":      vncAsset.ID,
		"credential_id": lockedVNC.ID,
	}, adminCookie, http.StatusBadRequest)
	vncSessionRec := assertStatus(t, handler, http.MethodPost, "/api/connections/vnc", map[string]any{
		"asset_id": vncAsset.ID,
	}, adminCookie, http.StatusCreated)
	var vncSession model.ConnectionSession
	decodeResponse(t, vncSessionRec, &vncSession)
	if vncSession.CredentialID != enabledVNC.ID {
		t.Fatalf("vnc session used credential %q, want enabled credential %q", vncSession.CredentialID, enabledVNC.ID)
	}
	vncReq := httptest.NewRequest(http.MethodGet, "/api/connections/vnc/"+vncSession.ID+"/tunnel", nil)
	vncReq.AddCookie(adminCookie)
	if _, ok := srv.desktopTunnelConfig(httptest.NewRecorder(), vncReq, vncSession.ID, model.ProtocolVNC); !ok {
		t.Fatal("expected vnc session to resolve before disabling asset")
	}
	assertStatus(t, handler, http.MethodPatch, "/api/admin/assets/"+vncAsset.ID, map[string]any{"status": "disabled"}, adminCookie, http.StatusOK)
	disabledVNCAssetRec := httptest.NewRecorder()
	if _, ok := srv.desktopTunnelConfig(disabledVNCAssetRec, vncReq, vncSession.ID, model.ProtocolVNC); ok || disabledVNCAssetRec.Code != http.StatusNotFound {
		t.Fatalf("disabled vnc asset resolved: ok=%v status=%d body=%s", ok, disabledVNCAssetRec.Code, disabledVNCAssetRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPatch, "/api/admin/assets/"+vncAsset.ID, map[string]any{"status": "enabled"}, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, "/api/admin/assets/"+vncAsset.ID, map[string]any{"status": "locked"}, adminCookie, http.StatusOK)
	lockedVNCAssetRec := httptest.NewRecorder()
	if _, ok := srv.desktopTunnelConfig(lockedVNCAssetRec, vncReq, vncSession.ID, model.ProtocolVNC); ok || lockedVNCAssetRec.Code != http.StatusNotFound {
		t.Fatalf("locked vnc asset resolved: ok=%v status=%d body=%s", ok, lockedVNCAssetRec.Code, lockedVNCAssetRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPatch, "/api/admin/assets/"+vncAsset.ID, map[string]any{"status": "enabled"}, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, "/api/admin/credentials/"+enabledVNC.ID, map[string]any{"status": "disabled"}, adminCookie, http.StatusOK)
	disabledVNCCredentialRec := httptest.NewRecorder()
	if _, ok := srv.desktopTunnelConfig(disabledVNCCredentialRec, vncReq, vncSession.ID, model.ProtocolVNC); ok || disabledVNCCredentialRec.Code != http.StatusNotFound {
		t.Fatalf("disabled vnc credential resolved: ok=%v status=%d body=%s", ok, disabledVNCCredentialRec.Code, disabledVNCCredentialRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPatch, "/api/admin/credentials/"+enabledVNC.ID, map[string]any{"status": "encrypted"}, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, "/api/admin/credentials/"+enabledVNC.ID, map[string]any{"status": "locked"}, adminCookie, http.StatusOK)
	lockedVNCCredentialRec := httptest.NewRecorder()
	if _, ok := srv.desktopTunnelConfig(lockedVNCCredentialRec, vncReq, vncSession.ID, model.ProtocolVNC); ok || lockedVNCCredentialRec.Code != http.StatusNotFound {
		t.Fatalf("locked vnc credential resolved: ok=%v status=%d body=%s", ok, lockedVNCCredentialRec.Code, lockedVNCCredentialRec.Body.String())
	}

	databaseCredentialRec := assertStatus(t, handler, http.MethodPost, "/api/admin/credentials", map[string]any{
		"name":     "toggle-db-disabled",
		"type":     "database_password",
		"status":   "disabled",
		"username": "db",
		"password": "db-secret",
	}, adminCookie, http.StatusCreated)
	var databaseCredential model.PlatformItem
	decodeResponse(t, databaseCredentialRec, &databaseCredential)
	databaseAssetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/database-assets", map[string]any{
		"name":     "toggle-db",
		"type":     "sqlite",
		"status":   "enabled",
		"protocol": "database",
		"metadata": map[string]any{"sqlite_path": "toggle-disabled-credential.db", "credential_id": databaseCredential.ID},
	}, adminCookie, http.StatusCreated)
	var databaseAsset model.PlatformItem
	decodeResponse(t, databaseAssetRec, &databaseAsset)
	dbRec := assertStatus(t, handler, http.MethodPost, "/api/access/database/"+databaseAsset.ID+"/query", map[string]any{
		"sql": "SELECT 1",
	}, adminCookie, http.StatusBadRequest)
	if !strings.Contains(dbRec.Body.String(), "is disabled") {
		t.Fatalf("disabled database credential response did not explain state: %s", dbRec.Body.String())
	}
	lockedDatabaseCredentialRec := assertStatus(t, handler, http.MethodPost, "/api/admin/credentials", map[string]any{
		"name":     "toggle-db-locked",
		"type":     "database_password",
		"status":   "locked",
		"username": "db",
		"password": "db-secret",
	}, adminCookie, http.StatusCreated)
	var lockedDatabaseCredential model.PlatformItem
	decodeResponse(t, lockedDatabaseCredentialRec, &lockedDatabaseCredential)
	lockedDatabaseAssetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/database-assets", map[string]any{
		"name":     "toggle-db-locked",
		"type":     "sqlite",
		"status":   "enabled",
		"protocol": "database",
		"metadata": map[string]any{"sqlite_path": "toggle-locked-credential.db", "credential_id": lockedDatabaseCredential.ID},
	}, adminCookie, http.StatusCreated)
	var lockedDatabaseAsset model.PlatformItem
	decodeResponse(t, lockedDatabaseAssetRec, &lockedDatabaseAsset)
	lockedDBRec := assertStatus(t, handler, http.MethodPost, "/api/access/database/"+lockedDatabaseAsset.ID+"/query", map[string]any{
		"sql": "SELECT 1",
	}, adminCookie, http.StatusBadRequest)
	if !strings.Contains(lockedDBRec.Body.String(), "is disabled") {
		t.Fatalf("locked database credential response did not explain state: %s", lockedDBRec.Body.String())
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

func TestAccessPortalDesktopRecordingUsesPolicyDefault(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	assetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "portal-rdp-recording-policy",
		"type":     "windows",
		"status":   "enabled",
		"protocol": "rdp",
		"host":     "127.0.0.1",
		"port":     3389,
	}, adminCookie, http.StatusCreated)
	var asset model.PlatformItem
	decodeResponse(t, assetRec, &asset)
	credentialRec := assertStatus(t, handler, http.MethodPost, "/api/admin/credentials", map[string]any{
		"name":      "portal-rdp-recording-policy",
		"type":      "rdp_password",
		"status":    "encrypted",
		"username":  "Administrator",
		"password":  "secret",
		"target_id": asset.ID,
	}, adminCookie, http.StatusCreated)
	var credential model.PlatformItem
	decodeResponse(t, credentialRec, &credential)

	defaultRec := assertStatus(t, handler, http.MethodPost, "/api/access/rdp/"+asset.ID, map[string]any{
		"width":  1440,
		"height": 900,
		"dpi":    96,
	}, adminCookie, http.StatusAccepted)
	var defaultSession model.ConnectionSession
	decodeResponse(t, defaultRec, &defaultSession)
	if defaultSession.RecordingPath != "" {
		t.Fatalf("desktop access should not record when policy default is disabled: %#v", defaultSession)
	}

	explicitRec := assertStatus(t, handler, http.MethodPost, "/api/access/rdp/"+asset.ID, map[string]any{
		"credential_id":     credential.ID,
		"width":             1440,
		"height":            900,
		"dpi":               96,
		"recording_enabled": true,
	}, adminCookie, http.StatusAccepted)
	var explicitSession model.ConnectionSession
	decodeResponse(t, explicitRec, &explicitSession)
	if explicitSession.RecordingPath == "" {
		t.Fatal("explicit desktop recording request did not create recording path")
	}
	if _, err := os.Stat(explicitSession.RecordingPath); err != nil {
		t.Fatalf("explicit recording directory missing: %v", err)
	}
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

func TestAccessAuthorizationSupportsWebAndDatabaseAssetGroups(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app/health" {
			t.Fatalf("upstream path = %q, want /app/health", r.URL.Path)
		}
		_, _ = w.Write([]byte("group web ok"))
	}))
	defer upstream.Close()

	handler, adminCookie := newTestHandler(t)
	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "group-resource-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)

	parentWebGroupRec := assertStatus(t, handler, http.MethodPost, "/api/admin/asset-groups", map[string]any{
		"name":     "Web Fleet",
		"type":     "web",
		"protocol": "http",
		"status":   "enabled",
	}, adminCookie, http.StatusCreated)
	var parentWebGroup model.PlatformItem
	decodeResponse(t, parentWebGroupRec, &parentWebGroup)
	childWebGroupRec := assertStatus(t, handler, http.MethodPost, "/api/admin/asset-groups", map[string]any{
		"name":      "Production Web",
		"type":      "web",
		"protocol":  "http",
		"status":    "enabled",
		"parent_id": parentWebGroup.ID,
	}, adminCookie, http.StatusCreated)
	var childWebGroup model.PlatformItem
	decodeResponse(t, childWebGroupRec, &childWebGroup)
	parentDBGroupRec := assertStatus(t, handler, http.MethodPost, "/api/admin/asset-groups", map[string]any{
		"name":     "Database Fleet",
		"type":     "database",
		"protocol": "database",
		"status":   "enabled",
	}, adminCookie, http.StatusCreated)
	var parentDBGroup model.PlatformItem
	decodeResponse(t, parentDBGroupRec, &parentDBGroup)
	childDBGroupRec := assertStatus(t, handler, http.MethodPost, "/api/admin/asset-groups", map[string]any{
		"name":      "Production Database",
		"type":      "database",
		"protocol":  "database",
		"status":    "enabled",
		"parent_id": parentDBGroup.ID,
	}, adminCookie, http.StatusCreated)
	var childDBGroup model.PlatformItem
	decodeResponse(t, childDBGroupRec, &childDBGroup)

	webRec := assertStatus(t, handler, http.MethodPost, "/api/admin/websites", map[string]any{
		"name":     "group-web",
		"type":     "http",
		"status":   "enabled",
		"protocol": "http",
		"group":    childWebGroup.ID,
		"metadata": map[string]any{"target_url": upstream.URL + "/app"},
	}, adminCookie, http.StatusCreated)
	var webAsset model.PlatformItem
	decodeResponse(t, webRec, &webAsset)
	dbRec := assertStatus(t, handler, http.MethodPost, "/api/admin/database-assets", map[string]any{
		"name":     "group-db",
		"type":     "sqlite",
		"status":   "enabled",
		"protocol": "database",
		"group":    childDBGroup.ID,
		"metadata": map[string]any{"sqlite_path": "group-auth.db", "row_limit": 10},
	}, adminCookie, http.StatusCreated)
	var databaseAsset model.PlatformItem
	decodeResponse(t, dbRec, &databaseAsset)

	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "group-resource-user", "password": "password123"}, nil, http.StatusOK)
	userCookie := loginRec.Result().Cookies()[0]
	assertStatus(t, handler, http.MethodGet, "/api/access/http/"+webAsset.ID+"/proxy/health", nil, userCookie, http.StatusForbidden)
	assertStatus(t, handler, http.MethodPost, "/api/access/database/"+databaseAsset.ID+"/query", map[string]any{"sql": "SELECT 7 AS grouped_answer"}, userCookie, http.StatusForbidden)

	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/websites", map[string]any{
		"name":      "web group grant",
		"owner_id":  user.ID,
		"target_id": parentWebGroup.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/databases", map[string]any{
		"name":      "database group grant",
		"owner_id":  user.ID,
		"target_id": parentDBGroup.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)

	accessRec := assertStatus(t, handler, http.MethodGet, "/api/access/assets", nil, userCookie, http.StatusOK)
	accessBody := accessRec.Body.String()
	if !strings.Contains(accessBody, webAsset.ID) || !strings.Contains(accessBody, databaseAsset.ID) {
		t.Fatalf("group authorization did not expose web/database assets: %s", accessBody)
	}
	proxyRec := assertStatus(t, handler, http.MethodGet, "/api/access/http/"+webAsset.ID+"/proxy/health", nil, userCookie, http.StatusOK)
	if proxyRec.Body.String() != "group web ok" {
		t.Fatalf("group-authorized web proxy body = %q", proxyRec.Body.String())
	}
	queryRec := assertStatus(t, handler, http.MethodPost, "/api/access/database/"+databaseAsset.ID+"/query", map[string]any{"sql": "SELECT 7 AS grouped_answer"}, userCookie, http.StatusOK)
	if !strings.Contains(queryRec.Body.String(), "grouped_answer") || !strings.Contains(queryRec.Body.String(), "7") {
		t.Fatalf("group-authorized database query response = %s", queryRec.Body.String())
	}
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

	invalidSingleRec := assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/assets", map[string]any{
		"name":      "invalid expiry direct grant",
		"status":    "enabled",
		"owner_id":  user.ID,
		"target_id": asset.ID,
		"metadata":  map[string]any{"expires_at": "not-a-date"},
	}, adminCookie, http.StatusBadRequest)
	if !strings.Contains(invalidSingleRec.Body.String(), "expires_at") {
		t.Fatalf("invalid direct authorization expiry did not identify field: %s", invalidSingleRec.Body.String())
	}
	invalidBulkRec := assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/assets/bulk", map[string]any{
		"subject_ids": []string{user.ID},
		"target_ids":  []string{asset.ID},
		"expires_at":  "not-a-date",
	}, adminCookie, http.StatusBadRequest)
	if !strings.Contains(invalidBulkRec.Body.String(), "expires_at") {
		t.Fatalf("invalid bulk authorization expiry did not identify field: %s", invalidBulkRec.Body.String())
	}

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
	partialBulkAssetARec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "partial-bulk-a",
		"type":     "linux",
		"status":   "active",
		"protocol": "ssh",
		"host":     "10.20.0.21",
		"port":     22,
	}, adminCookie, http.StatusCreated)
	var partialBulkAssetA model.PlatformItem
	decodeResponse(t, partialBulkAssetARec, &partialBulkAssetA)
	partialBulkAssetBRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "partial-bulk-b",
		"type":     "linux",
		"status":   "active",
		"protocol": "ssh",
		"host":     "10.20.0.22",
		"port":     22,
	}, adminCookie, http.StatusCreated)
	var partialBulkAssetB model.PlatformItem
	decodeResponse(t, partialBulkAssetBRec, &partialBulkAssetB)
	removePartialBulkBlocker := blockPlatformCollectionSavePayloadFragment(t, handler.(*Server).cfg.Store, "authorized_assets", `"target_id":"`+partialBulkAssetB.ID+`"`)
	partialBulkFailureRec := assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/assets/bulk", map[string]any{
		"subject_ids": []string{user.ID},
		"target_ids":  []string{partialBulkAssetA.ID, partialBulkAssetB.ID},
	}, adminCookie, http.StatusInternalServerError)
	removePartialBulkBlocker()
	if !strings.Contains(partialBulkFailureRec.Body.String(), "forced platform collection payload save failure") {
		t.Fatalf("partial bulk authorization failure was not reported: %s", partialBulkFailureRec.Body.String())
	}
	partialBulkAccessRec := assertStatus(t, handler, http.MethodGet, "/api/access/assets", nil, userCookie, http.StatusOK)
	if strings.Contains(partialBulkAccessRec.Body.String(), partialBulkAssetA.ID) || strings.Contains(partialBulkAccessRec.Body.String(), partialBulkAssetB.ID) {
		t.Fatalf("partial bulk authorization left unaudited access: %s", partialBulkAccessRec.Body.String())
	}
	accessRec := assertStatus(t, handler, http.MethodGet, "/api/access/assets", nil, userCookie, http.StatusOK)
	accessBody := accessRec.Body.String()
	var accessPayload struct {
		Authorized               []model.PlatformItem `json:"authorized"`
		AuthorizedAssets         []model.PlatformItem `json:"authorized_assets"`
		AuthorizedWebAssets      []model.PlatformItem `json:"authorized_web_assets"`
		AuthorizedDatabaseAssets []model.PlatformItem `json:"authorized_database_assets"`
	}
	decodeResponse(t, accessRec, &accessPayload)
	hasGrant := func(items []model.PlatformItem, targetID string) bool {
		for _, item := range items {
			if item.TargetID == targetID {
				return true
			}
		}
		return false
	}
	for _, want := range []string{asset.ID, webAsset.ID, databaseAsset.ID} {
		if !strings.Contains(accessBody, want) {
			t.Fatalf("bulk authorization did not expose %s in access portal: %s", want, accessBody)
		}
	}
	if strings.Contains(accessBody, expiredAsset.ID) {
		t.Fatalf("expired bulk authorization exposed asset: %s", accessBody)
	}
	if !hasGrant(accessPayload.AuthorizedAssets, asset.ID) || !hasGrant(accessPayload.AuthorizedWebAssets, webAsset.ID) || !hasGrant(accessPayload.AuthorizedDatabaseAssets, databaseAsset.ID) {
		t.Fatalf("access portal did not return typed authorization records: %#v", accessPayload)
	}
	for _, targetID := range []string{asset.ID, webAsset.ID, databaseAsset.ID} {
		if !hasGrant(accessPayload.Authorized, targetID) {
			t.Fatalf("access portal compatible authorized list missing target %s: %#v", targetID, accessPayload.Authorized)
		}
	}
	if hasGrant(accessPayload.Authorized, expiredAsset.ID) || hasGrant(accessPayload.AuthorizedAssets, expiredAsset.ID) {
		t.Fatalf("access portal returned expired authorization record: %#v", accessPayload)
	}
	removeBulkAuthBlocker := blockOperationLogName(t, handler.(*Server).cfg.Store, "authorized_assets.bulk_create")
	blockedRenewRec := assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/assets/bulk", map[string]any{
		"subject_ids": []string{user.ID},
		"target_ids":  []string{expiredAsset.ID},
		"expires_at":  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}, adminCookie, http.StatusInternalServerError)
	removeBulkAuthBlocker()
	if !strings.Contains(blockedRenewRec.Body.String(), "persist operation log failed") {
		t.Fatalf("bulk authorization operation log failure was not reported: %s", blockedRenewRec.Body.String())
	}
	blockedRenewAccessRec := assertStatus(t, handler, http.MethodGet, "/api/access/assets", nil, userCookie, http.StatusOK)
	if strings.Contains(blockedRenewAccessRec.Body.String(), expiredAsset.ID) {
		t.Fatalf("bulk authorization update survived operation log failure: %s", blockedRenewAccessRec.Body.String())
	}
	renewRec := assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/assets/bulk", map[string]any{
		"subject_ids": []string{user.ID},
		"target_ids":  []string{expiredAsset.ID},
		"expires_at":  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}, adminCookie, http.StatusCreated)
	if !strings.Contains(renewRec.Body.String(), `"updated":1`) || !strings.Contains(renewRec.Body.String(), `"created":0`) {
		t.Fatalf("expired bulk authorization was not renewed: %s", renewRec.Body.String())
	}
	renewedAccessRec := assertStatus(t, handler, http.MethodGet, "/api/access/assets", nil, userCookie, http.StatusOK)
	if !strings.Contains(renewedAccessRec.Body.String(), expiredAsset.ID) {
		t.Fatalf("renewed bulk authorization did not expose asset: %s", renewedAccessRec.Body.String())
	}
	authorizationsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/authorizations/assets", nil, adminCookie, http.StatusOK)
	var authorizationsList struct {
		Items []model.PlatformItem `json:"items"`
	}
	decodeResponse(t, authorizationsRec, &authorizationsList)
	expiredGrantCount := 0
	for _, item := range authorizationsList.Items {
		if item.OwnerID == user.ID && item.TargetID == expiredAsset.ID {
			expiredGrantCount++
			if !authorizationRecordActive(item) {
				t.Fatalf("renewed authorization should be active: %#v", item)
			}
		}
	}
	if expiredGrantCount != 1 {
		t.Fatalf("renewed bulk authorization should update existing grant, got %d records", expiredGrantCount)
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
	userAccessRec := assertStatus(t, handler, http.MethodGet, "/api/access/command-snippets", nil, userCookie, http.StatusOK)
	userAccessBody := userAccessRec.Body.String()
	if !strings.Contains(userAccessBody, publicSnippet.ID) || !strings.Contains(userAccessBody, ownedSnippet.ID) {
		t.Fatalf("user access snippets did not include public and owned snippets: %s", userAccessBody)
	}
	if strings.Contains(userAccessBody, otherSnippet.ID) || strings.Contains(userAccessBody, disabledSnippet.ID) {
		t.Fatalf("user access snippets leaked private or disabled snippets: %s", userAccessBody)
	}
	adminAccessRec := assertStatus(t, handler, http.MethodGet, "/api/access/command-snippets", nil, adminCookie, http.StatusOK)
	adminAccessBody := adminAccessRec.Body.String()
	for _, want := range []string{publicSnippet.ID, ownedSnippet.ID, otherSnippet.ID} {
		if !strings.Contains(adminAccessBody, want) {
			t.Fatalf("admin access snippets missing %s: %s", want, adminAccessBody)
		}
	}
	if strings.Contains(adminAccessBody, disabledSnippet.ID) {
		t.Fatalf("admin access snippets leaked disabled snippet: %s", adminAccessBody)
	}
}

func TestWebAssetProxyRequiresAuthorizationAndLogs(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-OpenWebServerManager-User") == "" || r.Header.Get("X-OpenWebServerManager-Asset") == "" {
			t.Fatal("upstream did not receive proxy identity headers")
		}
		username, password, ok := r.BasicAuth()
		switch r.URL.Path {
		case "/root/newauth":
			if !ok || username != "proxy-user-2" || password != "proxy-secret-2" {
				t.Fatalf("upstream basic auth = %q/%q ok=%v, want proxy-user-2/proxy-secret-2", username, password, ok)
			}
		case "/root/noauth":
			if ok || username != "" || password != "" {
				t.Fatalf("upstream basic auth = %q/%q ok=%v, want no upstream credentials", username, password, ok)
			}
		default:
			if !ok || username != "proxy-user" || password != "proxy-secret" {
				t.Fatalf("upstream basic auth = %q/%q ok=%v, want proxy-user/proxy-secret", username, password, ok)
			}
		}
		if _, err := r.Cookie(authCookieName); err == nil {
			t.Fatal("upstream received internal auth cookie")
		}
		if r.URL.Query().Get("from") != "asset" {
			t.Fatalf("upstream query missing base query: %q", r.URL.RawQuery)
		}
		switch r.URL.Path {
		case "/root/hello":
			if r.URL.Query().Get("x") != "1" {
				t.Fatalf("upstream hello query = %q, want x=1", r.URL.RawQuery)
			}
			if cookie, err := r.Cookie("upstream_theme"); err != nil || cookie.Value != "dark" {
				t.Fatalf("upstream cookie = %v/%v, want upstream_theme=dark", cookie, err)
			}
			if r.Header.Get("X-Remove-Me") != "" {
				t.Fatal("hop-by-hop header leaked to upstream")
			}
			if r.Header.Get("X-Forwarded-Prefix") == "" || !strings.Contains(r.Header.Get("X-Forwarded-Uri"), "/proxy/hello") {
				t.Fatalf("forwarded headers missing proxy context: prefix=%q uri=%q", r.Header.Get("X-Forwarded-Prefix"), r.Header.Get("X-Forwarded-Uri"))
			}
			w.Header().Set("X-Upstream", "ok")
			_, _ = w.Write([]byte("proxied ok"))
		case "/root/page":
			if r.Header.Get("Accept-Encoding") != "identity" {
				t.Fatalf("upstream compressed response control = %q, want identity", r.Header.Get("Accept-Encoding"))
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			body := `<html><head>` +
				`<meta http-equiv="refresh" content="0; url=/root/refresh-login">` +
				`<script src="/static/app.js"></script>` +
				`<style>@import "/root/styles/theme.css";.hero{background:url('/root/assets/bg.png')}.external{background:url("https://cdn.example.test/bg.png")}</style>` +
				`<script type="module">` +
				`import boot from "/root/modules/boot.js";` +
				`import "/root/modules/side-effect.js";` +
				`export { boot as default } from "http://` + r.Host + `/root/modules/export.js";` +
				`const lazy = import('/root/modules/lazy.js');` +
				`fetch("/root/api/data?x=1");` +
				`new EventSource('/root/events');` +
				`new WebSocket('ws://` + r.Host + `/root/socket');` +
				`new Worker("/root/worker.js");` +
				`navigator.sendBeacon('/root/beacon');` +
				`window.open('/root/popout');` +
				`location.assign("/root/next");` +
				`fetch("https://cdn.example.test/api");` +
				`</script>` +
				`</head><body>` +
				`<img srcset="/root/img-small.png 480w, http://` + r.Host + `/root/img-large.png 960w, https://cdn.example.test/img.png 2x, data:image/png;base64,abc 1x">` +
				`<a href="/root/dashboard?tab=1">Dashboard</a>` +
				`<a href="http://` + r.Host + `/root/reports">Reports</a>` +
				`<a href="mailto:ops@example.test">Mail</a>` +
				`<form action="http://` + r.Host + `/root/login?next=/root/dashboard"></form>` +
				`</body></html>`
			_, _ = w.Write([]byte(body))
		case "/root/redirect":
			http.SetCookie(w, &http.Cookie{Name: "upstream_session", Value: "abc", Domain: "upstream.internal", Path: "/root", HttpOnly: true})
			http.SetCookie(w, &http.Cookie{Name: authCookieName, Value: "upstream", Domain: "upstream.internal", Path: "/", HttpOnly: true})
			http.Redirect(w, r, "/root/dashboard?tab=1", http.StatusFound)
		case "/root/fail":
			if r.URL.Query().Get("x") != "2" {
				t.Fatalf("upstream fail query = %q, want x=2", r.URL.RawQuery)
			}
			http.Error(w, "upstream failed", http.StatusInternalServerError)
		case "/root/newauth":
			_, _ = w.Write([]byte("new credentials ok"))
		case "/root/noauth":
			_, _ = w.Write([]byte("cleared credentials ok"))
		default:
			t.Fatalf("upstream path = %q, want /root/hello, /root/page, /root/redirect, /root/fail, /root/newauth or /root/noauth", r.URL.Path)
		}
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}
	upstreamTarget := *upstreamURL
	upstreamTarget.User = url.UserPassword("proxy-user", "proxy-secret")
	upstreamTarget.Path = "/root"
	upstreamTarget.RawQuery = "from=asset"

	handler, adminCookie := newTestHandler(t)
	server := handler.(*Server)
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
		"metadata": map[string]any{"target_url": upstreamTarget.String()},
	}, adminCookie, http.StatusCreated)
	webCreateBody := webRec.Body.String()
	if strings.Contains(webCreateBody, "proxy-user") || strings.Contains(webCreateBody, "proxy-secret") || !strings.Contains(webCreateBody, "target_url_credentials_set") {
		t.Fatalf("web asset create response did not redact upstream credentials: %s", webCreateBody)
	}
	var webAsset model.PlatformItem
	decodeResponse(t, webRec, &webAsset)
	if targetURL := firstMetadataString(webAsset.Metadata, "target_url"); strings.Contains(targetURL, "@") || strings.Contains(targetURL, "proxy-user") || strings.Contains(targetURL, "proxy-secret") {
		t.Fatalf("web asset create payload retained upstream userinfo: %#v", webAsset.Metadata)
	}
	rawWebAsset, ok, err := server.cfg.Store.GetPlatformItem("web_assets", webAsset.ID)
	if err != nil || !ok {
		t.Fatalf("load raw web asset: ok=%v err=%v", ok, err)
	}
	if rawTargetURL := firstMetadataString(rawWebAsset.Metadata, "target_url"); strings.Contains(rawTargetURL, "@") || strings.Contains(rawTargetURL, "proxy-user") || strings.Contains(rawTargetURL, "proxy-secret") {
		t.Fatalf("raw web asset retained plaintext upstream credentials: %#v", rawWebAsset.Metadata)
	}
	encryptedUpstream := firstMetadataString(rawWebAsset.Metadata, "web_upstream_url_encrypted")
	if encryptedUpstream == "" {
		t.Fatalf("raw web asset did not store encrypted upstream credentials: %#v", rawWebAsset.Metadata)
	}
	decryptedUpstream, err := server.cfg.Store.DecryptPlatformSecret(encryptedUpstream)
	if err != nil {
		t.Fatalf("decrypt web asset upstream: %v", err)
	}
	if decryptedUpstream != upstreamTarget.String() {
		t.Fatalf("decrypted web upstream = %q, want %q", decryptedUpstream, upstreamTarget.String())
	}
	patchRec := assertStatus(t, handler, http.MethodPatch, "/api/admin/websites/"+webAsset.ID, map[string]any{
		"metadata": map[string]any{
			"target_url": firstMetadataString(webAsset.Metadata, "target_url"),
			"display":    "patched without resubmitting credentials",
		},
	}, adminCookie, http.StatusOK)
	patchBody := patchRec.Body.String()
	for _, leaked := range []string{"proxy-user", "proxy-secret", "web_upstream_url_encrypted"} {
		if strings.Contains(patchBody, leaked) {
			t.Fatalf("web asset patch response leaked %q: %s", leaked, patchBody)
		}
	}
	rawWebAsset, ok, err = server.cfg.Store.GetPlatformItem("web_assets", webAsset.ID)
	if err != nil || !ok {
		t.Fatalf("reload raw web asset after patch: ok=%v err=%v", ok, err)
	}
	if firstMetadataString(rawWebAsset.Metadata, "web_upstream_url_encrypted") == "" {
		t.Fatalf("web asset patch with unchanged redacted URL dropped encrypted upstream credentials: %#v", rawWebAsset.Metadata)
	}
	preservedEncryptedUpstream := firstMetadataString(rawWebAsset.Metadata, "web_upstream_url_encrypted")
	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "web-user", "password": "password123"}, nil, http.StatusOK)
	userCookie := loginRec.Result().Cookies()[0]

	assertStatus(t, handler, http.MethodGet, "/api/access/http/"+webAsset.ID+"/proxy/hello?x=1", nil, userCookie, http.StatusForbidden)
	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/websites", map[string]any{
		"name":      "web-user internal app",
		"owner_id":  user.ID,
		"target_id": webAsset.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)
	for _, rec := range []*httptest.ResponseRecorder{
		assertStatus(t, handler, http.MethodGet, "/api/admin/websites", nil, adminCookie, http.StatusOK),
		assertStatus(t, handler, http.MethodGet, "/api/admin/websites/"+webAsset.ID, nil, adminCookie, http.StatusOK),
		assertStatus(t, handler, http.MethodGet, "/api/access/assets", nil, userCookie, http.StatusOK),
	} {
		body := rec.Body.String()
		if strings.Contains(body, "proxy-user") || strings.Contains(body, "proxy-secret") || strings.Contains(body, "proxy-user:proxy-secret") {
			t.Fatalf("web asset API leaked upstream credentials: %s", body)
		}
	}
	proxyRec := assertStatusWithHeaders(t, handler, http.MethodGet, "/api/access/http/"+webAsset.ID+"/proxy/hello?x=1", nil, userCookie, map[string]string{
		"Connection":  "X-Remove-Me",
		"Cookie":      authCookieName + "=invalid; upstream_theme=dark",
		"Referer":     "https://docs.example.test/start",
		"User-Agent":  "openwebservermanager-test",
		"X-Remove-Me": "secret",
	}, http.StatusOK)
	if proxyRec.Body.String() != "proxied ok" || proxyRec.Header().Get("X-Upstream") != "ok" {
		t.Fatalf("proxy response body/header = %q/%q", proxyRec.Body.String(), proxyRec.Header().Get("X-Upstream"))
	}
	pageRec := assertStatusWithHeaders(t, handler, http.MethodGet, "/api/access/http/"+webAsset.ID+"/proxy/page", nil, userCookie, map[string]string{
		"Accept-Encoding": "gzip",
		"User-Agent":      "openwebservermanager-test",
	}, http.StatusOK)
	pageBody := pageRec.Body.String()
	proxyBase := "/api/access/http/" + webAsset.ID + "/proxy"
	for _, want := range []string{
		`src="` + proxyBase + `/static/app.js"`,
		`href="` + proxyBase + `/dashboard?tab=1"`,
		`href="` + proxyBase + `/reports"`,
		`action="` + proxyBase + `/login?next=/root/dashboard"`,
		`@import "` + proxyBase + `/styles/theme.css"`,
		`url('` + proxyBase + `/assets/bg.png')`,
		`content="0; url=` + proxyBase + `/refresh-login"`,
		`srcset="` + proxyBase + `/img-small.png 480w, ` + proxyBase + `/img-large.png 960w, https://cdn.example.test/img.png 2x, data:image/png;base64,abc 1x"`,
		`from "` + proxyBase + `/modules/boot.js"`,
		`import "` + proxyBase + `/modules/side-effect.js"`,
		`from "` + proxyBase + `/modules/export.js"`,
		`import('` + proxyBase + `/modules/lazy.js')`,
		`fetch("` + proxyBase + `/api/data?x=1")`,
		`new EventSource('` + proxyBase + `/events')`,
		`new WebSocket('` + proxyBase + `/socket')`,
		`new Worker("` + proxyBase + `/worker.js")`,
		`navigator.sendBeacon('` + proxyBase + `/beacon')`,
		`window.open('` + proxyBase + `/popout')`,
		`location.assign("` + proxyBase + `/next")`,
		`href="mailto:ops@example.test"`,
		`url("https://cdn.example.test/bg.png")`,
		`fetch("https://cdn.example.test/api")`,
	} {
		if !strings.Contains(pageBody, want) {
			t.Fatalf("rewritten proxy page missing %q: %s", want, pageBody)
		}
	}
	for _, leaked := range []string{`href="/root/dashboard`, `src="/static/app.js"`, `url=/root/refresh-login`, `/root/img-small.png`, `@import "/root/styles/theme.css"`, `from "/root/modules`, `import "/root/modules`, `fetch("/root/api`, `EventSource('/root/events`, `WebSocket('ws://` + upstreamURL.Host + `/root/socket`, `Worker("/root/worker`, `sendBeacon('/root/beacon`, `window.open('/root/popout`, `location.assign("/root/next`, upstreamURL.Host + `/root/reports`, upstreamURL.Host + `/root/login`, upstreamURL.Host + `/root/img-large.png`, upstreamURL.Host + `/root/modules/export.js`} {
		if strings.Contains(pageBody, leaked) {
			t.Fatalf("rewritten proxy page retained upstream URL %q: %s", leaked, pageBody)
		}
	}
	redirectRec := assertStatus(t, handler, http.MethodGet, "/api/access/http/"+webAsset.ID+"/proxy/redirect", nil, userCookie, http.StatusFound)
	if got, want := redirectRec.Header().Get("Location"), "/api/access/http/"+webAsset.ID+"/proxy/dashboard?tab=1"; got != want {
		t.Fatalf("proxy redirect location = %q, want %q", got, want)
	}
	var upstreamCookie *http.Cookie
	for _, cookie := range redirectRec.Result().Cookies() {
		if cookie.Name == "upstream_session" {
			upstreamCookie = cookie
			break
		}
	}
	if upstreamCookie == nil || upstreamCookie.Path != "/api/access/http/"+webAsset.ID+"/proxy" || upstreamCookie.Domain != "" {
		t.Fatalf("rewritten upstream cookie = %#v", upstreamCookie)
	}
	for _, cookie := range redirectRec.Result().Cookies() {
		if cookie.Name == authCookieName {
			t.Fatalf("proxy forwarded reserved auth cookie from upstream: %#v", cookie)
		}
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
	var logsPayload struct {
		Items []model.PlatformItem `json:"items"`
	}
	decodeResponse(t, logsRec, &logsPayload)
	var helloLog *model.PlatformItem
	for index := range logsPayload.Items {
		if strings.Contains(firstMetadataString(logsPayload.Items[index].Metadata, "uri"), "/proxy/hello") {
			helloLog = &logsPayload.Items[index]
			break
		}
	}
	if helloLog == nil {
		t.Fatalf("access logs did not include hello request item: %s", logsBody)
	}
	if helloLog.OwnerID != user.ID || helloLog.TargetID != webAsset.ID || helloLog.Type != http.MethodGet || helloLog.Status != "200" {
		t.Fatalf("access log basic fields = %#v", helloLog)
	}
	for key, want := range map[string]string{
		"asset_id":      webAsset.ID,
		"user_id":       user.ID,
		"client_ip":     "192.0.2.1",
		"domain":        upstreamURL.Hostname(),
		"upstream_host": upstreamURL.Host,
		"method":        http.MethodGet,
		"user_agent":    "openwebservermanager-test",
		"referer":       "https://docs.example.test/start",
	} {
		if got := firstMetadataString(helloLog.Metadata, key); got != want {
			t.Fatalf("access log metadata %s = %q, want %q in %#v", key, got, want, helloLog.Metadata)
		}
	}
	for key, want := range map[string]int{
		"status_code":   http.StatusOK,
		"response_size": len("proxied ok"),
	} {
		got, ok := metadataInt(helloLog.Metadata[key])
		if !ok || got != want {
			t.Fatalf("access log metadata %s = %v/%v, want %d in %#v", key, got, ok, want, helloLog.Metadata)
		}
	}
	if _, ok := metadataInt(helloLog.Metadata["duration_ms"]); !ok {
		t.Fatalf("access log missing duration_ms: %#v", helloLog.Metadata)
	}
	upstreamLogURL := firstMetadataString(helloLog.Metadata, "upstream")
	if !strings.Contains(upstreamLogURL, upstreamURL.Host) || strings.Contains(upstreamLogURL, "proxy-user") || strings.Contains(upstreamLogURL, "proxy-secret") || strings.Contains(upstreamLogURL, "@") {
		t.Fatalf("access log upstream url was not redacted: %q", upstreamLogURL)
	}
	if strings.Contains(logsBody, "proxy-user") || strings.Contains(logsBody, "proxy-secret") {
		t.Fatalf("access logs leaked upstream userinfo: %s", logsBody)
	}
	if requestHost := firstMetadataString(helloLog.Metadata, "request_host"); requestHost == "" {
		t.Fatalf("access log missing request_host: %#v", helloLog.Metadata)
	}
	statsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/access-stats", nil, adminCookie, http.StatusOK)
	statsBody := statsRec.Body.String()
	for _, want := range []string{"access-stat-summary", "request_count", "unique_ips", "traffic_bytes", "error_rate", "docs.example.test", "/api/access/http/" + webAsset.ID + "/proxy/hello", "500"} {
		if !strings.Contains(statsBody, want) {
			t.Fatalf("access stats did not include %q", want)
		}
	}

	replacementTarget := upstreamTarget
	replacementTarget.User = url.UserPassword("proxy-user-2", "proxy-secret-2")
	replaceRec := assertStatus(t, handler, http.MethodPatch, "/api/admin/websites/"+webAsset.ID, map[string]any{
		"metadata": map[string]any{
			"target_url": replacementTarget.String(),
			"display":    "patched with replacement credentials",
		},
	}, adminCookie, http.StatusOK)
	replaceBody := replaceRec.Body.String()
	for _, leaked := range []string{"proxy-user-2", "proxy-secret-2", "web_upstream_url_encrypted"} {
		if strings.Contains(replaceBody, leaked) {
			t.Fatalf("web asset replacement response leaked %q: %s", leaked, replaceBody)
		}
	}
	var replacedWebAsset model.PlatformItem
	decodeResponse(t, replaceRec, &replacedWebAsset)
	rawWebAsset, ok, err = server.cfg.Store.GetPlatformItem("web_assets", webAsset.ID)
	if err != nil || !ok {
		t.Fatalf("reload raw web asset after replacement: ok=%v err=%v", ok, err)
	}
	replacedEncryptedUpstream := firstMetadataString(rawWebAsset.Metadata, "web_upstream_url_encrypted")
	if replacedEncryptedUpstream == "" || replacedEncryptedUpstream == preservedEncryptedUpstream {
		t.Fatalf("web asset replacement did not rotate encrypted upstream credentials: %#v", rawWebAsset.Metadata)
	}
	decryptedUpstream, err = server.cfg.Store.DecryptPlatformSecret(replacedEncryptedUpstream)
	if err != nil {
		t.Fatalf("decrypt replaced web asset upstream: %v", err)
	}
	if decryptedUpstream != replacementTarget.String() {
		t.Fatalf("decrypted replaced web upstream = %q, want %q", decryptedUpstream, replacementTarget.String())
	}
	replaceProxyRec := assertStatus(t, handler, http.MethodGet, "/api/access/http/"+webAsset.ID+"/proxy/newauth?x=1", nil, userCookie, http.StatusOK)
	if replaceProxyRec.Body.String() != "new credentials ok" {
		t.Fatalf("replacement credential proxy body = %q", replaceProxyRec.Body.String())
	}

	clearRec := assertStatus(t, handler, http.MethodPatch, "/api/admin/websites/"+webAsset.ID, map[string]any{
		"metadata": map[string]any{
			"target_url":                     firstMetadataString(replacedWebAsset.Metadata, "target_url"),
			"display":                        "patched with cleared credentials",
			"web_upstream_credentials_clear": true,
		},
	}, adminCookie, http.StatusOK)
	clearBody := clearRec.Body.String()
	for _, leaked := range []string{"proxy-user", "proxy-secret", "proxy-user-2", "proxy-secret-2", "web_upstream_url_encrypted", "web_upstream_credentials_clear", "target_url_credentials_set"} {
		if strings.Contains(clearBody, leaked) {
			t.Fatalf("web asset clear response leaked %q: %s", leaked, clearBody)
		}
	}
	rawWebAsset, ok, err = server.cfg.Store.GetPlatformItem("web_assets", webAsset.ID)
	if err != nil || !ok {
		t.Fatalf("reload raw web asset after clearing upstream credentials: ok=%v err=%v", ok, err)
	}
	upstreamURLSet, _ := metadataBoolValue(rawWebAsset.Metadata["web_upstream_url_set"])
	upstreamCredentialsSet, _ := metadataBoolValue(rawWebAsset.Metadata["upstream_credentials_set"])
	targetURLCredentialsSet, _ := metadataBoolValue(rawWebAsset.Metadata["target_url_credentials_set"])
	if firstMetadataString(rawWebAsset.Metadata, "web_upstream_url_encrypted") != "" || upstreamURLSet || upstreamCredentialsSet || targetURLCredentialsSet {
		t.Fatalf("web asset clear retained upstream credential state: %#v", rawWebAsset.Metadata)
	}
	clearProxyRec := assertStatus(t, handler, http.MethodGet, "/api/access/http/"+webAsset.ID+"/proxy/noauth?x=1", nil, userCookie, http.StatusOK)
	if clearProxyRec.Body.String() != "cleared credentials ok" {
		t.Fatalf("cleared credential proxy body = %q", clearProxyRec.Body.String())
	}
}

func TestWebAssetProxyAccessLogPersistenceFailures(t *testing.T) {
	upstreamHits := make(chan string, 4)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits <- r.URL.Path
		_, _ = w.Write([]byte("proxied ok"))
	}))
	defer upstream.Close()

	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)
	webRec := assertStatus(t, handler, http.MethodPost, "/api/admin/websites", map[string]any{
		"name":     "access-log-persistence-web",
		"type":     "http",
		"status":   "enabled",
		"metadata": map[string]any{"target_url": upstream.URL},
	}, adminCookie, http.StatusCreated)
	var webAsset model.PlatformItem
	decodeResponse(t, webRec, &webAsset)

	removeCreateBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "access_logs")
	createFailureRec := assertStatus(t, handler, http.MethodGet, "/api/access/http/"+webAsset.ID+"/proxy/ok", nil, adminCookie, http.StatusInternalServerError)
	removeCreateBlocker()
	if !strings.Contains(createFailureRec.Body.String(), "persist access log failed") {
		t.Fatalf("access log create failure was not reported: %s", createFailureRec.Body.String())
	}
	if strings.Contains(createFailureRec.Body.String(), "proxied ok") {
		t.Fatalf("proxy returned upstream body after access log create failure: %s", createFailureRec.Body.String())
	}
	select {
	case path := <-upstreamHits:
		t.Fatalf("upstream was called before access log create succeeded: %s", path)
	default:
	}

	removeUpdateBlocker := blockPlatformItemCollectionStatusUpdate(t, srv.cfg.Store, "access_logs", "200")
	updateFailureRec := assertStatus(t, handler, http.MethodGet, "/api/access/http/"+webAsset.ID+"/proxy/ok", nil, adminCookie, http.StatusInternalServerError)
	removeUpdateBlocker()
	if !strings.Contains(updateFailureRec.Body.String(), "persist access log failed") {
		t.Fatalf("access log update failure was not reported: %s", updateFailureRec.Body.String())
	}
	if strings.Contains(updateFailureRec.Body.String(), "proxied ok") {
		t.Fatalf("proxy returned upstream body after access log update failure: %s", updateFailureRec.Body.String())
	}
	select {
	case path := <-upstreamHits:
		if path != "/ok" {
			t.Fatalf("upstream path = %q, want /ok", path)
		}
	default:
		t.Fatal("upstream was not called before access log finalize path")
	}
	operationLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(operationLogsRec.Body.String(), "access.log.persist_failed") {
		t.Fatalf("access log persistence failure was not audited: %s", operationLogsRec.Body.String())
	}
	accessLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/access-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(accessLogsRec.Body.String(), `"status":"pending"`) {
		t.Fatalf("failed access log finalize did not leave a pending access log: %s", accessLogsRec.Body.String())
	}

	proxyRec := assertStatus(t, handler, http.MethodGet, "/api/access/http/"+webAsset.ID+"/proxy/ok", nil, adminCookie, http.StatusOK)
	if proxyRec.Body.String() != "proxied ok" {
		t.Fatalf("proxy response after restoring access log persistence = %q", proxyRec.Body.String())
	}
}

func TestWebAssetProxyUsesMTLSCertificate(t *testing.T) {
	caPEM, clientCertPEM, clientKeyPEM, serverCert := testMTLSMaterials(t)
	clientCAPool := x509.NewCertPool()
	if !clientCAPool.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to build client CA pool")
	}
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			t.Fatal("upstream did not receive a client certificate")
		}
		if got := r.TLS.PeerCertificates[0].Subject.CommonName; got != "owm-mtls-client" {
			t.Fatalf("client certificate CN = %q, want owm-mtls-client", got)
		}
		_, _ = w.Write([]byte("mtls web ok"))
	}))
	upstream.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool,
		MinVersion:   tls.VersionTLS12,
	}
	upstream.StartTLS()
	defer upstream.Close()

	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)
	cert, err := srv.cfg.Store.CreatePlatformItem("certificates", model.PlatformItemRequest{
		Name:   "web client certificate",
		Type:   "uploaded",
		Status: "issued",
		Metadata: map[string]any{
			"certificate":        string(clientCertPEM),
			"private_key":        string(clientKeyPEM),
			"has_private_key":    true,
			"mtls_enabled":       true,
			"mtls_client_ca":     string(caPEM),
			"mtls_client_ca_set": true,
		},
	})
	if err != nil {
		t.Fatalf("create mTLS certificate: %v", err)
	}
	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "web-mtls-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)
	webRec := assertStatus(t, handler, http.MethodPost, "/api/admin/websites", map[string]any{
		"name":   "mTLS upstream",
		"type":   "https",
		"status": "enabled",
		"metadata": map[string]any{
			"target_url":     upstream.URL,
			"certificate_id": cert.ID,
		},
	}, adminCookie, http.StatusCreated)
	var webAsset model.PlatformItem
	decodeResponse(t, webRec, &webAsset)
	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/websites", map[string]any{
		"name":      "web-mtls-user upstream",
		"owner_id":  user.ID,
		"target_id": webAsset.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)
	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "web-mtls-user", "password": "password123"}, nil, http.StatusOK)
	userCookie := loginRec.Result().Cookies()[0]

	proxyRec := assertStatus(t, handler, http.MethodGet, "/api/access/http/"+webAsset.ID+"/proxy/", nil, userCookie, http.StatusOK)
	if proxyRec.Body.String() != "mtls web ok" {
		t.Fatalf("mTLS proxy body = %q, want mtls web ok", proxyRec.Body.String())
	}
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/access-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), cert.ID) || !strings.Contains(logsRec.Body.String(), "mtls_certificate_id") {
		t.Fatalf("access logs missing mTLS certificate id: %s", logsRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPatch, "/api/admin/certificates/"+cert.ID, map[string]any{
		"status": "disabled",
	}, adminCookie, http.StatusOK)
	disabledProxyRec := assertStatus(t, handler, http.MethodGet, "/api/access/http/"+webAsset.ID+"/proxy/", nil, userCookie, http.StatusBadRequest)
	if !strings.Contains(disabledProxyRec.Body.String(), "not usable") {
		t.Fatalf("disabled mTLS certificate response did not explain state: %s", disabledProxyRec.Body.String())
	}
}

func TestDatabaseAssetQueryRequiresAuthorizationAndLogs(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)

	assertStatus(t, handler, http.MethodPost, "/api/admin/roles", map[string]any{
		"name":   "sql-self-approver",
		"type":   "custom",
		"status": "enabled",
		"metadata": map[string]any{
			"api_permissions": []string{
				"POST /api/admin/sql-work-orders/*",
			},
		},
	}, adminCookie, http.StatusCreated)
	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "database-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "sql-self-approver"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)
	assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "database-limited-approver",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "sql-self-approver"},
	}, adminCookie, http.StatusCreated)

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
	limitedLoginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "database-limited-approver", "password": "password123"}, nil, http.StatusOK)
	limitedCookie := limitedLoginRec.Result().Cookies()[0]

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

	removeSQLRequestLogBlocker := blockOperationLogName(t, srv.cfg.Store, "sql_work_order.request")
	blockedSQLRequestRec := assertStatus(t, handler, http.MethodPost, "/api/access/database/"+databaseAsset.ID+"/work-orders", map[string]any{
		"sql":    "CREATE TABLE blocked_request_table(name TEXT)",
		"reason": "blocked sql request log",
	}, userCookie, http.StatusInternalServerError)
	removeSQLRequestLogBlocker()
	if !strings.Contains(blockedSQLRequestRec.Body.String(), "persist operation log failed") {
		t.Fatalf("sql work order request log persistence failure did not explain error: %s", blockedSQLRequestRec.Body.String())
	}
	blockedRequestListRec := assertStatus(t, handler, http.MethodGet, "/api/admin/sql-work-orders", nil, adminCookie, http.StatusOK)
	if strings.Contains(blockedRequestListRec.Body.String(), "blocked sql request log") {
		t.Fatalf("sql work order request was not rolled back after log failure: %s", blockedRequestListRec.Body.String())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "operation.log.persist_failed") {
		t.Fatal("sql work order request operation log failure was not audited")
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

	removeSQLLogCreateBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "sql_logs")
	blockedSQLLogCreateRec := assertStatus(t, handler, http.MethodPost, "/api/access/database/"+databaseAsset.ID+"/query", map[string]any{
		"sql": "CREATE TABLE missing_log_table(id INTEGER)",
	}, userCookie, http.StatusInternalServerError)
	removeSQLLogCreateBlocker()
	if !strings.Contains(blockedSQLLogCreateRec.Body.String(), "persist sql log failed") {
		t.Fatalf("sql log create failure response did not explain persistence failure: %s", blockedSQLLogCreateRec.Body.String())
	}
	missingLogTableRec := assertStatus(t, handler, http.MethodPost, "/api/access/database/"+databaseAsset.ID+"/query", map[string]any{
		"sql": "SELECT COUNT(*) AS present FROM sqlite_master WHERE type = 'table' AND name = 'missing_log_table'",
	}, userCookie, http.StatusOK)
	if !strings.Contains(missingLogTableRec.Body.String(), `"present":0`) {
		t.Fatalf("SQL executed even though the initial sql log could not be persisted: %s", missingLogTableRec.Body.String())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "sql.log.persist_failed") {
		t.Fatal("sql log create persistence failure was not written to core audit logs")
	}

	removeSQLLogFinalizeBlocker := blockPlatformItemCollectionStatusUpdate(t, srv.cfg.Store, "sql_logs", "success")
	blockedSQLLogFinalizeRec := assertStatus(t, handler, http.MethodPost, "/api/access/database/"+databaseAsset.ID+"/query", map[string]any{
		"sql": "CREATE TABLE finalize_blocked_table(id INTEGER)",
	}, userCookie, http.StatusInternalServerError)
	removeSQLLogFinalizeBlocker()
	if !strings.Contains(blockedSQLLogFinalizeRec.Body.String(), "persist sql log failed") {
		t.Fatalf("sql log finalize failure response did not explain persistence failure: %s", blockedSQLLogFinalizeRec.Body.String())
	}
	finalizedTableRec := assertStatus(t, handler, http.MethodPost, "/api/access/database/"+databaseAsset.ID+"/query", map[string]any{
		"sql": "SELECT COUNT(*) AS present FROM sqlite_master WHERE type = 'table' AND name = 'finalize_blocked_table'",
	}, userCookie, http.StatusOK)
	if !strings.Contains(finalizedTableRec.Body.String(), `"present":1`) {
		t.Fatalf("SQL did not execute before the final sql log update failure: %s", finalizedTableRec.Body.String())
	}
	runningSQLLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/sql-logs", nil, adminCookie, http.StatusOK)
	runningSQLLogsBody := runningSQLLogsRec.Body.String()
	if !strings.Contains(runningSQLLogsBody, "finalize_blocked_table") || !strings.Contains(runningSQLLogsBody, `"status":"running"`) {
		t.Fatalf("final sql log update failure did not leave a running audit trace: %s", runningSQLLogsBody)
	}

	workOrderRec := assertStatus(t, handler, http.MethodPost, "/api/access/database/"+databaseAsset.ID+"/work-orders", map[string]any{
		"sql":    "CREATE TABLE work_order_hosts(name TEXT)",
		"reason": "create host review table",
	}, userCookie, http.StatusCreated)
	var workOrder model.PlatformItem
	decodeResponse(t, workOrderRec, &workOrder)
	if workOrder.Status != "pending" || workOrder.TargetID != databaseAsset.ID || workOrder.OwnerID != user.ID {
		t.Fatalf("work order = status %q target %q owner %q", workOrder.Status, workOrder.TargetID, workOrder.OwnerID)
	}
	if got := firstMetadataString(workOrder.Metadata, "requested_by"); got != user.ID {
		t.Fatalf("work order requested_by = %q, want %q", got, user.ID)
	}
	requestLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(requestLogsRec.Body.String(), "sql_work_order.request") || !strings.Contains(requestLogsRec.Body.String(), workOrder.ID) {
		t.Fatalf("sql work order request was not written to operation logs: %s", requestLogsRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+workOrder.ID+"/execute", map[string]any{}, adminCookie, http.StatusConflict)
	selfApproveRec := assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+workOrder.ID+"/approve", map[string]any{"note": "self approve"}, userCookie, http.StatusForbidden)
	if !strings.Contains(selfApproveRec.Body.String(), "self-approved") {
		t.Fatalf("self approval denial did not explain reason: %s", selfApproveRec.Body.String())
	}
	selfApproveLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(selfApproveLogsRec.Body.String(), "sql_work_order.approve.denied") || !strings.Contains(selfApproveLogsRec.Body.String(), workOrder.ID) {
		t.Fatalf("self approval denial was not audited: %s", selfApproveLogsRec.Body.String())
	}
	assetDeniedApproveRec := assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+workOrder.ID+"/approve", map[string]any{"note": "no database auth"}, limitedCookie, http.StatusForbidden)
	if !strings.Contains(assetDeniedApproveRec.Body.String(), "database asset access denied") {
		t.Fatalf("asset authorization denial did not explain reason: %s", assetDeniedApproveRec.Body.String())
	}
	assetDeniedLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(assetDeniedLogsRec.Body.String(), "sql_work_order.database_access.denied") || !strings.Contains(assetDeniedLogsRec.Body.String(), workOrder.ID) || !strings.Contains(assetDeniedLogsRec.Body.String(), databaseAsset.ID) {
		t.Fatalf("sql work order asset denial was not audited: %s", assetDeniedLogsRec.Body.String())
	}
	removeSQLApproveLogBlocker := blockOperationLogName(t, srv.cfg.Store, "sql_work_order.approved")
	blockedSQLApproveRec := assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+workOrder.ID+"/approve", map[string]any{"note": "blocked operation log"}, adminCookie, http.StatusInternalServerError)
	removeSQLApproveLogBlocker()
	if !strings.Contains(blockedSQLApproveRec.Body.String(), "persist operation log failed") {
		t.Fatalf("sql work order approve log persistence failure did not explain error: %s", blockedSQLApproveRec.Body.String())
	}
	blockedSQLApproveStatusRec := assertStatus(t, handler, http.MethodGet, "/api/admin/sql-work-orders/"+workOrder.ID, nil, adminCookie, http.StatusOK)
	if !strings.Contains(blockedSQLApproveStatusRec.Body.String(), `"status":"pending"`) || strings.Contains(blockedSQLApproveStatusRec.Body.String(), "blocked operation log") {
		t.Fatalf("sql work order was not restored after approve log failure: %s", blockedSQLApproveStatusRec.Body.String())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "operation.log.persist_failed") {
		t.Fatal("sql work order approve operation log failure was not audited")
	}
	approveRec := assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+workOrder.ID+"/approve", map[string]any{"note": "approved for test"}, adminCookie, http.StatusOK)
	var approvedOrder model.PlatformItem
	decodeResponse(t, approveRec, &approvedOrder)
	if got := firstMetadataString(approvedOrder.Metadata, "approval_note"); got != "approved for test" {
		t.Fatalf("approval_note = %q, want approved for test", got)
	}
	assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+workOrder.ID+"/reject", map[string]any{"note": "too late"}, adminCookie, http.StatusConflict)
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
	removeSQLRejectLogBlocker := blockOperationLogName(t, srv.cfg.Store, "sql_work_order.rejected")
	blockedSQLRejectRec := assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+rejectedOrder.ID+"/reject", map[string]any{"note": "blocked reject log"}, adminCookie, http.StatusInternalServerError)
	removeSQLRejectLogBlocker()
	if !strings.Contains(blockedSQLRejectRec.Body.String(), "persist operation log failed") {
		t.Fatalf("sql work order reject log persistence failure did not explain error: %s", blockedSQLRejectRec.Body.String())
	}
	blockedSQLRejectStatusRec := assertStatus(t, handler, http.MethodGet, "/api/admin/sql-work-orders/"+rejectedOrder.ID, nil, adminCookie, http.StatusOK)
	if !strings.Contains(blockedSQLRejectStatusRec.Body.String(), `"status":"pending"`) || strings.Contains(blockedSQLRejectStatusRec.Body.String(), "blocked reject log") {
		t.Fatalf("sql work order was not restored after reject log failure: %s", blockedSQLRejectStatusRec.Body.String())
	}
	rejectRec := assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+rejectedOrder.ID+"/reject", map[string]any{"note": "not allowed"}, adminCookie, http.StatusOK)
	var rejectedDecision model.PlatformItem
	decodeResponse(t, rejectRec, &rejectedDecision)
	if got := firstMetadataString(rejectedDecision.Metadata, "rejection_note"); got != "not allowed" {
		t.Fatalf("rejection_note = %q, want not allowed", got)
	}
	assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+rejectedOrder.ID+"/approve", map[string]any{"note": "revive rejected"}, adminCookie, http.StatusConflict)
	assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+rejectedOrder.ID+"/execute", map[string]any{}, adminCookie, http.StatusConflict)

	failingRec := assertStatus(t, handler, http.MethodPost, "/api/access/database/"+databaseAsset.ID+"/work-orders", map[string]any{
		"sql":    "SELECT * FROM missing_work_order_table",
		"reason": "exercise failed execution state",
	}, userCookie, http.StatusCreated)
	var failingOrder model.PlatformItem
	decodeResponse(t, failingRec, &failingOrder)
	assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+failingOrder.ID+"/approve", map[string]any{"note": "approved failure path"}, adminCookie, http.StatusOK)
	failingExecuteRec := assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+failingOrder.ID+"/execute", map[string]any{}, adminCookie, http.StatusBadRequest)
	var failingLog model.PlatformItem
	decodeResponse(t, failingExecuteRec, &failingLog)
	if failingLog.Status != "failed" || failingLog.ID == "" || !strings.Contains(failingLog.Description, "missing_work_order_table") {
		t.Fatalf("failing work order log missing failure details: %#v", failingLog)
	}
	failingStatusRec := assertStatus(t, handler, http.MethodGet, "/api/admin/sql-work-orders/"+failingOrder.ID, nil, adminCookie, http.StatusOK)
	var failedOrder model.PlatformItem
	decodeResponse(t, failingStatusRec, &failedOrder)
	if failedOrder.Status != "failed" || firstMetadataString(failedOrder.Metadata, "sql_log_id") != failingLog.ID || !strings.Contains(firstMetadataString(failedOrder.Metadata, "execution_error"), "missing_work_order_table") {
		t.Fatalf("failed work order did not persist execution failure state: %#v", failedOrder)
	}
	assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+failingOrder.ID+"/approve", map[string]any{"note": "retry by re-approval"}, adminCookie, http.StatusConflict)
	assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+failingOrder.ID+"/reject", map[string]any{"note": "reject failed order"}, adminCookie, http.StatusConflict)

	blockedPersistRec := assertStatus(t, handler, http.MethodPost, "/api/access/database/"+databaseAsset.ID+"/work-orders", map[string]any{
		"sql":    "CREATE TABLE blocked_status_update(name TEXT)",
		"reason": "exercise status persistence failure",
	}, userCookie, http.StatusCreated)
	var blockedPersistOrder model.PlatformItem
	decodeResponse(t, blockedPersistRec, &blockedPersistOrder)
	assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+blockedPersistOrder.ID+"/approve", map[string]any{"note": "approved persistence failure path"}, adminCookie, http.StatusOK)
	removeExecutedBlocker := blockSQLWorkOrderStatusUpdate(t, srv.cfg.Store, blockedPersistOrder.ID, "executed")
	blockedPersistExecuteRec := assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+blockedPersistOrder.ID+"/execute", map[string]any{}, adminCookie, http.StatusInternalServerError)
	removeExecutedBlocker()
	if !strings.Contains(blockedPersistExecuteRec.Body.String(), "persist sql work order executed state failed") {
		t.Fatalf("status persistence failure did not explain executed state error: %s", blockedPersistExecuteRec.Body.String())
	}
	blockedPersistStatusRec := assertStatus(t, handler, http.MethodGet, "/api/admin/sql-work-orders/"+blockedPersistOrder.ID, nil, adminCookie, http.StatusOK)
	var stillApprovedOrder model.PlatformItem
	decodeResponse(t, blockedPersistStatusRec, &stillApprovedOrder)
	if stillApprovedOrder.Status != "approved" {
		t.Fatalf("blocked status update unexpectedly changed work order status to %q", stillApprovedOrder.Status)
	}

	blockedFailureRec := assertStatus(t, handler, http.MethodPost, "/api/access/database/"+databaseAsset.ID+"/work-orders", map[string]any{
		"sql":    "SELECT * FROM missing_persist_failure_table",
		"reason": "exercise failed status persistence failure",
	}, userCookie, http.StatusCreated)
	var blockedFailureOrder model.PlatformItem
	decodeResponse(t, blockedFailureRec, &blockedFailureOrder)
	assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+blockedFailureOrder.ID+"/approve", map[string]any{"note": "approved failed persistence path"}, adminCookie, http.StatusOK)
	removeFailedBlocker := blockSQLWorkOrderStatusUpdate(t, srv.cfg.Store, blockedFailureOrder.ID, "failed")
	blockedFailureExecuteRec := assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+blockedFailureOrder.ID+"/execute", map[string]any{}, adminCookie, http.StatusInternalServerError)
	removeFailedBlocker()
	if !strings.Contains(blockedFailureExecuteRec.Body.String(), "persist sql work order failed state failed") {
		t.Fatalf("status persistence failure did not explain failed state error: %s", blockedFailureExecuteRec.Body.String())
	}
	persistFailureLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(persistFailureLogsRec.Body.String(), "sql_work_order.execute.persist_failed") {
		t.Fatalf("sql work order status persistence failure was not audited: %s", persistFailureLogsRec.Body.String())
	}

	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/sql-logs", nil, adminCookie, http.StatusOK)
	logsBody := logsRec.Body.String()
	for _, want := range []string{databaseAsset.ID, user.ID, "database_access", "alpha", "missing_table", "failed", "work_order", workOrder.ID, "work_order_hosts", failingOrder.ID, "missing_work_order_table"} {
		if !strings.Contains(logsBody, want) {
			t.Fatalf("sql logs did not include %q", want)
		}
	}
	operationLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(operationLogsRec.Body.String(), "sql_work_order.execute.failed") {
		t.Fatalf("failed sql work order execution was not audited: %s", operationLogsRec.Body.String())
	}

	sshCredentialRec := assertStatus(t, handler, http.MethodPost, "/api/admin/credentials", map[string]any{
		"name":     "database should reject ssh credential",
		"type":     "ssh_password",
		"status":   "enabled",
		"username": "root",
		"password": "ssh-secret",
	}, adminCookie, http.StatusCreated)
	var sshCredential model.PlatformItem
	decodeResponse(t, sshCredentialRec, &sshCredential)
	wrongDatabaseRec := assertStatus(t, handler, http.MethodPost, "/api/admin/database-assets", map[string]any{
		"name":     "wrong-credential-db",
		"type":     "sqlite",
		"status":   "enabled",
		"protocol": "database",
		"metadata": map[string]any{"sqlite_path": "wrong-credential.db", "credential_id": sshCredential.ID},
	}, adminCookie, http.StatusCreated)
	var wrongDatabaseAsset model.PlatformItem
	decodeResponse(t, wrongDatabaseRec, &wrongDatabaseAsset)
	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/databases", map[string]any{
		"name":      "database-user wrong credential db",
		"owner_id":  user.ID,
		"target_id": wrongDatabaseAsset.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)
	wrongCredentialQueryRec := assertStatus(t, handler, http.MethodPost, "/api/access/database/"+wrongDatabaseAsset.ID+"/query", map[string]any{
		"sql": "SELECT 1",
	}, userCookie, http.StatusBadRequest)
	if !strings.Contains(wrongCredentialQueryRec.Body.String(), "not compatible") {
		t.Fatalf("wrong database credential response did not explain compatibility: %s", wrongCredentialQueryRec.Body.String())
	}
}

func TestDatabaseAssetSQLiteRejectsSymlinkDirectory(t *testing.T) {
	dataDir := t.TempDir()
	handler, adminCookie := newTestServer(t, func(cfg *Config) {
		cfg.DataDir = dataDir
	})
	root := filepath.Join(dataDir, "database-assets")
	if err := os.MkdirAll(root, 0o770); err != nil {
		t.Fatalf("create database asset root: %v", err)
	}
	externalDir := filepath.Join(t.TempDir(), "external")
	if err := os.MkdirAll(externalDir, 0o770); err != nil {
		t.Fatalf("create external dir: %v", err)
	}
	linkDir := filepath.Join(root, "linked")
	if err := os.Symlink(externalDir, linkDir); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	databaseRec := assertStatus(t, handler, http.MethodPost, "/api/admin/database-assets", map[string]any{
		"name":     "symlink-sqlite",
		"type":     "sqlite",
		"status":   "enabled",
		"protocol": "database",
		"metadata": map[string]any{"sqlite_path": "linked/escape.db"},
	}, adminCookie, http.StatusCreated)
	var databaseAsset model.PlatformItem
	decodeResponse(t, databaseRec, &databaseAsset)

	queryRec := assertStatus(t, handler, http.MethodPost, "/api/access/database/"+databaseAsset.ID+"/query", map[string]any{
		"sql": "CREATE TABLE escaped(id INTEGER)",
	}, adminCookie, http.StatusBadRequest)
	if !strings.Contains(queryRec.Body.String(), "non-directory") {
		t.Fatalf("symlink sqlite path response did not explain rejection: %s", queryRec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(externalDir, "escape.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("sqlite symlink path created or touched external database file: %v", err)
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
	wrongCredentialRec := assertStatus(t, handler, http.MethodPost, "/api/admin/credentials", map[string]any{
		"name":     "ssh credential must not be used by database",
		"type":     "ssh_password",
		"status":   "enabled",
		"username": "ssh_user",
		"password": "ssh-secret",
	}, adminCookie, http.StatusCreated)
	var wrongCredential model.PlatformItem
	decodeResponse(t, wrongCredentialRec, &wrongCredential)
	wrongAssetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/database-assets", map[string]any{
		"name":     "wrong credential postgres",
		"type":     "postgres",
		"status":   "enabled",
		"protocol": "database",
		"host":     "postgres.internal",
		"metadata": map[string]any{"database": "app", "credential_id": wrongCredential.ID},
	}, adminCookie, http.StatusCreated)
	var wrongAsset model.PlatformItem
	decodeResponse(t, wrongAssetRec, &wrongAsset)
	if _, err := server.databaseAssetConnection(wrongAsset); err == nil || !strings.Contains(err.Error(), "not compatible") {
		t.Fatalf("database asset accepted non-database credential: %v", err)
	}
}

func TestDatabaseAssetDirectDSNIsEncryptedAndRedacted(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	server := handler.(*Server)

	dsn := "postgres://dsn_user:dsn-secret@postgres.internal:5432/app?sslmode=disable"
	assetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/database-assets", map[string]any{
		"name":     "dsn-backed postgres",
		"type":     "postgres",
		"status":   "enabled",
		"protocol": "database",
		"metadata": map[string]any{"dsn": dsn},
	}, adminCookie, http.StatusCreated)
	assetBody := assetRec.Body.String()
	for _, leaked := range []string{"dsn-secret", "postgres://dsn_user", `"dsn":`, "connection_string", "database_dsn_encrypted"} {
		if strings.Contains(assetBody, leaked) {
			t.Fatalf("database asset create response leaked %q: %s", leaked, assetBody)
		}
	}
	if !strings.Contains(assetBody, "database_dsn_set") {
		t.Fatalf("database asset response did not expose dsn presence flag: %s", assetBody)
	}
	var asset model.PlatformItem
	decodeResponse(t, assetRec, &asset)

	rawAsset, ok, err := server.cfg.Store.GetPlatformItem("database_assets", asset.ID)
	if err != nil || !ok {
		t.Fatalf("load raw database asset: ok=%v err=%v", ok, err)
	}
	if firstMetadataString(rawAsset.Metadata, "dsn", "connection_string", "connectionString", "database_url", "databaseUrl", "url") != "" {
		t.Fatalf("raw database asset retained plain dsn metadata: %#v", rawAsset.Metadata)
	}
	dsnSet, _ := metadataBoolValue(rawAsset.Metadata["database_dsn_set"])
	if firstMetadataString(rawAsset.Metadata, "database_dsn_encrypted") == "" || !dsnSet {
		t.Fatalf("raw database asset did not store encrypted dsn with presence flag: %#v", rawAsset.Metadata)
	}

	connection, err := server.databaseAssetConnection(asset)
	if err != nil {
		t.Fatalf("database asset connection: %v", err)
	}
	parsed, err := url.Parse(connection.DSN)
	if err != nil {
		t.Fatalf("parse decrypted postgres dsn: %v", err)
	}
	password, _ := parsed.User.Password()
	if connection.Driver != "pgx" || parsed.User.Username() != "dsn_user" || password != "dsn-secret" {
		t.Fatalf("decrypted connection = %#v dsn=%q", connection, connection.DSN)
	}
	if strings.Contains(connection.Name, "dsn-secret") || strings.Contains(connection.Name, "postgres://") {
		t.Fatalf("database display name leaked dsn material: %q", connection.Name)
	}

	patchRec := assertStatus(t, handler, http.MethodPatch, "/api/admin/database-assets/"+asset.ID, map[string]any{
		"metadata": map[string]any{"row_limit": 50},
	}, adminCookie, http.StatusOK)
	patchBody := patchRec.Body.String()
	for _, leaked := range []string{"dsn-secret", "postgres://dsn_user", `"dsn":`, "database_dsn_encrypted"} {
		if strings.Contains(patchBody, leaked) {
			t.Fatalf("database asset update response leaked %q: %s", leaked, patchBody)
		}
	}
	connection, err = server.databaseAssetConnection(asset)
	if err != nil {
		t.Fatalf("database asset connection after metadata update: %v", err)
	}
	parsed, err = url.Parse(connection.DSN)
	if err != nil {
		t.Fatalf("parse decrypted postgres dsn after update: %v", err)
	}
	password, _ = parsed.User.Password()
	if password != "dsn-secret" {
		t.Fatalf("database dsn secret was not preserved across metadata update: %q", connection.DSN)
	}

	clearRec := assertStatus(t, handler, http.MethodPatch, "/api/admin/database-assets/"+asset.ID, map[string]any{
		"metadata": map[string]any{"database_dsn_clear": true, "row_limit": 75},
	}, adminCookie, http.StatusOK)
	clearBody := clearRec.Body.String()
	for _, leaked := range []string{"dsn-secret", "postgres://dsn_user", `"dsn":`, "database_dsn_encrypted", "database_dsn_clear", "database_dsn_set"} {
		if strings.Contains(clearBody, leaked) {
			t.Fatalf("database asset clear response leaked %q: %s", leaked, clearBody)
		}
	}
	rawCleared, ok, err := server.cfg.Store.GetPlatformItem("database_assets", asset.ID)
	if err != nil || !ok {
		t.Fatalf("load cleared database asset: ok=%v err=%v", ok, err)
	}
	for _, key := range []string{"dsn", "connection_string", "connectionString", "database_url", "databaseUrl", "url", "database_dsn_encrypted", "database_dsn_set", "database_dsn_updated_at", "database_dsn_clear", "clear_database_dsn", "dsn_clear", "clear_dsn"} {
		if _, exists := rawCleared.Metadata[key]; exists {
			t.Fatalf("database asset retained dsn metadata %q after clear: %#v", key, rawCleared.Metadata)
		}
	}
	if _, err = server.databaseAssetConnection(asset); err == nil || !strings.Contains(err.Error(), "database host is required") {
		t.Fatalf("database asset connection reused cleared dsn, err=%v", err)
	}

	listRec := assertStatus(t, handler, http.MethodGet, "/api/admin/database-assets", nil, adminCookie, http.StatusOK)
	listBody := listRec.Body.String()
	for _, leaked := range []string{"dsn-secret", "postgres://dsn_user", `"dsn":`, "database_dsn_encrypted"} {
		if strings.Contains(listBody, leaked) {
			t.Fatalf("database asset list leaked %q: %s", leaked, listBody)
		}
	}

	legacyItem, err := server.cfg.Store.SavePlatformItem("database_assets", model.PlatformItem{
		ID:       "legacy_dsn_asset",
		Module:   "database_assets",
		Name:     "legacy dsn postgres",
		Type:     "postgres",
		Status:   "enabled",
		Protocol: model.ProtocolDatabase,
		Metadata: map[string]any{"dsn": dsn},
	})
	if err != nil {
		t.Fatalf("save legacy dsn asset: %v", err)
	}
	assertStatus(t, handler, http.MethodPatch, "/api/admin/database-assets/"+legacyItem.ID, map[string]any{
		"metadata": map[string]any{"row_limit": 25},
	}, adminCookie, http.StatusOK)
	rawLegacy, ok, err := server.cfg.Store.GetPlatformItem("database_assets", legacyItem.ID)
	if err != nil || !ok {
		t.Fatalf("load migrated legacy database asset: ok=%v err=%v", ok, err)
	}
	if firstMetadataString(rawLegacy.Metadata, "dsn", "connection_string", "connectionString", "database_url", "databaseUrl", "url") != "" {
		t.Fatalf("legacy database asset kept plain dsn after update: %#v", rawLegacy.Metadata)
	}
	if firstMetadataString(rawLegacy.Metadata, "database_dsn_encrypted") == "" {
		t.Fatalf("legacy database asset did not migrate dsn to encrypted metadata: %#v", rawLegacy.Metadata)
	}
	connection, err = server.databaseAssetConnection(legacyItem)
	if err != nil {
		t.Fatalf("legacy database asset connection after migration: %v", err)
	}
	parsed, err = url.Parse(connection.DSN)
	if err != nil {
		t.Fatalf("parse migrated legacy postgres dsn: %v", err)
	}
	password, _ = parsed.User.Password()
	if password != "dsn-secret" {
		t.Fatalf("legacy dsn secret was not preserved across migration: %q", connection.DSN)
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
	assertStatus(t, handler, http.MethodGet, "/api/admin/assets/"+allowedAsset.ID, nil, readerCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodGet, "/api/admin/assets/"+allowedAsset.ID+"/unexpected", nil, readerCookie, http.StatusForbidden)
	assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{"name": "blocked"}, readerCookie, http.StatusForbidden)
	assertStatus(t, handler, http.MethodGet, "/api/admin/assets/"+allowedAsset.ID+"/unexpected", nil, adminCookie, http.StatusNotFound)
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

	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "custom-role-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "asset-menu-reader"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)
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
	assertStatus(t, handler, http.MethodGet, "/api/admin/assets/"+asset.ID, nil, userCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodGet, "/api/admin/assets/"+asset.ID+"/unexpected", nil, userCookie, http.StatusForbidden)
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
	roleDisabledMeRec := assertStatus(t, handler, http.MethodGet, "/api/auth/me", nil, userCookie, http.StatusOK)
	if strings.Contains(roleDisabledMeRec.Body.String(), "GET /api/admin/assets") || strings.Contains(roleDisabledMeRec.Body.String(), "menu_permissions") {
		t.Fatalf("disabled custom role still exposed permissions: %s", roleDisabledMeRec.Body.String())
	}

	assertStatus(t, handler, http.MethodPatch, "/api/admin/roles/"+role.ID, map[string]any{
		"name":   "asset-menu-reader",
		"type":   "custom",
		"status": "enabled",
	}, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodGet, "/api/admin/assets", nil, userCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, "/api/admin/users/"+user.ID, map[string]any{
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodGet, "/api/admin/assets", nil, userCookie, http.StatusForbidden)
	downgradedMeRec := assertStatus(t, handler, http.MethodGet, "/api/auth/me", nil, userCookie, http.StatusOK)
	if strings.Contains(downgradedMeRec.Body.String(), "GET /api/admin/assets") || strings.Contains(downgradedMeRec.Body.String(), "menu_permissions") {
		t.Fatalf("downgraded user session still exposed custom role permissions: %s", downgradedMeRec.Body.String())
	}
	downgradedBootstrapRec := assertStatus(t, handler, http.MethodGet, "/api/bootstrap", nil, userCookie, http.StatusOK)
	if strings.Contains(downgradedBootstrapRec.Body.String(), asset.ID) {
		t.Fatalf("downgraded user bootstrap leaked custom-role asset: %s", downgradedBootstrapRec.Body.String())
	}

	assertStatus(t, handler, http.MethodPatch, "/api/admin/users/"+user.ID, map[string]any{
		"status": "disabled",
	}, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodGet, "/api/auth/me", nil, userCookie, http.StatusUnauthorized)
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
	var locks struct {
		Items []model.PlatformItem `json:"items"`
	}
	decodeResponse(t, locksRec, &locks)
	var lockID string
	for _, lock := range locks.Items {
		if lock.Name == "lock-user" {
			lockID = lock.ID
			break
		}
	}
	if lockID == "" {
		t.Fatal("lock-user lock id was not returned")
	}
	removeUnlockLogBlocker := blockOperationLogName(t, handler.(*Server).cfg.Store, "login_locks.unlock")
	blockedUnlockRec := assertStatus(t, handler, http.MethodDelete, "/api/admin/login-locked/"+lockID, nil, adminCookie, http.StatusInternalServerError)
	removeUnlockLogBlocker()
	if !strings.Contains(blockedUnlockRec.Body.String(), "persist operation log failed") {
		t.Fatalf("login lock unlock operation log failure was not reported: %s", blockedUnlockRec.Body.String())
	}
	if !coreAuditLogsContainAction(handler.(*Server).cfg.Store, "operation.log.persist_failed") {
		t.Fatal("login lock unlock operation log failure was not audited")
	}
	blockedLocksRec := assertStatus(t, handler, http.MethodGet, "/api/admin/login-locked", nil, adminCookie, http.StatusOK)
	if !strings.Contains(blockedLocksRec.Body.String(), lockID) || !strings.Contains(blockedLocksRec.Body.String(), "lock-user") {
		t.Fatalf("login lock was not restored after unlock log failure: %s", blockedLocksRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "lock-user", "password": "password123"}, nil, http.StatusTooManyRequests)
	assertStatus(t, handler, http.MethodDelete, "/api/admin/login-locked/"+lockID, nil, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "lock-user", "password": "password123"}, nil, http.StatusOK)

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

func TestLoginPolicyAllowListRequiresMatchingClient(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "allow-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	createRec := assertStatus(t, handler, http.MethodPost, "/api/admin/login-policies", map[string]any{
		"name":     "allow different network",
		"type":     "allow",
		"status":   "enabled",
		"username": "allow-user",
		"host":     "198.51.100.0/24",
		"metadata": map[string]any{"action": "allow", "account": "allow-user", "cidr": "198.51.100.0/24"},
	}, adminCookie, http.StatusCreated)
	var policy model.PlatformItem
	decodeResponse(t, createRec, &policy)

	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username": "allow-user",
		"password": "password123",
	}, nil, http.StatusForbidden)
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/login-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), "no allow login policy matched") {
		t.Fatal("allowlist miss was not written to login logs")
	}

	assertStatus(t, handler, http.MethodPatch, "/api/admin/login-policies/"+policy.ID, map[string]any{
		"name":     "allow httptest network",
		"type":     "allow",
		"status":   "enabled",
		"username": "allow-user",
		"host":     "192.0.2.0/24",
		"metadata": map[string]any{"action": "allow", "account": "allow-user", "cidr": "192.0.2.0/24"},
	}, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username": "allow-user",
		"password": "password123",
	}, nil, http.StatusOK)
}

func TestConfigurableLoginFailureLockPolicy(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "Login security",
		"type":   "security",
		"status": "enabled",
		"metadata": map[string]any{
			"login_failure_threshold":      2,
			"login_failure_window_minutes": 30,
			"login_lock_minutes":           1,
		},
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "custom-lock-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)

	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "custom-lock-user", "password": "wrong-password"}, nil, http.StatusUnauthorized)
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "custom-lock-user", "password": "wrong-password"}, nil, http.StatusUnauthorized)
	lockedRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "custom-lock-user", "password": "password123"}, nil, http.StatusTooManyRequests)
	if lockedRec.Result().Header.Get("Retry-After") == "" {
		t.Fatal("locked login response did not include Retry-After")
	}
	loginLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/login-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(loginLogsRec.Body.String(), `"type":"lock"`) || !strings.Contains(loginLogsRec.Body.String(), "account or client ip is locked") {
		t.Fatalf("locked login denial was not written to login logs: %s", loginLogsRec.Body.String())
	}

	locksRec := assertStatus(t, handler, http.MethodGet, "/api/admin/login-locked", nil, adminCookie, http.StatusOK)
	var locks struct {
		Items []model.PlatformItem `json:"items"`
	}
	decodeResponse(t, locksRec, &locks)
	for _, lock := range locks.Items {
		if lock.Name != "custom-lock-user" {
			continue
		}
		if loginCountFromAny(lock.Metadata["failure_count"]) != 2 {
			t.Fatalf("failure_count = %v, want 2", lock.Metadata["failure_count"])
		}
		if stringValueFromAny(lock.Metadata["locked_until"]) == "" {
			t.Fatal("locked_until was not recorded")
		}
		return
	}
	t.Fatalf("custom-lock-user lock was not created: %#v", locks.Items)
}

func TestLoginLogPersistenceFailureReturnsServerError(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)

	removeFailureBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "login_logs")
	failedLoginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "wrong-password"}, nil, http.StatusInternalServerError)
	removeFailureBlocker()
	if !strings.Contains(failedLoginRec.Body.String(), "persist login log failed") {
		t.Fatalf("failed login log persistence failure was not reported: %s", failedLoginRec.Body.String())
	}
	operationLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(operationLogsRec.Body.String(), "auth.login.log.persist_failed") {
		t.Fatalf("failed login log persistence failure was not audited: %s", operationLogsRec.Body.String())
	}

	beforeSuccessFailure := rawPlatformUserByName(t, srv, "admin")
	removeSuccessBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "login_logs")
	successLoginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusInternalServerError)
	removeSuccessBlocker()
	if !strings.Contains(successLoginRec.Body.String(), "persist login log failed") {
		t.Fatalf("successful login log persistence failure was not reported: %s", successLoginRec.Body.String())
	}
	if cookies := successLoginRec.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("successful login issued cookies even though login log persistence failed: %#v", cookies)
	}
	afterSuccessFailure := rawPlatformUserByName(t, srv, "admin")
	for _, key := range []string{"last_login_at", "last_login_ip", "last_seen_at", "last_user_agent"} {
		if firstMetadataString(afterSuccessFailure.Metadata, key) != firstMetadataString(beforeSuccessFailure.Metadata, key) {
			t.Fatalf("successful login updated %s after login log failure: before=%#v after=%#v", key, beforeSuccessFailure.Metadata, afterSuccessFailure.Metadata)
		}
	}
	if metadataIntDefault(afterSuccessFailure.Metadata["login_count"], 0) != metadataIntDefault(beforeSuccessFailure.Metadata["login_count"], 0) {
		t.Fatalf("successful login updated login_count after login log failure: before=%#v after=%#v", beforeSuccessFailure.Metadata, afterSuccessFailure.Metadata)
	}
}

func TestLoginStatePersistenceFailureReturnsServerError(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)

	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "login-state-failure-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)

	beforeFailure, ok, err := srv.cfg.Store.GetPlatformItem("users", user.ID)
	if err != nil || !ok {
		t.Fatalf("load user before failed login: ok=%v err=%v", ok, err)
	}
	removeStateBlocker := blockPlatformItemSavePayloadFragment(t, srv.cfg.Store, "users", user.ID, `"login_count":1`)
	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": user.Name, "password": "password123"}, nil, http.StatusInternalServerError)
	removeStateBlocker()
	if !strings.Contains(loginRec.Body.String(), "persist user login state failed") {
		t.Fatalf("login state persistence failure was not reported: %s", loginRec.Body.String())
	}
	if cookies := loginRec.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("login issued cookies even though login state persistence failed: %#v", cookies)
	}
	if srv.auth.hasUserSession(user.ID) {
		t.Fatal("login state persistence failure left an in-memory user session")
	}
	afterFailure, ok, err := srv.cfg.Store.GetPlatformItem("users", user.ID)
	if err != nil || !ok {
		t.Fatalf("load user after failed login: ok=%v err=%v", ok, err)
	}
	for _, key := range []string{"online", "last_login_at", "last_login_ip", "last_seen_at", "last_user_agent"} {
		if fmt.Sprint(afterFailure.Metadata[key]) != fmt.Sprint(beforeFailure.Metadata[key]) {
			t.Fatalf("failed login updated %s after state persistence failure: before=%#v after=%#v", key, beforeFailure.Metadata, afterFailure.Metadata)
		}
	}
	if metadataIntDefault(afterFailure.Metadata["login_count"], 0) != metadataIntDefault(beforeFailure.Metadata["login_count"], 0) {
		t.Fatalf("failed login updated login_count after state persistence failure: before=%#v after=%#v", beforeFailure.Metadata, afterFailure.Metadata)
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "auth.login.state.persist_failed") {
		t.Fatal("login state persistence failure was not written to core audit logs")
	}
}

func TestLogoutStatePersistenceFailureKeepsSession(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)

	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "logout-state-failure-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)

	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": user.Name, "password": "password123"}, nil, http.StatusOK)
	cookies := loginRec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("login did not issue cookie")
	}
	userCookie := cookies[0]
	if !srv.auth.hasUserSession(user.ID) {
		t.Fatal("login did not create in-memory user session")
	}
	removeLogoutBlocker := blockPlatformItemSavePayloadFragment(t, srv.cfg.Store, "users", user.ID, `"online":false`)
	logoutRec := assertStatus(t, handler, http.MethodPost, "/api/auth/logout", nil, userCookie, http.StatusInternalServerError)
	removeLogoutBlocker()
	if !strings.Contains(logoutRec.Body.String(), "persist user logout state failed") {
		t.Fatalf("logout state persistence failure was not reported: %s", logoutRec.Body.String())
	}
	if expiredCookies := logoutRec.Result().Cookies(); len(expiredCookies) != 0 {
		t.Fatalf("logout state persistence failure cleared cookie: %#v", expiredCookies)
	}
	if !srv.auth.hasUserSession(user.ID) {
		t.Fatal("logout state persistence failure deleted in-memory session")
	}
	meRec := assertStatus(t, handler, http.MethodGet, "/api/auth/me", nil, userCookie, http.StatusOK)
	if !strings.Contains(meRec.Body.String(), user.ID) {
		t.Fatalf("session was not usable after failed logout: %s", meRec.Body.String())
	}
	afterFailure, ok, err := srv.cfg.Store.GetPlatformItem("users", user.ID)
	if err != nil || !ok {
		t.Fatalf("load user after failed logout: ok=%v err=%v", ok, err)
	}
	online, _ := afterFailure.Metadata["online"].(bool)
	if !online {
		t.Fatalf("failed logout marked user offline: %#v", afterFailure.Metadata)
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "auth.logout.state.persist_failed") {
		t.Fatal("logout state persistence failure was not written to core audit logs")
	}

	successLogoutRec := assertStatus(t, handler, http.MethodPost, "/api/auth/logout", nil, userCookie, http.StatusOK)
	if len(successLogoutRec.Result().Cookies()) == 0 {
		t.Fatal("successful logout did not clear cookie")
	}
	if srv.auth.hasUserSession(user.ID) {
		t.Fatal("successful retry logout left in-memory session")
	}
	assertStatus(t, handler, http.MethodGet, "/api/auth/me", nil, userCookie, http.StatusUnauthorized)
	afterSuccess, ok, err := srv.cfg.Store.GetPlatformItem("users", user.ID)
	if err != nil || !ok {
		t.Fatalf("load user after successful logout: ok=%v err=%v", ok, err)
	}
	online, _ = afterSuccess.Metadata["online"].(bool)
	if online {
		t.Fatalf("successful logout did not mark user offline: %#v", afterSuccess.Metadata)
	}
}

func TestLogoutKeepsUserOnlineWhenOtherSessionsRemain(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)

	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "multi-session-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)

	firstLogin := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": user.Name, "password": "password123"}, nil, http.StatusOK)
	secondLogin := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": user.Name, "password": "password123"}, nil, http.StatusOK)
	if len(firstLogin.Result().Cookies()) == 0 || len(secondLogin.Result().Cookies()) == 0 {
		t.Fatal("multi-session login did not issue cookies")
	}
	firstCookie := firstLogin.Result().Cookies()[0]
	secondCookie := secondLogin.Result().Cookies()[0]

	assertStatus(t, handler, http.MethodPost, "/api/auth/logout", nil, firstCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodGet, "/api/auth/me", nil, firstCookie, http.StatusUnauthorized)
	assertStatus(t, handler, http.MethodGet, "/api/auth/me", nil, secondCookie, http.StatusOK)
	afterFirstLogout, ok, err := srv.cfg.Store.GetPlatformItem("users", user.ID)
	if err != nil || !ok {
		t.Fatalf("load user after first logout: ok=%v err=%v", ok, err)
	}
	online, _ := afterFirstLogout.Metadata["online"].(bool)
	if !online {
		t.Fatalf("first logout marked user offline while another session remained: %#v", afterFirstLogout.Metadata)
	}
	if firstMetadataString(afterFirstLogout.Metadata, "last_logout_at") != "" {
		t.Fatalf("first logout wrote last_logout_at while another session remained: %#v", afterFirstLogout.Metadata)
	}

	assertStatus(t, handler, http.MethodPost, "/api/auth/logout", nil, secondCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodGet, "/api/auth/me", nil, secondCookie, http.StatusUnauthorized)
	afterSecondLogout, ok, err := srv.cfg.Store.GetPlatformItem("users", user.ID)
	if err != nil || !ok {
		t.Fatalf("load user after second logout: ok=%v err=%v", ok, err)
	}
	online, _ = afterSecondLogout.Metadata["online"].(bool)
	if online || firstMetadataString(afterSecondLogout.Metadata, "last_logout_at") == "" {
		t.Fatalf("last logout did not mark user offline with logout time: %#v", afterSecondLogout.Metadata)
	}
}

func TestRecordUserLoginAndLogoutMissingUserReturnNotExist(t *testing.T) {
	srv, _ := newTestServer(t, nil)

	if err := srv.cfg.Store.RecordUserLogin("missing-user", "", ""); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("RecordUserLogin missing user error = %v, want os.ErrNotExist", err)
	}
	if err := srv.cfg.Store.RecordUserLogout("missing-user"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("RecordUserLogout missing user error = %v, want os.ErrNotExist", err)
	}
}

func TestRecordUserLoginMigratesLegacyAdminPlatformUser(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	admin, ok := srv.cfg.Store.AdminUser()
	if !ok {
		t.Fatal("test server missing legacy admin")
	}
	if err := srv.cfg.Store.DeletePlatformItem("users", admin.UserID); err != nil {
		t.Fatalf("delete admin platform user: %v", err)
	}

	if err := srv.cfg.Store.RecordUserLogin(admin.UserID, "192.0.2.10", "legacy-admin-test"); err != nil {
		t.Fatalf("RecordUserLogin legacy admin error: %v", err)
	}
	item, ok, err := srv.cfg.Store.GetPlatformItem("users", admin.UserID)
	if err != nil || !ok {
		t.Fatalf("load migrated legacy admin platform user: ok=%v err=%v", ok, err)
	}
	online, _ := item.Metadata["online"].(bool)
	if item.Name != admin.Username || firstMetadataString(item.Metadata, "role") == "" || !online {
		t.Fatalf("legacy admin platform user was not migrated with login state: %#v", item)
	}

	if err := srv.cfg.Store.RecordUserLogout(admin.UserID); err != nil {
		t.Fatalf("RecordUserLogout migrated legacy admin error: %v", err)
	}
	item, ok, err = srv.cfg.Store.GetPlatformItem("users", admin.UserID)
	if err != nil || !ok {
		t.Fatalf("load migrated legacy admin after logout: ok=%v err=%v", ok, err)
	}
	online, _ = item.Metadata["online"].(bool)
	if online {
		t.Fatalf("legacy admin logout did not mark user offline: %#v", item.Metadata)
	}
}

func TestLoginLockPersistenceFailureReturnsServerError(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "Login lock persistence policy",
		"type":   "security",
		"status": "enabled",
		"metadata": map[string]any{
			"login_failure_threshold":      2,
			"login_failure_window_minutes": 30,
			"login_lock_minutes":           1,
		},
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "persist-lock-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)

	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "persist-lock-user", "password": "wrong-password"}, nil, http.StatusUnauthorized)
	removeBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "login_locks")
	lockFailureRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "persist-lock-user", "password": "wrong-password"}, nil, http.StatusInternalServerError)
	removeBlocker()
	if !strings.Contains(lockFailureRec.Body.String(), "persist login lock failed") {
		t.Fatalf("login lock persistence failure was not reported: %s", lockFailureRec.Body.String())
	}

	operationLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(operationLogsRec.Body.String(), "auth.login.lock.persist_failed") {
		t.Fatalf("login lock persistence failure was not audited: %s", operationLogsRec.Body.String())
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
	regenerateRec := assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/recovery-codes", map[string]any{
		"current_password": "password123",
		"mfa_code":         totpCode(secret, time.Now().UTC()),
	}, adminCookie, http.StatusOK)
	var regenerated map[string]any
	decodeResponse(t, regenerateRec, &regenerated)
	regeneratedCodes := stringSliceFromAny(regenerated["recovery_codes"])
	if len(regeneratedCodes) != 8 {
		t.Fatalf("regenerated recovery code count = %d, want 8", len(regeneratedCodes))
	}
	if regeneratedCodes[0] == recoveryCodes[0] {
		t.Fatal("regenerated recovery code unexpectedly matched old code")
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
	reusedAfterFailureRec := assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/complete-login", map[string]any{
		"token":    token,
		"mfa_code": totpCode(secret, time.Now().UTC()),
	}, nil, http.StatusUnauthorized)
	if len(reusedAfterFailureRec.Result().Cookies()) > 0 {
		t.Fatal("failed MFA challenge token was reused to create a session")
	}
	loginChallengeRec = assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusAccepted)
	decodeResponse(t, loginChallengeRec, &challenge)
	token, _ = challenge["mfa_token"].(string)
	if token == "" || challenge["mfa_required"] != true {
		t.Fatalf("second login did not return MFA challenge: %v", challenge)
	}
	completeRec := assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/complete-login", map[string]any{
		"token":    token,
		"mfa_code": totpCode(secret, time.Now().UTC()),
	}, nil, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/complete-login", map[string]any{
		"token":    token,
		"mfa_code": totpCode(secret, time.Now().UTC()),
	}, nil, http.StatusUnauthorized)
	if len(completeRec.Result().Cookies()) == 0 {
		t.Fatal("MFA completion did not set auth cookie")
	}

	recoveryChallengeRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusAccepted)
	var recoveryChallenge map[string]any
	decodeResponse(t, recoveryChallengeRec, &recoveryChallenge)
	recoveryToken, _ := recoveryChallenge["mfa_token"].(string)
	assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/complete-login", map[string]any{
		"token":         recoveryToken,
		"recovery_code": recoveryCodes[0],
	}, nil, http.StatusUnauthorized)
	recoveryChallengeRec = assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusAccepted)
	decodeResponse(t, recoveryChallengeRec, &recoveryChallenge)
	recoveryToken, _ = recoveryChallenge["mfa_token"].(string)
	recoveryLoginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/complete-login", map[string]any{
		"token":         recoveryToken,
		"recovery_code": regeneratedCodes[0],
	}, nil, http.StatusOK)
	recoveryCookie := recoveryLoginRec.Result().Cookies()[0]
	reusedChallengeRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusAccepted)
	var reusedChallenge map[string]any
	decodeResponse(t, reusedChallengeRec, &reusedChallenge)
	assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/complete-login", map[string]any{
		"token":         reusedChallenge["mfa_token"],
		"recovery_code": regeneratedCodes[0],
	}, nil, http.StatusUnauthorized)

	assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/disable", map[string]any{
		"current_password": "password123",
		"mfa_code":         totpCode(secret, time.Now().UTC()),
	}, recoveryCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusOK)
}

func TestMFAOperationLogFailureRollsBackMutations(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)
	adminUser := rawPlatformUserByName(t, srv, "admin")
	loadAdmin := func() model.PlatformItem {
		t.Helper()
		item, ok, err := srv.cfg.Store.GetPlatformItem("users", adminUser.ID)
		if err != nil || !ok {
			t.Fatalf("load admin user: ok=%v err=%v", ok, err)
		}
		return item
	}
	recoveryHashesJSON := func(item model.PlatformItem) string {
		t.Helper()
		data, err := json.Marshal(item.Metadata["mfa_recovery_hashes"])
		if err != nil {
			t.Fatalf("marshal recovery hashes: %v", err)
		}
		return string(data)
	}

	secret, err := generateTOTPSecret()
	if err != nil {
		t.Fatalf("generate TOTP secret: %v", err)
	}
	removeEnableBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	enableFailureRec := assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/enable", map[string]any{
		"secret":   secret,
		"mfa_code": totpCode(secret, time.Now().UTC()),
	}, adminCookie, http.StatusInternalServerError)
	removeEnableBlocker()
	if !strings.Contains(enableFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("MFA enable operation log failure was not reported: %s", enableFailureRec.Body.String())
	}
	profile, _, err := srv.cfg.Store.UserMFAProfile(adminUser.ID)
	if err != nil {
		t.Fatalf("load MFA profile after failed enable: %v", err)
	}
	if profile.Enabled {
		t.Fatalf("MFA remained enabled after failed enable operation log: %#v", profile)
	}

	enableRec := assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/enable", map[string]any{
		"secret":   secret,
		"mfa_code": totpCode(secret, time.Now().UTC()),
	}, adminCookie, http.StatusOK)
	var enabled map[string]any
	decodeResponse(t, enableRec, &enabled)
	if len(stringSliceFromAny(enabled["recovery_codes"])) != 8 {
		t.Fatalf("successful MFA enable did not return recovery codes: %s", enableRec.Body.String())
	}

	beforeRecovery := loadAdmin()
	beforeRecoveryHashes := recoveryHashesJSON(beforeRecovery)
	removeRecoveryBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	recoveryFailureRec := assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/recovery-codes", map[string]any{
		"current_password": "password123",
		"mfa_code":         totpCode(secret, time.Now().UTC()),
	}, adminCookie, http.StatusInternalServerError)
	removeRecoveryBlocker()
	if !strings.Contains(recoveryFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("MFA recovery operation log failure was not reported: %s", recoveryFailureRec.Body.String())
	}
	afterRecovery := loadAdmin()
	if afterRecoveryHashes := recoveryHashesJSON(afterRecovery); afterRecoveryHashes != beforeRecoveryHashes {
		t.Fatalf("MFA recovery hashes changed after failed operation log: before=%s after=%s", beforeRecoveryHashes, afterRecoveryHashes)
	}

	removeDisableBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	disableFailureRec := assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/disable", map[string]any{
		"current_password": "password123",
		"mfa_code":         totpCode(secret, time.Now().UTC()),
	}, adminCookie, http.StatusInternalServerError)
	removeDisableBlocker()
	if !strings.Contains(disableFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("MFA disable operation log failure was not reported: %s", disableFailureRec.Body.String())
	}
	profile, _, err = srv.cfg.Store.UserMFAProfile(adminUser.ID)
	if err != nil {
		t.Fatalf("load MFA profile after failed disable: %v", err)
	}
	if !profile.Enabled || profile.Secret != secret || profile.RecoveryCount != 8 {
		t.Fatalf("MFA disable did not restore enabled profile after failed operation log: %#v", profile)
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "operation.log.persist_failed") {
		t.Fatal("MFA operation log persistence failure was not written to core audit logs")
	}

	removeDisableLogBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	removeMFARestoreBlocker := blockPlatformItemSavePayloadFragment(t, srv.cfg.Store, "users", adminUser.ID, `"mfa_enabled":true`)
	restoreFailureRec := assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/disable", map[string]any{
		"current_password": "password123",
		"mfa_code":         totpCode(secret, time.Now().UTC()),
	}, adminCookie, http.StatusInternalServerError)
	removeMFARestoreBlocker()
	removeDisableLogBlocker()
	if !strings.Contains(restoreFailureRec.Body.String(), "failed to restore MFA state") {
		t.Fatalf("MFA restore failure was not reported: %s", restoreFailureRec.Body.String())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "auth.mfa.restore_failed") {
		t.Fatal("MFA restore failure was not written to core audit logs")
	}
}

func TestMFACompleteLoginLogFailureRollsBackMutations(t *testing.T) {
	t.Run("forced enrollment", func(t *testing.T) {
		srv, adminCookie := newTestServer(t, nil)
		handler := http.Handler(srv)
		adminUser := rawPlatformUserByName(t, srv, "admin")

		assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
			"name":   "Force MFA rollback",
			"type":   "security",
			"status": "enabled",
			"metadata": map[string]any{
				"force_mfa": true,
			},
		}, adminCookie, http.StatusCreated)
		loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusAccepted)
		var challenge map[string]any
		decodeResponse(t, loginRec, &challenge)
		token, _ := challenge["mfa_token"].(string)
		secret, _ := challenge["secret"].(string)
		if token == "" || secret == "" || challenge["mfa_setup_required"] != true {
			t.Fatalf("forced MFA did not return setup challenge: %v", challenge)
		}

		removeBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "login_logs")
		completeRec := assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/complete-login", map[string]any{
			"token":    token,
			"mfa_code": totpCode(secret, time.Now().UTC()),
		}, nil, http.StatusInternalServerError)
		removeBlocker()
		if !strings.Contains(completeRec.Body.String(), "persist login log failed") {
			t.Fatalf("forced MFA login log failure was not reported: %s", completeRec.Body.String())
		}
		if len(completeRec.Result().Cookies()) > 0 {
			t.Fatalf("forced MFA completion issued cookies after failed login log write: %#v", completeRec.Result().Cookies())
		}
		profile, _, err := srv.cfg.Store.UserMFAProfile(adminUser.ID)
		if err != nil {
			t.Fatalf("load MFA profile after failed forced enrollment: %v", err)
		}
		if profile.Enabled {
			t.Fatalf("forced MFA enrollment survived failed login log write: %#v", profile)
		}
		if !coreAuditLogsContainAction(srv.cfg.Store, "auth.login.log.persist_failed") {
			t.Fatal("forced MFA login log persistence failure was not written to core audit logs")
		}
	})

	t.Run("recovery code", func(t *testing.T) {
		srv, adminCookie := newTestServer(t, nil)
		handler := http.Handler(srv)
		adminUser := rawPlatformUserByName(t, srv, "admin")

		setupRec := assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/setup", nil, adminCookie, http.StatusOK)
		var setup map[string]any
		decodeResponse(t, setupRec, &setup)
		secret, _ := setup["secret"].(string)
		enableRec := assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/enable", map[string]any{
			"secret":   secret,
			"mfa_code": totpCode(secret, time.Now().UTC()),
		}, adminCookie, http.StatusOK)
		var enabled map[string]any
		decodeResponse(t, enableRec, &enabled)
		recoveryCodes := stringSliceFromAny(enabled["recovery_codes"])
		if len(recoveryCodes) == 0 {
			t.Fatalf("MFA enable did not return recovery codes: %s", enableRec.Body.String())
		}

		loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusAccepted)
		var challenge map[string]any
		decodeResponse(t, loginRec, &challenge)
		token, _ := challenge["mfa_token"].(string)
		if token == "" {
			t.Fatalf("MFA login did not return challenge: %v", challenge)
		}

		removeBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "login_logs")
		completeRec := assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/complete-login", map[string]any{
			"token":         token,
			"recovery_code": recoveryCodes[0],
		}, nil, http.StatusInternalServerError)
		removeBlocker()
		if !strings.Contains(completeRec.Body.String(), "persist login log failed") {
			t.Fatalf("recovery MFA login log failure was not reported: %s", completeRec.Body.String())
		}
		if len(completeRec.Result().Cookies()) > 0 {
			t.Fatalf("recovery MFA completion issued cookies after failed login log write: %#v", completeRec.Result().Cookies())
		}
		profile, _, err := srv.cfg.Store.UserMFAProfile(adminUser.ID)
		if err != nil {
			t.Fatalf("load MFA profile after failed recovery login: %v", err)
		}
		if !profile.Enabled || profile.RecoveryCount != 8 {
			t.Fatalf("recovery MFA login did not restore consumed code after failed login log: %#v", profile)
		}

		retryLoginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusAccepted)
		decodeResponse(t, retryLoginRec, &challenge)
		retryToken, _ := challenge["mfa_token"].(string)
		retryRec := assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/complete-login", map[string]any{
			"token":         retryToken,
			"recovery_code": recoveryCodes[0],
		}, nil, http.StatusOK)
		if len(retryRec.Result().Cookies()) == 0 {
			t.Fatal("restored recovery code did not complete MFA login")
		}
		if !coreAuditLogsContainAction(srv.cfg.Store, "auth.login.log.persist_failed") {
			t.Fatal("recovery MFA login log persistence failure was not written to core audit logs")
		}
	})

	t.Run("recovery code restore failure", func(t *testing.T) {
		srv, adminCookie := newTestServer(t, nil)
		handler := http.Handler(srv)
		adminUser := rawPlatformUserByName(t, srv, "admin")

		setupRec := assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/setup", nil, adminCookie, http.StatusOK)
		var setup map[string]any
		decodeResponse(t, setupRec, &setup)
		secret, _ := setup["secret"].(string)
		enableRec := assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/enable", map[string]any{
			"secret":   secret,
			"mfa_code": totpCode(secret, time.Now().UTC()),
		}, adminCookie, http.StatusOK)
		var enabled map[string]any
		decodeResponse(t, enableRec, &enabled)
		recoveryCodes := stringSliceFromAny(enabled["recovery_codes"])
		if len(recoveryCodes) == 0 {
			t.Fatalf("MFA enable did not return recovery codes: %s", enableRec.Body.String())
		}

		loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusAccepted)
		var challenge map[string]any
		decodeResponse(t, loginRec, &challenge)
		token, _ := challenge["mfa_token"].(string)
		if token == "" {
			t.Fatalf("MFA login did not return challenge: %v", challenge)
		}

		removeLoginLogBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "login_logs")
		removeRestoreBlocker := blockPlatformItemSavePayloadFragment(t, srv.cfg.Store, "users", adminUser.ID, `"mfa_recovery_count":8`)
		restoreFailureRec := assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/complete-login", map[string]any{
			"token":         token,
			"recovery_code": recoveryCodes[0],
		}, nil, http.StatusInternalServerError)
		removeRestoreBlocker()
		removeLoginLogBlocker()
		if !strings.Contains(restoreFailureRec.Body.String(), "failed to restore MFA state") {
			t.Fatalf("recovery MFA restore failure was not reported: %s", restoreFailureRec.Body.String())
		}
		if len(restoreFailureRec.Result().Cookies()) > 0 {
			t.Fatalf("recovery MFA completion issued cookies after failed restore: %#v", restoreFailureRec.Result().Cookies())
		}
		if !coreAuditLogsContainAction(srv.cfg.Store, "auth.mfa.restore_failed") {
			t.Fatal("recovery MFA restore failure was not written to core audit logs")
		}
	})
}

func TestLoginMFAFailuresAccumulateAcrossPasswordChallenges(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	setupRec := assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/setup", nil, adminCookie, http.StatusOK)
	var setup map[string]any
	decodeResponse(t, setupRec, &setup)
	secret, _ := setup["secret"].(string)
	if secret == "" {
		t.Fatal("MFA setup did not return secret")
	}
	assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/enable", map[string]any{
		"secret":   secret,
		"mfa_code": totpCode(secret, time.Now().UTC()),
	}, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "MFA lock policy",
		"type":   "security",
		"status": "enabled",
		"metadata": map[string]any{
			"login_failure_threshold":      2,
			"login_failure_window_minutes": 30,
			"login_lock_minutes":           5,
		},
	}, adminCookie, http.StatusCreated)

	for attempt := 0; attempt < 2; attempt++ {
		loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusAccepted)
		var challenge map[string]any
		decodeResponse(t, loginRec, &challenge)
		token, _ := challenge["mfa_token"].(string)
		if token == "" {
			t.Fatalf("login attempt %d did not return MFA token: %v", attempt+1, challenge)
		}
		assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/complete-login", map[string]any{"token": token, "mfa_code": "000000"}, nil, http.StatusUnauthorized)
	}

	lockedRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusTooManyRequests)
	if lockedRec.Result().Header.Get("Retry-After") == "" {
		t.Fatal("MFA failure lock response did not include Retry-After")
	}
	locksRec := assertStatus(t, handler, http.MethodGet, "/api/admin/login-locked", nil, adminCookie, http.StatusOK)
	if !strings.Contains(locksRec.Body.String(), "admin") || !strings.Contains(locksRec.Body.String(), `"failure_count":2`) {
		t.Fatalf("MFA failures did not create expected login lock: %s", locksRec.Body.String())
	}
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
	assertStatus(t, handler, http.MethodPost, "/api/auth/mfa/complete-login", map[string]any{
		"token":    token,
		"mfa_code": totpCode(secret, time.Now().UTC()),
	}, nil, http.StatusUnauthorized)

	nextLoginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusAccepted)
	if !strings.Contains(nextLoginRec.Body.String(), `"mfa_required":true`) {
		t.Fatal("enrolled forced MFA account did not require MFA on next login")
	}
}

func TestOIDCProviderAuthorizationCodeFlow(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)

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
	if strings.Contains(clientRec.Body.String(), "client-secret") || strings.Contains(clientRec.Body.String(), "client_secret_hash") {
		t.Fatal("oidc client secret leaked in create response")
	}
	if !strings.Contains(clientRec.Body.String(), `"client_secret_set":true`) {
		t.Fatalf("oidc client create response did not expose secret-set state: %s", clientRec.Body.String())
	}
	var client model.PlatformItem
	decodeResponse(t, clientRec, &client)
	rawClient, ok, err := srv.cfg.Store.GetPlatformItem("oidc_clients", client.ID)
	if err != nil || !ok {
		t.Fatalf("load oidc client: ok=%v err=%v", ok, err)
	}
	if firstMetadataString(rawClient.Metadata, "client_secret_hash") == "" {
		t.Fatalf("confidential oidc client did not persist client secret hash: %#v", rawClient.Metadata)
	}
	if secretSet, ok := metadataBoolValue(rawClient.Metadata["client_secret_set"]); !ok || !secretSet {
		t.Fatalf("confidential oidc client did not expose secret-set metadata: %#v", rawClient.Metadata)
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
	postUserInfoRec := assertStatusWithHeaders(t, handler, http.MethodPost, "/api/oidc/userinfo", nil, nil, map[string]string{
		"Authorization": "bearer " + accessToken,
	}, http.StatusOK)
	var postUserInfo map[string]any
	decodeResponse(t, postUserInfoRec, &postUserInfo)
	role, _ := postUserInfo["role"].(string)
	if postUserInfo["preferred_username"] != "admin" || normalizeBuiltInRole(role) != roleSuperAdmin {
		t.Fatalf("post userinfo did not include signed-in user claims: %v", postUserInfo)
	}
	formUserInfoRec := assertFormStatus(t, handler, "/api/oidc/userinfo", url.Values{"access_token": {accessToken}}, nil, nil, http.StatusOK)
	if !strings.Contains(formUserInfoRec.Body.String(), `"preferred_username":"admin"`) || !strings.Contains(formUserInfoRec.Body.String(), `"sub"`) {
		t.Fatal("form userinfo did not include signed-in user claims")
	}
	assertStatusWithHeaders(t, handler, http.MethodGet, "/api/oidc/userinfo", nil, nil, map[string]string{
		"Authorization": "Bearer invalid",
	}, http.StatusUnauthorized)
	assertFormStatus(t, handler, "/api/oidc/userinfo", url.Values{"access_token": {"invalid"}}, nil, nil, http.StatusUnauthorized)

	clearedClientRec := assertStatus(t, handler, http.MethodPatch, "/api/admin/oidc-clients/"+client.ID, map[string]any{
		"name":   "openweb-test",
		"type":   "confidential",
		"status": "enabled",
		"metadata": map[string]any{
			"client_id":                  "openweb-test",
			"redirect_uris":              []string{"https://client.example/callback"},
			"scopes":                     []string{"openid", "profile", "email"},
			"token_endpoint_auth_method": "client_secret_basic",
			"client_secret_clear":        true,
		},
	}, adminCookie, http.StatusOK)
	if strings.Contains(clearedClientRec.Body.String(), "client-secret") || strings.Contains(clearedClientRec.Body.String(), "client_secret_hash") || strings.Contains(clearedClientRec.Body.String(), "client_secret_set") || strings.Contains(clearedClientRec.Body.String(), "client_secret_clear") {
		t.Fatalf("cleared oidc client response leaked or retained secret state: %s", clearedClientRec.Body.String())
	}
	rawClearedClient, ok, err := srv.cfg.Store.GetPlatformItem("oidc_clients", client.ID)
	if err != nil || !ok {
		t.Fatalf("load cleared oidc client: ok=%v err=%v", ok, err)
	}
	for _, key := range []string{"client_secret_hash", "client_secret_set", "client_secret_clear", "clear_client_secret"} {
		if _, exists := rawClearedClient.Metadata[key]; exists {
			t.Fatalf("cleared confidential oidc client retained %s: %#v", key, rawClearedClient.Metadata)
		}
	}

	clearedCodeVerifier := "cleared-verifier-1234567890"
	clearedChallengeRaw := sha256.Sum256([]byte(clearedCodeVerifier))
	clearedCodeChallenge := base64.RawURLEncoding.EncodeToString(clearedChallengeRaw[:])
	clearedAuthorizePath := "/api/oidc/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {"openweb-test"},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid profile"},
		"state":                 {"state-cleared"},
		"nonce":                 {"nonce-cleared"},
		"code_challenge":        {clearedCodeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()
	clearedAuthorizeRec := assertStatus(t, handler, http.MethodGet, clearedAuthorizePath, nil, adminCookie, http.StatusFound)
	clearedLocation, err := url.Parse(clearedAuthorizeRec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse cleared authorize redirect: %v", err)
	}
	clearedCode := clearedLocation.Query().Get("code")
	if clearedCode == "" {
		t.Fatal("cleared authorize redirect did not include code")
	}
	clearedTokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"openweb-test"},
		"code":          {clearedCode},
		"redirect_uri":  {redirectURI},
		"code_verifier": {clearedCodeVerifier},
	}
	assertFormStatus(t, handler, "/api/oidc/token", clearedTokenForm, nil, map[string]string{
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("openweb-test:client-secret")),
	}, http.StatusUnauthorized)
	assertFormStatus(t, handler, "/api/oidc/token", clearedTokenForm, nil, nil, http.StatusUnauthorized)

	publicClientRec := assertStatus(t, handler, http.MethodPatch, "/api/admin/oidc-clients/"+client.ID, map[string]any{
		"name":   "openweb-test",
		"type":   "public",
		"status": "enabled",
		"metadata": map[string]any{
			"client_id":                  "openweb-test",
			"redirect_uris":              []string{"https://client.example/callback"},
			"scopes":                     []string{"openid", "profile", "email"},
			"token_endpoint_auth_method": "none",
		},
	}, adminCookie, http.StatusOK)
	if strings.Contains(publicClientRec.Body.String(), "client-secret") || strings.Contains(publicClientRec.Body.String(), "client_secret_hash") || strings.Contains(publicClientRec.Body.String(), "client_secret_set") {
		t.Fatalf("public oidc client response leaked or retained secret state: %s", publicClientRec.Body.String())
	}
	rawPublicClient, ok, err := srv.cfg.Store.GetPlatformItem("oidc_clients", client.ID)
	if err != nil || !ok {
		t.Fatalf("load public oidc client: ok=%v err=%v", ok, err)
	}
	if firstMetadataString(rawPublicClient.Metadata, "client_secret_hash") != "" {
		t.Fatalf("public oidc client retained old secret hash: %#v", rawPublicClient.Metadata)
	}
	if secretSet, ok := metadataBoolValue(rawPublicClient.Metadata["client_secret_set"]); ok && secretSet {
		t.Fatalf("public oidc client retained secret-set metadata: %#v", rawPublicClient.Metadata)
	}

	publicNoPKCEAuthorizePath := "/api/oidc/authorize?" + url.Values{
		"response_type": {"code"},
		"client_id":     {"openweb-test"},
		"redirect_uri":  {redirectURI},
		"scope":         {"openid profile"},
		"state":         {"state-public-no-pkce"},
	}.Encode()
	publicNoPKCERec := assertStatus(t, handler, http.MethodGet, publicNoPKCEAuthorizePath, nil, adminCookie, http.StatusFound)
	publicNoPKCELocation, err := url.Parse(publicNoPKCERec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse public no-pkce authorize redirect: %v", err)
	}
	if publicNoPKCELocation.Query().Get("error") != "invalid_request" || publicNoPKCELocation.Query().Get("state") != "state-public-no-pkce" || publicNoPKCELocation.Query().Get("code") != "" {
		t.Fatalf("public client without PKCE redirect = %q", publicNoPKCELocation.String())
	}
	if !strings.Contains(publicNoPKCELocation.Query().Get("error_description"), "PKCE") {
		t.Fatalf("public client without PKCE error did not explain requirement: %q", publicNoPKCELocation.String())
	}

	publicCodeVerifier := "public-verifier-1234567890"
	publicChallengeRaw := sha256.Sum256([]byte(publicCodeVerifier))
	publicCodeChallenge := base64.RawURLEncoding.EncodeToString(publicChallengeRaw[:])
	publicAuthorizePath := "/api/oidc/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {"openweb-test"},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid profile"},
		"state":                 {"state-public"},
		"nonce":                 {"nonce-public"},
		"code_challenge":        {publicCodeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()
	publicAuthorizeRec := assertStatus(t, handler, http.MethodGet, publicAuthorizePath, nil, adminCookie, http.StatusFound)
	publicLocation, err := url.Parse(publicAuthorizeRec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse public authorize redirect: %v", err)
	}
	publicCode := publicLocation.Query().Get("code")
	if publicCode == "" {
		t.Fatal("public authorize redirect did not include code")
	}
	publicTokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"openweb-test"},
		"code":          {publicCode},
		"redirect_uri":  {redirectURI},
		"code_verifier": {publicCodeVerifier},
	}
	assertFormStatus(t, handler, "/api/oidc/token", publicTokenForm, nil, map[string]string{
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("openweb-test:client-secret")),
	}, http.StatusUnauthorized)
	publicTokenRec := assertFormStatus(t, handler, "/api/oidc/token", publicTokenForm, nil, nil, http.StatusOK)
	var publicTokenResponse map[string]any
	decodeResponse(t, publicTokenRec, &publicTokenResponse)
	if publicTokenResponse["access_token"] == "" || publicTokenResponse["token_type"] != "Bearer" {
		t.Fatalf("public oidc client token response missing access token: %v", publicTokenResponse)
	}
}

func TestOIDCTokenOperationLogPersistenceFailure(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)

	assertStatus(t, handler, http.MethodPost, "/api/admin/oidc-clients", map[string]any{
		"name":   "blocked-token-client",
		"type":   "public",
		"status": "enabled",
		"metadata": map[string]any{
			"client_id":                  "blocked-token-client",
			"redirect_uris":              []string{"https://client.example/blocked-callback"},
			"scopes":                     []string{"openid", "profile"},
			"token_endpoint_auth_method": "none",
		},
	}, adminCookie, http.StatusCreated)

	codeVerifier := "blocked-verifier-1234567890"
	challengeRaw := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(challengeRaw[:])
	redirectURI := "https://client.example/blocked-callback"
	authorizePath := "/api/oidc/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {"blocked-token-client"},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid profile"},
		"state":                 {"blocked-token-state"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()
	authorizeRec := assertStatus(t, handler, http.MethodGet, authorizePath, nil, adminCookie, http.StatusFound)
	location, err := url.Parse(authorizeRec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse blocked token authorize redirect: %v", err)
	}
	code := location.Query().Get("code")
	if code == "" {
		t.Fatal("blocked token authorize redirect did not include code")
	}

	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"blocked-token-client"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
	}
	removeBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	tokenRec := assertFormStatus(t, handler, "/api/oidc/token", tokenForm, nil, nil, http.StatusInternalServerError)
	removeBlocker()
	body := tokenRec.Body.String()
	if !strings.Contains(body, "persist operation log failed") {
		t.Fatalf("oidc token operation log failure was not reported: %s", body)
	}
	if strings.Contains(body, "access_token") || strings.Contains(body, "id_token") {
		t.Fatalf("oidc token response included tokens after operation log failure: %s", body)
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "operation.log.persist_failed") {
		t.Fatal("oidc token operation log persistence failure was not written to core audit logs")
	}
	retryRec := assertFormStatus(t, handler, "/api/oidc/token", tokenForm, nil, nil, http.StatusOK)
	var retryPayload map[string]any
	decodeResponse(t, retryRec, &retryPayload)
	if retryPayload["access_token"] == "" || retryPayload["id_token"] == "" {
		t.Fatalf("oidc token retry after operation log failure did not issue tokens: %v", retryPayload)
	}
	assertFormStatus(t, handler, "/api/oidc/token", tokenForm, nil, nil, http.StatusBadRequest)
}

func TestOIDCUserInfoRejectsDisabledClientAndUser(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	clientRec := assertStatus(t, handler, http.MethodPost, "/api/admin/oidc-clients", map[string]any{
		"name":     "userinfo-client",
		"type":     "confidential",
		"status":   "enabled",
		"password": "client-secret",
		"metadata": map[string]any{
			"client_id":     "userinfo-client",
			"redirect_uris": []string{"https://client.example/callback"},
			"scopes":        []string{"openid", "profile"},
		},
	}, adminCookie, http.StatusCreated)
	var client model.PlatformItem
	decodeResponse(t, clientRec, &client)

	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "oidc-userinfo-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)
	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username": "oidc-userinfo-user",
		"password": "password123",
	}, nil, http.StatusOK)
	userCookie := loginRec.Result().Cookies()[0]

	redirectURI := "https://client.example/callback"
	issueToken := func() string {
		authorizePath := "/api/oidc/authorize?" + url.Values{
			"response_type": {"code"},
			"client_id":     {"userinfo-client"},
			"redirect_uri":  {redirectURI},
			"scope":         {"openid profile"},
			"state":         {"state-userinfo"},
		}.Encode()
		authorizeRec := assertStatus(t, handler, http.MethodGet, authorizePath, nil, userCookie, http.StatusFound)
		location, err := url.Parse(authorizeRec.Header().Get("Location"))
		if err != nil {
			t.Fatalf("parse authorize redirect: %v", err)
		}
		code := location.Query().Get("code")
		if code == "" {
			t.Fatal("authorize redirect did not include code")
		}
		tokenRec := assertFormStatus(t, handler, "/api/oidc/token", url.Values{
			"grant_type":   {"authorization_code"},
			"code":         {code},
			"redirect_uri": {redirectURI},
		}, nil, map[string]string{
			"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("userinfo-client:client-secret")),
		}, http.StatusOK)
		var tokenResponse map[string]any
		decodeResponse(t, tokenRec, &tokenResponse)
		accessToken, _ := tokenResponse["access_token"].(string)
		if accessToken == "" {
			t.Fatalf("token response missing access token: %v", tokenResponse)
		}
		return accessToken
	}

	clientToken := issueToken()
	assertStatusWithHeaders(t, handler, http.MethodGet, "/api/oidc/userinfo", nil, nil, map[string]string{
		"Authorization": "Bearer " + clientToken,
	}, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, "/api/admin/oidc-clients/"+client.ID, map[string]any{
		"status": "disabled",
	}, adminCookie, http.StatusOK)
	assertStatusWithHeaders(t, handler, http.MethodGet, "/api/oidc/userinfo", nil, nil, map[string]string{
		"Authorization": "Bearer " + clientToken,
	}, http.StatusUnauthorized)

	assertStatus(t, handler, http.MethodPatch, "/api/admin/oidc-clients/"+client.ID, map[string]any{
		"status": "enabled",
	}, adminCookie, http.StatusOK)
	userToken := issueToken()
	assertStatus(t, handler, http.MethodPatch, "/api/admin/users/"+user.ID, map[string]any{
		"status": "disabled",
	}, adminCookie, http.StatusOK)
	assertStatusWithHeaders(t, handler, http.MethodGet, "/api/oidc/userinfo", nil, nil, map[string]string{
		"Authorization": "Bearer " + userToken,
	}, http.StatusUnauthorized)
}

func TestExternalOIDCLoginCreatesUserAndSession(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)
	var authorizeState string
	var authorizeNonce string
	var tokenEndpointCalls int
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
			tokenEndpointCalls++
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

	settingRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
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
	var setting model.PlatformItem
	decodeResponse(t, settingRec, &setting)
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
	if tokenEndpointCalls != 1 {
		t.Fatalf("oidc token endpoint calls = %d, want 1", tokenEndpointCalls)
	}
	assertStatus(t, handler, http.MethodGet, callbackURL.RequestURI(), nil, nil, http.StatusBadRequest)
	if tokenEndpointCalls != 1 {
		t.Fatalf("replayed oidc callback reached provider token endpoint again: calls = %d", tokenEndpointCalls)
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

	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+setting.ID, map[string]any{
		"metadata": map[string]any{
			"oidc_login_enabled":          true,
			"oidc_provider_id":            "fake-sso",
			"oidc_provider_name":          "Fake SSO",
			"oidc_authorization_endpoint": provider.URL + "/authorize",
			"oidc_token_endpoint":         provider.URL + "/token",
			"oidc_userinfo_endpoint":      provider.URL + "/userinfo",
			"oidc_client_id":              "openweb-client",
			"oidc_client_secret_clear":    true,
			"oidc_scopes":                 []string{"openid", "profile", "email"},
			"oidc_role":                   "user",
		},
	}, adminCookie, http.StatusOK)
	rawSetting, ok, err := srv.cfg.Store.GetPlatformItem("system_settings", setting.ID)
	if err != nil || !ok {
		t.Fatalf("get raw oidc setting after clear ok=%v err=%v", ok, err)
	}
	for _, key := range []string{"oidc_client_secret_encrypted", "oidc_client_secret_set", "oidc_client_secret_updated_at", "oidc_client_secret_clear"} {
		if _, exists := rawSetting.Metadata[key]; exists {
			t.Fatalf("cleared oidc setting still has %s in raw metadata: %#v", key, rawSetting.Metadata)
		}
	}
	clearedProviders, err := srv.externalOIDCProvidersFromMetadata(rawSetting.Metadata)
	if err != nil {
		t.Fatalf("parse cleared oidc providers: %v", err)
	}
	if len(clearedProviders) != 1 || clearedProviders[0].ClientSecret != "" {
		t.Fatalf("cleared oidc provider should keep config without old secret: %#v", clearedProviders)
	}
	clearedSettingsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/system-settings", nil, adminCookie, http.StatusOK)
	for _, leaked := range []string{"openweb-secret", "oidc_client_secret_encrypted", "oidc_client_secret_clear"} {
		if strings.Contains(clearedSettingsRec.Body.String(), leaked) {
			t.Fatalf("cleared oidc settings leaked sensitive value %q: %s", leaked, clearedSettingsRec.Body.String())
		}
	}
}

func TestExternalOIDCLoginLogFailureRollsBackAutoCreatedUser(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)
	var tokenEndpointCalls int
	var stateNonce string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenEndpointCalls++
			writeJSON(w, http.StatusOK, map[string]any{"access_token": "rollback-access", "token_type": "Bearer", "expires_in": 300})
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer rollback-access" {
				http.Error(w, "bad bearer", http.StatusUnauthorized)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"sub":                "rollback-subject",
				"preferred_username": "oidc-rollback-user",
				"nonce":              stateNonce,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "External OIDC rollback",
		"type":   "identity",
		"status": "enabled",
		"metadata": map[string]any{
			"oidc_login_enabled":          true,
			"oidc_provider_id":            "rollback-sso",
			"oidc_provider_name":          "Rollback SSO",
			"oidc_authorization_endpoint": provider.URL + "/authorize",
			"oidc_token_endpoint":         provider.URL + "/token",
			"oidc_userinfo_endpoint":      provider.URL + "/userinfo",
			"oidc_client_id":              "openweb-client",
			"oidc_client_secret":          "openweb-secret",
			"oidc_scopes":                 []string{"openid", "profile"},
			"oidc_role":                   "user",
		},
	}, adminCookie, http.StatusCreated)
	state, nonce, err := srv.auth.createExternalOIDCState("rollback-sso", "/app/access")
	if err != nil {
		t.Fatalf("create external oidc state: %v", err)
	}
	stateNonce = nonce

	removeBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "login_logs")
	callbackRec := assertStatus(t, handler, http.MethodGet, "/api/auth/oidc/callback?state="+url.QueryEscape(state)+"&code=rollback-code", nil, nil, http.StatusInternalServerError)
	removeBlocker()
	if !strings.Contains(callbackRec.Body.String(), "persist login log failed") {
		t.Fatalf("oidc login log failure was not reported: %s", callbackRec.Body.String())
	}
	if len(callbackRec.Result().Cookies()) > 0 {
		t.Fatalf("oidc callback issued cookies after failed login log write: %#v", callbackRec.Result().Cookies())
	}
	if tokenEndpointCalls != 1 {
		t.Fatalf("oidc token endpoint calls = %d, want 1", tokenEndpointCalls)
	}
	usersRec := assertStatus(t, handler, http.MethodGet, "/api/admin/users", nil, adminCookie, http.StatusOK)
	if strings.Contains(usersRec.Body.String(), "oidc-rollback-user") || strings.Contains(usersRec.Body.String(), "rollback-subject") {
		t.Fatalf("oidc auto-created user survived failed login log write: %s", usersRec.Body.String())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "auth.login.log.persist_failed") {
		t.Fatal("oidc login log persistence failure was not written to core audit logs")
	}

	state, nonce, err = srv.auth.createExternalOIDCState("rollback-sso", "/app/access")
	if err != nil {
		t.Fatalf("create external oidc state for restore failure: %v", err)
	}
	stateNonce = nonce
	removeBlocker = blockPlatformItemCreate(t, srv.cfg.Store, "login_logs")
	removeRestoreBlocker := blockPlatformItemDeletePayloadFragment(t, srv.cfg.Store, "users", `"external_subject":"rollback-subject"`)
	restoreFailureRec := assertStatus(t, handler, http.MethodGet, "/api/auth/oidc/callback?state="+url.QueryEscape(state)+"&code=rollback-code", nil, nil, http.StatusInternalServerError)
	removeRestoreBlocker()
	removeBlocker()
	if !strings.Contains(restoreFailureRec.Body.String(), "failed to remove external user after login log failure") {
		t.Fatalf("oidc external user restore failure was not reported: %s", restoreFailureRec.Body.String())
	}
	if len(restoreFailureRec.Result().Cookies()) > 0 {
		t.Fatalf("oidc callback issued cookies after failed external user restore: %#v", restoreFailureRec.Result().Cookies())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "auth.external_user.restore_failed") {
		t.Fatal("oidc external user restore failure was not written to core audit logs")
	}
}

func TestExternalOIDCLoginStateFailureRollsBackAutoCreatedUser(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)
	var tokenEndpointCalls int
	var stateNonce string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenEndpointCalls++
			writeJSON(w, http.StatusOK, map[string]any{"access_token": "state-rollback-access", "token_type": "Bearer", "expires_in": 300})
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer state-rollback-access" {
				http.Error(w, "bad bearer", http.StatusUnauthorized)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"sub":                "state-rollback-subject",
				"preferred_username": "oidc-state-rollback-user",
				"nonce":              stateNonce,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "External OIDC state rollback",
		"type":   "identity",
		"status": "enabled",
		"metadata": map[string]any{
			"oidc_login_enabled":          true,
			"oidc_provider_id":            "state-rollback-sso",
			"oidc_provider_name":          "State Rollback SSO",
			"oidc_authorization_endpoint": provider.URL + "/authorize",
			"oidc_token_endpoint":         provider.URL + "/token",
			"oidc_userinfo_endpoint":      provider.URL + "/userinfo",
			"oidc_client_id":              "openweb-client",
			"oidc_client_secret":          "openweb-secret",
			"oidc_scopes":                 []string{"openid", "profile"},
			"oidc_role":                   "user",
		},
	}, adminCookie, http.StatusCreated)
	state, nonce, err := srv.auth.createExternalOIDCState("state-rollback-sso", "/app/access")
	if err != nil {
		t.Fatalf("create external oidc state: %v", err)
	}
	stateNonce = nonce

	removeBlocker := blockPlatformCollectionSavePayloadFragment(t, srv.cfg.Store, "users", `"online":true`)
	callbackRec := assertStatus(t, handler, http.MethodGet, "/api/auth/oidc/callback?state="+url.QueryEscape(state)+"&code=state-rollback-code", nil, nil, http.StatusInternalServerError)
	removeBlocker()
	if !strings.Contains(callbackRec.Body.String(), "persist user login state failed") {
		t.Fatalf("oidc login state failure was not reported: %s", callbackRec.Body.String())
	}
	if len(callbackRec.Result().Cookies()) > 0 {
		t.Fatalf("oidc callback issued cookies after failed login state write: %#v", callbackRec.Result().Cookies())
	}
	if tokenEndpointCalls != 1 {
		t.Fatalf("oidc token endpoint calls = %d, want 1", tokenEndpointCalls)
	}
	assertNoAuthSessionForUsername(t, srv, "oidc-state-rollback-user")
	usersRec := assertStatus(t, handler, http.MethodGet, "/api/admin/users", nil, adminCookie, http.StatusOK)
	if strings.Contains(usersRec.Body.String(), "oidc-state-rollback-user") || strings.Contains(usersRec.Body.String(), "state-rollback-subject") {
		t.Fatalf("oidc auto-created user survived failed login state write: %s", usersRec.Body.String())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "auth.login.state.persist_failed") {
		t.Fatal("oidc login state persistence failure was not written to core audit logs")
	}

	state, nonce, err = srv.auth.createExternalOIDCState("state-rollback-sso", "/app/access")
	if err != nil {
		t.Fatalf("create external oidc state for retry: %v", err)
	}
	stateNonce = nonce
	retryRec := assertStatus(t, handler, http.MethodGet, "/api/auth/oidc/callback?state="+url.QueryEscape(state)+"&code=state-rollback-code", nil, nil, http.StatusFound)
	if retryRec.Header().Get("Location") != "/app/access" {
		t.Fatalf("oidc retry did not redirect to requested next path: %s", retryRec.Header().Get("Location"))
	}
	if len(retryRec.Result().Cookies()) == 0 {
		t.Fatal("oidc retry after login state failure did not set auth cookie")
	}
}

func TestExternalOIDCCallbackAutoCreateDisabledIsAudited(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)
	var tokenEndpointCalls int
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenEndpointCalls++
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			clientID, clientSecret, _ := r.BasicAuth()
			if clientID != "openweb-client" || clientSecret != "openweb-secret" || r.PostForm.Get("code") != "denied-code" {
				http.Error(w, "bad token request", http.StatusUnauthorized)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"access_token": "denied-access", "token_type": "Bearer", "expires_in": 300})
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer denied-access" {
				http.Error(w, "bad bearer", http.StatusUnauthorized)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"sub":                "external-denied-subject",
				"preferred_username": "oidc-denied",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "External OIDC deny auto create",
		"type":   "identity",
		"status": "enabled",
		"metadata": map[string]any{
			"oidc_login_enabled":          true,
			"oidc_provider_id":            "deny-sso",
			"oidc_provider_name":          "Deny SSO",
			"oidc_authorization_endpoint": provider.URL + "/authorize",
			"oidc_token_endpoint":         provider.URL + "/token",
			"oidc_userinfo_endpoint":      provider.URL + "/userinfo",
			"oidc_client_id":              "openweb-client",
			"oidc_client_secret":          "openweb-secret",
			"oidc_scopes":                 []string{"openid", "profile"},
			"oidc_role":                   "user",
			"oidc_auto_create":            false,
		},
	}, adminCookie, http.StatusCreated)
	state, _, err := srv.auth.createExternalOIDCState("deny-sso", "/app/access")
	if err != nil {
		t.Fatalf("create external oidc state: %v", err)
	}
	deniedRec := assertStatus(t, handler, http.MethodGet, "/api/auth/oidc/callback?state="+url.QueryEscape(state)+"&code=denied-code", nil, nil, http.StatusForbidden)
	if !strings.Contains(deniedRec.Body.String(), "auto creation is disabled") {
		t.Fatalf("oidc auto-create denial response missing reason: %s", deniedRec.Body.String())
	}
	if tokenEndpointCalls != 1 {
		t.Fatalf("oidc token endpoint calls = %d, want 1", tokenEndpointCalls)
	}
	usersRec := assertStatus(t, handler, http.MethodGet, "/api/admin/users", nil, adminCookie, http.StatusOK)
	if strings.Contains(usersRec.Body.String(), "oidc-denied") {
		t.Fatalf("oidc auto-create disabled still created user: %s", usersRec.Body.String())
	}
	loginLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/login-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(loginLogsRec.Body.String(), `"type":"oidc"`) || !strings.Contains(loginLogsRec.Body.String(), `"status":"failed"`) || !strings.Contains(loginLogsRec.Body.String(), "deny-sso") || !strings.Contains(loginLogsRec.Body.String(), "auto creation is disabled") {
		t.Fatalf("oidc failed login log missing denial details: %s", loginLogsRec.Body.String())
	}
	operationLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(operationLogsRec.Body.String(), "auth.oidc.login_failed") {
		t.Fatalf("oidc failed login audit missing: %s", operationLogsRec.Body.String())
	}
}

func TestExternalOIDCCallbackProviderErrorConsumesStateAndAudits(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "External OIDC provider error",
		"type":   "identity",
		"status": "enabled",
		"metadata": map[string]any{
			"oidc_login_enabled":          true,
			"oidc_provider_id":            "error-sso",
			"oidc_provider_name":          "Error SSO",
			"oidc_authorization_endpoint": "https://sso.example.test/authorize",
			"oidc_token_endpoint":         "https://sso.example.test/token",
			"oidc_userinfo_endpoint":      "https://sso.example.test/userinfo",
			"oidc_client_id":              "openweb-client",
			"oidc_client_secret":          "openweb-secret",
			"oidc_scopes":                 []string{"openid", "profile"},
		},
	}, adminCookie, http.StatusCreated)
	state, _, err := srv.auth.createExternalOIDCState("error-sso", "/app/access")
	if err != nil {
		t.Fatalf("create external oidc state: %v", err)
	}
	failedRec := assertStatus(t, handler, http.MethodGet, "/api/auth/oidc/callback?state="+url.QueryEscape(state)+"&error=access_denied", nil, nil, http.StatusBadRequest)
	if !strings.Contains(failedRec.Body.String(), "oidc provider returned error: access_denied") {
		t.Fatalf("oidc provider error response missing reason: %s", failedRec.Body.String())
	}
	reuseRec := assertStatus(t, handler, http.MethodGet, "/api/auth/oidc/callback?state="+url.QueryEscape(state)+"&code=reused-code", nil, nil, http.StatusBadRequest)
	if !strings.Contains(reuseRec.Body.String(), "oidc state is invalid or expired") {
		t.Fatalf("oidc provider error did not consume state: %s", reuseRec.Body.String())
	}
	loginLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/login-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(loginLogsRec.Body.String(), `"type":"oidc"`) || !strings.Contains(loginLogsRec.Body.String(), `"status":"failed"`) || !strings.Contains(loginLogsRec.Body.String(), "error-sso") || !strings.Contains(loginLogsRec.Body.String(), "access_denied") {
		t.Fatalf("oidc provider error login log missing details: %s", loginLogsRec.Body.String())
	}
	operationLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(operationLogsRec.Body.String(), "auth.oidc.login_failed") || !strings.Contains(operationLogsRec.Body.String(), "access_denied") {
		t.Fatalf("oidc provider error operation audit missing: %s", operationLogsRec.Body.String())
	}
}

func TestExternalOIDCCallbackTokenFailureIsAuditedAndRedacted(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)
	clientSecret := "openweb secret+/=?:&"
	escapedClientSecret := url.QueryEscape(clientSecret)
	var tokenEndpointCalls int
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		tokenEndpointCalls++
		http.Error(w, "provider down with "+clientSecret+" and "+escapedClientSecret, http.StatusBadGateway)
	}))
	defer provider.Close()

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "External OIDC token failure",
		"type":   "identity",
		"status": "enabled",
		"metadata": map[string]any{
			"oidc_login_enabled":          true,
			"oidc_provider_id":            "broken-sso",
			"oidc_provider_name":          "Broken SSO",
			"oidc_authorization_endpoint": provider.URL + "/authorize",
			"oidc_token_endpoint":         provider.URL + "/token",
			"oidc_userinfo_endpoint":      provider.URL + "/userinfo",
			"oidc_client_id":              "openweb-client",
			"oidc_client_secret":          clientSecret,
			"oidc_scopes":                 []string{"openid", "profile"},
		},
	}, adminCookie, http.StatusCreated)
	state, _, err := srv.auth.createExternalOIDCState("broken-sso", "/app/access")
	if err != nil {
		t.Fatalf("create external oidc state: %v", err)
	}
	failedRec := assertStatus(t, handler, http.MethodGet, "/api/auth/oidc/callback?state="+url.QueryEscape(state)+"&code=broken-code", nil, nil, http.StatusBadGateway)
	if !strings.Contains(failedRec.Body.String(), "provider down") || strings.Contains(failedRec.Body.String(), clientSecret) || strings.Contains(failedRec.Body.String(), escapedClientSecret) {
		t.Fatalf("oidc token failure response missing sanitized reason or leaked secret: %s", failedRec.Body.String())
	}
	if tokenEndpointCalls != 1 {
		t.Fatalf("oidc token endpoint calls = %d, want 1", tokenEndpointCalls)
	}
	loginLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/login-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(loginLogsRec.Body.String(), `"type":"oidc"`) || !strings.Contains(loginLogsRec.Body.String(), `"status":"failed"`) || !strings.Contains(loginLogsRec.Body.String(), "broken-sso") || !strings.Contains(loginLogsRec.Body.String(), "provider down") || strings.Contains(loginLogsRec.Body.String(), clientSecret) || strings.Contains(loginLogsRec.Body.String(), escapedClientSecret) {
		t.Fatalf("oidc token failure log missing details or leaked secret: %s", loginLogsRec.Body.String())
	}
	operationLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(operationLogsRec.Body.String(), "auth.oidc.login_failed") || strings.Contains(operationLogsRec.Body.String(), clientSecret) || strings.Contains(operationLogsRec.Body.String(), escapedClientSecret) {
		t.Fatalf("oidc token failure audit missing or leaked secret: %s", operationLogsRec.Body.String())
	}
}

func TestExternalOIDCLoginUsesVerifiedIDTokenWhenUserInfoAbsent(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)
	signer := newOIDCManager()
	var providerURL string
	var expectedNonce string
	var tokenEndpointCalls int
	var jwksEndpointCalls int
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenEndpointCalls++
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			clientID, clientSecret, _ := r.BasicAuth()
			if clientID != "openweb-client" || clientSecret != "openweb-secret" || r.PostForm.Get("code") != "id-token-code" {
				http.Error(w, "bad token request", http.StatusUnauthorized)
				return
			}
			idToken, err := signer.signJWT(map[string]any{
				"iss":                providerURL,
				"sub":                "external-idtoken-subject",
				"aud":                "openweb-client",
				"exp":                time.Now().UTC().Add(5 * time.Minute).Unix(),
				"iat":                time.Now().UTC().Unix(),
				"nonce":              expectedNonce,
				"preferred_username": "oidc-idtoken-user",
				"name":               "OIDC ID Token User",
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"access_token": "id-token-access", "token_type": "Bearer", "expires_in": 300, "id_token": idToken})
		case "/jwks":
			jwksEndpointCalls++
			writeJSON(w, http.StatusOK, externalOIDCTestJWKS(signer))
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	providerURL = provider.URL

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "External OIDC id token",
		"type":   "identity",
		"status": "enabled",
		"metadata": map[string]any{
			"oidc_login_enabled":          true,
			"oidc_provider_id":            "id-token-sso",
			"oidc_provider_name":          "ID Token SSO",
			"oidc_issuer":                 provider.URL,
			"oidc_authorization_endpoint": provider.URL + "/authorize",
			"oidc_token_endpoint":         provider.URL + "/token",
			"oidc_jwks_uri":               provider.URL + "/jwks",
			"oidc_client_id":              "openweb-client",
			"oidc_client_secret":          "openweb-secret",
			"oidc_scopes":                 []string{"openid", "profile"},
			"oidc_role":                   "user",
		},
	}, adminCookie, http.StatusCreated)
	state, nonce, err := srv.auth.createExternalOIDCState("id-token-sso", "/app/access")
	if err != nil {
		t.Fatalf("create external oidc state: %v", err)
	}
	expectedNonce = nonce
	callbackRec := assertStatus(t, handler, http.MethodGet, "/api/auth/oidc/callback?state="+url.QueryEscape(state)+"&code=id-token-code", nil, nil, http.StatusFound)
	if callbackRec.Header().Get("Location") != "/app/access" {
		t.Fatalf("callback did not redirect to requested next path: %s", callbackRec.Header().Get("Location"))
	}
	if tokenEndpointCalls != 1 {
		t.Fatalf("oidc token endpoint calls = %d, want 1", tokenEndpointCalls)
	}
	if jwksEndpointCalls != 1 {
		t.Fatalf("oidc jwks endpoint calls = %d, want 1", jwksEndpointCalls)
	}
	cookies := callbackRec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("callback did not set auth cookie")
	}
	meRec := assertStatus(t, handler, http.MethodGet, "/api/auth/me", nil, cookies[0], http.StatusOK)
	if !strings.Contains(meRec.Body.String(), `"username":"oidc-idtoken-user"`) || !strings.Contains(meRec.Body.String(), `"role":"user"`) {
		t.Fatalf("verified id_token login did not create authenticated user: %s", meRec.Body.String())
	}
}

func TestExternalOIDCIDTokenValidationRejectsTamperedSignature(t *testing.T) {
	signer := newOIDCManager()
	var providerURL string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks" {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, externalOIDCTestJWKS(signer))
	}))
	defer provider.Close()
	providerURL = provider.URL

	idToken, err := signer.signJWT(map[string]any{
		"iss":   providerURL,
		"sub":   "external-tampered-subject",
		"aud":   "openweb-client",
		"exp":   time.Now().UTC().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().UTC().Unix(),
		"nonce": "nonce-1",
	})
	if err != nil {
		t.Fatalf("sign id_token: %v", err)
	}
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("signed id_token parts = %d, want 3", len(parts))
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode id_token signature: %v", err)
	}
	signature[0] ^= 0xff
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	tampered := strings.Join(parts, ".")
	_, err = verifyExternalOIDCIDToken(http.Client{Timeout: time.Second}, externalOIDCProvider{
		Issuer:       provider.URL,
		JWKSEndpoint: provider.URL + "/jwks",
		ClientID:     "openweb-client",
	}, tampered, "nonce-1")
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("tampered id_token was not rejected by signature validation: %v", err)
	}
}

func TestExternalOIDCCallbackRejectsIDTokenMissingNonce(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)
	signer := newOIDCManager()
	var providerURL string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			idToken, err := signer.signJWT(map[string]any{
				"iss":                providerURL,
				"sub":                "external-missing-nonce-subject",
				"aud":                "openweb-client",
				"exp":                time.Now().UTC().Add(5 * time.Minute).Unix(),
				"iat":                time.Now().UTC().Unix(),
				"preferred_username": "oidc-missing-nonce",
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"access_token": "missing-nonce-access", "token_type": "Bearer", "expires_in": 300, "id_token": idToken})
		case "/jwks":
			writeJSON(w, http.StatusOK, externalOIDCTestJWKS(signer))
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	providerURL = provider.URL

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "External OIDC missing nonce",
		"type":   "identity",
		"status": "enabled",
		"metadata": map[string]any{
			"oidc_login_enabled":          true,
			"oidc_provider_id":            "missing-nonce-sso",
			"oidc_provider_name":          "Missing Nonce SSO",
			"oidc_issuer":                 provider.URL,
			"oidc_authorization_endpoint": provider.URL + "/authorize",
			"oidc_token_endpoint":         provider.URL + "/token",
			"oidc_jwks_uri":               provider.URL + "/jwks",
			"oidc_client_id":              "openweb-client",
			"oidc_client_secret":          "openweb-secret",
			"oidc_scopes":                 []string{"openid", "profile"},
		},
	}, adminCookie, http.StatusCreated)
	state, _, err := srv.auth.createExternalOIDCState("missing-nonce-sso", "/app/access")
	if err != nil {
		t.Fatalf("create external oidc state: %v", err)
	}
	failedRec := assertStatus(t, handler, http.MethodGet, "/api/auth/oidc/callback?state="+url.QueryEscape(state)+"&code=missing-nonce-code", nil, nil, http.StatusBadGateway)
	if !strings.Contains(failedRec.Body.String(), "nonce mismatch") {
		t.Fatalf("missing nonce failure response did not explain nonce validation: %s", failedRec.Body.String())
	}
	usersRec := assertStatus(t, handler, http.MethodGet, "/api/admin/users", nil, adminCookie, http.StatusOK)
	if strings.Contains(usersRec.Body.String(), "oidc-missing-nonce") {
		t.Fatalf("missing nonce id_token created user: %s", usersRec.Body.String())
	}
}

func TestExternalOIDCCallbackDoesNotFallbackToIDTokenWhenUserInfoFails(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)
	signer := newOIDCManager()
	var providerURL string
	var expectedNonce string
	var jwksEndpointCalls int
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			idToken, err := signer.signJWT(map[string]any{
				"iss":                providerURL,
				"sub":                "external-fallback-subject",
				"aud":                "openweb-client",
				"exp":                time.Now().UTC().Add(5 * time.Minute).Unix(),
				"iat":                time.Now().UTC().Unix(),
				"nonce":              expectedNonce,
				"preferred_username": "oidc-fallback-user",
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"access_token": "fallback-access", "token_type": "Bearer", "expires_in": 300, "id_token": idToken})
		case "/userinfo":
			http.Error(w, "userinfo down", http.StatusInternalServerError)
		case "/jwks":
			jwksEndpointCalls++
			writeJSON(w, http.StatusOK, externalOIDCTestJWKS(signer))
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	providerURL = provider.URL

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "External OIDC userinfo failure",
		"type":   "identity",
		"status": "enabled",
		"metadata": map[string]any{
			"oidc_login_enabled":          true,
			"oidc_provider_id":            "userinfo-failure-sso",
			"oidc_provider_name":          "UserInfo Failure SSO",
			"oidc_issuer":                 provider.URL,
			"oidc_authorization_endpoint": provider.URL + "/authorize",
			"oidc_token_endpoint":         provider.URL + "/token",
			"oidc_userinfo_endpoint":      provider.URL + "/userinfo",
			"oidc_jwks_uri":               provider.URL + "/jwks",
			"oidc_client_id":              "openweb-client",
			"oidc_client_secret":          "openweb-secret",
			"oidc_scopes":                 []string{"openid", "profile"},
		},
	}, adminCookie, http.StatusCreated)
	state, nonce, err := srv.auth.createExternalOIDCState("userinfo-failure-sso", "/app/access")
	if err != nil {
		t.Fatalf("create external oidc state: %v", err)
	}
	expectedNonce = nonce
	failedRec := assertStatus(t, handler, http.MethodGet, "/api/auth/oidc/callback?state="+url.QueryEscape(state)+"&code=fallback-code", nil, nil, http.StatusBadGateway)
	if !strings.Contains(failedRec.Body.String(), "userinfo failed") {
		t.Fatalf("userinfo failure response did not explain failure: %s", failedRec.Body.String())
	}
	if jwksEndpointCalls != 0 {
		t.Fatalf("userinfo failure fell back to id_token and fetched jwks: calls = %d", jwksEndpointCalls)
	}
	usersRec := assertStatus(t, handler, http.MethodGet, "/api/admin/users", nil, adminCookie, http.StatusOK)
	if strings.Contains(usersRec.Body.String(), "oidc-fallback-user") {
		t.Fatalf("userinfo failure fallback created user: %s", usersRec.Body.String())
	}
}

func externalOIDCTestJWKS(signer *oidcManager) map[string]any {
	publicKey := signer.privateKey.Public().(*rsa.PublicKey)
	return map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"use": "sig",
			"kid": signer.keyID,
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
		}},
	}
}

func TestOIDCIntegrationAuthorizationEndpointTest(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	clientSecret := "openweb secret+/=?:&"
	escapedClientSecret := url.QueryEscape(clientSecret)
	var gotClientID string
	var gotRedirectURI string
	var gotScope string
	var gotState string
	var gotNonce string
	var authorizeCalls int
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			authorizeCalls++
			query := r.URL.Query()
			gotClientID = query.Get("client_id")
			gotRedirectURI = query.Get("redirect_uri")
			gotScope = query.Get("scope")
			gotState = query.Get("state")
			gotNonce = query.Get("nonce")
			if query.Get("response_type") != "code" || gotClientID != "openweb-client" || !strings.Contains(gotRedirectURI, "/api/auth/oidc/callback") || gotScope != "openid profile email" {
				http.Error(w, "bad authorize request", http.StatusBadRequest)
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
		case "/bad-authorize":
			http.Error(w, "invalid client secret "+clientSecret+" encoded "+escapedClientSecret, http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	settingRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "External OIDC identity",
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
			"oidc_client_secret":          clientSecret,
			"oidc_scopes":                 []string{"openid", "profile", "email"},
			"oidc_role":                   "user",
		},
	}, adminCookie, http.StatusCreated)
	var setting model.PlatformItem
	decodeResponse(t, settingRec, &setting)

	settingsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/system-settings", nil, adminCookie, http.StatusOK)
	for _, leaked := range []string{clientSecret, escapedClientSecret, "oidc_client_secret_encrypted", "client_secret_encrypted"} {
		if strings.Contains(settingsRec.Body.String(), leaked) {
			t.Fatalf("oidc settings leaked sensitive value %q: %s", leaked, settingsRec.Body.String())
		}
	}
	testRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/oidc/test", map[string]any{
		"setting_id": setting.ID,
	}, adminCookie, http.StatusOK)
	if gotClientID != "openweb-client" || !strings.Contains(gotRedirectURI, "/api/auth/oidc/callback") || gotScope != "openid profile email" || gotState == "" || gotNonce == "" {
		t.Fatalf("bad oidc authorize probe client=%q redirect=%q scope=%q state=%q nonce=%q", gotClientID, gotRedirectURI, gotScope, gotState, gotNonce)
	}
	body := testRec.Body.String()
	for _, expected := range []string{`"ok":true`, `"provider_id":"fake-sso"`, `"client_id":"openweb-client"`, `"status_code":302`, "openid", "/api/auth/oidc/callback"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("oidc test response missing %q: %s", expected, body)
		}
	}
	for _, leaked := range []string{clientSecret, escapedClientSecret, "client_secret", "oidc_client_secret_encrypted", "client_secret_encrypted"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("oidc test response leaked sensitive value %q: %s", leaked, body)
		}
	}
	usersRec := assertStatus(t, handler, http.MethodGet, "/api/admin/users", nil, adminCookie, http.StatusOK)
	if strings.Contains(usersRec.Body.String(), `"type":"oidc"`) {
		t.Fatalf("oidc authorization test unexpectedly created a user: %s", usersRec.Body.String())
	}
	removeLogBlocker := blockPlatformItemCreate(t, handler.(*Server).cfg.Store, "operation_logs")
	logFailureRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/oidc/test", map[string]any{
		"setting_id": setting.ID,
	}, adminCookie, http.StatusInternalServerError)
	removeLogBlocker()
	if !strings.Contains(logFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("oidc test log failure did not surface operation log error: %s", logFailureRec.Body.String())
	}
	if authorizeCalls != 2 {
		t.Fatalf("oidc test should probe before failing on operation log, calls=%d", authorizeCalls)
	}
	if !coreAuditLogsContainAction(handler.(*Server).cfg.Store, "operation.log.persist_failed") {
		t.Fatalf("oidc test log failure did not create core audit failure")
	}
	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+setting.ID, map[string]any{
		"status": "disabled",
	}, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/oidc/test", map[string]any{
		"setting_id": setting.ID,
	}, adminCookie, http.StatusNotFound)
	if authorizeCalls != 2 {
		t.Fatalf("disabled oidc setting should not call authorization endpoint, calls=%d", authorizeCalls)
	}

	badSettingRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "Broken External OIDC identity",
		"type":   "identity",
		"status": "enabled",
		"metadata": map[string]any{
			"oidc_login_enabled":          true,
			"oidc_provider_id":            "bad-sso",
			"oidc_provider_name":          "Bad SSO",
			"oidc_authorization_endpoint": provider.URL + "/bad-authorize",
			"oidc_token_endpoint":         provider.URL + "/token",
			"oidc_client_id":              "openweb-client",
			"oidc_client_secret":          clientSecret,
		},
	}, adminCookie, http.StatusCreated)
	var badSetting model.PlatformItem
	decodeResponse(t, badSettingRec, &badSetting)
	failedRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/oidc/test", map[string]any{
		"setting_id": badSetting.ID,
	}, adminCookie, http.StatusBadGateway)
	if strings.Contains(failedRec.Body.String(), clientSecret) || strings.Contains(failedRec.Body.String(), escapedClientSecret) {
		t.Fatalf("oidc failed test leaked secret: %s", failedRec.Body.String())
	}
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), "system_settings.oidc_test") || !strings.Contains(logsRec.Body.String(), "system_settings.oidc_test.failed") || strings.Contains(logsRec.Body.String(), clientSecret) || strings.Contains(logsRec.Body.String(), escapedClientSecret) {
		t.Fatalf("oidc test operation logs missing entries or leaked secret: %s", logsRec.Body.String())
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

func TestExternalLDAPLoginLogFailureRollsBackAutoCreatedUser(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)
	fakeLDAP := &fakeLDAPAuthenticator{
		users: map[string]fakeLDAPUser{
			"ldap-rollback": {
				password: "directory-password",
				claims: externalLDAPClaims{
					Subject:     "uid=ldap-rollback,ou=people,dc=example,dc=test",
					DN:          "uid=ldap-rollback,ou=people,dc=example,dc=test",
					Username:    "ldap-rollback",
					DisplayName: "LDAP Rollback",
					Email:       "ldap-rollback@example.test",
				},
			},
		},
	}
	srv.ldap = fakeLDAP

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "LDAP rollback identity",
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
		},
	}, adminCookie, http.StatusCreated)

	removeBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "login_logs")
	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username": "ldap-rollback",
		"password": "directory-password",
	}, nil, http.StatusInternalServerError)
	removeBlocker()
	if !strings.Contains(loginRec.Body.String(), "persist login log failed") {
		t.Fatalf("ldap login log failure was not reported: %s", loginRec.Body.String())
	}
	if cookies := loginRec.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("ldap login issued cookies after failed login log write: %#v", cookies)
	}
	usersRec := assertStatus(t, handler, http.MethodGet, "/api/admin/users", nil, adminCookie, http.StatusOK)
	if strings.Contains(usersRec.Body.String(), "ldap-rollback") || strings.Contains(usersRec.Body.String(), "uid=ldap-rollback") {
		t.Fatalf("ldap auto-created user survived failed login log write: %s", usersRec.Body.String())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "auth.login.log.persist_failed") {
		t.Fatal("ldap login log persistence failure was not written to core audit logs")
	}

	removeBlocker = blockPlatformItemCreate(t, srv.cfg.Store, "login_logs")
	removeRestoreBlocker := blockPlatformItemDeletePayloadFragment(t, srv.cfg.Store, "users", `"external_subject":"uid=ldap-rollback,ou=people,dc=example,dc=test"`)
	restoreFailureRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username": "ldap-rollback",
		"password": "directory-password",
	}, nil, http.StatusInternalServerError)
	removeRestoreBlocker()
	removeBlocker()
	if !strings.Contains(restoreFailureRec.Body.String(), "failed to remove external user after login log failure") {
		t.Fatalf("ldap external user restore failure was not reported: %s", restoreFailureRec.Body.String())
	}
	if cookies := restoreFailureRec.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("ldap login issued cookies after failed external user restore: %#v", cookies)
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "auth.external_user.restore_failed") {
		t.Fatal("ldap external user restore failure was not written to core audit logs")
	}
}

func TestExternalLDAPLoginStateFailureRollsBackAutoCreatedUser(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)
	fakeLDAP := &fakeLDAPAuthenticator{
		users: map[string]fakeLDAPUser{
			"ldap-state-rollback": {
				password: "directory-password",
				claims: externalLDAPClaims{
					Subject:     "uid=ldap-state-rollback,ou=people,dc=example,dc=test",
					DN:          "uid=ldap-state-rollback,ou=people,dc=example,dc=test",
					Username:    "ldap-state-rollback",
					DisplayName: "LDAP State Rollback",
					Email:       "ldap-state-rollback@example.test",
				},
			},
		},
	}
	srv.ldap = fakeLDAP

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "LDAP state rollback identity",
		"type":   "identity",
		"status": "enabled",
		"metadata": map[string]any{
			"disable_password_login":      true,
			"ldap_enabled":                true,
			"ldap_provider_id":            "state-rollback-ldap",
			"ldap_provider_name":          "State Rollback LDAP",
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
		},
	}, adminCookie, http.StatusCreated)

	removeBlocker := blockPlatformCollectionSavePayloadFragment(t, srv.cfg.Store, "users", `"online":true`)
	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username": "ldap-state-rollback",
		"password": "directory-password",
	}, nil, http.StatusInternalServerError)
	removeBlocker()
	if !strings.Contains(loginRec.Body.String(), "persist user login state failed") {
		t.Fatalf("ldap login state failure was not reported: %s", loginRec.Body.String())
	}
	if cookies := loginRec.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("ldap login issued cookies after failed login state write: %#v", cookies)
	}
	assertNoAuthSessionForUsername(t, srv, "ldap-state-rollback")
	usersRec := assertStatus(t, handler, http.MethodGet, "/api/admin/users", nil, adminCookie, http.StatusOK)
	if strings.Contains(usersRec.Body.String(), "ldap-state-rollback") || strings.Contains(usersRec.Body.String(), "uid=ldap-state-rollback") {
		t.Fatalf("ldap auto-created user survived failed login state write: %s", usersRec.Body.String())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "auth.login.state.persist_failed") {
		t.Fatal("ldap login state persistence failure was not written to core audit logs")
	}

	retryRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username": "ldap-state-rollback",
		"password": "directory-password",
	}, nil, http.StatusOK)
	if cookies := retryRec.Result().Cookies(); len(cookies) == 0 {
		t.Fatal("ldap retry after login state failure did not set auth cookie")
	}
}

func TestExternalLDAPLoginFailureRedactsSecrets(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)
	fakeLDAP := &fakeLDAPAuthenticator{
		err: errors.New("bind failed with directory-secret and user password directory-password"),
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
		},
	}, adminCookie, http.StatusCreated)

	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username": "ldap-operator",
		"password": "directory-password",
	}, nil, http.StatusBadGateway)
	loginBody := loginRec.Body.String()
	for _, leaked := range []string{"directory-secret", "directory-password"} {
		if strings.Contains(loginBody, leaked) {
			t.Fatalf("ldap login failure response leaked secret %q: %s", leaked, loginBody)
		}
	}
	if !strings.Contains(loginBody, "[redacted]") {
		t.Fatalf("ldap login failure response did not contain redaction marker: %s", loginBody)
	}

	loginLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/login-logs", nil, adminCookie, http.StatusOK)
	loginLogsBody := loginLogsRec.Body.String()
	for _, leaked := range []string{"directory-secret", "directory-password"} {
		if strings.Contains(loginLogsBody, leaked) {
			t.Fatalf("ldap login log leaked secret %q: %s", leaked, loginLogsBody)
		}
	}
	if !strings.Contains(loginLogsBody, `"type":"ldap"`) || !strings.Contains(loginLogsBody, "[redacted]") {
		t.Fatalf("ldap login log missing redacted ldap failure: %s", loginLogsBody)
	}
	operationLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	operationLogsBody := operationLogsRec.Body.String()
	if !strings.Contains(operationLogsBody, "auth.ldap.login_failed") || strings.Contains(operationLogsBody, "directory-secret") || strings.Contains(operationLogsBody, "directory-password") {
		t.Fatalf("ldap login failure audit missing or leaked secret: %s", operationLogsBody)
	}
}

func TestExternalLDAPLoginRejectsAutoCreateDisabledAndDisabledUsers(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)
	fakeLDAP := &fakeLDAPAuthenticator{
		users: map[string]fakeLDAPUser{
			"ldap-no-create": {
				password: "directory-password",
				claims: externalLDAPClaims{
					Subject:     "uid=ldap-no-create,ou=people,dc=example,dc=test",
					DN:          "uid=ldap-no-create,ou=people,dc=example,dc=test",
					Username:    "ldap-no-create",
					DisplayName: "LDAP No Create",
					Email:       "ldap-no-create@example.test",
				},
			},
			"ldap-disabled": {
				password: "directory-password",
				claims: externalLDAPClaims{
					Subject:     "uid=ldap-disabled,ou=people,dc=example,dc=test",
					DN:          "uid=ldap-disabled,ou=people,dc=example,dc=test",
					Username:    "ldap-disabled",
					DisplayName: "LDAP Disabled",
					Email:       "ldap-disabled@example.test",
				},
			},
		},
	}
	srv.ldap = fakeLDAP

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "LDAP identity no auto create",
		"type":   "identity",
		"status": "enabled",
		"metadata": map[string]any{
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
			"ldap_auto_create":            false,
		},
	}, adminCookie, http.StatusCreated)

	noCreateRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username": "ldap-no-create",
		"password": "directory-password",
	}, nil, http.StatusForbidden)
	if !strings.Contains(noCreateRec.Body.String(), "auto creation is disabled") {
		t.Fatalf("ldap auto-create denial response missing reason: %s", noCreateRec.Body.String())
	}
	usersRec := assertStatus(t, handler, http.MethodGet, "/api/admin/users", nil, adminCookie, http.StatusOK)
	if strings.Contains(usersRec.Body.String(), "ldap-no-create") {
		t.Fatalf("ldap login created user despite ldap_auto_create=false: %s", usersRec.Body.String())
	}

	assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":   "ldap-disabled",
		"type":   "ldap",
		"status": "disabled",
		"metadata": map[string]any{
			"role":                 "user",
			"external_provider":    "ldap",
			"external_provider_id": "corp-ldap",
			"external_subject":     "uid=ldap-disabled,ou=people,dc=example,dc=test",
			"external_dn":          "uid=ldap-disabled,ou=people,dc=example,dc=test",
		},
	}, adminCookie, http.StatusCreated)
	disabledRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username": "ldap-disabled",
		"password": "directory-password",
	}, nil, http.StatusForbidden)
	if !strings.Contains(disabledRec.Body.String(), "external ldap user is disabled") {
		t.Fatalf("ldap disabled user denial response missing reason: %s", disabledRec.Body.String())
	}
	if fakeLDAP.calls != 2 {
		t.Fatalf("ldap authenticator calls = %d, want 2", fakeLDAP.calls)
	}
	loginLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/login-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(loginLogsRec.Body.String(), `"type":"ldap"`) || !strings.Contains(loginLogsRec.Body.String(), `"status":"failed"`) || !strings.Contains(loginLogsRec.Body.String(), "auto creation is disabled") || !strings.Contains(loginLogsRec.Body.String(), "external ldap user is disabled") {
		t.Fatalf("ldap failed login logs missing denial reasons: %s", loginLogsRec.Body.String())
	}
}

func TestLDAPIntegrationTestLogin(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)
	fakeLDAP := &fakeLDAPAuthenticator{
		users: map[string]fakeLDAPUser{
			"ldap-probe": {
				password: "directory-password",
				claims: externalLDAPClaims{
					Subject:     "uid=ldap-probe,ou=people,dc=example,dc=test",
					DN:          "uid=ldap-probe,ou=people,dc=example,dc=test",
					Username:    "ldap-probe",
					DisplayName: "LDAP Probe",
					Email:       "ldap-probe@example.test",
					Groups:      []string{"cn=ops,ou=groups,dc=example,dc=test"},
				},
			},
		},
	}
	srv.ldap = fakeLDAP

	settingRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "LDAP identity",
		"type":   "identity",
		"status": "enabled",
		"metadata": map[string]any{
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
		},
	}, adminCookie, http.StatusCreated)
	var setting model.PlatformItem
	decodeResponse(t, settingRec, &setting)

	testRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/ldap/test", map[string]any{
		"setting_id": setting.ID,
		"username":   "ldap-probe",
		"password":   "directory-password",
	}, adminCookie, http.StatusOK)
	if fakeLDAP.calls != 1 {
		t.Fatalf("ldap authenticator calls = %d, want 1", fakeLDAP.calls)
	}
	if fakeLDAP.lastProvider.ID != "corp-ldap" || fakeLDAP.lastProvider.BindPassword != "directory-secret" || fakeLDAP.lastProvider.BaseDN != "ou=people,dc=example,dc=test" {
		t.Fatalf("ldap provider was not parsed/decrypted correctly: %#v", fakeLDAP.lastProvider)
	}
	body := testRec.Body.String()
	for _, expected := range []string{`"ok":true`, `"provider_id":"corp-ldap"`, `"username":"ldap-probe"`, `"display_name":"LDAP Probe"`, `"email":"ldap-probe@example.test"`, "cn=ops"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("ldap test response missing %q: %s", expected, body)
		}
	}
	for _, leaked := range []string{"directory-secret", "directory-password", "ldap_bind_password_encrypted", "bind_password_encrypted"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("ldap test response leaked sensitive value %q: %s", leaked, body)
		}
	}
	usersRec := assertStatus(t, handler, http.MethodGet, "/api/admin/users", nil, adminCookie, http.StatusOK)
	if strings.Contains(usersRec.Body.String(), "ldap-probe") {
		t.Fatalf("ldap test unexpectedly created a user: %s", usersRec.Body.String())
	}
	removeLogBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	logFailureRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/ldap/test", map[string]any{
		"setting_id": setting.ID,
		"username":   "ldap-probe",
		"password":   "directory-password",
	}, adminCookie, http.StatusInternalServerError)
	removeLogBlocker()
	if !strings.Contains(logFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("ldap test log failure did not surface operation log error: %s", logFailureRec.Body.String())
	}
	if fakeLDAP.calls != 2 {
		t.Fatalf("ldap test should authenticate before failing on operation log, calls=%d", fakeLDAP.calls)
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "operation.log.persist_failed") {
		t.Fatalf("ldap test log failure did not create core audit failure")
	}

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/ldap/test", map[string]any{
		"setting_id": setting.ID,
		"username":   "ldap-probe",
		"password":   "wrong-password",
	}, adminCookie, http.StatusUnauthorized)
	if fakeLDAP.calls != 3 {
		t.Fatalf("ldap authenticator calls after failed probe = %d, want 3", fakeLDAP.calls)
	}
	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+setting.ID, map[string]any{
		"metadata": map[string]any{
			"ldap_enabled":                true,
			"ldap_provider_id":            "corp-ldap",
			"ldap_provider_name":          "Corp LDAP",
			"ldap_url":                    "ldap://directory.example.test:389",
			"ldap_bind_dn":                "cn=reader,dc=example,dc=test",
			"ldap_bind_password_clear":    true,
			"ldap_base_dn":                "ou=people,dc=example,dc=test",
			"ldap_user_filter":            "(uid={username})",
			"ldap_username_attribute":     "uid",
			"ldap_display_name_attribute": "cn",
			"ldap_email_attribute":        "mail",
			"ldap_role":                   "user",
			"ldap_auto_create":            true,
		},
	}, adminCookie, http.StatusOK)
	rawSetting, ok, err := srv.cfg.Store.GetPlatformItem("system_settings", setting.ID)
	if err != nil || !ok {
		t.Fatalf("get raw ldap setting after clear ok=%v err=%v", ok, err)
	}
	for _, key := range []string{"ldap_bind_password_encrypted", "ldap_bind_password_set", "ldap_bind_password_updated_at", "ldap_bind_password_clear"} {
		if _, exists := rawSetting.Metadata[key]; exists {
			t.Fatalf("cleared ldap setting still has %s in raw metadata: %#v", key, rawSetting.Metadata)
		}
	}
	clearedRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/ldap/test", map[string]any{
		"setting_id": setting.ID,
		"username":   "ldap-probe",
		"password":   "directory-password",
	}, adminCookie, http.StatusBadGateway)
	if fakeLDAP.calls != 4 {
		t.Fatalf("ldap authenticator calls after cleared password probe = %d, want 4", fakeLDAP.calls)
	}
	if fakeLDAP.lastProvider.BindPassword != "" {
		t.Fatalf("cleared ldap provider kept old bind password: %#v", fakeLDAP.lastProvider)
	}
	for _, leaked := range []string{"directory-secret", "ldap_bind_password_encrypted", "ldap_bind_password_clear"} {
		if strings.Contains(clearedRec.Body.String(), leaked) {
			t.Fatalf("cleared ldap test leaked sensitive value %q: %s", leaked, clearedRec.Body.String())
		}
	}
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), "system_settings.ldap_test") || !strings.Contains(logsRec.Body.String(), "system_settings.ldap_test.failed") {
		t.Fatalf("ldap test operation logs missing success or failure entries: %s", logsRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+setting.ID, map[string]any{
		"status": "disabled",
	}, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/ldap/test", map[string]any{
		"setting_id": setting.ID,
		"username":   "ldap-probe",
		"password":   "directory-password",
	}, adminCookie, http.StatusNotFound)
	if fakeLDAP.calls != 4 {
		t.Fatalf("disabled ldap setting should not call authenticator, calls=%d", fakeLDAP.calls)
	}
}

func TestLDAPIntegrationTestFailureRedactsSecrets(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)
	fakeLDAP := &fakeLDAPAuthenticator{
		err: errors.New("directory error exposed directory-secret and directory-password"),
	}
	srv.ldap = fakeLDAP

	settingRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "LDAP identity",
		"type":   "identity",
		"status": "enabled",
		"metadata": map[string]any{
			"ldap_enabled":                true,
			"ldap_provider_id":            "corp-ldap",
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
		},
	}, adminCookie, http.StatusCreated)
	var setting model.PlatformItem
	decodeResponse(t, settingRec, &setting)

	failedRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/ldap/test", map[string]any{
		"setting_id": setting.ID,
		"username":   "ldap-probe",
		"password":   "directory-password",
	}, adminCookie, http.StatusBadGateway)
	responseBody := failedRec.Body.String()
	for _, leaked := range []string{"directory-secret", "directory-password"} {
		if strings.Contains(responseBody, leaked) {
			t.Fatalf("ldap test failure response leaked secret %q: %s", leaked, responseBody)
		}
	}
	if !strings.Contains(responseBody, "[redacted]") {
		t.Fatalf("ldap test failure response did not contain redaction marker: %s", responseBody)
	}

	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	logsBody := logsRec.Body.String()
	for _, leaked := range []string{"directory-secret", "directory-password"} {
		if strings.Contains(logsBody, leaked) {
			t.Fatalf("ldap test failure operation log leaked secret %q: %s", leaked, logsBody)
		}
	}
	if !strings.Contains(logsBody, "system_settings.ldap_test.failed") || !strings.Contains(logsBody, "[redacted]") {
		t.Fatalf("ldap test failure operation log missing redacted failure entry: %s", logsBody)
	}
}

func TestWeComIntegrationTokenTest(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	badSecret := "bad secret+/=?:&"
	escapedBadSecret := url.QueryEscape(badSecret)
	var gotCorpID string
	var gotSecret string
	var tokenCalls int
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gettoken" {
			http.NotFound(w, r)
			return
		}
		tokenCalls++
		gotCorpID = r.URL.Query().Get("corpid")
		gotSecret = r.URL.Query().Get("corpsecret")
		if gotCorpID != "ww-openweb" || gotSecret != "wecom-secret" {
			writeJSON(w, http.StatusOK, map[string]any{"errcode": 40014, "errmsg": "invalid " + gotSecret + " query " + r.URL.RawQuery})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"errcode": 0, "access_token": "wecom-access", "expires_in": 7200})
	}))
	defer provider.Close()

	settingRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "Enterprise WeChat identity",
		"type":   "identity",
		"status": "enabled",
		"metadata": map[string]any{
			"wecom_enabled":           true,
			"wecom_provider_id":       "corp-wecom",
			"wecom_provider_name":     "Corp WeCom",
			"wecom_corp_id":           "ww-openweb",
			"wecom_agent_id":          "100001",
			"wecom_agent_secret":      "wecom-secret",
			"wecom_token_endpoint":    provider.URL + "/gettoken",
			"wecom_userinfo_endpoint": provider.URL + "/getuserinfo",
		},
	}, adminCookie, http.StatusCreated)
	var setting model.PlatformItem
	decodeResponse(t, settingRec, &setting)

	settingsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/system-settings", nil, adminCookie, http.StatusOK)
	for _, leaked := range []string{"wecom-secret", "wecom_agent_secret_encrypted", "agent_secret_encrypted"} {
		if strings.Contains(settingsRec.Body.String(), leaked) {
			t.Fatalf("wecom settings leaked sensitive value %q: %s", leaked, settingsRec.Body.String())
		}
	}
	testRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/wecom/test", map[string]any{
		"setting_id": setting.ID,
	}, adminCookie, http.StatusOK)
	if gotCorpID != "ww-openweb" || gotSecret != "wecom-secret" {
		t.Fatalf("wecom token endpoint received corp_id=%q secret=%q", gotCorpID, gotSecret)
	}
	body := testRec.Body.String()
	for _, expected := range []string{`"ok":true`, `"provider_id":"corp-wecom"`, `"corp_id":"ww-openweb"`, `"agent_id":"100001"`, `"expires_in_seconds":7200`} {
		if !strings.Contains(body, expected) {
			t.Fatalf("wecom test response missing %q: %s", expected, body)
		}
	}
	for _, leaked := range []string{"wecom-secret", "wecom-access", "corpsecret", "wecom_agent_secret_encrypted", "agent_secret_encrypted"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("wecom test response leaked sensitive value %q: %s", leaked, body)
		}
	}
	usersRec := assertStatus(t, handler, http.MethodGet, "/api/admin/users", nil, adminCookie, http.StatusOK)
	if strings.Contains(usersRec.Body.String(), `"type":"wecom"`) {
		t.Fatalf("wecom token test unexpectedly created a user: %s", usersRec.Body.String())
	}
	removeLogBlocker := blockPlatformItemCreate(t, handler.(*Server).cfg.Store, "operation_logs")
	logFailureRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/wecom/test", map[string]any{
		"setting_id": setting.ID,
	}, adminCookie, http.StatusInternalServerError)
	removeLogBlocker()
	if !strings.Contains(logFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("wecom test log failure did not surface operation log error: %s", logFailureRec.Body.String())
	}
	if tokenCalls != 2 {
		t.Fatalf("wecom test should call token endpoint before failing on operation log, calls=%d", tokenCalls)
	}
	if !coreAuditLogsContainAction(handler.(*Server).cfg.Store, "operation.log.persist_failed") {
		t.Fatalf("wecom test log failure did not create core audit failure")
	}
	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+setting.ID, map[string]any{
		"metadata": map[string]any{
			"wecom_enabled":            true,
			"wecom_provider_id":        "corp-wecom",
			"wecom_provider_name":      "Corp WeCom",
			"wecom_corp_id":            "ww-openweb",
			"wecom_agent_id":           "100001",
			"wecom_agent_secret_clear": true,
			"wecom_token_endpoint":     provider.URL + "/gettoken",
			"wecom_userinfo_endpoint":  provider.URL + "/getuserinfo",
		},
	}, adminCookie, http.StatusOK)
	rawSetting, ok, err := handler.(*Server).cfg.Store.GetPlatformItem("system_settings", setting.ID)
	if err != nil || !ok {
		t.Fatalf("get raw wecom setting after clear ok=%v err=%v", ok, err)
	}
	for _, key := range []string{"wecom_agent_secret_encrypted", "wecom_agent_secret_set", "wecom_agent_secret_updated_at", "wecom_agent_secret_clear"} {
		if _, exists := rawSetting.Metadata[key]; exists {
			t.Fatalf("cleared wecom setting still has %s in raw metadata: %#v", key, rawSetting.Metadata)
		}
	}
	clearedRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/wecom/test", map[string]any{
		"setting_id": setting.ID,
	}, adminCookie, http.StatusBadRequest)
	if tokenCalls != 2 {
		t.Fatalf("cleared wecom setting should not call token endpoint, calls=%d", tokenCalls)
	}
	for _, leaked := range []string{"wecom-secret", "wecom_agent_secret_encrypted", "wecom_agent_secret_clear"} {
		if strings.Contains(clearedRec.Body.String(), leaked) {
			t.Fatalf("cleared wecom test leaked sensitive value %q: %s", leaked, clearedRec.Body.String())
		}
	}
	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+setting.ID, map[string]any{
		"status": "disabled",
	}, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/wecom/test", map[string]any{
		"setting_id": setting.ID,
	}, adminCookie, http.StatusNotFound)
	if tokenCalls != 2 {
		t.Fatalf("disabled wecom setting should not call token endpoint, calls=%d", tokenCalls)
	}

	badSettingRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "Broken Enterprise WeChat identity",
		"type":   "identity",
		"status": "enabled",
		"metadata": map[string]any{
			"wecom_enabled":           true,
			"wecom_provider_id":       "bad-wecom",
			"wecom_provider_name":     "Bad WeCom",
			"wecom_corp_id":           "ww-openweb",
			"wecom_agent_secret":      badSecret,
			"wecom_token_endpoint":    provider.URL + "/gettoken",
			"wecom_userinfo_endpoint": provider.URL + "/getuserinfo",
		},
	}, adminCookie, http.StatusCreated)
	var badSetting model.PlatformItem
	decodeResponse(t, badSettingRec, &badSetting)
	failedRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/wecom/test", map[string]any{
		"setting_id": badSetting.ID,
	}, adminCookie, http.StatusBadGateway)
	if strings.Contains(failedRec.Body.String(), badSecret) || strings.Contains(failedRec.Body.String(), escapedBadSecret) {
		t.Fatalf("wecom failed test leaked secret: %s", failedRec.Body.String())
	}
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), "system_settings.wecom_test") || !strings.Contains(logsRec.Body.String(), "system_settings.wecom_test.failed") || strings.Contains(logsRec.Body.String(), badSecret) || strings.Contains(logsRec.Body.String(), escapedBadSecret) {
		t.Fatalf("wecom test operation logs missing entries or leaked secret: %s", logsRec.Body.String())
	}
}

func TestExternalWeComLoginCreatesUserAndSession(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	var authorizeState string
	var tokenEndpointCalls int
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			query := r.URL.Query()
			if query.Get("appid") != "ww-openweb" || query.Get("response_type") != "code" || query.Get("redirect_uri") == "" || query.Get("agentid") != "100001" {
				http.Error(w, "bad authorize request", http.StatusBadRequest)
				return
			}
			authorizeState = query.Get("state")
			callback, _ := url.Parse(query.Get("redirect_uri"))
			values := callback.Query()
			values.Set("code", "wecom-code")
			values.Set("state", authorizeState)
			callback.RawQuery = values.Encode()
			http.Redirect(w, r, callback.String(), http.StatusFound)
		case "/gettoken":
			tokenEndpointCalls++
			if r.URL.Query().Get("corpid") != "ww-openweb" || r.URL.Query().Get("corpsecret") != "wecom-secret" {
				http.Error(w, "bad token request", http.StatusUnauthorized)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"errcode": 0, "access_token": "wecom-access", "expires_in": 7200})
		case "/getuserinfo":
			if r.URL.Query().Get("access_token") != "wecom-access" || r.URL.Query().Get("code") != "wecom-code" {
				http.Error(w, "bad userinfo request", http.StatusUnauthorized)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"errcode": 0, "UserId": "wecom-user-1"})
		case "/userget":
			if r.URL.Query().Get("access_token") != "wecom-access" || r.URL.Query().Get("userid") != "wecom-user-1" {
				http.Error(w, "bad user detail request", http.StatusUnauthorized)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"errcode": 0,
				"userid":  "wecom-user-1",
				"name":    "WeCom Operator",
				"email":   "wecom-operator@example.test",
				"mobile":  "13800000000",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "Enterprise WeChat identity",
		"type":   "identity",
		"status": "enabled",
		"metadata": map[string]any{
			"wecom_enabled":              true,
			"wecom_provider_id":          "corp-wecom",
			"wecom_provider_name":        "Corp WeCom",
			"wecom_corp_id":              "ww-openweb",
			"wecom_agent_id":             "100001",
			"wecom_agent_secret":         "wecom-secret",
			"wecom_authorize_endpoint":   provider.URL + "/authorize",
			"wecom_token_endpoint":       provider.URL + "/gettoken",
			"wecom_userinfo_endpoint":    provider.URL + "/getuserinfo",
			"wecom_user_detail_endpoint": provider.URL + "/userget",
			"wecom_role":                 "user",
			"wecom_providers": []any{
				map[string]any{
					"id":                 "disabled-wecom",
					"enabled":            false,
					"corp_id":            "ww-disabled",
					"agent_secret":       "disabled-wecom-secret",
					"authorize_endpoint": provider.URL + "/disabled-authorize",
					"token_endpoint":     provider.URL + "/disabled-token",
					"userinfo_endpoint":  provider.URL + "/disabled-userinfo",
				},
			},
		},
	}, adminCookie, http.StatusCreated)
	settingsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/system-settings", nil, adminCookie, http.StatusOK)
	for _, leaked := range []string{"wecom-secret", "disabled-wecom-secret", "wecom_agent_secret_encrypted", "agent_secret_encrypted"} {
		if strings.Contains(settingsRec.Body.String(), leaked) {
			t.Fatalf("wecom settings leaked sensitive value %q: %s", leaked, settingsRec.Body.String())
		}
	}

	providersRec := assertStatus(t, handler, http.MethodGet, "/api/auth/wecom/providers", nil, nil, http.StatusOK)
	if !strings.Contains(providersRec.Body.String(), "corp-wecom") || !strings.Contains(providersRec.Body.String(), "Corp WeCom") || strings.Contains(providersRec.Body.String(), "wecom-secret") {
		t.Fatalf("external wecom providers response invalid: %s", providersRec.Body.String())
	}
	startRec := assertStatus(t, handler, http.MethodGet, "/api/auth/wecom/start?provider=corp-wecom&next=/app/access", nil, nil, http.StatusFound)
	providerLocation := startRec.Header().Get("Location")
	if !strings.HasPrefix(providerLocation, provider.URL+"/authorize?") {
		t.Fatalf("start did not redirect to wecom provider: %s", providerLocation)
	}
	noRedirectClient := provider.Client()
	noRedirectClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	providerResp, err := noRedirectClient.Get(providerLocation)
	if err != nil {
		t.Fatalf("call fake wecom authorize: %v", err)
	}
	_ = providerResp.Body.Close()
	if providerResp.StatusCode != http.StatusFound {
		t.Fatalf("fake wecom authorize status = %d", providerResp.StatusCode)
	}
	callbackLocation := providerResp.Header.Get("Location")
	callbackURL, err := url.Parse(callbackLocation)
	if err != nil {
		t.Fatalf("parse wecom callback location: %v", err)
	}
	if callbackURL.Path != "/api/auth/wecom/callback" || callbackURL.Query().Get("state") != authorizeState || callbackURL.Query().Get("code") == "" {
		t.Fatalf("bad wecom callback location: %s", callbackLocation)
	}
	callbackRec := assertStatus(t, handler, http.MethodGet, callbackURL.RequestURI(), nil, nil, http.StatusFound)
	if callbackRec.Header().Get("Location") != "/app/access" {
		t.Fatalf("callback did not redirect to requested next path: %s", callbackRec.Header().Get("Location"))
	}
	cookies := callbackRec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("wecom callback did not set auth cookie")
	}
	if tokenEndpointCalls != 1 {
		t.Fatalf("wecom token endpoint calls = %d, want 1", tokenEndpointCalls)
	}
	assertStatus(t, handler, http.MethodGet, callbackURL.RequestURI(), nil, nil, http.StatusBadRequest)
	if tokenEndpointCalls != 1 {
		t.Fatalf("replayed wecom callback reached token endpoint again: calls = %d", tokenEndpointCalls)
	}
	meRec := assertStatus(t, handler, http.MethodGet, "/api/auth/me", nil, cookies[0], http.StatusOK)
	if !strings.Contains(meRec.Body.String(), `"username":"wecom-user-1"`) || !strings.Contains(meRec.Body.String(), `"role":"user"`) {
		t.Fatalf("wecom login did not create authenticated user: %s", meRec.Body.String())
	}
	usersRec := assertStatus(t, handler, http.MethodGet, "/api/admin/users", nil, adminCookie, http.StatusOK)
	if !strings.Contains(usersRec.Body.String(), "wecom-user-1") || !strings.Contains(usersRec.Body.String(), `"type":"wecom"`) || strings.Contains(usersRec.Body.String(), "wecom-secret") || strings.Contains(usersRec.Body.String(), "password_hash") {
		t.Fatalf("external wecom user list invalid: %s", usersRec.Body.String())
	}
	loginLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/login-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(loginLogsRec.Body.String(), `"type":"wecom"`) || !strings.Contains(loginLogsRec.Body.String(), "corp-wecom") {
		t.Fatalf("wecom login log missing: %s", loginLogsRec.Body.String())
	}
}

func TestExternalWeComLoginLogFailureRollsBackAutoCreatedUser(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)
	var tokenEndpointCalls int
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gettoken":
			tokenEndpointCalls++
			writeJSON(w, http.StatusOK, map[string]any{"errcode": 0, "access_token": "wecom-rollback-access", "expires_in": 7200})
		case "/getuserinfo":
			if r.URL.Query().Get("access_token") != "wecom-rollback-access" || r.URL.Query().Get("code") != "rollback-code" {
				http.Error(w, "bad userinfo request", http.StatusUnauthorized)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"errcode": 0, "UserId": "wecom-rollback-user"})
		case "/userget":
			if r.URL.Query().Get("access_token") != "wecom-rollback-access" || r.URL.Query().Get("userid") != "wecom-rollback-user" {
				http.Error(w, "bad user detail request", http.StatusUnauthorized)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"errcode": 0,
				"userid":  "wecom-rollback-user",
				"name":    "WeCom Rollback User",
				"email":   "wecom-rollback@example.test",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "Enterprise WeChat rollback",
		"type":   "identity",
		"status": "enabled",
		"metadata": map[string]any{
			"wecom_enabled":              true,
			"wecom_provider_id":          "rollback-wecom",
			"wecom_provider_name":        "Rollback WeCom",
			"wecom_corp_id":              "ww-openweb",
			"wecom_agent_id":             "100001",
			"wecom_agent_secret":         "wecom-secret",
			"wecom_authorize_endpoint":   provider.URL + "/authorize",
			"wecom_token_endpoint":       provider.URL + "/gettoken",
			"wecom_userinfo_endpoint":    provider.URL + "/getuserinfo",
			"wecom_user_detail_endpoint": provider.URL + "/userget",
			"wecom_role":                 "user",
		},
	}, adminCookie, http.StatusCreated)
	state, err := srv.auth.createExternalWeComState("rollback-wecom", "/app/access")
	if err != nil {
		t.Fatalf("create external wecom state: %v", err)
	}

	removeBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "login_logs")
	callbackRec := assertStatus(t, handler, http.MethodGet, "/api/auth/wecom/callback?state="+url.QueryEscape(state)+"&code=rollback-code", nil, nil, http.StatusInternalServerError)
	removeBlocker()
	if !strings.Contains(callbackRec.Body.String(), "persist login log failed") {
		t.Fatalf("wecom login log failure was not reported: %s", callbackRec.Body.String())
	}
	if len(callbackRec.Result().Cookies()) > 0 {
		t.Fatalf("wecom callback issued cookies after failed login log write: %#v", callbackRec.Result().Cookies())
	}
	if tokenEndpointCalls != 1 {
		t.Fatalf("wecom token endpoint calls = %d, want 1", tokenEndpointCalls)
	}
	usersRec := assertStatus(t, handler, http.MethodGet, "/api/admin/users", nil, adminCookie, http.StatusOK)
	if strings.Contains(usersRec.Body.String(), "wecom-rollback-user") || strings.Contains(usersRec.Body.String(), "wecom-rollback@example.test") {
		t.Fatalf("wecom auto-created user survived failed login log write: %s", usersRec.Body.String())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "auth.login.log.persist_failed") {
		t.Fatal("wecom login log persistence failure was not written to core audit logs")
	}

	state, err = srv.auth.createExternalWeComState("rollback-wecom", "/app/access")
	if err != nil {
		t.Fatalf("create external wecom state for restore failure: %v", err)
	}
	removeBlocker = blockPlatformItemCreate(t, srv.cfg.Store, "login_logs")
	removeRestoreBlocker := blockPlatformItemDeletePayloadFragment(t, srv.cfg.Store, "users", `"external_subject":"wecom-rollback-user"`)
	restoreFailureRec := assertStatus(t, handler, http.MethodGet, "/api/auth/wecom/callback?state="+url.QueryEscape(state)+"&code=rollback-code", nil, nil, http.StatusInternalServerError)
	removeRestoreBlocker()
	removeBlocker()
	if !strings.Contains(restoreFailureRec.Body.String(), "failed to remove external user after login log failure") {
		t.Fatalf("wecom external user restore failure was not reported: %s", restoreFailureRec.Body.String())
	}
	if len(restoreFailureRec.Result().Cookies()) > 0 {
		t.Fatalf("wecom callback issued cookies after failed external user restore: %#v", restoreFailureRec.Result().Cookies())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "auth.external_user.restore_failed") {
		t.Fatal("wecom external user restore failure was not written to core audit logs")
	}
}

func TestExternalWeComLoginStateFailureRollsBackAutoCreatedUser(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)
	var tokenEndpointCalls int
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gettoken":
			tokenEndpointCalls++
			writeJSON(w, http.StatusOK, map[string]any{"errcode": 0, "access_token": "wecom-state-rollback-access", "expires_in": 7200})
		case "/getuserinfo":
			if r.URL.Query().Get("access_token") != "wecom-state-rollback-access" || r.URL.Query().Get("code") != "state-rollback-code" {
				http.Error(w, "bad userinfo request", http.StatusUnauthorized)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"errcode": 0, "UserId": "wecom-state-rollback-user"})
		case "/userget":
			if r.URL.Query().Get("access_token") != "wecom-state-rollback-access" || r.URL.Query().Get("userid") != "wecom-state-rollback-user" {
				http.Error(w, "bad user detail request", http.StatusUnauthorized)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"errcode": 0,
				"userid":  "wecom-state-rollback-user",
				"name":    "WeCom State Rollback User",
				"email":   "wecom-state-rollback@example.test",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "Enterprise WeChat state rollback",
		"type":   "identity",
		"status": "enabled",
		"metadata": map[string]any{
			"wecom_enabled":              true,
			"wecom_provider_id":          "state-rollback-wecom",
			"wecom_provider_name":        "State Rollback WeCom",
			"wecom_corp_id":              "ww-openweb",
			"wecom_agent_id":             "100001",
			"wecom_agent_secret":         "wecom-secret",
			"wecom_authorize_endpoint":   provider.URL + "/authorize",
			"wecom_token_endpoint":       provider.URL + "/gettoken",
			"wecom_userinfo_endpoint":    provider.URL + "/getuserinfo",
			"wecom_user_detail_endpoint": provider.URL + "/userget",
			"wecom_role":                 "user",
		},
	}, adminCookie, http.StatusCreated)
	state, err := srv.auth.createExternalWeComState("state-rollback-wecom", "/app/access")
	if err != nil {
		t.Fatalf("create external wecom state: %v", err)
	}

	removeBlocker := blockPlatformCollectionSavePayloadFragment(t, srv.cfg.Store, "users", `"online":true`)
	callbackRec := assertStatus(t, handler, http.MethodGet, "/api/auth/wecom/callback?state="+url.QueryEscape(state)+"&code=state-rollback-code", nil, nil, http.StatusInternalServerError)
	removeBlocker()
	if !strings.Contains(callbackRec.Body.String(), "persist user login state failed") {
		t.Fatalf("wecom login state failure was not reported: %s", callbackRec.Body.String())
	}
	if len(callbackRec.Result().Cookies()) > 0 {
		t.Fatalf("wecom callback issued cookies after failed login state write: %#v", callbackRec.Result().Cookies())
	}
	if tokenEndpointCalls != 1 {
		t.Fatalf("wecom token endpoint calls = %d, want 1", tokenEndpointCalls)
	}
	assertNoAuthSessionForUsername(t, srv, "wecom-state-rollback-user")
	usersRec := assertStatus(t, handler, http.MethodGet, "/api/admin/users", nil, adminCookie, http.StatusOK)
	if strings.Contains(usersRec.Body.String(), "wecom-state-rollback-user") || strings.Contains(usersRec.Body.String(), "wecom-state-rollback@example.test") {
		t.Fatalf("wecom auto-created user survived failed login state write: %s", usersRec.Body.String())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "auth.login.state.persist_failed") {
		t.Fatal("wecom login state persistence failure was not written to core audit logs")
	}

	state, err = srv.auth.createExternalWeComState("state-rollback-wecom", "/app/access")
	if err != nil {
		t.Fatalf("create external wecom state for retry: %v", err)
	}
	retryRec := assertStatus(t, handler, http.MethodGet, "/api/auth/wecom/callback?state="+url.QueryEscape(state)+"&code=state-rollback-code", nil, nil, http.StatusFound)
	if retryRec.Header().Get("Location") != "/app/access" {
		t.Fatalf("wecom retry did not redirect to requested next path: %s", retryRec.Header().Get("Location"))
	}
	if len(retryRec.Result().Cookies()) == 0 {
		t.Fatal("wecom retry after login state failure did not set auth cookie")
	}
}

func TestExternalWeComCallbackAutoCreateDisabledIsAudited(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)
	var tokenEndpointCalls int
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gettoken":
			tokenEndpointCalls++
			if r.URL.Query().Get("corpid") != "ww-openweb" || r.URL.Query().Get("corpsecret") != "wecom-secret" {
				http.Error(w, "bad token request", http.StatusUnauthorized)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"errcode": 0, "access_token": "wecom-denied-access", "expires_in": 7200})
		case "/getuserinfo":
			if r.URL.Query().Get("access_token") != "wecom-denied-access" || r.URL.Query().Get("code") != "denied-code" {
				http.Error(w, "bad userinfo request", http.StatusUnauthorized)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"errcode": 0, "UserId": "wecom-denied-user"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "Enterprise WeChat deny auto create",
		"type":   "identity",
		"status": "enabled",
		"metadata": map[string]any{
			"wecom_enabled":            true,
			"wecom_provider_id":        "deny-wecom",
			"wecom_provider_name":      "Deny WeCom",
			"wecom_corp_id":            "ww-openweb",
			"wecom_agent_id":           "100001",
			"wecom_agent_secret":       "wecom-secret",
			"wecom_authorize_endpoint": provider.URL + "/authorize",
			"wecom_token_endpoint":     provider.URL + "/gettoken",
			"wecom_userinfo_endpoint":  provider.URL + "/getuserinfo",
			"wecom_role":               "user",
			"wecom_auto_create":        false,
		},
	}, adminCookie, http.StatusCreated)
	state, err := srv.auth.createExternalWeComState("deny-wecom", "/app/access")
	if err != nil {
		t.Fatalf("create external wecom state: %v", err)
	}
	deniedRec := assertStatus(t, handler, http.MethodGet, "/api/auth/wecom/callback?state="+url.QueryEscape(state)+"&code=denied-code", nil, nil, http.StatusForbidden)
	if !strings.Contains(deniedRec.Body.String(), "auto creation is disabled") {
		t.Fatalf("wecom auto-create denial response missing reason: %s", deniedRec.Body.String())
	}
	if tokenEndpointCalls != 1 {
		t.Fatalf("wecom token endpoint calls = %d, want 1", tokenEndpointCalls)
	}
	usersRec := assertStatus(t, handler, http.MethodGet, "/api/admin/users", nil, adminCookie, http.StatusOK)
	if strings.Contains(usersRec.Body.String(), "wecom-denied-user") {
		t.Fatalf("wecom auto-create disabled still created user: %s", usersRec.Body.String())
	}
	loginLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/login-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(loginLogsRec.Body.String(), `"type":"wecom"`) || !strings.Contains(loginLogsRec.Body.String(), `"status":"failed"`) || !strings.Contains(loginLogsRec.Body.String(), "deny-wecom") || !strings.Contains(loginLogsRec.Body.String(), "auto creation is disabled") {
		t.Fatalf("wecom failed login log missing denial details: %s", loginLogsRec.Body.String())
	}
	operationLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(operationLogsRec.Body.String(), "auth.wecom.login_failed") {
		t.Fatalf("wecom failed login audit missing: %s", operationLogsRec.Body.String())
	}
}

func TestExternalWeComCallbackProviderErrorConsumesStateAndAudits(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "Enterprise WeChat provider error",
		"type":   "identity",
		"status": "enabled",
		"metadata": map[string]any{
			"wecom_enabled":            true,
			"wecom_provider_id":        "error-wecom",
			"wecom_provider_name":      "Error WeCom",
			"wecom_corp_id":            "ww-openweb",
			"wecom_agent_id":           "100001",
			"wecom_agent_secret":       "wecom-secret",
			"wecom_authorize_endpoint": "https://wecom.example.test/authorize",
			"wecom_token_endpoint":     "https://wecom.example.test/gettoken",
			"wecom_userinfo_endpoint":  "https://wecom.example.test/getuserinfo",
			"wecom_role":               "user",
		},
	}, adminCookie, http.StatusCreated)
	state, err := srv.auth.createExternalWeComState("error-wecom", "/app/access")
	if err != nil {
		t.Fatalf("create external wecom state: %v", err)
	}
	failedRec := assertStatus(t, handler, http.MethodGet, "/api/auth/wecom/callback?state="+url.QueryEscape(state)+"&error=access_denied", nil, nil, http.StatusBadRequest)
	if !strings.Contains(failedRec.Body.String(), "wecom provider returned error: access_denied") {
		t.Fatalf("wecom provider error response missing reason: %s", failedRec.Body.String())
	}
	reuseRec := assertStatus(t, handler, http.MethodGet, "/api/auth/wecom/callback?state="+url.QueryEscape(state)+"&code=reused-code", nil, nil, http.StatusBadRequest)
	if !strings.Contains(reuseRec.Body.String(), "wecom state is invalid or expired") {
		t.Fatalf("wecom provider error did not consume state: %s", reuseRec.Body.String())
	}
	loginLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/login-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(loginLogsRec.Body.String(), `"type":"wecom"`) || !strings.Contains(loginLogsRec.Body.String(), `"status":"failed"`) || !strings.Contains(loginLogsRec.Body.String(), "error-wecom") || !strings.Contains(loginLogsRec.Body.String(), "access_denied") {
		t.Fatalf("wecom provider error login log missing details: %s", loginLogsRec.Body.String())
	}
	operationLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(operationLogsRec.Body.String(), "auth.wecom.login_failed") || !strings.Contains(operationLogsRec.Body.String(), "access_denied") {
		t.Fatalf("wecom provider error operation audit missing: %s", operationLogsRec.Body.String())
	}
}

func TestExternalWeComCallbackTokenFailureIsAuditedAndRedacted(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)
	agentSecret := "wecom secret+/=?:&"
	escapedAgentSecret := url.QueryEscape(agentSecret)
	var tokenEndpointCalls int
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gettoken" {
			http.NotFound(w, r)
			return
		}
		tokenEndpointCalls++
		writeJSON(w, http.StatusOK, map[string]any{"errcode": 40001, "errmsg": "bad corpsecret " + agentSecret + " query " + r.URL.RawQuery})
	}))
	defer provider.Close()

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "Enterprise WeChat token failure",
		"type":   "identity",
		"status": "enabled",
		"metadata": map[string]any{
			"wecom_enabled":            true,
			"wecom_provider_id":        "broken-wecom",
			"wecom_provider_name":      "Broken WeCom",
			"wecom_corp_id":            "ww-openweb",
			"wecom_agent_id":           "100001",
			"wecom_agent_secret":       agentSecret,
			"wecom_authorize_endpoint": provider.URL + "/authorize",
			"wecom_token_endpoint":     provider.URL + "/gettoken",
			"wecom_userinfo_endpoint":  provider.URL + "/getuserinfo",
			"wecom_role":               "user",
		},
	}, adminCookie, http.StatusCreated)
	state, err := srv.auth.createExternalWeComState("broken-wecom", "/app/access")
	if err != nil {
		t.Fatalf("create external wecom state: %v", err)
	}
	failedRec := assertStatus(t, handler, http.MethodGet, "/api/auth/wecom/callback?state="+url.QueryEscape(state)+"&code=broken-code", nil, nil, http.StatusBadGateway)
	if !strings.Contains(failedRec.Body.String(), "bad corpsecret") || strings.Contains(failedRec.Body.String(), agentSecret) || strings.Contains(failedRec.Body.String(), escapedAgentSecret) {
		t.Fatalf("wecom token failure response missing sanitized reason or leaked secret: %s", failedRec.Body.String())
	}
	if tokenEndpointCalls != 1 {
		t.Fatalf("wecom token endpoint calls = %d, want 1", tokenEndpointCalls)
	}
	loginLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/login-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(loginLogsRec.Body.String(), `"type":"wecom"`) || !strings.Contains(loginLogsRec.Body.String(), `"status":"failed"`) || !strings.Contains(loginLogsRec.Body.String(), "broken-wecom") || !strings.Contains(loginLogsRec.Body.String(), "bad corpsecret") || strings.Contains(loginLogsRec.Body.String(), agentSecret) || strings.Contains(loginLogsRec.Body.String(), escapedAgentSecret) {
		t.Fatalf("wecom token failure log missing details or leaked secret: %s", loginLogsRec.Body.String())
	}
	operationLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(operationLogsRec.Body.String(), "auth.wecom.login_failed") || strings.Contains(operationLogsRec.Body.String(), agentSecret) || strings.Contains(operationLogsRec.Body.String(), escapedAgentSecret) {
		t.Fatalf("wecom token failure audit missing or leaked secret: %s", operationLogsRec.Body.String())
	}
}

func TestToolsAndMonitoringEndpoints(t *testing.T) {
	handler, cookie := newTestHandler(t)
	monitorRec := assertStatus(t, handler, http.MethodGet, "/api/system/monitoring", nil, cookie, http.StatusOK)
	var monitor map[string]any
	decodeResponse(t, monitorRec, &monitor)
	for _, key := range []string{"runtime", "memory", "database", "storage", "sessions_state", "ssh_gateway", "guacd", "uptime_seconds", "cpu_cores"} {
		if _, ok := monitor[key]; !ok {
			t.Fatalf("monitoring response missing %s: %v", key, monitor)
		}
	}
	if runtimeInfo, ok := monitor["runtime"].(map[string]any); !ok || runtimeInfo["go_version"] == "" || runtimeInfo["os"] == "" {
		t.Fatalf("monitoring runtime info incomplete: %v", monitor["runtime"])
	}
	if databaseInfo, ok := monitor["database"].(map[string]any); !ok || databaseInfo["path"] == "" || databaseInfo["connection_pool_state"] == "" {
		t.Fatalf("monitoring database info incomplete: %v", monitor["database"])
	}
	if storageInfo, ok := monitor["storage"].(map[string]any); !ok || storageInfo["data_dir"] == nil || storageInfo["total_bytes"] == nil {
		t.Fatalf("monitoring storage info incomplete: %v", monitor["storage"])
	}
	assertStatus(t, handler, http.MethodPost, "/api/tools/ping", map[string]any{"target": "localhost", "count": 1, "mode": "icmp"}, cookie, http.StatusOK)
	listener, closeListener := startAppTestTCPListener(t)
	defer closeListener()
	tcpRec := assertStatus(t, handler, http.MethodPost, "/api/tools/ping", map[string]any{"target": listener.Addr().String(), "count": 2, "mode": "tcp"}, cookie, http.StatusOK)
	tcpBody := tcpRec.Body.String()
	if !strings.Contains(tcpBody, `"mode":"tcp"`) || !strings.Contains(tcpBody, `"status":"ok"`) || !strings.Contains(tcpBody, "tcp connection established") {
		t.Fatalf("tcp ping did not report successful connection: %s", tcpBody)
	}
	badTCPRec := assertStatus(t, handler, http.MethodPost, "/api/tools/ping", map[string]any{"target": "localhost", "count": 1, "mode": "tcp"}, cookie, http.StatusBadRequest)
	if !strings.Contains(badTCPRec.Body.String(), "host:port") {
		t.Fatalf("invalid tcp ping target did not return clear error: %s", badTCPRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, "/api/tools/ping", map[string]any{"target": "", "count": 1}, cookie, http.StatusBadRequest)
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, cookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), "tool.ping") {
		t.Fatalf("ping tool did not write operation log: %s", logsRec.Body.String())
	}
}

func TestNotificationsReflectRuntimeAndFilterByUser(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	assertStatus(t, handler, http.MethodGet, "/api/notifications", nil, nil, http.StatusUnauthorized)
	assertStatus(t, handler, http.MethodPost, "/api/notifications/read", map[string]any{"keys": []string{"notice:connection-workspace"}}, nil, http.StatusUnauthorized)
	assertStatus(t, handler, http.MethodPost, "/api/admin/audit/online-sessions", map[string]any{
		"name":     "admin ssh",
		"type":     "ssh",
		"status":   "active",
		"protocol": "ssh",
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/audit/login-logs", map[string]any{
		"name":        "root",
		"type":        "password",
		"status":      "failed",
		"description": "invalid username or password",
		"metadata":    map[string]any{"account": "root", "client_ip": "198.51.100.10"},
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/audit/operation-logs", map[string]any{
		"name":        "asset health check",
		"type":        "scheduled_task",
		"status":      "failed",
		"description": "asset check failed",
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/agent-gateways", map[string]any{
		"name":   "edge-offline",
		"type":   "agent",
		"status": "offline",
	}, adminCookie, http.StatusCreated)

	adminRec := assertStatus(t, handler, http.MethodGet, "/api/notifications", nil, adminCookie, http.StatusOK)
	adminBody := adminRec.Body.String()
	for _, want := range []string{"rdpGatewayOffline", "notification.activeSessions", "notification.loginFailed", "notification.taskFailed", "notification.agentGatewayOffline"} {
		if !strings.Contains(adminBody, want) {
			t.Fatalf("admin notifications missing %q: %s", want, adminBody)
		}
	}
	var adminPayload struct {
		Items    []notificationItem `json:"items"`
		ReadKeys []string           `json:"read_keys"`
	}
	decodeResponse(t, adminRec, &adminPayload)
	if len(adminPayload.Items) == 0 {
		t.Fatalf("admin notifications did not return timeline items: %s", adminBody)
	}
	if len(adminPayload.ReadKeys) != 0 {
		t.Fatalf("new admin notification read state should be empty: %#v", adminPayload.ReadKeys)
	}
	readKey := "timeline:" + adminPayload.Items[0].ID
	readRec := assertStatus(t, handler, http.MethodPost, "/api/notifications/read", map[string]any{
		"keys": []string{"notice:connection-workspace", readKey, readKey, "bad\nkey", strings.Repeat("x", 201)},
	}, adminCookie, http.StatusOK)
	readBody := readRec.Body.String()
	if !strings.Contains(readBody, "notice:connection-workspace") || !strings.Contains(readBody, readKey) || strings.Contains(readBody, "bad\\nkey") || strings.Contains(readBody, strings.Repeat("x", 201)) {
		t.Fatalf("notification read response did not persist sanitized keys: %s", readBody)
	}
	readBackRec := assertStatus(t, handler, http.MethodGet, "/api/notifications", nil, adminCookie, http.StatusOK)
	if !strings.Contains(readBackRec.Body.String(), readKey) {
		t.Fatalf("notification read keys were not returned on next fetch: %s", readBackRec.Body.String())
	}
	adminBootstrapRec := assertStatus(t, handler, http.MethodGet, "/api/bootstrap", nil, adminCookie, http.StatusOK)
	if !strings.Contains(adminBootstrapRec.Body.String(), `"guacd"`) {
		t.Fatalf("admin bootstrap missing runtime guacd state: %s", adminBootstrapRec.Body.String())
	}
	if strings.Contains(adminBootstrapRec.Body.String(), "notification_reads") || strings.Contains(adminBootstrapRec.Body.String(), readKey) {
		t.Fatalf("bootstrap leaked private notification read state: %s", adminBootstrapRec.Body.String())
	}

	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "limited-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)
	assertStatus(t, handler, http.MethodPost, "/api/admin/audit/login-logs", map[string]any{
		"name":        "limited-user",
		"type":        "password",
		"status":      "failed",
		"owner_id":    user.ID,
		"description": "invalid username or password",
		"metadata":    map[string]any{"account": "limited-user"},
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/audit/login-logs", map[string]any{
		"name":        "other-user",
		"type":        "password",
		"status":      "failed",
		"description": "invalid username or password",
		"metadata":    map[string]any{"account": "other-user"},
	}, adminCookie, http.StatusCreated)
	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "limited-user", "password": "password123"}, nil, http.StatusOK)
	userCookie := loginRec.Result().Cookies()[0]
	limitedRec := assertStatus(t, handler, http.MethodGet, "/api/notifications", nil, userCookie, http.StatusOK)
	limitedBody := limitedRec.Body.String()
	if !strings.Contains(limitedBody, "limited-user") {
		t.Fatalf("limited user did not receive own login notification: %s", limitedBody)
	}
	if strings.Contains(limitedBody, "other-user") || strings.Contains(limitedBody, "notification.taskFailed") || strings.Contains(limitedBody, "rdpGatewayOffline") || strings.Contains(limitedBody, `"category":"runtime"`) {
		t.Fatalf("limited user received another user's/system notification: %s", limitedBody)
	}
	limitedReadRec := assertStatus(t, handler, http.MethodPost, "/api/notifications/read", map[string]any{"keys": []string{"timeline:limited-only"}}, userCookie, http.StatusOK)
	if !strings.Contains(limitedReadRec.Body.String(), "timeline:limited-only") {
		t.Fatalf("limited user's notification read state was not saved: %s", limitedReadRec.Body.String())
	}
	adminReadBackRec := assertStatus(t, handler, http.MethodGet, "/api/notifications", nil, adminCookie, http.StatusOK)
	if strings.Contains(adminReadBackRec.Body.String(), "timeline:limited-only") {
		t.Fatalf("admin notification read state included another user's key: %s", adminReadBackRec.Body.String())
	}
	limitedBootstrapRec := assertStatus(t, handler, http.MethodGet, "/api/bootstrap", nil, userCookie, http.StatusOK)
	if strings.Contains(limitedBootstrapRec.Body.String(), `"guacd"`) {
		t.Fatalf("limited user bootstrap leaked runtime guacd state: %s", limitedBootstrapRec.Body.String())
	}
	if strings.Contains(limitedBootstrapRec.Body.String(), "notification_reads") || strings.Contains(limitedBootstrapRec.Body.String(), "timeline:limited-only") {
		t.Fatalf("limited bootstrap leaked private notification read state: %s", limitedBootstrapRec.Body.String())
	}
}

func TestAgentGatewayRegistrationHeartbeatAndTimeout(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)

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
	expiresAtText, _ := tokenPayload["expires_at"].(string)
	expiresAt, err := time.Parse(time.RFC3339Nano, expiresAtText)
	if err != nil {
		t.Fatalf("registration token expires_at = %q, want RFC3339 timestamp: %v", expiresAtText, err)
	}
	if !expiresAt.After(time.Now().UTC().Add(29*24*time.Hour)) || !expiresAt.Before(time.Now().UTC().Add(31*24*time.Hour)) {
		t.Fatalf("registration token expires_at = %s, want about 30 days from now", expiresAt)
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
		"metrics": map[string]any{
			"queue_depth": 2,
			"password":    "agent-metric-password",
			"nested": map[string]any{
				"private_key": "agent-metric-private-key",
				"label":       "agent-metric-safe-label",
			},
			"tokens": []any{
				map[string]any{"token": "agent-metric-token", "value": "safe-token-counter"},
			},
		},
	}, nil, map[string]string{
		"Authorization": "Bearer " + registrationToken,
	}, http.StatusOK)
	for _, want := range []string{`"latency_ms":18`, `"cpu_percent":12.5`, `"memory_percent":50`, `"active_sessions":3`, "queue_depth"} {
		if !strings.Contains(heartbeatRec.Body.String(), want) {
			t.Fatalf("heartbeat response did not include %q", want)
		}
	}
	for _, leaked := range []string{"agent-metric-password", "agent-metric-private-key", "agent-metric-token"} {
		if strings.Contains(heartbeatRec.Body.String(), leaked) {
			t.Fatalf("heartbeat response leaked metric secret %q: %s", leaked, heartbeatRec.Body.String())
		}
	}
	rawHeartbeatGateway, ok, err := srv.cfg.Store.GetPlatformItem("agent_gateways", gateway.ID)
	if err != nil || !ok {
		t.Fatalf("load heartbeat gateway: ok=%v err=%v", ok, err)
	}
	rawHeartbeatJSON, err := json.Marshal(rawHeartbeatGateway)
	if err != nil {
		t.Fatalf("marshal raw heartbeat gateway: %v", err)
	}
	rawHeartbeatText := string(rawHeartbeatJSON)
	for _, leaked := range []string{"agent-metric-password", "agent-metric-private-key", "agent-metric-token"} {
		if strings.Contains(rawHeartbeatText, leaked) {
			t.Fatalf("raw agent gateway persisted metric secret %q: %s", leaked, rawHeartbeatText)
		}
	}
	for _, kept := range []string{"queue_depth", "agent-metric-safe-label", "safe-token-counter"} {
		if !strings.Contains(rawHeartbeatText, kept) {
			t.Fatalf("raw agent gateway lost non-sensitive metric %q: %s", kept, rawHeartbeatText)
		}
	}

	listRec := assertStatus(t, handler, http.MethodGet, "/api/admin/agent-gateways", nil, adminCookie, http.StatusOK)
	if !strings.Contains(listRec.Body.String(), `"status":"online"`) || !strings.Contains(listRec.Body.String(), `"latency_ms":18`) {
		t.Fatal("agent gateway list did not include online heartbeat metrics")
	}
	if strings.Contains(listRec.Body.String(), "agent_token_hash") || strings.Contains(listRec.Body.String(), registrationToken) || strings.Contains(listRec.Body.String(), "agent-metric-password") || strings.Contains(listRec.Body.String(), "agent-metric-private-key") || strings.Contains(listRec.Body.String(), "agent-metric-token") {
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
	patchedGateway, ok, err := srv.cfg.Store.GetPlatformItem("agent_gateways", gateway.ID)
	if err != nil || !ok {
		t.Fatalf("load patched gateway: ok=%v err=%v", ok, err)
	}
	if got := firstMetadataString(patchedGateway.Metadata, "token_expires_at"); got != expiresAtText {
		t.Fatalf("agent gateway metadata patch did not preserve token_expires_at: got %q want %q", got, expiresAtText)
	}
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

	rotatedTokenRec := assertStatus(t, handler, http.MethodPost, "/api/admin/agent-gateways/"+gateway.ID+"/token", nil, adminCookie, http.StatusOK)
	var rotatedTokenPayload map[string]any
	decodeResponse(t, rotatedTokenRec, &rotatedTokenPayload)
	rotatedRegistrationToken, _ := rotatedTokenPayload["registration_token"].(string)
	if rotatedRegistrationToken == "" || rotatedRegistrationToken == registrationToken {
		t.Fatalf("rotated registration token = %q, old token = %q", rotatedRegistrationToken, registrationToken)
	}
	if strings.Contains(rotatedTokenRec.Body.String(), "agent_token_hash") || strings.Contains(rotatedTokenRec.Body.String(), registrationToken) {
		t.Fatalf("rotated token response leaked token material: %s", rotatedTokenRec.Body.String())
	}
	rotatedStatusRec := assertStatus(t, handler, http.MethodGet, "/api/admin/agent-gateways", nil, adminCookie, http.StatusOK)
	if !strings.Contains(rotatedStatusRec.Body.String(), `"status":"offline"`) || !strings.Contains(rotatedStatusRec.Body.String(), "token rotated") {
		t.Fatalf("token rotation did not mark gateway offline: %s", rotatedStatusRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, "/api/agent/gateways/heartbeat", map[string]any{
		"registration_token": registrationToken,
		"latency_ms":         7,
	}, nil, http.StatusUnauthorized)
	assertStatus(t, handler, http.MethodPost, "/api/agent/gateways/heartbeat", map[string]any{
		"registration_token": rotatedRegistrationToken,
		"latency_ms":         6,
	}, nil, http.StatusOK)
	rotatedRecoveredRec := assertStatus(t, handler, http.MethodGet, "/api/admin/agent-gateways", nil, adminCookie, http.StatusOK)
	if !strings.Contains(rotatedRecoveredRec.Body.String(), `"status":"online"`) || !strings.Contains(rotatedRecoveredRec.Body.String(), `"latency_ms":6`) {
		t.Fatalf("rotated token heartbeat did not recover gateway: %s", rotatedRecoveredRec.Body.String())
	}
	expiredGateway, ok, err := srv.cfg.Store.GetPlatformItem("agent_gateways", gateway.ID)
	if err != nil || !ok {
		t.Fatalf("load gateway before expiry check: ok=%v err=%v", ok, err)
	}
	expiredGateway.Metadata["token_expires_at"] = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	if _, err := srv.cfg.Store.SavePlatformItem("agent_gateways", expiredGateway); err != nil {
		t.Fatalf("save expired gateway token metadata: %v", err)
	}
	expiredHeartbeatRec := assertStatus(t, handler, http.MethodPost, "/api/agent/gateways/heartbeat", map[string]any{
		"registration_token": rotatedRegistrationToken,
		"latency_ms":         5,
	}, nil, http.StatusUnauthorized)
	if !strings.Contains(expiredHeartbeatRec.Body.String(), "expired") {
		t.Fatalf("expired agent token did not return clear error: %s", expiredHeartbeatRec.Body.String())
	}

	assertStatus(t, handler, http.MethodPatch, "/api/admin/agent-gateways/"+gateway.ID, map[string]any{
		"status": "disabled",
	}, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/agent/gateways/heartbeat", map[string]any{
		"registration_token": rotatedRegistrationToken,
		"latency_ms":         5,
	}, nil, http.StatusForbidden)
	assertStatus(t, handler, http.MethodPost, "/api/admin/agent-gateways/"+gateway.ID+"/token", nil, adminCookie, http.StatusForbidden)
	disabledRec := assertStatus(t, handler, http.MethodGet, "/api/admin/agent-gateways/"+gateway.ID, nil, adminCookie, http.StatusOK)
	if !strings.Contains(disabledRec.Body.String(), `"status":"disabled"`) || strings.Contains(disabledRec.Body.String(), `"latency_ms":5`) {
		t.Fatalf("disabled gateway accepted heartbeat or changed status: %s", disabledRec.Body.String())
	}

	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	logsBody := logsRec.Body.String()
	for _, want := range []string{"agent.gateway.register", "agent_gateway.token", "agent.gateway.timeout", "agent.gateway.recovered"} {
		if !strings.Contains(logsBody, want) {
			t.Fatalf("agent gateway operation %q was not audited: %s", want, logsBody)
		}
	}
}

func TestAgentGatewayOperationLogPersistenceFailures(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)

	gatewayRec := assertStatus(t, handler, http.MethodPost, "/api/admin/agent-gateways", map[string]any{
		"name":     "blocked-agent-gateway",
		"type":     "agent",
		"status":   "offline",
		"metadata": map[string]any{"heartbeat_timeout_seconds": 30},
	}, adminCookie, http.StatusCreated)
	var gateway model.PlatformItem
	decodeResponse(t, gatewayRec, &gateway)

	removeTokenBlocker := blockOperationLogName(t, srv.cfg.Store, "agent_gateway.token")
	tokenFailureRec := assertStatus(t, handler, http.MethodPost, "/api/admin/agent-gateways/"+gateway.ID+"/token", nil, adminCookie, http.StatusInternalServerError)
	removeTokenBlocker()
	if !strings.Contains(tokenFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("agent token operation log failure was not reported: %s", tokenFailureRec.Body.String())
	}
	if strings.Contains(tokenFailureRec.Body.String(), "registration_token") || strings.Contains(tokenFailureRec.Body.String(), `"token":`) {
		t.Fatalf("agent token operation log failure leaked token material: %s", tokenFailureRec.Body.String())
	}
	storedGateway, ok, err := srv.cfg.Store.GetPlatformItem("agent_gateways", gateway.ID)
	if err != nil || !ok {
		t.Fatalf("load gateway after failed token issue: ok=%v err=%v", ok, err)
	}
	if firstMetadataString(storedGateway.Metadata, "agent_token_hash") != "" || firstMetadataString(storedGateway.Metadata, "token_expires_at") != "" || metadataIntDefault(storedGateway.Metadata["token_generation"], 0) != 0 {
		t.Fatalf("agent token issue changed gateway token state before audit log persisted: %#v", storedGateway)
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "operation.log.persist_failed") {
		t.Fatal("agent token operation log persistence failure was not written to core audit logs")
	}

	tokenRestoreGatewayRec := assertStatus(t, handler, http.MethodPost, "/api/admin/agent-gateways", map[string]any{
		"name":   "token-restore-failure-gateway",
		"type":   "agent",
		"status": "offline",
		"metadata": map[string]any{
			"heartbeat_timeout_seconds": 30,
			"token_generation":          0,
		},
	}, adminCookie, http.StatusCreated)
	var tokenRestoreGateway model.PlatformItem
	decodeResponse(t, tokenRestoreGatewayRec, &tokenRestoreGateway)
	removeTokenLogBlocker := blockOperationLogName(t, srv.cfg.Store, "agent_gateway.token")
	removeTokenRestoreBlocker := blockPlatformItemSavePayloadFragment(t, srv.cfg.Store, "agent_gateways", tokenRestoreGateway.ID, `"token_generation":0`)
	tokenRestoreFailureRec := assertStatus(t, handler, http.MethodPost, "/api/admin/agent-gateways/"+tokenRestoreGateway.ID+"/token", nil, adminCookie, http.StatusInternalServerError)
	removeTokenRestoreBlocker()
	removeTokenLogBlocker()
	if !strings.Contains(tokenRestoreFailureRec.Body.String(), "failed to restore agent gateway after token operation log failure") {
		t.Fatalf("agent token restore failure was not reported: %s", tokenRestoreFailureRec.Body.String())
	}
	if strings.Contains(tokenRestoreFailureRec.Body.String(), "registration_token") || strings.Contains(tokenRestoreFailureRec.Body.String(), `"token":`) {
		t.Fatalf("agent token restore failure leaked token material: %s", tokenRestoreFailureRec.Body.String())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "agent_gateway.restore_failed") {
		t.Fatal("agent token restore failure was not written to core audit logs")
	}

	tokenRec := assertStatus(t, handler, http.MethodPost, "/api/admin/agent-gateways/"+gateway.ID+"/token", nil, adminCookie, http.StatusOK)
	var tokenPayload map[string]any
	decodeResponse(t, tokenRec, &tokenPayload)
	registrationToken, _ := tokenPayload["registration_token"].(string)
	if registrationToken == "" {
		t.Fatal("agent token response did not include registration token")
	}

	removeRegisterBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	registerFailureRec := assertStatus(t, handler, http.MethodPost, "/api/agent/gateways/register", map[string]any{
		"registration_token": registrationToken,
		"hostname":           "blocked-edge-01",
		"version":            "9.9.9",
	}, nil, http.StatusInternalServerError)
	removeRegisterBlocker()
	if !strings.Contains(registerFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("agent register operation log failure was not reported: %s", registerFailureRec.Body.String())
	}
	storedGateway, ok, err = srv.cfg.Store.GetPlatformItem("agent_gateways", gateway.ID)
	if err != nil || !ok {
		t.Fatalf("load gateway after failed register: ok=%v err=%v", ok, err)
	}
	if storedGateway.Status != "offline" || firstMetadataString(storedGateway.Metadata, "registered_at") != "" || firstMetadataString(storedGateway.Metadata, "hostname") == "blocked-edge-01" {
		t.Fatalf("agent register changed gateway state before audit log persisted: %#v", storedGateway)
	}

	registerRestoreGatewayRec := assertStatus(t, handler, http.MethodPost, "/api/admin/agent-gateways", map[string]any{
		"name":     "register-restore-failure-gateway",
		"type":     "agent",
		"status":   "offline",
		"metadata": map[string]any{"heartbeat_timeout_seconds": 30},
	}, adminCookie, http.StatusCreated)
	var registerRestoreGateway model.PlatformItem
	decodeResponse(t, registerRestoreGatewayRec, &registerRestoreGateway)
	registerRestoreTokenRec := assertStatus(t, handler, http.MethodPost, "/api/admin/agent-gateways/"+registerRestoreGateway.ID+"/token", nil, adminCookie, http.StatusOK)
	var registerRestoreTokenPayload map[string]any
	decodeResponse(t, registerRestoreTokenRec, &registerRestoreTokenPayload)
	registerRestoreToken, _ := registerRestoreTokenPayload["registration_token"].(string)
	removeRegisterLogBlocker := blockOperationLogName(t, srv.cfg.Store, "agent.gateway.register")
	removeRegisterRestoreBlocker := blockPlatformItemSavePayloadFragment(t, srv.cfg.Store, "agent_gateways", registerRestoreGateway.ID, `"status":"offline"`)
	registerRestoreFailureRec := assertStatus(t, handler, http.MethodPost, "/api/agent/gateways/register", map[string]any{
		"registration_token": registerRestoreToken,
		"hostname":           "register-restore-edge",
		"version":            "9.9.9",
	}, nil, http.StatusInternalServerError)
	removeRegisterRestoreBlocker()
	removeRegisterLogBlocker()
	if !strings.Contains(registerRestoreFailureRec.Body.String(), "failed to restore agent gateway after register operation log failure") {
		t.Fatalf("agent register restore failure was not reported: %s", registerRestoreFailureRec.Body.String())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "agent_gateway.restore_failed") {
		t.Fatal("agent register restore failure was not written to core audit logs")
	}

	assertStatus(t, handler, http.MethodPost, "/api/agent/gateways/register", map[string]any{
		"registration_token": registrationToken,
		"hostname":           "blocked-edge-01",
		"version":            "1.0.0",
	}, nil, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, "/api/admin/agent-gateways/"+gateway.ID, map[string]any{
		"status": "offline",
		"metadata": map[string]any{
			"last_heartbeat_at":         time.Now().UTC().Format(time.RFC3339Nano),
			"heartbeat_timeout_seconds": 30,
			"latency_ms":                100,
		},
	}, adminCookie, http.StatusOK)

	heartbeatRestoreGatewayRec := assertStatus(t, handler, http.MethodPost, "/api/admin/agent-gateways", map[string]any{
		"name":     "heartbeat-restore-failure-gateway",
		"type":     "agent",
		"status":   "offline",
		"metadata": map[string]any{"heartbeat_timeout_seconds": 30},
	}, adminCookie, http.StatusCreated)
	var heartbeatRestoreGateway model.PlatformItem
	decodeResponse(t, heartbeatRestoreGatewayRec, &heartbeatRestoreGateway)
	heartbeatRestoreTokenRec := assertStatus(t, handler, http.MethodPost, "/api/admin/agent-gateways/"+heartbeatRestoreGateway.ID+"/token", nil, adminCookie, http.StatusOK)
	var heartbeatRestoreTokenPayload map[string]any
	decodeResponse(t, heartbeatRestoreTokenRec, &heartbeatRestoreTokenPayload)
	heartbeatRestoreToken, _ := heartbeatRestoreTokenPayload["registration_token"].(string)
	assertStatus(t, handler, http.MethodPost, "/api/agent/gateways/register", map[string]any{
		"registration_token": heartbeatRestoreToken,
		"hostname":           "heartbeat-restore-edge",
		"version":            "1.0.0",
	}, nil, http.StatusOK)
	assertStatus(t, handler, http.MethodPatch, "/api/admin/agent-gateways/"+heartbeatRestoreGateway.ID, map[string]any{
		"status": "offline",
		"metadata": map[string]any{
			"last_heartbeat_at":         time.Now().UTC().Format(time.RFC3339Nano),
			"heartbeat_timeout_seconds": 30,
			"latency_ms":                44,
		},
	}, adminCookie, http.StatusOK)
	removeHeartbeatLogBlocker := blockOperationLogName(t, srv.cfg.Store, "agent.gateway.recovered")
	removeHeartbeatRestoreBlocker := blockPlatformItemSavePayloadFragment(t, srv.cfg.Store, "agent_gateways", heartbeatRestoreGateway.ID, `"status":"offline"`)
	heartbeatRestoreFailureRec := assertStatus(t, handler, http.MethodPost, "/api/agent/gateways/heartbeat", map[string]any{
		"registration_token": heartbeatRestoreToken,
		"latency_ms":         11,
	}, nil, http.StatusInternalServerError)
	removeHeartbeatRestoreBlocker()
	removeHeartbeatLogBlocker()
	if !strings.Contains(heartbeatRestoreFailureRec.Body.String(), "failed to restore agent gateway after recovered event failure") {
		t.Fatalf("agent heartbeat restore failure was not reported: %s", heartbeatRestoreFailureRec.Body.String())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "agent_gateway.restore_failed") {
		t.Fatal("agent heartbeat restore failure was not written to core audit logs")
	}

	removeHeartbeatBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	heartbeatFailureRec := assertStatus(t, handler, http.MethodPost, "/api/agent/gateways/heartbeat", map[string]any{
		"registration_token": registrationToken,
		"latency_ms":         12,
	}, nil, http.StatusInternalServerError)
	removeHeartbeatBlocker()
	if !strings.Contains(heartbeatFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("agent heartbeat operation log failure was not reported: %s", heartbeatFailureRec.Body.String())
	}
	storedGateway, ok, err = srv.cfg.Store.GetPlatformItem("agent_gateways", gateway.ID)
	if err != nil || !ok {
		t.Fatalf("load gateway after failed heartbeat: ok=%v err=%v", ok, err)
	}
	if storedGateway.Status != "offline" || metadataIntDefault(storedGateway.Metadata["latency_ms"], 0) != 100 {
		t.Fatalf("agent heartbeat recovered gateway before audit log persisted: %#v", storedGateway)
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "operation.log.persist_failed") {
		t.Fatal("agent operation log persistence failure was not written to core audit logs")
	}
}

func TestGatewayGroupStatusResolvesMembers(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	onlineAgentRec := assertStatus(t, handler, http.MethodPost, "/api/admin/agent-gateways", map[string]any{
		"name":   "prod-edge-online",
		"type":   "agent",
		"status": "online",
		"tags":   []string{"prod", "edge"},
		"metadata": map[string]any{
			"capabilities":    []string{"ssh", "rdp"},
			"latency_ms":      25,
			"active_sessions": 2,
		},
	}, adminCookie, http.StatusCreated)
	var onlineAgent model.PlatformItem
	decodeResponse(t, onlineAgentRec, &onlineAgent)

	offlineAgentRec := assertStatus(t, handler, http.MethodPost, "/api/admin/agent-gateways", map[string]any{
		"name":   "prod-edge-offline",
		"type":   "agent",
		"status": "offline",
		"tags":   []string{"prod", "edge"},
		"metadata": map[string]any{
			"capabilities":    []string{"ssh"},
			"latency_ms":      5,
			"offline_reason":  "test offline",
			"active_sessions": 0,
		},
	}, adminCookie, http.StatusCreated)
	var offlineAgent model.PlatformItem
	decodeResponse(t, offlineAgentRec, &offlineAgent)

	devAgentRec := assertStatus(t, handler, http.MethodPost, "/api/admin/agent-gateways", map[string]any{
		"name":     "dev-edge-online",
		"type":     "agent",
		"status":   "online",
		"tags":     []string{"dev"},
		"metadata": map[string]any{"capabilities": []string{"ssh"}},
	}, adminCookie, http.StatusCreated)
	var devAgent model.PlatformItem
	decodeResponse(t, devAgentRec, &devAgent)

	sshGatewayRec := assertStatus(t, handler, http.MethodPost, "/api/admin/ssh-gateways", map[string]any{
		"name":   "native-ssh-gateway",
		"type":   "builtin",
		"status": "enabled",
		"host":   "127.0.0.1",
		"port":   2022,
	}, adminCookie, http.StatusCreated)
	var sshGateway model.PlatformItem
	decodeResponse(t, sshGatewayRec, &sshGateway)

	manualGroupRec := assertStatus(t, handler, http.MethodPost, "/api/admin/gateway-groups", map[string]any{
		"name":   "manual failover",
		"type":   "manual",
		"status": "enabled",
		"metadata": map[string]any{
			"gateway_ids": []string{offlineAgent.ID, sshGateway.ID, onlineAgent.ID},
		},
	}, adminCookie, http.StatusCreated)
	var manualGroup model.PlatformItem
	decodeResponse(t, manualGroupRec, &manualGroup)

	autoGroupRec := assertStatus(t, handler, http.MethodPost, "/api/admin/gateway-groups", map[string]any{
		"name":   "auto prod ssh",
		"type":   "auto",
		"status": "enabled",
		"metadata": map[string]any{
			"labels":       []string{"prod", "edge"},
			"capabilities": []string{"ssh"},
		},
	}, adminCookie, http.StatusCreated)
	var autoGroup model.PlatformItem
	decodeResponse(t, autoGroupRec, &autoGroup)

	statusRec := assertStatus(t, handler, http.MethodGet, "/api/admin/gateway-groups/status", nil, adminCookie, http.StatusOK)
	var statusPayload struct {
		Items []gatewayGroupStatus `json:"items"`
	}
	decodeResponse(t, statusRec, &statusPayload)
	manualStatus := gatewayGroupStatusByID(statusPayload.Items, manualGroup.ID)
	if manualStatus == nil {
		t.Fatalf("manual gateway group missing from status payload: %s", statusRec.Body.String())
	}
	if len(manualStatus.Members) != 3 || manualStatus.Online != 2 || manualStatus.Offline != 1 || manualStatus.SelectedGatewayID != sshGateway.ID {
		t.Fatalf("manual gateway group status = %#v", manualStatus)
	}
	if manualStatus.Members[0].ID != offlineAgent.ID || manualStatus.Members[1].ID != sshGateway.ID || manualStatus.Members[2].ID != onlineAgent.ID {
		t.Fatalf("manual gateway group did not preserve configured order: %#v", manualStatus.Members)
	}

	autoStatus := gatewayGroupStatusByID(statusPayload.Items, autoGroup.ID)
	if autoStatus == nil {
		t.Fatalf("auto gateway group missing from status payload: %s", statusRec.Body.String())
	}
	if len(autoStatus.Members) != 2 || autoStatus.Online != 1 || autoStatus.Offline != 1 || autoStatus.SelectedGatewayID != onlineAgent.ID {
		t.Fatalf("auto gateway group status = %#v", autoStatus)
	}
	for _, member := range autoStatus.Members {
		if member.ID == devAgent.ID || member.ID == sshGateway.ID {
			t.Fatalf("auto gateway group included non-matching gateway: %#v", autoStatus.Members)
		}
	}

	listRec := assertStatus(t, handler, http.MethodGet, "/api/admin/gateway-groups", nil, adminCookie, http.StatusOK)
	listBody := listRec.Body.String()
	for _, want := range []string{"member_count", "online_count", "offline_count", "selected_gateway_id", sshGateway.ID, onlineAgent.ID} {
		if !strings.Contains(listBody, want) {
			t.Fatalf("gateway group list missing %q: %s", want, listBody)
		}
	}
}

func gatewayGroupStatusByID(items []gatewayGroupStatus, id string) *gatewayGroupStatus {
	for index := range items {
		if items[index].ID == id {
			return &items[index]
		}
	}
	return nil
}

func TestAccessPortalEnforcesGatewayGroupRouting(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	offlineGatewayRec := assertStatus(t, handler, http.MethodPost, "/api/admin/agent-gateways", map[string]any{
		"name":   "route-offline",
		"type":   "agent",
		"status": "offline",
		"tags":   []string{"prod"},
		"metadata": map[string]any{
			"capabilities": []string{"ssh", "database"},
		},
	}, adminCookie, http.StatusCreated)
	var offlineGateway model.PlatformItem
	decodeResponse(t, offlineGatewayRec, &offlineGateway)

	blockedGroupRec := assertStatus(t, handler, http.MethodPost, "/api/admin/gateway-groups", map[string]any{
		"name":   "blocked-route",
		"type":   "manual",
		"status": "enabled",
		"metadata": map[string]any{
			"gateway_ids": []string{offlineGateway.ID},
		},
	}, adminCookie, http.StatusCreated)
	var blockedGroup model.PlatformItem
	decodeResponse(t, blockedGroupRec, &blockedGroup)

	blockedAssetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "blocked-route-linux",
		"type":     "linux",
		"status":   "active",
		"protocol": "ssh",
		"host":     "127.0.0.1",
		"port":     22,
		"metadata": map[string]any{"gateway_group_id": blockedGroup.ID},
	}, adminCookie, http.StatusCreated)
	var blockedAsset model.PlatformItem
	decodeResponse(t, blockedAssetRec, &blockedAsset)
	assertStatus(t, handler, http.MethodPost, "/api/admin/credentials", map[string]any{
		"name":      "blocked-route-root",
		"type":      "ssh_password",
		"status":    "encrypted",
		"username":  "root",
		"password":  "target-secret",
		"target_id": blockedAsset.ID,
	}, adminCookie, http.StatusCreated)

	blockedRec := assertStatus(t, handler, http.MethodPost, "/api/access/ssh/"+blockedAsset.ID, map[string]any{
		"cols": 120,
		"rows": 32,
	}, adminCookie, http.StatusServiceUnavailable)
	if !strings.Contains(blockedRec.Body.String(), "gateway group has no online gateway") {
		t.Fatalf("blocked route response did not explain gateway status: %s", blockedRec.Body.String())
	}

	onlineGatewayRec := assertStatus(t, handler, http.MethodPost, "/api/admin/agent-gateways", map[string]any{
		"name":   "route-online",
		"type":   "agent",
		"status": "online",
		"tags":   []string{"prod"},
		"metadata": map[string]any{
			"capabilities":    []string{"ssh", "database"},
			"latency_ms":      10,
			"active_sessions": 0,
		},
	}, adminCookie, http.StatusCreated)
	var onlineGateway model.PlatformItem
	decodeResponse(t, onlineGatewayRec, &onlineGateway)

	routeGroupRec := assertStatus(t, handler, http.MethodPost, "/api/admin/gateway-groups", map[string]any{
		"name":   "active-route",
		"type":   "manual",
		"status": "enabled",
		"metadata": map[string]any{
			"gateway_ids": []string{offlineGateway.ID, onlineGateway.ID},
		},
	}, adminCookie, http.StatusCreated)
	var routeGroup model.PlatformItem
	decodeResponse(t, routeGroupRec, &routeGroup)

	assetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "routed-linux",
		"type":     "linux",
		"status":   "active",
		"protocol": "ssh",
		"host":     "127.0.0.1",
		"port":     22,
		"metadata": map[string]any{"gateway_group_id": routeGroup.ID},
	}, adminCookie, http.StatusCreated)
	var asset model.PlatformItem
	decodeResponse(t, assetRec, &asset)
	assertStatus(t, handler, http.MethodPost, "/api/admin/credentials", map[string]any{
		"name":      "routed-root",
		"type":      "ssh_password",
		"status":    "encrypted",
		"username":  "root",
		"password":  "target-secret",
		"target_id": asset.ID,
	}, adminCookie, http.StatusCreated)

	sessionRec := assertStatus(t, handler, http.MethodPost, "/api/access/ssh/"+asset.ID, map[string]any{
		"cols": 100,
		"rows": 24,
	}, adminCookie, http.StatusAccepted)
	var session model.ConnectionSession
	decodeResponse(t, sessionRec, &session)
	if session.GatewayGroupID != routeGroup.ID || session.GatewayID != onlineGateway.ID || session.GatewayName != onlineGateway.Name || session.GatewayCollection != "agent_gateways" {
		t.Fatalf("session missing selected gateway route: %#v", session)
	}
	onlineSessionsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/online-sessions", nil, adminCookie, http.StatusOK)
	if !strings.Contains(onlineSessionsRec.Body.String(), onlineGateway.ID) || !strings.Contains(onlineSessionsRec.Body.String(), routeGroup.ID) {
		t.Fatalf("online session audit index missing gateway route metadata: %s", onlineSessionsRec.Body.String())
	}

	databaseRec := assertStatus(t, handler, http.MethodPost, "/api/admin/database-assets", map[string]any{
		"name":     "routed-sqlite",
		"type":     "sqlite",
		"status":   "enabled",
		"protocol": "database",
		"metadata": map[string]any{
			"sqlite_path":      "routed-sqlite.db",
			"gateway_group_id": routeGroup.ID,
		},
	}, adminCookie, http.StatusCreated)
	var databaseAsset model.PlatformItem
	decodeResponse(t, databaseRec, &databaseAsset)
	sqlLogRec := assertStatus(t, handler, http.MethodPost, "/api/access/database/"+databaseAsset.ID+"/query", map[string]any{
		"sql": "SELECT 1 AS routed",
	}, adminCookie, http.StatusOK)
	var sqlLog model.PlatformItem
	decodeResponse(t, sqlLogRec, &sqlLog)
	if firstMetadataString(sqlLog.Metadata, "gateway_group_id") != routeGroup.ID || firstMetadataString(sqlLog.Metadata, "gateway_id") != onlineGateway.ID {
		t.Fatalf("sql log missing selected gateway route: %#v", sqlLog.Metadata)
	}
}

func TestResourceOperationEndpoints(t *testing.T) {
	handler, cookie := newTestHandler(t)
	server := handler.(*Server)

	assetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":        "linux-export",
		"type":        "linux",
		"status":      "active",
		"protocol":    "ssh",
		"host":        "127.0.0.1",
		"port":        22,
		"group":       "ops",
		"tags":        []string{"linux", "export"},
		"description": "export fixture",
		"metadata":    map[string]any{"credential_id": "cred-export", "gateway_group_id": "gw-export"},
	}, cookie, http.StatusCreated)
	var asset model.PlatformItem
	decodeResponse(t, assetRec, &asset)
	exportRec := assertStatus(t, handler, http.MethodGet, "/api/admin/assets/export", nil, cookie, http.StatusOK)
	if !strings.Contains(exportRec.Body.String(), asset.ID) {
		t.Fatal("asset export did not include created asset")
	}
	exportCSVRec := assertStatus(t, handler, http.MethodGet, "/api/admin/assets/export?format=csv", nil, cookie, http.StatusOK)
	if contentType := exportCSVRec.Header().Get("Content-Type"); !strings.Contains(contentType, "text/csv") {
		t.Fatalf("asset csv export content type = %q", contentType)
	}
	rows, err := csv.NewReader(strings.NewReader(exportCSVRec.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("parse asset csv export: %v", err)
	}
	if len(rows) < 2 || strings.Join(rows[0], ",") != "name,type,status,protocol,host,port,username,group,owner_id,parent_id,target_id,tags,description,metadata_json" {
		t.Fatalf("asset csv export header/rows invalid: %#v", rows)
	}
	foundExportRow := false
	for _, row := range rows[1:] {
		if len(row) >= 14 && row[0] == "linux-export" {
			foundExportRow = row[3] == "ssh" &&
				row[4] == "127.0.0.1" &&
				row[5] == "22" &&
				row[7] == "ops" &&
				row[11] == "linux,export" &&
				row[12] == "export fixture" &&
				strings.Contains(row[13], `"credential_id":"cred-export"`) &&
				strings.Contains(row[13], `"gateway_group_id":"gw-export"`)
		}
	}
	if !foundExportRow {
		t.Fatalf("asset csv export missing created asset row: %#v", rows)
	}
	removeAssetExportBlocker := blockOperationLogName(t, server.cfg.Store, "assets.export")
	blockedAssetExportRec := assertStatus(t, handler, http.MethodGet, "/api/admin/assets/export", nil, cookie, http.StatusInternalServerError)
	removeAssetExportBlocker()
	if !strings.Contains(blockedAssetExportRec.Body.String(), "persist operation log failed") {
		t.Fatalf("asset export operation log failure was not reported: %s", blockedAssetExportRec.Body.String())
	}
	if blockedAssetExportRec.Header().Get("Content-Disposition") != "" || strings.Contains(blockedAssetExportRec.Body.String(), asset.ID) {
		t.Fatalf("asset export returned data after operation log failure: %s", blockedAssetExportRec.Body.String())
	}
	if !coreAuditLogsContainAction(server.cfg.Store, "operation.log.persist_failed") {
		t.Fatal("asset export operation log failure was not written to core audit logs")
	}

	credentialRec := assertStatus(t, handler, http.MethodPost, "/api/admin/credentials", map[string]any{
		"name":        "credential-export",
		"type":        "ssh_password",
		"status":      "enabled",
		"username":    "root",
		"password":    "credential-export-password",
		"private_key": "credential-export-private-key",
		"metadata": map[string]any{
			"nested": map[string]any{
				"secret": "credential-export-nested-secret",
				"label":  "kept-label",
			},
		},
	}, cookie, http.StatusCreated)
	var credential model.PlatformItem
	decodeResponse(t, credentialRec, &credential)
	credentialJSONRec := assertStatus(t, handler, http.MethodGet, "/api/admin/credentials/export", nil, cookie, http.StatusOK)
	credentialJSONBody := credentialJSONRec.Body.String()
	for _, leaked := range []string{"credential-export-password", "credential-export-private-key", "credential-export-nested-secret", "encrypted_password", "encrypted_private_key"} {
		if strings.Contains(credentialJSONBody, leaked) {
			t.Fatalf("credential json export leaked %q: %s", leaked, credentialJSONBody)
		}
	}
	if !strings.Contains(credentialJSONBody, credential.ID) || !strings.Contains(credentialJSONBody, "kept-label") {
		t.Fatalf("credential json export missing sanitized credential: %s", credentialJSONBody)
	}
	credentialCSVRec := assertStatus(t, handler, http.MethodGet, "/api/admin/credentials/export?format=csv", nil, cookie, http.StatusOK)
	if contentType := credentialCSVRec.Header().Get("Content-Type"); !strings.Contains(contentType, "text/csv") {
		t.Fatalf("credential csv export content type = %q", contentType)
	}
	credentialRows, err := csv.NewReader(strings.NewReader(credentialCSVRec.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("parse credential csv export: %v", err)
	}
	if len(credentialRows) < 2 || strings.Join(credentialRows[0], ",") != "id,module,name,type,status,protocol,host,port,username,group,owner_id,parent_id,target_id,tags,permissions_json,description,created_at,updated_at,metadata_json" {
		t.Fatalf("credential csv export header/rows invalid: %#v", credentialRows)
	}
	for _, leaked := range []string{"credential-export-password", "credential-export-private-key", "credential-export-nested-secret", "encrypted_password", "encrypted_private_key"} {
		if strings.Contains(credentialCSVRec.Body.String(), leaked) {
			t.Fatalf("credential csv export leaked %q: %s", leaked, credentialCSVRec.Body.String())
		}
	}
	removeCredentialExportBlocker := blockOperationLogName(t, server.cfg.Store, "credentials.export")
	blockedCredentialExportRec := assertStatus(t, handler, http.MethodGet, "/api/admin/credentials/export", nil, cookie, http.StatusInternalServerError)
	removeCredentialExportBlocker()
	if !strings.Contains(blockedCredentialExportRec.Body.String(), "persist operation log failed") {
		t.Fatalf("credential export operation log failure was not reported: %s", blockedCredentialExportRec.Body.String())
	}
	if blockedCredentialExportRec.Header().Get("Content-Disposition") != "" || strings.Contains(blockedCredentialExportRec.Body.String(), credential.ID) {
		t.Fatalf("credential export returned data after operation log failure: %s", blockedCredentialExportRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, "/api/admin/credentials/export", nil, cookie, http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodGet, "/api/admin/credentials/export?format=xml", nil, cookie, http.StatusBadRequest)

	authorizationRec := assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/assets", map[string]any{
		"name":      "authorization-export",
		"type":      "user",
		"status":    "enabled",
		"owner_id":  "admin",
		"target_id": asset.ID,
		"metadata": map[string]any{
			"approval_note": "kept-authorization-note",
			"token":         "authorization-export-token",
		},
	}, cookie, http.StatusCreated)
	var authorization model.PlatformItem
	decodeResponse(t, authorizationRec, &authorization)
	authorizationJSONRec := assertStatus(t, handler, http.MethodGet, "/api/admin/authorizations/assets/export", nil, cookie, http.StatusOK)
	authorizationJSONBody := authorizationJSONRec.Body.String()
	if strings.Contains(authorizationJSONBody, "authorization-export-token") {
		t.Fatalf("authorization json export leaked token: %s", authorizationJSONBody)
	}
	if !strings.Contains(authorizationJSONBody, authorization.ID) || !strings.Contains(authorizationJSONBody, "kept-authorization-note") {
		t.Fatalf("authorization json export missing sanitized authorization: %s", authorizationJSONBody)
	}
	authorizationCSVRec := assertStatus(t, handler, http.MethodGet, "/api/admin/authorizations/assets/export?format=csv", nil, cookie, http.StatusOK)
	if contentType := authorizationCSVRec.Header().Get("Content-Type"); !strings.Contains(contentType, "text/csv") {
		t.Fatalf("authorization csv export content type = %q", contentType)
	}
	if strings.Contains(authorizationCSVRec.Body.String(), "authorization-export-token") || !strings.Contains(authorizationCSVRec.Body.String(), "kept-authorization-note") {
		t.Fatalf("authorization csv export redaction/content invalid: %s", authorizationCSVRec.Body.String())
	}

	importAssetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets/import", map[string]any{
		"items": []map[string]any{{
			"name":     "imported-rdp",
			"type":     "windows",
			"status":   "active",
			"protocol": "rdp",
			"host":     "192.0.2.10",
			"port":     3389,
		}},
	}, cookie, http.StatusCreated)
	if !strings.Contains(importAssetRec.Body.String(), `"created":1`) || !strings.Contains(importAssetRec.Body.String(), `"total":1`) {
		t.Fatalf("asset import summary missing: %s", importAssetRec.Body.String())
	}
	removeAssetImportCreateBlocker := blockOperationLogName(t, server.cfg.Store, "assets.import")
	assetImportCreateFailureRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets/import", map[string]any{
		"items": []map[string]any{{
			"name":     "rollback-imported-asset",
			"type":     "linux",
			"status":   "active",
			"protocol": "ssh",
			"host":     "192.0.2.30",
			"port":     22,
		}},
	}, cookie, http.StatusInternalServerError)
	removeAssetImportCreateBlocker()
	if !strings.Contains(assetImportCreateFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("asset import create operation log failure was not reported: %s", assetImportCreateFailureRec.Body.String())
	}
	assetListAfterCreateFailure := assertStatus(t, handler, http.MethodGet, "/api/admin/assets", nil, cookie, http.StatusOK)
	if strings.Contains(assetListAfterCreateFailure.Body.String(), "rollback-imported-asset") {
		t.Fatalf("asset import create survived operation log failure: %s", assetListAfterCreateFailure.Body.String())
	}
	removePartialAssetImportBlocker := blockPlatformCollectionSavePayloadFragment(t, server.cfg.Store, "assets", `"name":"partial-blocked-asset"`)
	partialAssetImportFailureRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets/import", map[string]any{
		"items": []map[string]any{{
			"name":     "partial-created-asset",
			"type":     "linux",
			"status":   "active",
			"protocol": "ssh",
			"host":     "192.0.2.32",
			"port":     22,
		}, {
			"name":     "partial-blocked-asset",
			"type":     "linux",
			"status":   "active",
			"protocol": "ssh",
			"host":     "192.0.2.33",
			"port":     22,
		}},
	}, cookie, http.StatusInternalServerError)
	removePartialAssetImportBlocker()
	if !strings.Contains(partialAssetImportFailureRec.Body.String(), "forced platform collection payload save failure") {
		t.Fatalf("partial asset import failure was not reported: %s", partialAssetImportFailureRec.Body.String())
	}
	assetListAfterPartialFailure := assertStatus(t, handler, http.MethodGet, "/api/admin/assets", nil, cookie, http.StatusOK)
	if strings.Contains(assetListAfterPartialFailure.Body.String(), "partial-created-asset") || strings.Contains(assetListAfterPartialFailure.Body.String(), "partial-blocked-asset") {
		t.Fatalf("partial asset import left unaudited records: %s", assetListAfterPartialFailure.Body.String())
	}
	removeAssetImportUpdateBlocker := blockOperationLogName(t, server.cfg.Store, "assets.import")
	assetImportUpdateFailureRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets/import", map[string]any{
		"update_existing": true,
		"items": []map[string]any{{
			"name":        "linux-export",
			"type":        "linux",
			"status":      "disabled",
			"protocol":    "ssh",
			"host":        "192.0.2.31",
			"port":        2222,
			"description": "blocked import update",
		}},
	}, cookie, http.StatusInternalServerError)
	removeAssetImportUpdateBlocker()
	if !strings.Contains(assetImportUpdateFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("asset import update operation log failure was not reported: %s", assetImportUpdateFailureRec.Body.String())
	}
	assetDetailAfterUpdateFailure := assertStatus(t, handler, http.MethodGet, "/api/admin/assets/"+asset.ID, nil, cookie, http.StatusOK)
	if strings.Contains(assetDetailAfterUpdateFailure.Body.String(), "192.0.2.31") || strings.Contains(assetDetailAfterUpdateFailure.Body.String(), "blocked import update") || !strings.Contains(assetDetailAfterUpdateFailure.Body.String(), `"status":"active"`) {
		t.Fatalf("asset import update was not rolled back after operation log failure: %s", assetDetailAfterUpdateFailure.Body.String())
	}
	skipAssetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets/import", map[string]any{
		"items": []map[string]any{{
			"name":     "imported-rdp",
			"type":     "windows",
			"status":   "active",
			"protocol": "rdp",
			"host":     "192.0.2.20",
			"port":     3389,
		}},
	}, cookie, http.StatusCreated)
	if !strings.Contains(skipAssetRec.Body.String(), `"created":0`) || !strings.Contains(skipAssetRec.Body.String(), `"skipped":1`) {
		t.Fatalf("asset import skip summary missing: %s", skipAssetRec.Body.String())
	}
	updateAssetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets/import", map[string]any{
		"update_existing": true,
		"items": []map[string]any{{
			"name":     "imported-rdp",
			"type":     "windows",
			"status":   "maintenance",
			"protocol": "rdp",
			"host":     "192.0.2.77",
			"port":     3390,
		}},
	}, cookie, http.StatusCreated)
	if !strings.Contains(updateAssetRec.Body.String(), `"updated":1`) || !strings.Contains(updateAssetRec.Body.String(), `"skipped":0`) {
		t.Fatalf("asset import update summary missing: %s", updateAssetRec.Body.String())
	}
	listAssetsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/assets", nil, cookie, http.StatusOK)
	if strings.Count(listAssetsRec.Body.String(), "imported-rdp") != 1 || !strings.Contains(listAssetsRec.Body.String(), "192.0.2.77") || strings.Contains(listAssetsRec.Body.String(), "192.0.2.20") {
		t.Fatalf("asset import should update existing asset without duplicates: %s", listAssetsRec.Body.String())
	}
	csvAssetBody := strings.Join([]string{
		"name,type,status,protocol,host,port,group,tags,credential_id,gateway_group_id,metadata_json",
		`csv-ssh,linux,active,ssh,192.0.2.88,22,ops,"linux,csv",cred-csv,gw-csv,"{""import_note"":""csv-ok""}"`,
	}, "\n")
	csvAssetRec := assertRawStatus(t, handler, http.MethodPost, "/api/admin/assets/import?format=csv", "text/csv", csvAssetBody, cookie, http.StatusCreated)
	if !strings.Contains(csvAssetRec.Body.String(), `"created":1`) || !strings.Contains(csvAssetRec.Body.String(), "csv-ok") {
		t.Fatalf("csv asset import response missing created asset metadata: %s", csvAssetRec.Body.String())
	}
	csvAssetListRec := assertStatus(t, handler, http.MethodGet, "/api/admin/assets", nil, cookie, http.StatusOK)
	for _, want := range []string{"csv-ssh", "192.0.2.88", "cred-csv", "gw-csv", "csv-ok"} {
		if !strings.Contains(csvAssetListRec.Body.String(), want) {
			t.Fatalf("csv asset import list missing %q: %s", want, csvAssetListRec.Body.String())
		}
	}
	assertStatus(t, handler, http.MethodPost, "/api/admin/assets/import", map[string]any{
		"items": []map[string]any{{
			"name": "duplicate-in-file",
			"host": "192.0.2.30",
		}, {
			"name": "duplicate-in-file",
			"host": "192.0.2.31",
		}},
	}, cookie, http.StatusBadRequest)

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
	if cert.Metadata["has_private_key"] != true {
		t.Fatalf("self-signed certificate response missing private key flag: %#v", cert.Metadata)
	}
	rawCert, ok, err := server.cfg.Store.GetPlatformItem("certificates", cert.ID)
	if err != nil || !ok {
		t.Fatalf("load raw self-signed certificate: ok=%v err=%v", ok, err)
	}
	if firstMetadataString(rawCert.Metadata, "private_key", "privateKey", "key", "private_key_pem") != "" {
		t.Fatalf("raw self-signed certificate retained plaintext private key: %#v", rawCert.Metadata)
	}
	encryptedPrivateKey := firstMetadataString(rawCert.Metadata, "certificate_private_key_encrypted")
	privateKeySet, _ := metadataBoolValue(rawCert.Metadata["private_key_set"])
	if encryptedPrivateKey == "" || !privateKeySet || rawCert.Metadata["has_private_key"] != true {
		t.Fatalf("raw self-signed certificate did not store encrypted private key state: %#v", rawCert.Metadata)
	}
	decryptedPrivateKey, err := server.cfg.Store.DecryptPlatformSecret(encryptedPrivateKey)
	if err != nil {
		t.Fatalf("decrypt raw self-signed certificate private key: %v", err)
	}
	if !strings.Contains(decryptedPrivateKey, "BEGIN RSA PRIVATE KEY") {
		t.Fatal("decrypted self-signed private key did not contain PEM material")
	}
	for _, leaked := range []string{"PRIVATE KEY", `"private_key"`} {
		if strings.Contains(certRec.Body.String(), leaked) {
			t.Fatalf("self-signed certificate response leaked %s", leaked)
		}
	}
	certDownload := assertStatus(t, handler, http.MethodGet, "/api/admin/certificates/"+cert.ID+"/download", nil, cookie, http.StatusOK)
	if !strings.Contains(certDownload.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatal("certificate download did not return pem")
	}
	certBundle := assertStatus(t, handler, http.MethodGet, "/api/admin/certificates/"+cert.ID+"/bundle", nil, cookie, http.StatusOK)
	if certBundle.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("certificate bundle content type = %q", certBundle.Header().Get("Content-Type"))
	}
	certBundleZip, err := zip.NewReader(bytes.NewReader(certBundle.Body.Bytes()), int64(certBundle.Body.Len()))
	if err != nil {
		t.Fatalf("open certificate bundle zip: %v", err)
	}
	for _, filename := range []string{"certificate.pem", "private.key", "README.txt"} {
		if !zipHasEntry(certBundleZip, filename) {
			t.Fatalf("certificate bundle missing %s", filename)
		}
	}
	if !strings.Contains(zipEntryText(t, certBundleZip, "certificate.pem"), "BEGIN CERTIFICATE") {
		t.Fatal("certificate bundle certificate.pem did not include certificate PEM")
	}
	if !strings.Contains(zipEntryText(t, certBundleZip, "private.key"), "BEGIN RSA PRIVATE KEY") {
		t.Fatal("certificate bundle private.key did not include private key PEM")
	}
	uploadCertPEM, uploadKeyPEM, err := makeSelfSignedCertificate(certificateRequest{Domain: "uploaded.example.test", Days: 90})
	if err != nil {
		t.Fatalf("make upload certificate: %v", err)
	}
	mismatchCertPEM, _, err := makeSelfSignedCertificate(certificateRequest{Domain: "mismatch.example.test", Days: 90})
	if err != nil {
		t.Fatalf("make mismatch certificate: %v", err)
	}
	uploadedCertRec := assertMultipartFilesStatus(t, handler, "/api/admin/certificates/upload", map[string]string{"name": "uploaded-cert"}, map[string]multipartFile{
		"certificate": {Name: "uploaded.crt", Content: uploadCertPEM},
		"private_key": {Name: "uploaded.key", Content: uploadKeyPEM},
	}, cookie, http.StatusCreated)
	if !strings.Contains(uploadedCertRec.Body.String(), `"has_private_key":true`) {
		t.Fatal("uploaded certificate response did not mark private key state")
	}
	var uploadedCert model.PlatformItem
	decodeResponse(t, uploadedCertRec, &uploadedCert)
	rawUploadedCert, ok, err := server.cfg.Store.GetPlatformItem("certificates", uploadedCert.ID)
	if err != nil || !ok {
		t.Fatalf("load raw uploaded certificate: ok=%v err=%v", ok, err)
	}
	if firstMetadataString(rawUploadedCert.Metadata, "private_key", "privateKey", "key", "private_key_pem") != "" || firstMetadataString(rawUploadedCert.Metadata, "certificate_private_key_encrypted") == "" {
		t.Fatalf("raw uploaded certificate private key was not encrypted: %#v", rawUploadedCert.Metadata)
	}
	for _, leaked := range []string{"PRIVATE KEY", `"private_key"`} {
		if strings.Contains(uploadedCertRec.Body.String(), leaked) {
			t.Fatalf("uploaded certificate response leaked %s", leaked)
		}
	}
	badUploadRec := assertMultipartFilesStatus(t, handler, "/api/admin/certificates/upload", map[string]string{"name": "bad-cert"}, map[string]multipartFile{
		"certificate": {Name: "bad.crt", Content: mismatchCertPEM},
		"private_key": {Name: "uploaded.key", Content: uploadKeyPEM},
	}, cookie, http.StatusBadRequest)
	if !strings.Contains(badUploadRec.Body.String(), "private key does not match certificate") {
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

	dnsProviderRec := assertStatus(t, handler, http.MethodPost, "/api/admin/certificates/dns-providers", map[string]any{
		"name":     "cloudflare-test",
		"provider": "cloudflare",
		"zone":     "example.test",
		"token":    "dns-secret-token",
	}, cookie, http.StatusCreated)
	var dnsProvider model.PlatformItem
	decodeResponse(t, dnsProviderRec, &dnsProvider)
	if dnsProvider.Metadata["dns_api_token_set"] != true {
		t.Fatal("dns provider response did not mark token as configured")
	}
	for _, leaked := range []string{"dns-secret-token", "dns_api_token_encrypted"} {
		if strings.Contains(dnsProviderRec.Body.String(), leaked) {
			t.Fatalf("dns provider response leaked %s", leaked)
		}
	}
	dnsProvidersRec := assertStatus(t, handler, http.MethodGet, "/api/admin/certificates/dns-providers", nil, cookie, http.StatusOK)
	if !strings.Contains(dnsProvidersRec.Body.String(), "cloudflare-test") || !strings.Contains(dnsProvidersRec.Body.String(), "dns_api_token_set") {
		t.Fatal("dns provider list did not include configured provider state")
	}
	for _, leaked := range []string{"dns-secret-token", "dns_api_token_encrypted"} {
		if strings.Contains(dnsProvidersRec.Body.String(), leaked) {
			t.Fatalf("dns provider list leaked %s", leaked)
		}
	}
	missingDNSProviderACMERec := assertStatus(t, handler, http.MethodPost, "/api/admin/certificates/acme", map[string]any{
		"name":            "missing-provider-acme",
		"domain":          "missing-provider.example.test",
		"dns_provider_id": "missing-dns-provider",
	}, cookie, http.StatusNotFound)
	if !strings.Contains(missingDNSProviderACMERec.Body.String(), "dns provider not found") || strings.Contains(missingDNSProviderACMERec.Body.String(), "dns-secret-token") {
		t.Fatalf("missing dns provider ACME response missing safe error: %s", missingDNSProviderACMERec.Body.String())
	}

	acmeRec := assertStatus(t, handler, http.MethodPost, "/api/admin/certificates/acme", map[string]any{
		"name":            "acme-cert",
		"domain":          "acme.example.test",
		"dns":             []string{"www.acme.example.test"},
		"ip":              []string{"127.0.0.1"},
		"email":           "ops@example.test",
		"challenge_type":  "http-01",
		"dns_provider_id": dnsProvider.ID,
		"days":            45,
		"default":         true,
		"mtls_enabled":    true,
		"metadata":        map[string]any{"environment": "test"},
	}, cookie, http.StatusCreated)
	var acmeCert model.PlatformItem
	decodeResponse(t, acmeRec, &acmeCert)
	if acmeCert.Status != "issued" || acmeCert.Type != "acme" {
		t.Fatalf("unexpected acme certificate state: %#v", acmeCert)
	}
	if acmeCert.Metadata["certificate"] == "" || acmeCert.Metadata["expires_at"] == nil || acmeCert.Metadata["acme_http_url"] == "" {
		t.Fatalf("acme response missing certificate metadata: %#v", acmeCert.Metadata)
	}
	if firstMetadataString(acmeCert.Metadata, "dns_provider_name") != "cloudflare-test" || firstMetadataString(acmeCert.Metadata, "dns_provider_zone") != "example.test" {
		t.Fatalf("acme response missing dns provider metadata: %#v", acmeCert.Metadata)
	}
	rawACMECert, ok, err := server.cfg.Store.GetPlatformItem("certificates", acmeCert.ID)
	if err != nil || !ok {
		t.Fatalf("load raw acme certificate: ok=%v err=%v", ok, err)
	}
	if firstMetadataString(rawACMECert.Metadata, "private_key", "privateKey", "key", "private_key_pem") != "" || firstMetadataString(rawACMECert.Metadata, "certificate_private_key_encrypted") == "" {
		t.Fatalf("raw acme certificate private key was not encrypted: %#v", rawACMECert.Metadata)
	}
	for _, leaked := range []string{"PRIVATE KEY", `"private_key"`, "dns-secret-token"} {
		if strings.Contains(acmeRec.Body.String(), leaked) {
			t.Fatalf("acme response leaked %s", leaked)
		}
	}
	token, _ := acmeCert.Metadata["acme_http_token"].(string)
	keyAuthorization, _ := acmeCert.Metadata["acme_http_key_authorization"].(string)
	if token == "" || keyAuthorization == "" {
		t.Fatalf("acme response missing challenge values: %#v", acmeCert.Metadata)
	}
	challengeRec := assertStatus(t, handler, http.MethodGet, "/.well-known/acme-challenge/"+token, nil, nil, http.StatusOK)
	if strings.TrimSpace(challengeRec.Body.String()) != keyAuthorization {
		t.Fatalf("challenge response = %q, want %q", challengeRec.Body.String(), keyAuthorization)
	}
	acmeDownloadRec := assertStatus(t, handler, http.MethodGet, "/api/admin/certificates/"+acmeCert.ID+"/download", nil, cookie, http.StatusOK)
	if !strings.Contains(acmeDownloadRec.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatal("acme certificate download did not return pem")
	}
	defaultRec := assertStatus(t, handler, http.MethodPost, "/api/admin/certificates/"+cert.ID+"/default", map[string]any{}, cookie, http.StatusOK)
	var defaultCert model.PlatformItem
	decodeResponse(t, defaultRec, &defaultCert)
	if defaultCert.ID != cert.ID || defaultCert.Metadata["default"] != true {
		t.Fatalf("default certificate response = %#v", defaultCert)
	}
	assertStatus(t, handler, http.MethodPatch, "/api/admin/certificates/"+acmeCert.ID, map[string]any{
		"status": "disabled",
	}, cookie, http.StatusOK)
	disabledDefaultRec := assertStatus(t, handler, http.MethodPost, "/api/admin/certificates/"+acmeCert.ID+"/default", map[string]any{}, cookie, http.StatusBadRequest)
	if !strings.Contains(disabledDefaultRec.Body.String(), "not usable") {
		t.Fatalf("disabled certificate default response did not explain state: %s", disabledDefaultRec.Body.String())
	}
	assertStatus(t, handler, http.MethodGet, "/.well-known/acme-challenge/"+token, nil, nil, http.StatusNotFound)
	clientCAPEM, _, err := makeSelfSignedCertificate(certificateRequest{Domain: "client-ca.example.test", Days: 365})
	if err != nil {
		t.Fatalf("make client ca certificate: %v", err)
	}
	mtlsRec := assertStatus(t, handler, http.MethodPost, "/api/admin/certificates/"+cert.ID+"/mtls", map[string]any{
		"enabled":   true,
		"client_ca": string(clientCAPEM),
	}, cookie, http.StatusOK)
	var mtlsCert model.PlatformItem
	decodeResponse(t, mtlsRec, &mtlsCert)
	if mtlsCert.Metadata["mtls_enabled"] != true || mtlsCert.Metadata["mtls_client_ca_set"] != true {
		t.Fatalf("mTLS response missing enabled/set flags: %#v", mtlsCert.Metadata)
	}
	if strings.Contains(mtlsRec.Body.String(), `"mtls_client_ca":`) {
		t.Fatalf("mTLS response leaked client CA: %s", mtlsRec.Body.String())
	}
	if strings.Contains(mtlsRec.Body.String(), string(clientCAPEM)) {
		t.Fatal("mTLS response leaked client CA PEM")
	}
	certificatesAfterOpsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/certificates", nil, cookie, http.StatusOK)
	certificatesAfterOpsBody := certificatesAfterOpsRec.Body.String()
	for _, leaked := range []string{"PRIVATE KEY", `"private_key"`, "dns-secret-token", `"mtls_client_ca":`} {
		if strings.Contains(certificatesAfterOpsBody, leaked) {
			t.Fatalf("certificate list leaked %s", leaked)
		}
	}
	if strings.Count(certificatesAfterOpsBody, `"default":true`) != 1 || !strings.Contains(certificatesAfterOpsBody, `"mtls_client_ca_set":true`) {
		t.Fatalf("certificate list missing default/mTLS state: %s", certificatesAfterOpsBody)
	}
	disableMTLSRec := assertStatus(t, handler, http.MethodPost, "/api/admin/certificates/"+cert.ID+"/mtls", map[string]any{
		"enabled": false,
	}, cookie, http.StatusOK)
	var disabledMTLSCert model.PlatformItem
	decodeResponse(t, disableMTLSRec, &disabledMTLSCert)
	if disabledMTLSCert.Metadata["mtls_enabled"] == true || disabledMTLSCert.Metadata["mtls_client_ca_set"] == true {
		t.Fatalf("disabled mTLS response retained enabled/CA state: %#v", disabledMTLSCert.Metadata)
	}
	if strings.Contains(disableMTLSRec.Body.String(), `"mtls_client_ca":`) || strings.Contains(disableMTLSRec.Body.String(), string(clientCAPEM)) {
		t.Fatalf("disabled mTLS response leaked or retained client CA: %s", disableMTLSRec.Body.String())
	}
	rawDisabledMTLSCert, ok, err := server.cfg.Store.GetPlatformItem("certificates", cert.ID)
	if err != nil || !ok {
		t.Fatalf("load disabled mTLS certificate: ok=%v err=%v", ok, err)
	}
	for _, key := range []string{"mtls_client_ca", "client_ca", "mtls_ca", "tls_ca", "ca_certificate", "root_ca"} {
		if firstMetadataString(rawDisabledMTLSCert.Metadata, key) != "" {
			t.Fatalf("disabled mTLS certificate retained %s: %#v", key, rawDisabledMTLSCert.Metadata)
		}
	}
	if rawDisabledMTLSCert.Metadata["mtls_client_ca_set"] == true {
		t.Fatalf("disabled mTLS certificate retained CA flag: %#v", rawDisabledMTLSCert.Metadata)
	}
	certificatesAfterDisableMTLSRec := assertStatus(t, handler, http.MethodGet, "/api/admin/certificates", nil, cookie, http.StatusOK)
	certificatesAfterDisableMTLSBody := certificatesAfterDisableMTLSRec.Body.String()
	if strings.Contains(certificatesAfterDisableMTLSBody, `"mtls_client_ca_set":true`) || strings.Contains(certificatesAfterDisableMTLSBody, `"mtls_client_ca":`) {
		t.Fatalf("certificate list retained disabled mTLS CA state: %s", certificatesAfterDisableMTLSBody)
	}
	certificateLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/certificates/"+cert.ID+"/logs", nil, cookie, http.StatusOK)
	certificateLogsBody := certificateLogsRec.Body.String()
	for _, want := range []string{"certificate.self_signed", "certificate.bundle_download", "certificate.default", "certificate.mtls.update"} {
		if !strings.Contains(certificateLogsBody, want) {
			t.Fatalf("certificate logs missing %s in %s", want, certificateLogsBody)
		}
	}
	acmeLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/certificates/"+acmeCert.ID+"/logs", nil, cookie, http.StatusOK)
	if !strings.Contains(acmeLogsRec.Body.String(), "certificate.acme.request") || !strings.Contains(acmeLogsRec.Body.String(), "certificate.acme.issue") {
		t.Fatalf("acme logs missing request/issue events: %s", acmeLogsRec.Body.String())
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
		"metadata": map[string]any{"sqlite_path": "resource-ops.db", "query_timeout_ms": 1234},
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
	if !strings.Contains(sqlLogRec.Body.String(), "answer") || !strings.Contains(sqlLogRec.Body.String(), `"timeout_ms":1234`) {
		t.Fatal("sql execution log did not include query result and timeout metadata")
	}
	canceledReq := httptest.NewRequest(http.MethodPost, "/api/access/database/"+databaseAsset.ID+"/query", nil)
	ctx, cancel := context.WithCancel(canceledReq.Context())
	cancel()
	canceledReq = canceledReq.WithContext(ctx)
	canceledLog, statusCode, err := server.executeDatabaseAssetSQL(canceledReq, databaseAsset, "admin", "SELECT 1 AS canceled", databaseSQLExecutionOptions{
		Source:  "test",
		LogType: "database_timeout",
	})
	if err != nil {
		t.Fatalf("canceled sql execution returned infrastructure error: %v", err)
	}
	if statusCode != http.StatusBadRequest || canceledLog.Status != "failed" || !strings.Contains(canceledLog.Description, "context canceled") {
		t.Fatalf("canceled sql execution did not fail through query context: status=%d log=%#v", statusCode, canceledLog)
	}
	if got, ok := metadataInt(canceledLog.Metadata["timeout_ms"]); !ok || got != 1234 {
		t.Fatalf("canceled sql log timeout_ms = %v/%v, want 1234 in %#v", got, ok, canceledLog.Metadata)
	}
}

func TestCertificateOperationLogPersistenceFailureRollsBackMutations(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)

	assertNoCertificateNamed := func(name string) {
		t.Helper()
		rec := assertStatus(t, handler, http.MethodGet, "/api/admin/certificates", nil, adminCookie, http.StatusOK)
		if strings.Contains(rec.Body.String(), name) {
			t.Fatalf("certificate %q exists after failed audited operation: %s", name, rec.Body.String())
		}
	}

	removeSelfSignedBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	selfSignedFailureRec := assertStatus(t, handler, http.MethodPost, "/api/admin/certificates/self-signed", map[string]any{
		"name":   "no-audit-self-signed",
		"domain": "no-audit-self-signed.example.test",
	}, adminCookie, http.StatusInternalServerError)
	removeSelfSignedBlocker()
	if !strings.Contains(selfSignedFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("self-signed operation log failure was not reported: %s", selfSignedFailureRec.Body.String())
	}
	assertNoCertificateNamed("no-audit-self-signed")

	certRec := assertStatus(t, handler, http.MethodPost, "/api/admin/certificates/self-signed", map[string]any{
		"name":   "audited-cert-a",
		"domain": "audited-a.example.test",
	}, adminCookie, http.StatusCreated)
	var certA model.PlatformItem
	decodeResponse(t, certRec, &certA)
	certBRec := assertStatus(t, handler, http.MethodPost, "/api/admin/certificates/self-signed", map[string]any{
		"name":   "audited-cert-b",
		"domain": "audited-b.example.test",
	}, adminCookie, http.StatusCreated)
	var certB model.PlatformItem
	decodeResponse(t, certBRec, &certB)

	removeDownloadBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	downloadFailureRec := assertStatus(t, handler, http.MethodGet, "/api/admin/certificates/"+certA.ID+"/download", nil, adminCookie, http.StatusInternalServerError)
	removeDownloadBlocker()
	if !strings.Contains(downloadFailureRec.Body.String(), "persist operation log failed") || strings.Contains(downloadFailureRec.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatalf("certificate download returned content or hid operation log failure: %s", downloadFailureRec.Body.String())
	}

	removeBundleBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	bundleFailureRec := assertStatus(t, handler, http.MethodGet, "/api/admin/certificates/"+certA.ID+"/bundle", nil, adminCookie, http.StatusInternalServerError)
	removeBundleBlocker()
	if !strings.Contains(bundleFailureRec.Body.String(), "persist operation log failed") || strings.Contains(bundleFailureRec.Body.String(), "BEGIN RSA PRIVATE KEY") {
		t.Fatalf("certificate bundle returned secret material or hid operation log failure: %s", bundleFailureRec.Body.String())
	}

	assertStatus(t, handler, http.MethodPost, "/api/admin/certificates/"+certA.ID+"/default", map[string]any{}, adminCookie, http.StatusOK)
	removeDefaultBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	defaultFailureRec := assertStatus(t, handler, http.MethodPost, "/api/admin/certificates/"+certB.ID+"/default", map[string]any{}, adminCookie, http.StatusInternalServerError)
	removeDefaultBlocker()
	if !strings.Contains(defaultFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("default certificate operation log failure was not reported: %s", defaultFailureRec.Body.String())
	}
	storedA, ok, err := srv.cfg.Store.GetPlatformItem("certificates", certA.ID)
	if err != nil || !ok {
		t.Fatalf("load certificate A after failed default: ok=%v err=%v", ok, err)
	}
	storedB, ok, err := srv.cfg.Store.GetPlatformItem("certificates", certB.ID)
	if err != nil || !ok {
		t.Fatalf("load certificate B after failed default: ok=%v err=%v", ok, err)
	}
	if storedA.Metadata["default"] != true || storedB.Metadata["default"] == true {
		t.Fatalf("default certificate change was not rolled back: A=%#v B=%#v", storedA.Metadata, storedB.Metadata)
	}

	clientCAPEM, _, err := makeSelfSignedCertificate(certificateRequest{Domain: "blocked-mtls-ca.example.test", Days: 365})
	if err != nil {
		t.Fatalf("make blocked mTLS client CA: %v", err)
	}
	removeMTLSBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	mtlsFailureRec := assertStatus(t, handler, http.MethodPost, "/api/admin/certificates/"+certA.ID+"/mtls", map[string]any{
		"enabled":   true,
		"client_ca": string(clientCAPEM),
	}, adminCookie, http.StatusInternalServerError)
	removeMTLSBlocker()
	if !strings.Contains(mtlsFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("mTLS operation log failure was not reported: %s", mtlsFailureRec.Body.String())
	}
	storedAfterMTLS, ok, err := srv.cfg.Store.GetPlatformItem("certificates", certA.ID)
	if err != nil || !ok {
		t.Fatalf("load certificate after failed mTLS: ok=%v err=%v", ok, err)
	}
	if storedAfterMTLS.Metadata["mtls_enabled"] == true || firstMetadataString(storedAfterMTLS.Metadata, "mtls_client_ca") != "" {
		t.Fatalf("mTLS update was not rolled back after operation log failure: %#v", storedAfterMTLS.Metadata)
	}

	uploadCertPEM, uploadKeyPEM, err := makeSelfSignedCertificate(certificateRequest{Domain: "no-audit-upload.example.test", Days: 90})
	if err != nil {
		t.Fatalf("make upload certificate: %v", err)
	}
	removeUploadBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	uploadFailureRec := assertMultipartFilesStatus(t, handler, "/api/admin/certificates/upload", map[string]string{"name": "no-audit-upload"}, map[string]multipartFile{
		"certificate": {Name: "no-audit-upload.crt", Content: uploadCertPEM},
		"private_key": {Name: "no-audit-upload.key", Content: uploadKeyPEM},
	}, adminCookie, http.StatusInternalServerError)
	removeUploadBlocker()
	if !strings.Contains(uploadFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("certificate upload operation log failure was not reported: %s", uploadFailureRec.Body.String())
	}
	assertNoCertificateNamed("no-audit-upload")

	removeACMEBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	acmeFailureRec := assertStatus(t, handler, http.MethodPost, "/api/admin/certificates/acme", map[string]any{
		"name":   "no-audit-acme",
		"domain": "no-audit-acme.example.test",
	}, adminCookie, http.StatusInternalServerError)
	removeACMEBlocker()
	if !strings.Contains(acmeFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("ACME operation log failure was not reported: %s", acmeFailureRec.Body.String())
	}
	assertNoCertificateNamed("no-audit-acme")

	removeCorruptCertificate := insertRawPlatformRecord(t, srv.cfg.Store, "certificates", "corrupt-certificate-snapshot", "{")
	removeACMERollbackBlocker := blockPlatformItemDeletePayloadFragment(t, srv.cfg.Store, "certificates", `"name":"default-snapshot-cleanup"`)
	defaultSnapshotFailureRec := assertStatus(t, handler, http.MethodPost, "/api/admin/certificates/acme", map[string]any{
		"name":    "default-snapshot-cleanup",
		"domain":  "default-snapshot-cleanup.example.test",
		"default": true,
	}, adminCookie, http.StatusInternalServerError)
	removeACMERollbackBlocker()
	removeCorruptCertificate()
	deletePlatformRecordsPayloadFragment(t, srv.cfg.Store, "certificates", `"name":"default-snapshot-cleanup"`)
	if !strings.Contains(defaultSnapshotFailureRec.Body.String(), "failed to remove ACME certificate after default snapshot failure") {
		t.Fatalf("ACME default snapshot cleanup failure was not reported: %s", defaultSnapshotFailureRec.Body.String())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "certificate.acme.rollback_failed") {
		t.Fatal("ACME default snapshot cleanup failure was not written to core audit logs")
	}

	removeDNSBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	dnsFailureRec := assertStatus(t, handler, http.MethodPost, "/api/admin/certificates/dns-providers", map[string]any{
		"name":     "no-audit-dns",
		"provider": "cloudflare",
		"zone":     "example.test",
		"token":    "no-audit-dns-token",
	}, adminCookie, http.StatusInternalServerError)
	removeDNSBlocker()
	if !strings.Contains(dnsFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("DNS provider operation log failure was not reported: %s", dnsFailureRec.Body.String())
	}
	dnsListRec := assertStatus(t, handler, http.MethodGet, "/api/admin/certificates/dns-providers", nil, adminCookie, http.StatusOK)
	if strings.Contains(dnsListRec.Body.String(), "no-audit-dns") || strings.Contains(dnsListRec.Body.String(), "no-audit-dns-token") {
		t.Fatalf("DNS provider was not rolled back or leaked token after operation log failure: %s", dnsListRec.Body.String())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "operation.log.persist_failed") {
		t.Fatal("certificate operation log persistence failure was not written to core audit logs")
	}
}

func TestAssetSensitiveMetadataIsNotPersistedOrExported(t *testing.T) {
	handler, cookie := newTestHandler(t)
	server := handler.(*Server)

	createRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "secret-asset",
		"type":     "linux",
		"status":   "active",
		"protocol": "ssh",
		"host":     "127.0.0.1",
		"port":     22,
		"metadata": map[string]any{
			"password":    "asset-secret",
			"private_key": "asset-private-key",
			"note":        "safe-note",
			"nested": map[string]any{
				"api_token": "nested-token",
				"label":     "safe-label",
			},
		},
	}, cookie, http.StatusCreated)
	createBody := createRec.Body.String()
	for _, leaked := range []string{"asset-secret", "asset-private-key", "nested-token"} {
		if strings.Contains(createBody, leaked) {
			t.Fatalf("asset create response leaked secret %q: %s", leaked, createBody)
		}
	}
	var created model.PlatformItem
	decodeResponse(t, createRec, &created)
	rawCreated, ok, err := server.cfg.Store.GetPlatformItem("assets", created.ID)
	if err != nil || !ok {
		t.Fatalf("load raw created asset: ok=%v err=%v", ok, err)
	}
	rawCreatedJSON, _ := json.Marshal(rawCreated)
	rawCreatedText := string(rawCreatedJSON)
	for _, leaked := range []string{"asset-secret", "asset-private-key", "nested-token"} {
		if strings.Contains(rawCreatedText, leaked) {
			t.Fatalf("raw created asset persisted secret %q: %s", leaked, rawCreatedText)
		}
	}
	for _, kept := range []string{"safe-note", "safe-label"} {
		if !strings.Contains(rawCreatedText, kept) {
			t.Fatalf("raw created asset lost non-sensitive metadata %q: %s", kept, rawCreatedText)
		}
	}

	updateRec := assertStatus(t, handler, http.MethodPatch, "/api/admin/assets/"+created.ID, map[string]any{
		"metadata": map[string]any{
			"token": "update-token",
			"items": []any{
				map[string]any{"secret_key": "nested-secret", "label": "kept-after-update"},
			},
		},
	}, cookie, http.StatusOK)
	updateBody := updateRec.Body.String()
	for _, leaked := range []string{"update-token", "nested-secret"} {
		if strings.Contains(updateBody, leaked) {
			t.Fatalf("asset update response leaked secret %q: %s", leaked, updateBody)
		}
	}
	rawUpdated, ok, err := server.cfg.Store.GetPlatformItem("assets", created.ID)
	if err != nil || !ok {
		t.Fatalf("load raw updated asset: ok=%v err=%v", ok, err)
	}
	rawUpdatedJSON, _ := json.Marshal(rawUpdated)
	rawUpdatedText := string(rawUpdatedJSON)
	for _, leaked := range []string{"update-token", "nested-secret"} {
		if strings.Contains(rawUpdatedText, leaked) {
			t.Fatalf("raw updated asset persisted secret %q: %s", leaked, rawUpdatedText)
		}
	}
	if !strings.Contains(rawUpdatedText, "kept-after-update") {
		t.Fatalf("raw updated asset lost non-sensitive nested metadata: %s", rawUpdatedText)
	}

	importRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets/import", map[string]any{
		"items": []map[string]any{{
			"name":     "imported-asset",
			"type":     "linux",
			"status":   "active",
			"protocol": "ssh",
			"host":     "192.0.2.80",
			"port":     22,
			"metadata": map[string]any{
				"plain_password": "asset-import-password-value",
				"nested":         map[string]any{"privateKey": "asset-import-private-key-value", "label": "import-safe"},
			},
		}},
	}, cookie, http.StatusCreated)
	var importResponse struct {
		Items []model.PlatformItem `json:"items"`
	}
	decodeResponse(t, importRec, &importResponse)
	if len(importResponse.Items) != 1 {
		t.Fatalf("asset import response missing imported item: %s", importRec.Body.String())
	}
	rawImported, ok, err := server.cfg.Store.GetPlatformItem("assets", importResponse.Items[0].ID)
	if err != nil || !ok {
		t.Fatalf("load raw imported asset: ok=%v err=%v", ok, err)
	}
	rawImportedJSON, _ := json.Marshal(rawImported)
	rawImportedText := string(rawImportedJSON)
	for _, leaked := range []string{"asset-import-password-value", "asset-import-private-key-value"} {
		if strings.Contains(rawImportedText, leaked) {
			t.Fatalf("raw imported asset persisted secret %q: %s", leaked, rawImportedText)
		}
	}
	if !strings.Contains(rawImportedText, "import-safe") {
		t.Fatalf("raw imported asset lost non-sensitive metadata: %s", rawImportedText)
	}

	exportRec := assertStatus(t, handler, http.MethodGet, "/api/admin/assets/export", nil, cookie, http.StatusOK)
	exportBody := exportRec.Body.String()
	for _, leaked := range []string{"asset-secret", "asset-private-key", "nested-token", "update-token", "nested-secret", "asset-import-password-value", "asset-import-private-key-value"} {
		if strings.Contains(exportBody, leaked) {
			t.Fatalf("asset export leaked secret %q: %s", leaked, exportBody)
		}
	}
	for _, kept := range []string{"kept-after-update", "import-safe"} {
		if !strings.Contains(exportBody, kept) {
			t.Fatalf("asset export lost non-sensitive metadata %q: %s", kept, exportBody)
		}
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
	select {
	case authCommand := <-smtpServer.auths:
		if !strings.HasPrefix(authCommand, "AUTH ") {
			t.Fatalf("SMTP server recorded unexpected auth command: %q", authCommand)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SMTP server did not receive initial AUTH command")
	}
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, cookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), "system_settings.smtp_test") {
		t.Fatal("SMTP test did not write operation log")
	}
	removeLogBlocker := blockPlatformItemCreate(t, handler.(*Server).cfg.Store, "operation_logs")
	logFailureRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/smtp/test", map[string]any{
		"setting_id": setting.ID,
		"to":         "receiver@example.test",
		"subject":    "SMTP probe audit failure",
		"body":       "delivery works before audit failure",
	}, cookie, http.StatusInternalServerError)
	removeLogBlocker()
	if !strings.Contains(logFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("SMTP test log failure did not surface operation log error: %s", logFailureRec.Body.String())
	}
	select {
	case message := <-smtpServer.messages:
		if !strings.Contains(message, "Subject: SMTP probe audit failure") || !strings.Contains(message, "delivery works before audit failure") {
			t.Fatalf("SMTP message before audit failure missing expected content:\n%s", message)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SMTP server did not receive test email before audit failure")
	}
	select {
	case authCommand := <-smtpServer.auths:
		if !strings.HasPrefix(authCommand, "AUTH ") {
			t.Fatalf("SMTP server recorded unexpected auth command before audit failure: %q", authCommand)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SMTP server did not receive AUTH command before audit failure")
	}
	if !coreAuditLogsContainAction(handler.(*Server).cfg.Store, "operation.log.persist_failed") {
		t.Fatalf("SMTP test log failure did not create core audit failure")
	}
	clearRec := assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+setting.ID, map[string]any{
		"name":     "Notification integrations",
		"type":     "integration",
		"status":   "enabled",
		"host":     host,
		"port":     port,
		"username": "smtp-user",
		"metadata": map[string]any{
			"smtp_host":           host,
			"smtp_port":           port,
			"smtp_from":           "sender@example.test",
			"smtp_to":             "receiver@example.test",
			"smtp_username":       "smtp-user",
			"smtp_password_clear": true,
		},
	}, cookie, http.StatusOK)
	clearBody := clearRec.Body.String()
	for _, leaked := range []string{"smtp-secret", "smtp_password_encrypted", "smtp_password_clear", "smtp_password_set"} {
		if strings.Contains(clearBody, leaked) {
			t.Fatalf("SMTP password clear response leaked retained state %q: %s", leaked, clearBody)
		}
	}
	rawSetting, ok, err := handler.(*Server).cfg.Store.GetPlatformItem("system_settings", setting.ID)
	if err != nil || !ok {
		t.Fatalf("load cleared SMTP setting: ok=%v err=%v", ok, err)
	}
	if firstMetadataString(rawSetting.Metadata, "smtp_password_encrypted") != "" {
		t.Fatalf("cleared SMTP setting retained encrypted password: %#v", rawSetting.Metadata)
	}
	password, ok, err := handler.(*Server).cfg.Store.SystemSettingSMTPPassword(setting.ID)
	if err != nil || !ok || password != "" {
		t.Fatalf("cleared SMTP password = %q ok=%v err=%v", password, ok, err)
	}
	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/smtp/test", map[string]any{
		"setting_id": setting.ID,
		"to":         "receiver@example.test",
		"subject":    "SMTP probe without auth",
		"body":       "anonymous delivery works",
	}, cookie, http.StatusOK)
	select {
	case message := <-smtpServer.messages:
		if !strings.Contains(message, "Subject: SMTP probe without auth") || !strings.Contains(message, "anonymous delivery works") {
			t.Fatalf("SMTP message after password clear missing expected content:\n%s", message)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SMTP server did not receive test email after password clear")
	}
	select {
	case authCommand := <-smtpServer.auths:
		t.Fatalf("SMTP server received AUTH after password clear: %q", authCommand)
	case <-time.After(150 * time.Millisecond):
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
	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+setting.ID, map[string]any{
		"status": "disabled",
	}, cookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/smtp/test", map[string]any{
		"setting_id": setting.ID,
		"to":         "receiver@example.test",
	}, cookie, http.StatusNotFound)
}

func TestSMTPIntegrationTestFailureRedactsSecrets(t *testing.T) {
	handler, cookie := newTestHandler(t)
	authPayload := base64.StdEncoding.EncodeToString([]byte("\x00smtp-user\x00smtp-secret"))
	smtpServer := newFailingSMTPAuthServer(t, "5.7.8 invalid login smtp-secret "+authPayload)
	host, portText, err := net.SplitHostPort(smtpServer.addr)
	if err != nil {
		t.Fatalf("split smtp address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse smtp port: %v", err)
	}
	settingRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":     "Failing SMTP integration",
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
			"smtp_username": "smtp-user",
		},
	}, cookie, http.StatusCreated)
	var setting model.PlatformItem
	decodeResponse(t, settingRec, &setting)

	failedRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/smtp/test", map[string]any{
		"setting_id": setting.ID,
	}, cookie, http.StatusBadGateway)
	responseBody := failedRec.Body.String()
	for _, leaked := range []string{"smtp-secret", authPayload} {
		if strings.Contains(responseBody, leaked) {
			t.Fatalf("SMTP test failure response leaked secret %q: %s", leaked, responseBody)
		}
	}
	if !strings.Contains(responseBody, "[redacted]") {
		t.Fatalf("SMTP test failure response did not contain redaction marker: %s", responseBody)
	}

	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, cookie, http.StatusOK)
	logsBody := logsRec.Body.String()
	for _, leaked := range []string{"smtp-secret", authPayload} {
		if strings.Contains(logsBody, leaked) {
			t.Fatalf("SMTP test failure operation log leaked secret %q: %s", leaked, logsBody)
		}
	}
	if !strings.Contains(logsBody, "system_settings.smtp_test.failed") || !strings.Contains(logsBody, "[redacted]") {
		t.Fatalf("SMTP test failure operation log missing expected redacted failure entry: %s", logsBody)
	}
}

func TestLLMIntegrationTestPrompt(t *testing.T) {
	handler, cookie := newTestHandler(t)
	var gotAuth string
	var gotPath string
	var gotModel string
	var llmCalls int
	llmServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		llmCalls++
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode llm request: %v", err)
		}
		gotModel, _ = payload["model"].(string)
		writeJSON(w, http.StatusOK, map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"content": "pong"}},
			},
		})
	}))
	defer llmServer.Close()

	settingRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "LLM integrations",
		"type":   "integration",
		"status": "enabled",
		"metadata": map[string]any{
			"llm_provider": "openai-compatible",
			"llm_base_url": llmServer.URL + "/v1",
			"llm_model":    "test-model",
			"llm_api_key":  "llm-secret",
		},
	}, cookie, http.StatusCreated)
	var setting model.PlatformItem
	decodeResponse(t, settingRec, &setting)
	settingsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/system-settings", nil, cookie, http.StatusOK)
	settingsBody := settingsRec.Body.String()
	for _, leaked := range []string{"llm-secret", "llm_api_key_encrypted"} {
		if strings.Contains(settingsBody, leaked) {
			t.Fatalf("system settings leaked LLM secret value %q", leaked)
		}
	}
	if !strings.Contains(settingsBody, "llm_api_key_set") {
		t.Fatal("system settings did not expose LLM secret presence flag")
	}

	testRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/llm/test", map[string]any{
		"setting_id": setting.ID,
		"prompt":     "ping",
	}, cookie, http.StatusOK)
	if gotAuth != "Bearer llm-secret" || gotPath != "/v1/chat/completions" || gotModel != "test-model" {
		t.Fatalf("unexpected LLM provider request auth=%q path=%q model=%q", gotAuth, gotPath, gotModel)
	}
	if !strings.Contains(testRec.Body.String(), "pong") || strings.Contains(testRec.Body.String(), "llm-secret") {
		t.Fatalf("LLM test response missing completion or leaked secret: %s", testRec.Body.String())
	}
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, cookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), "system_settings.llm_test") {
		t.Fatal("LLM test did not write operation log")
	}
	removeLogBlocker := blockPlatformItemCreate(t, handler.(*Server).cfg.Store, "operation_logs")
	logFailureRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/llm/test", map[string]any{
		"setting_id": setting.ID,
		"prompt":     "ping",
	}, cookie, http.StatusInternalServerError)
	removeLogBlocker()
	if !strings.Contains(logFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("LLM test log failure did not surface operation log error: %s", logFailureRec.Body.String())
	}
	if llmCalls != 2 {
		t.Fatalf("LLM provider should be called before audit failure, calls=%d", llmCalls)
	}
	if !coreAuditLogsContainAction(handler.(*Server).cfg.Store, "operation.log.persist_failed") {
		t.Fatalf("LLM test log failure did not create core audit failure")
	}
	clearRec := assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+setting.ID, map[string]any{
		"name":   "LLM integrations",
		"type":   "integration",
		"status": "enabled",
		"metadata": map[string]any{
			"llm_provider":      "openai-compatible",
			"llm_base_url":      llmServer.URL + "/v1",
			"llm_model":         "test-model",
			"llm_api_key_clear": true,
		},
	}, cookie, http.StatusOK)
	clearBody := clearRec.Body.String()
	for _, leaked := range []string{"llm-secret", "llm_api_key_encrypted", "llm_api_key_clear", "llm_api_key_set"} {
		if strings.Contains(clearBody, leaked) {
			t.Fatalf("LLM API key clear response leaked retained state %q: %s", leaked, clearBody)
		}
	}
	rawSetting, ok, err := handler.(*Server).cfg.Store.GetPlatformItem("system_settings", setting.ID)
	if err != nil || !ok {
		t.Fatalf("load cleared LLM setting: ok=%v err=%v", ok, err)
	}
	if firstMetadataString(rawSetting.Metadata, "llm_api_key_encrypted") != "" {
		t.Fatalf("cleared LLM setting retained encrypted API key: %#v", rawSetting.Metadata)
	}
	apiKey, ok, err := handler.(*Server).cfg.Store.SystemSettingLLMAPIKey(setting.ID)
	if err != nil || !ok || apiKey != "" {
		t.Fatalf("cleared LLM API key = %q ok=%v err=%v", apiKey, ok, err)
	}
	gotAuth = "unexpected"
	clearTestRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/llm/test", map[string]any{
		"setting_id": setting.ID,
		"prompt":     "ping",
	}, cookie, http.StatusOK)
	if gotAuth != "" {
		t.Fatalf("LLM provider received Authorization after API key clear: %q", gotAuth)
	}
	if !strings.Contains(clearTestRec.Body.String(), "pong") || strings.Contains(clearTestRec.Body.String(), "llm-secret") {
		t.Fatalf("LLM test after key clear missing completion or leaked secret: %s", clearTestRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+setting.ID, map[string]any{
		"status": "disabled",
	}, cookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/llm/test", map[string]any{
		"setting_id": setting.ID,
		"prompt":     "ping",
	}, cookie, http.StatusNotFound)
	if llmCalls != 3 {
		t.Fatalf("disabled llm setting should not call provider endpoint, calls=%d", llmCalls)
	}

	failingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "provider down with "+r.Header.Get("Authorization"), http.StatusBadGateway)
	}))
	defer failingServer.Close()
	failingSettingRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "Failing LLM integrations",
		"type":   "integration",
		"status": "enabled",
		"metadata": map[string]any{
			"llm_base_url": failingServer.URL + "/v1",
			"llm_model":    "test-model",
			"llm_api_key":  "fail-secret",
		},
	}, cookie, http.StatusCreated)
	var failingSetting model.PlatformItem
	decodeResponse(t, failingSettingRec, &failingSetting)
	failedRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/llm/test", map[string]any{
		"setting_id": failingSetting.ID,
	}, cookie, http.StatusBadGateway)
	if !strings.Contains(failedRec.Body.String(), "send LLM test prompt") {
		t.Fatal("failed LLM test did not return a clear provider error")
	}
	if strings.Contains(failedRec.Body.String(), "fail-secret") || !strings.Contains(failedRec.Body.String(), "[redacted]") {
		t.Fatalf("failed LLM test response did not redact provider error: %s", failedRec.Body.String())
	}
	failedLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, cookie, http.StatusOK)
	failedLogsBody := failedLogsRec.Body.String()
	if strings.Contains(failedLogsBody, "fail-secret") || !strings.Contains(failedLogsBody, "system_settings.llm_test.failed") || !strings.Contains(failedLogsBody, "[redacted]") {
		t.Fatalf("failed LLM test audit log did not redact provider error: %s", failedLogsBody)
	}
	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/llm/test", map[string]any{
		"setting_id": "missing",
	}, cookie, http.StatusNotFound)
}

func TestProxyServiceSettingsPersistStatusAndSyncSSHGateway(t *testing.T) {
	handler, cookie := newTestHandler(t)
	srv := handler.(*Server)
	rdpListen := freeLocalTCPAddress(t)
	databaseListen := freeLocalTCPAddress(t)

	initialRec := assertStatus(t, handler, http.MethodGet, "/api/admin/proxy-services", nil, cookie, http.StatusOK)
	if !strings.Contains(initialRec.Body.String(), "ssh_gateway") || !strings.Contains(initialRec.Body.String(), "database_proxy") {
		t.Fatalf("initial proxy service status missing sections: %s", initialRec.Body.String())
	}

	saveRec := assertStatus(t, handler, http.MethodPost, "/api/admin/proxy-services", map[string]any{
		"ssh_enabled":                true,
		"ssh_listen_address":         "127.0.0.1:22022",
		"ssh_disable_password_auth":  true,
		"ssh_forward_allowlist":      []string{"db.internal:5432", "10.0.0.5:22"},
		"proxy_private_key":          "proxy-secret-key",
		"rdp_enabled":                true,
		"rdp_listen_address":         rdpListen,
		"rdp_forward_allowlist":      []string{"windows.internal:3389"},
		"database_enabled":           true,
		"database_listen_address":    databaseListen,
		"database_forward_allowlist": []string{"db.internal:3306"},
	}, cookie, http.StatusOK)
	saveBody := saveRec.Body.String()
	for _, want := range []string{"proxy_private_key_set", "127.0.0.1:22022", rdpListen, databaseListen, "db.internal:5432", "windows.internal:3389", "restart_required", "rdp_proxy", "database_proxy", `"state":"ready"`, `"allowlist_count":1`} {
		if !strings.Contains(saveBody, want) {
			t.Fatalf("proxy service response missing %s: %s", want, saveBody)
		}
	}
	for _, leaked := range []string{"proxy-secret-key", "proxy_private_key_encrypted", `"proxy_private_key":`, `"ssh_private_key":`} {
		if strings.Contains(saveBody, leaked) {
			t.Fatalf("proxy service response leaked %s: %s", leaked, saveBody)
		}
	}

	settingsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/system-settings", nil, cookie, http.StatusOK)
	settingsBody := settingsRec.Body.String()
	if !strings.Contains(settingsBody, "proxy_private_key_set") || !strings.Contains(settingsBody, "ssh_forward_allowlist") || !strings.Contains(settingsBody, "rdp_forward_allowlist") {
		t.Fatalf("system settings list missing proxy state: %s", settingsBody)
	}
	for _, leaked := range []string{"proxy-secret-key", "proxy_private_key_encrypted"} {
		if strings.Contains(settingsBody, leaked) {
			t.Fatalf("system settings leaked proxy secret %s: %s", leaked, settingsBody)
		}
	}
	proxyPrivateKey, ok, err := srv.cfg.Store.SystemSettingProxyPrivateKey()
	if err != nil || !ok || proxyPrivateKey != "proxy-secret-key" {
		t.Fatalf("proxy private key = %q ok=%v err=%v", proxyPrivateKey, ok, err)
	}

	sshGatewayRec := assertStatus(t, handler, http.MethodGet, "/api/admin/ssh-gateways", nil, cookie, http.StatusOK)
	sshGatewayBody := sshGatewayRec.Body.String()
	for _, want := range []string{`"status":"enabled"`, `"host":"127.0.0.1"`, `"port":22022`, "db.internal:5432", "proxy_services"} {
		if !strings.Contains(sshGatewayBody, want) {
			t.Fatalf("ssh gateway sync missing %s: %s", want, sshGatewayBody)
		}
	}

	clearKeyRec := assertStatus(t, handler, http.MethodPost, "/api/admin/proxy-services", map[string]any{
		"ssh_enabled":                true,
		"ssh_listen_address":         "127.0.0.1:22022",
		"ssh_disable_password_auth":  true,
		"ssh_forward_allowlist":      []string{"db.internal:5432", "10.0.0.5:22"},
		"proxy_private_key_clear":    true,
		"rdp_enabled":                true,
		"rdp_listen_address":         rdpListen,
		"rdp_forward_allowlist":      []string{"windows.internal:3389"},
		"database_enabled":           true,
		"database_listen_address":    databaseListen,
		"database_forward_allowlist": []string{"db.internal:3306"},
	}, cookie, http.StatusOK)
	clearKeyBody := clearKeyRec.Body.String()
	for _, leaked := range []string{"proxy-secret-key", "proxy_private_key_encrypted", "proxy_private_key_clear", `"proxy_private_key":`, `"ssh_private_key":`, "proxy_private_key_set"} {
		if strings.Contains(clearKeyBody, leaked) {
			t.Fatalf("proxy private key clear response leaked retained state %s: %s", leaked, clearKeyBody)
		}
	}
	proxySetting, ok, err := srv.rawSystemSettingByType("proxy")
	if err != nil || !ok {
		t.Fatalf("load proxy setting after key clear: ok=%v err=%v", ok, err)
	}
	for _, key := range []string{"proxy_private_key_encrypted", "proxy_private_key_set", "proxy_private_key_updated_at", "proxy_private_key_clear"} {
		if _, exists := proxySetting.Metadata[key]; exists {
			t.Fatalf("proxy setting retained %s after key clear: %#v", key, proxySetting.Metadata)
		}
	}
	proxyPrivateKey, ok, err = srv.cfg.Store.SystemSettingProxyPrivateKey()
	if err != nil || !ok || proxyPrivateKey != "" {
		t.Fatalf("cleared proxy private key = %q ok=%v err=%v", proxyPrivateKey, ok, err)
	}

	disableRec := assertStatus(t, handler, http.MethodPost, "/api/admin/proxy-services", map[string]any{
		"ssh_enabled":             false,
		"ssh_listen_address":      "127.0.0.1:22022",
		"rdp_enabled":             false,
		"database_enabled":        false,
		"database_listen_address": databaseListen,
	}, cookie, http.StatusOK)
	if !strings.Contains(disableRec.Body.String(), `"state":"disabled"`) {
		t.Fatalf("disabled proxy services did not report disabled state: %s", disableRec.Body.String())
	}
	disabledGatewayRec := assertStatus(t, handler, http.MethodGet, "/api/admin/ssh-gateways", nil, cookie, http.StatusOK)
	if !strings.Contains(disabledGatewayRec.Body.String(), `"status":"disabled"`) {
		t.Fatalf("disabled proxy services did not disable ssh gateway: %s", disabledGatewayRec.Body.String())
	}

	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, cookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), "proxy_services.update") {
		t.Fatalf("proxy service update was not audited: %s", logsRec.Body.String())
	}
}

func TestProxyServiceOperationLogFailureRollsBackSettings(t *testing.T) {
	handler, cookie := newTestHandler(t)
	srv := handler.(*Server)

	assertStatus(t, handler, http.MethodPost, "/api/admin/proxy-services", map[string]any{
		"ssh_enabled":               true,
		"ssh_listen_address":        "127.0.0.1:22024",
		"ssh_disable_password_auth": true,
		"ssh_forward_allowlist":     []string{"initial.internal:22"},
		"proxy_private_key":         "initial-proxy-secret",
	}, cookie, http.StatusOK)

	removeBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	failureRec := assertStatus(t, handler, http.MethodPost, "/api/admin/proxy-services", map[string]any{
		"ssh_enabled":               false,
		"ssh_listen_address":        "127.0.0.1:22025",
		"ssh_disable_password_auth": false,
		"ssh_forward_allowlist":     []string{"changed.internal:22"},
		"proxy_private_key":         "changed-proxy-secret",
	}, cookie, http.StatusInternalServerError)
	removeBlocker()
	if !strings.Contains(failureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("proxy operation log failure was not reported: %s", failureRec.Body.String())
	}

	setting, ok, err := srv.rawSystemSettingByType("proxy")
	if err != nil || !ok {
		t.Fatalf("load proxy setting after rollback: ok=%v err=%v", ok, err)
	}
	if firstMetadataString(setting.Metadata, "ssh_listen_address") != "127.0.0.1:22024" || setting.Metadata["ssh_gateway_enabled"] != true {
		t.Fatalf("proxy setting was not restored after operation log failure: %#v", setting.Metadata)
	}
	if strings.Contains(fmt.Sprint(setting.Metadata), "changed.internal") {
		t.Fatalf("proxy setting retained failed allowlist change: %#v", setting.Metadata)
	}
	proxyPrivateKey, ok, err := srv.cfg.Store.SystemSettingProxyPrivateKey()
	if err != nil || !ok || proxyPrivateKey != "initial-proxy-secret" {
		t.Fatalf("proxy private key after rollback = %q ok=%v err=%v", proxyPrivateKey, ok, err)
	}

	gateway, ok, err := srv.rawSSHGatewayForProxySettings()
	if err != nil || !ok {
		t.Fatalf("load ssh gateway after rollback: ok=%v err=%v", ok, err)
	}
	if gateway.Status != "enabled" || gateway.Host != "127.0.0.1" || gateway.Port != 22024 {
		t.Fatalf("ssh gateway was not restored after operation log failure: %#v", gateway)
	}
	if strings.Contains(fmt.Sprint(gateway.Metadata), "changed.internal") {
		t.Fatalf("ssh gateway retained failed allowlist change: %#v", gateway.Metadata)
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "operation.log.persist_failed") {
		t.Fatal("proxy operation log persistence failure was not written to core audit logs")
	}
}

func TestProxyServiceDatabaseProxyReportsConfigErrors(t *testing.T) {
	handler, cookie := newTestHandler(t)

	invalidRec := assertStatus(t, handler, http.MethodPost, "/api/admin/proxy-services", map[string]any{
		"database_enabled":           true,
		"database_listen_address":    "127.0.0.1:23306",
		"database_forward_allowlist": []string{"missing-port"},
	}, cookie, http.StatusOK)
	invalidBody := invalidRec.Body.String()
	for _, want := range []string{`"state":"invalid_config"`, "invalid database proxy allowlist entry", "missing-port"} {
		if !strings.Contains(invalidBody, want) {
			t.Fatalf("invalid database proxy response missing %s: %s", want, invalidBody)
		}
	}

	listener, closeListener := startAppTestTCPListener(t)
	defer closeListener()
	occupiedRec := assertStatus(t, handler, http.MethodPost, "/api/admin/proxy-services", map[string]any{
		"database_enabled":           true,
		"database_listen_address":    listener.Addr().String(),
		"database_forward_allowlist": []string{"db.internal:3306"},
	}, cookie, http.StatusOK)
	occupiedBody := occupiedRec.Body.String()
	for _, want := range []string{`"state":"port_unavailable"`, listener.Addr().String()} {
		if !strings.Contains(occupiedBody, want) {
			t.Fatalf("occupied database proxy response missing %s: %s", want, occupiedBody)
		}
	}
}

func TestProxyServiceRDPProxyReportsConfigErrors(t *testing.T) {
	handler, cookie := newTestHandler(t)

	invalidRec := assertStatus(t, handler, http.MethodPost, "/api/admin/proxy-services", map[string]any{
		"rdp_enabled":           true,
		"rdp_listen_address":    "127.0.0.1:23389",
		"rdp_forward_allowlist": []string{"missing-port"},
	}, cookie, http.StatusOK)
	invalidBody := invalidRec.Body.String()
	for _, want := range []string{`"state":"invalid_config"`, "invalid rdp proxy allowlist entry", "missing-port"} {
		if !strings.Contains(invalidBody, want) {
			t.Fatalf("invalid rdp proxy response missing %s: %s", want, invalidBody)
		}
	}

	listener, closeListener := startAppTestTCPListener(t)
	defer closeListener()
	occupiedRec := assertStatus(t, handler, http.MethodPost, "/api/admin/proxy-services", map[string]any{
		"rdp_enabled":           true,
		"rdp_listen_address":    listener.Addr().String(),
		"rdp_forward_allowlist": []string{"windows.internal:3389"},
	}, cookie, http.StatusOK)
	occupiedBody := occupiedRec.Body.String()
	for _, want := range []string{`"state":"port_unavailable"`, listener.Addr().String()} {
		if !strings.Contains(occupiedBody, want) {
			t.Fatalf("occupied rdp proxy response missing %s: %s", want, occupiedBody)
		}
	}
}

func TestProxyServiceSSHGatewayReportsConfigErrors(t *testing.T) {
	handler, cookie := newTestHandler(t)

	invalidRec := assertStatus(t, handler, http.MethodPost, "/api/admin/proxy-services", map[string]any{
		"ssh_enabled":        true,
		"ssh_listen_address": "not-a-listen-address",
	}, cookie, http.StatusOK)
	invalidBody := invalidRec.Body.String()
	for _, want := range []string{`"state":"invalid_config"`, "address must be host:port", "not-a-listen-address"} {
		if !strings.Contains(invalidBody, want) {
			t.Fatalf("invalid ssh gateway response missing %s: %s", want, invalidBody)
		}
	}

	listener, closeListener := startAppTestTCPListener(t)
	defer closeListener()
	occupiedRec := assertStatus(t, handler, http.MethodPost, "/api/admin/proxy-services", map[string]any{
		"ssh_enabled":        true,
		"ssh_listen_address": listener.Addr().String(),
	}, cookie, http.StatusOK)
	occupiedBody := occupiedRec.Body.String()
	for _, want := range []string{`"state":"port_unavailable"`, listener.Addr().String()} {
		if !strings.Contains(occupiedBody, want) {
			t.Fatalf("occupied ssh gateway response missing %s: %s", want, occupiedBody)
		}
	}
}

func TestProxyServiceSettingsReloadSSHGatewayRuntime(t *testing.T) {
	runtime := &fakeSSHGatewayRuntime{address: "127.0.0.1:22022"}
	handler, cookie := newTestServer(t, func(cfg *Config) {
		cfg.SSHGateway = runtime
	})

	saveRec := assertStatus(t, handler, http.MethodPost, "/api/admin/proxy-services", map[string]any{
		"ssh_enabled":        true,
		"ssh_listen_address": "127.0.0.1:22022",
	}, cookie, http.StatusOK)
	saveBody := saveRec.Body.String()
	if runtime.reloads != 1 {
		t.Fatalf("ssh gateway runtime reloads = %d, want 1", runtime.reloads)
	}
	for _, want := range []string{`"state":"running"`, `"live_address":"127.0.0.1:22022"`} {
		if !strings.Contains(saveBody, want) {
			t.Fatalf("proxy service response missing %s: %s", want, saveBody)
		}
	}
	if strings.Contains(saveBody, "restart_required") {
		t.Fatalf("proxy service still requires restart after runtime reload: %s", saveBody)
	}
}

func TestRDPProxyRuntimeForwardsAllowedTarget(t *testing.T) {
	upstreamAddress, received, closeUpstream := startEchoTCPServer(t)
	defer closeUpstream()
	listenAddress := freeLocalTCPAddress(t)
	var rdpProxy *RDPProxyManager
	handler, cookie := newTestServer(t, func(cfg *Config) {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		rdpProxy = NewRDPProxyManager(ctx, cfg.Store, slog.Default())
		t.Cleanup(func() { _ = rdpProxy.Close() })
		cfg.RDPProxy = rdpProxy
	})

	saveRec := assertStatus(t, handler, http.MethodPost, "/api/admin/proxy-services", map[string]any{
		"rdp_enabled":           true,
		"rdp_listen_address":    listenAddress,
		"rdp_forward_allowlist": []string{upstreamAddress},
	}, cookie, http.StatusOK)
	saveBody := saveRec.Body.String()
	for _, want := range []string{`"state":"running"`, `"live_address":"` + listenAddress + `"`, `"target":"` + upstreamAddress + `"`} {
		if !strings.Contains(saveBody, want) {
			t.Fatalf("rdp proxy runtime response missing %s: %s", want, saveBody)
		}
	}

	conn, err := net.DialTimeout("tcp", rdpProxy.Address(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial rdp proxy: %v", err)
	}
	if _, err := conn.Write([]byte("mstsc hello\n")); err != nil {
		t.Fatalf("write rdp proxy: %v", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read rdp proxy response: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close rdp proxy conn: %v", err)
	}
	if line != "echo:mstsc hello\n" {
		t.Fatalf("rdp proxy response = %q", line)
	}
	select {
	case got := <-received:
		if got != "mstsc hello\n" {
			t.Fatalf("upstream received %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive rdp proxy payload")
	}

	var logsBody string
	for i := 0; i < 20; i++ {
		logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, cookie, http.StatusOK)
		logsBody = logsRec.Body.String()
		if strings.Contains(logsBody, "rdp_proxy.connect") && strings.Contains(logsBody, upstreamAddress) {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !strings.Contains(logsBody, "rdp_proxy.connect") || !strings.Contains(logsBody, upstreamAddress) {
		t.Fatalf("rdp proxy connection was not audited: %s", logsBody)
	}

	func() {
		removeProxyLogBlocker := blockPlatformItemCreate(t, handler.cfg.Store, "operation_logs")
		defer removeProxyLogBlocker()
		blockedConn, err := net.DialTimeout("tcp", rdpProxy.Address(), 2*time.Second)
		if err != nil {
			t.Fatalf("dial rdp proxy with blocked audit log: %v", err)
		}
		if _, err := blockedConn.Write([]byte("audit blocked rdp\n")); err != nil {
			t.Fatalf("write rdp proxy with blocked audit log: %v", err)
		}
		blockedLine, err := bufio.NewReader(blockedConn).ReadString('\n')
		if err != nil {
			t.Fatalf("read rdp proxy response with blocked audit log: %v", err)
		}
		if err := blockedConn.Close(); err != nil {
			t.Fatalf("close rdp proxy conn with blocked audit log: %v", err)
		}
		if blockedLine != "echo:audit blocked rdp\n" {
			t.Fatalf("rdp proxy response with blocked audit log = %q", blockedLine)
		}
		waitForCondition(t, 2*time.Second, func() bool {
			return coreAuditLogsContainAction(handler.cfg.Store, "rdp_proxy.log.persist_failed")
		})
	}()

	assertStatus(t, handler, http.MethodPost, "/api/admin/proxy-services", map[string]any{
		"rdp_enabled":           false,
		"rdp_listen_address":    listenAddress,
		"rdp_forward_allowlist": []string{upstreamAddress},
	}, cookie, http.StatusOK)
	if rdpProxy.Address() != "" {
		t.Fatalf("rdp proxy address still active after disable: %s", rdpProxy.Address())
	}
	if disabledConn, err := net.DialTimeout("tcp", listenAddress, 100*time.Millisecond); err == nil {
		_ = disabledConn.Close()
		t.Fatal("rdp proxy listener still accepts connections after disable")
	}
}

func TestDatabaseProxyRuntimeForwardsAllowedTarget(t *testing.T) {
	upstreamAddress, received, closeUpstream := startEchoTCPServer(t)
	defer closeUpstream()
	listenAddress := freeLocalTCPAddress(t)
	var databaseProxy *DatabaseProxyManager
	handler, cookie := newTestServer(t, func(cfg *Config) {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		databaseProxy = NewDatabaseProxyManager(ctx, cfg.Store, slog.Default())
		t.Cleanup(func() { _ = databaseProxy.Close() })
		cfg.DatabaseProxy = databaseProxy
	})

	saveRec := assertStatus(t, handler, http.MethodPost, "/api/admin/proxy-services", map[string]any{
		"database_enabled":           true,
		"database_listen_address":    listenAddress,
		"database_forward_allowlist": []string{upstreamAddress},
	}, cookie, http.StatusOK)
	saveBody := saveRec.Body.String()
	for _, want := range []string{`"state":"running"`, `"live_address":"` + listenAddress + `"`, `"target":"` + upstreamAddress + `"`} {
		if !strings.Contains(saveBody, want) {
			t.Fatalf("database proxy runtime response missing %s: %s", want, saveBody)
		}
	}

	conn, err := net.DialTimeout("tcp", databaseProxy.Address(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial database proxy: %v", err)
	}
	if _, err := conn.Write([]byte("select 1\n")); err != nil {
		t.Fatalf("write database proxy: %v", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read database proxy response: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close database proxy conn: %v", err)
	}
	if line != "echo:select 1\n" {
		t.Fatalf("database proxy response = %q", line)
	}
	select {
	case got := <-received:
		if got != "select 1\n" {
			t.Fatalf("upstream received %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive database proxy payload")
	}

	var logsBody string
	for i := 0; i < 20; i++ {
		logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, cookie, http.StatusOK)
		logsBody = logsRec.Body.String()
		if strings.Contains(logsBody, "database_proxy.connect") && strings.Contains(logsBody, upstreamAddress) {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !strings.Contains(logsBody, "database_proxy.connect") || !strings.Contains(logsBody, upstreamAddress) {
		t.Fatalf("database proxy connection was not audited: %s", logsBody)
	}

	func() {
		removeProxyLogBlocker := blockPlatformItemCreate(t, handler.cfg.Store, "operation_logs")
		defer removeProxyLogBlocker()
		blockedConn, err := net.DialTimeout("tcp", databaseProxy.Address(), 2*time.Second)
		if err != nil {
			t.Fatalf("dial database proxy with blocked audit log: %v", err)
		}
		if _, err := blockedConn.Write([]byte("audit blocked database\n")); err != nil {
			t.Fatalf("write database proxy with blocked audit log: %v", err)
		}
		blockedLine, err := bufio.NewReader(blockedConn).ReadString('\n')
		if err != nil {
			t.Fatalf("read database proxy response with blocked audit log: %v", err)
		}
		if err := blockedConn.Close(); err != nil {
			t.Fatalf("close database proxy conn with blocked audit log: %v", err)
		}
		if blockedLine != "echo:audit blocked database\n" {
			t.Fatalf("database proxy response with blocked audit log = %q", blockedLine)
		}
		waitForCondition(t, 2*time.Second, func() bool {
			return coreAuditLogsContainAction(handler.cfg.Store, "database_proxy.log.persist_failed")
		})
	}()

	assertStatus(t, handler, http.MethodPost, "/api/admin/proxy-services", map[string]any{
		"database_enabled":           false,
		"database_listen_address":    listenAddress,
		"database_forward_allowlist": []string{upstreamAddress},
	}, cookie, http.StatusOK)
	if databaseProxy.Address() != "" {
		t.Fatalf("database proxy address still active after disable: %s", databaseProxy.Address())
	}
	if disabledConn, err := net.DialTimeout("tcp", listenAddress, 100*time.Millisecond); err == nil {
		_ = disabledConn.Close()
		t.Fatal("database proxy listener still accepts connections after disable")
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
	downloadLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, cookie, http.StatusOK)
	if !strings.Contains(downloadLogsRec.Body.String(), "backup.download") || !strings.Contains(downloadLogsRec.Body.String(), backupName) {
		t.Fatalf("backup download did not write operation log: %s", downloadLogsRec.Body.String())
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
	invalidBackupPayload := []byte("not a zip with restore-secret")
	invalidBackupRec := assertMultipartStatus(t, handler, "/api/admin/backups/restore", nil, "not-a-backup.zip", invalidBackupPayload, cookie, http.StatusBadRequest)
	if strings.Contains(invalidBackupRec.Body.String(), "restore-secret") {
		t.Fatalf("backup restore failure response leaked upload content: %s", invalidBackupRec.Body.String())
	}
	operationLogsBeforeRestore := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, cookie, http.StatusOK)
	operationLogsBeforeRestoreBody := operationLogsBeforeRestore.Body.String()
	if !strings.Contains(operationLogsBeforeRestoreBody, "backup.restore.validate") || !strings.Contains(operationLogsBeforeRestoreBody, "backup.restore.failed") {
		t.Fatalf("backup restore validation/failure logs missing: %s", operationLogsBeforeRestoreBody)
	}
	if strings.Contains(operationLogsBeforeRestoreBody, "restore-secret") {
		t.Fatalf("backup restore failure audit leaked upload content: %s", operationLogsBeforeRestoreBody)
	}

	unsafeUploadName := `C:\Users\ops\Downloads\` + backupName
	restoreRec := assertMultipartStatus(t, handler, "/api/admin/backups/restore", nil, unsafeUploadName, downloadRec.Body.Bytes(), cookie, http.StatusOK)
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
	logsBody := logsRec.Body.String()
	if !strings.Contains(logsBody, "backup.restore") {
		t.Fatal("backup restore did not write operation log")
	}
	if !strings.Contains(logsBody, backupName) || strings.Contains(logsBody, `C:\Users\ops`) || strings.Contains(logsBody, `Downloads\`) {
		t.Fatalf("backup restore audit did not sanitize uploaded filename: %s", logsBody)
	}
}

func TestBackupRestoreMigratesPlaintextPlatformSecrets(t *testing.T) {
	handler, cookie := newTestHandler(t)
	server := handler.(*Server)

	tempDir := t.TempDir()
	sqlitePath := filepath.Join(tempDir, "store.db")
	db, err := sql.Open("sqlite", sqlitePath)
	if err != nil {
		t.Fatalf("open restore sqlite: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE platform_records (
		collection TEXT NOT NULL,
		id TEXT NOT NULL,
		payload TEXT NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		PRIMARY KEY (collection, id)
	)`); err != nil {
		_ = db.Close()
		t.Fatalf("create restore platform table: %v", err)
	}
	now := time.Now().UTC()
	createdAt := now.Format(time.RFC3339Nano)
	dsn := "postgres://restore_user:restore-secret@postgres.internal:5432/app?sslmode=disable"
	databaseAsset := model.PlatformItem{
		ID:        "restore_plain_database_asset",
		Name:      "restored plaintext database",
		Type:      "postgres",
		Status:    "enabled",
		Protocol:  model.ProtocolDatabase,
		Metadata:  map[string]any{"dsn": dsn},
		CreatedAt: now,
		UpdatedAt: now,
	}
	webUpstream := "https://restore-web:restore-web-secret@web.internal/app"
	webAsset := model.PlatformItem{
		ID:        "restore_plain_web_asset",
		Name:      "restored plaintext web",
		Type:      "https",
		Status:    "enabled",
		Protocol:  model.ProtocolHTTP,
		Metadata:  map[string]any{"target_url": webUpstream},
		CreatedAt: now,
		UpdatedAt: now,
	}
	systemSetting := model.PlatformItem{
		ID:     "restore_plain_system_setting",
		Name:   "restored plaintext integrations",
		Type:   "integrations",
		Status: "enabled",
		Metadata: map[string]any{
			"smtp_host":     "smtp.internal",
			"smtp_password": "restore-smtp-secret",
			"llm_api_key":   "restore-llm-secret",
			"dns": map[string]any{
				"provider":      "cloudflare",
				"dns_api_token": "restore-dns-secret",
			},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	certPEM, certPrivateKeyPEM, err := makeSelfSignedCertificate(certificateRequest{Domain: "restore-cert.example.test", Days: 30})
	if err != nil {
		_ = db.Close()
		t.Fatalf("make restore certificate: %v", err)
	}
	certificateItem := model.PlatformItem{
		ID:     "restore_plain_certificate",
		Name:   "restored plaintext certificate",
		Type:   "self-signed",
		Status: "issued",
		Metadata: map[string]any{
			"certificate":     string(certPEM),
			"private_key":     string(certPrivateKeyPEM),
			"has_private_key": true,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	for _, record := range []struct {
		collection string
		item       model.PlatformItem
	}{
		{collection: "database_assets", item: databaseAsset},
		{collection: "web_assets", item: webAsset},
		{collection: "system_settings", item: systemSetting},
		{collection: "certificates", item: certificateItem},
	} {
		payload, err := json.Marshal(record.item)
		if err != nil {
			_ = db.Close()
			t.Fatalf("encode restore payload: %v", err)
		}
		if _, err := db.Exec(`INSERT INTO platform_records(collection, id, payload, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`, record.collection, record.item.ID, string(payload), createdAt, createdAt); err != nil {
			_ = db.Close()
			t.Fatalf("insert restore platform record: %v", err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close restore sqlite: %v", err)
	}

	var backup bytes.Buffer
	zipWriter := zip.NewWriter(&backup)
	manifestFile, err := zipWriter.Create("manifest.json")
	if err != nil {
		t.Fatalf("create restore manifest entry: %v", err)
	}
	if err := json.NewEncoder(manifestFile).Encode(map[string]any{
		"version":    "legacy-plaintext-platform-secrets",
		"created_at": createdAt,
	}); err != nil {
		t.Fatalf("write restore manifest: %v", err)
	}
	storeFile, err := zipWriter.Create("store.db")
	if err != nil {
		t.Fatalf("create restore sqlite entry: %v", err)
	}
	sqliteRaw, err := os.ReadFile(sqlitePath)
	if err != nil {
		t.Fatalf("read restore sqlite: %v", err)
	}
	if _, err := storeFile.Write(sqliteRaw); err != nil {
		t.Fatalf("write restore sqlite entry: %v", err)
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatalf("close restore zip: %v", err)
	}

	restoreRec := assertMultipartStatus(t, handler, "/api/admin/backups/restore", nil, "legacy-plaintext-secrets.zip", backup.Bytes(), cookie, http.StatusOK)
	restoreBody := restoreRec.Body.String()
	for _, leaked := range []string{"restore-secret", "restore-web-secret", "restore-smtp-secret", "restore-llm-secret", "restore-dns-secret", "postgres://restore_user", "PRIVATE KEY"} {
		if strings.Contains(restoreBody, leaked) {
			t.Fatalf("backup restore response leaked %q: %s", leaked, restoreBody)
		}
	}
	if !strings.Contains(restoreBody, `"restored":true`) || !strings.Contains(restoreBody, `"migrated_platform_secrets":4`) {
		t.Fatalf("backup restore response did not report migrated secrets: %s", restoreBody)
	}

	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusOK)
	newCookie := loginRec.Result().Cookies()[0]

	rawDatabaseAsset, ok, err := server.cfg.Store.GetPlatformItem("database_assets", databaseAsset.ID)
	if err != nil || !ok {
		t.Fatalf("load restored database asset: ok=%v err=%v", ok, err)
	}
	if firstMetadataString(rawDatabaseAsset.Metadata, "dsn", "connection_string", "connectionString", "database_url", "databaseUrl", "url") != "" {
		t.Fatalf("restored database asset retained plaintext dsn: %#v", rawDatabaseAsset.Metadata)
	}
	dsnSet, _ := metadataBoolValue(rawDatabaseAsset.Metadata["database_dsn_set"])
	if firstMetadataString(rawDatabaseAsset.Metadata, "database_dsn_encrypted") == "" || !dsnSet {
		t.Fatalf("restored database asset did not encrypt dsn: %#v", rawDatabaseAsset.Metadata)
	}
	connection, err := server.databaseAssetConnection(rawDatabaseAsset)
	if err != nil {
		t.Fatalf("restored database asset connection: %v", err)
	}
	parsed, err := url.Parse(connection.DSN)
	if err != nil {
		t.Fatalf("parse restored database dsn: %v", err)
	}
	password, _ := parsed.User.Password()
	if parsed.User.Username() != "restore_user" || password != "restore-secret" {
		t.Fatalf("restored database dsn was not decryptable: %q", connection.DSN)
	}

	rawWebAsset, ok, err := server.cfg.Store.GetPlatformItem("web_assets", webAsset.ID)
	if err != nil || !ok {
		t.Fatalf("load restored web asset: ok=%v err=%v", ok, err)
	}
	if rawTargetURL := firstMetadataString(rawWebAsset.Metadata, "target_url"); strings.Contains(rawTargetURL, "restore-web") || strings.Contains(rawTargetURL, "@") {
		t.Fatalf("restored web asset retained plaintext upstream credentials: %#v", rawWebAsset.Metadata)
	}
	encryptedWebUpstream := firstMetadataString(rawWebAsset.Metadata, "web_upstream_url_encrypted")
	webUpstreamSet, _ := metadataBoolValue(rawWebAsset.Metadata["web_upstream_url_set"])
	if encryptedWebUpstream == "" || !webUpstreamSet {
		t.Fatalf("restored web asset did not encrypt upstream credentials: %#v", rawWebAsset.Metadata)
	}
	decryptedWebUpstream, err := server.cfg.Store.DecryptPlatformSecret(encryptedWebUpstream)
	if err != nil {
		t.Fatalf("decrypt restored web upstream: %v", err)
	}
	if decryptedWebUpstream != webUpstream {
		t.Fatalf("restored web upstream = %q, want %q", decryptedWebUpstream, webUpstream)
	}

	rawSystemSetting, ok, err := server.cfg.Store.GetPlatformItem("system_settings", systemSetting.ID)
	if err != nil || !ok {
		t.Fatalf("load restored system setting: ok=%v err=%v", ok, err)
	}
	if firstMetadataString(rawSystemSetting.Metadata, "smtp_password", "smtpPassword", "plain_smtp_password", "llm_api_key", "llmApiKey", "plain_llm_api_key") != "" {
		t.Fatalf("restored system setting retained plaintext secret: %#v", rawSystemSetting.Metadata)
	}
	if firstMetadataString(rawSystemSetting.Metadata, "smtp_password_encrypted") == "" || firstMetadataString(rawSystemSetting.Metadata, "llm_api_key_encrypted") == "" {
		t.Fatalf("restored system setting did not encrypt top-level secrets: %#v", rawSystemSetting.Metadata)
	}
	rawSystemSettingJSON, err := json.Marshal(rawSystemSetting.Metadata)
	if err != nil {
		t.Fatalf("encode restored system setting metadata: %v", err)
	}
	if strings.Contains(string(rawSystemSettingJSON), "restore-dns-secret") || !strings.Contains(string(rawSystemSettingJSON), "dns_api_token_encrypted") {
		t.Fatalf("restored nested dns secret was not encrypted: %s", string(rawSystemSettingJSON))
	}
	smtpPassword, ok, err := server.cfg.Store.SystemSettingSMTPPassword(systemSetting.ID)
	if err != nil || !ok || smtpPassword != "restore-smtp-secret" {
		t.Fatalf("restored smtp password = %q ok=%v err=%v", smtpPassword, ok, err)
	}
	llmAPIKey, ok, err := server.cfg.Store.SystemSettingLLMAPIKey(systemSetting.ID)
	if err != nil || !ok || llmAPIKey != "restore-llm-secret" {
		t.Fatalf("restored llm api key = %q ok=%v err=%v", llmAPIKey, ok, err)
	}

	rawCertificate, ok, err := server.cfg.Store.GetPlatformItem("certificates", certificateItem.ID)
	if err != nil || !ok {
		t.Fatalf("load restored certificate: ok=%v err=%v", ok, err)
	}
	if firstMetadataString(rawCertificate.Metadata, "private_key", "privateKey", "key", "private_key_pem") != "" {
		t.Fatalf("restored certificate retained plaintext private key: %#v", rawCertificate.Metadata)
	}
	encryptedCertificateKey := firstMetadataString(rawCertificate.Metadata, "certificate_private_key_encrypted")
	if encryptedCertificateKey == "" || rawCertificate.Metadata["has_private_key"] != true {
		t.Fatalf("restored certificate did not encrypt private key: %#v", rawCertificate.Metadata)
	}
	decryptedCertificateKey, err := server.cfg.Store.DecryptPlatformSecret(encryptedCertificateKey)
	if err != nil {
		t.Fatalf("decrypt restored certificate private key: %v", err)
	}
	if strings.TrimSpace(decryptedCertificateKey) != strings.TrimSpace(string(certPrivateKeyPEM)) {
		t.Fatal("restored certificate private key did not decrypt to original PEM")
	}

	databaseDetailRec := assertStatus(t, handler, http.MethodGet, "/api/admin/database-assets/"+databaseAsset.ID, nil, newCookie, http.StatusOK)
	databaseDetailBody := databaseDetailRec.Body.String()
	for _, leaked := range []string{"restore-secret", "postgres://restore_user", `"dsn":`, "database_dsn_encrypted"} {
		if strings.Contains(databaseDetailBody, leaked) {
			t.Fatalf("database detail leaked %q: %s", leaked, databaseDetailBody)
		}
	}
	if !strings.Contains(databaseDetailBody, "database_dsn_set") {
		t.Fatalf("database detail did not expose dsn presence flag: %s", databaseDetailBody)
	}

	webDetailRec := assertStatus(t, handler, http.MethodGet, "/api/admin/websites/"+webAsset.ID, nil, newCookie, http.StatusOK)
	webDetailBody := webDetailRec.Body.String()
	for _, leaked := range []string{"restore-web-secret", "web_upstream_url_encrypted", "restore-web:"} {
		if strings.Contains(webDetailBody, leaked) {
			t.Fatalf("web detail leaked %q: %s", leaked, webDetailBody)
		}
	}
	if !strings.Contains(webDetailBody, "web_upstream_url_set") || !strings.Contains(webDetailBody, "target_url_credentials_set") {
		t.Fatalf("web detail did not expose upstream credential presence flags: %s", webDetailBody)
	}

	settingsDetailRec := assertStatus(t, handler, http.MethodGet, "/api/admin/system-settings/"+systemSetting.ID, nil, newCookie, http.StatusOK)
	settingsDetailBody := settingsDetailRec.Body.String()
	for _, leaked := range []string{"restore-smtp-secret", "restore-llm-secret", "restore-dns-secret", "smtp_password_encrypted", "llm_api_key_encrypted", "dns_api_token_encrypted"} {
		if strings.Contains(settingsDetailBody, leaked) {
			t.Fatalf("system setting detail leaked %q: %s", leaked, settingsDetailBody)
		}
	}
	for _, expected := range []string{"smtp_password_set", "llm_api_key_set", "dns_api_token_set"} {
		if !strings.Contains(settingsDetailBody, expected) {
			t.Fatalf("system setting detail did not expose %q: %s", expected, settingsDetailBody)
		}
	}
}

func TestBackupDeleteAndRetention(t *testing.T) {
	srv, cookie := newTestServer(t, nil)
	handler := http.Handler(srv)

	createBackupRec := assertStatus(t, handler, http.MethodPost, "/api/admin/backups", nil, cookie, http.StatusCreated)
	var backupMetadata map[string]any
	decodeResponse(t, createBackupRec, &backupMetadata)
	backupPath, _ := backupMetadata["backup_path"].(string)
	backupName := filepath.Base(filepath.FromSlash(backupPath))
	if backupName == "." || backupName == "" {
		t.Fatalf("backup path missing from metadata: %v", backupMetadata)
	}
	secondBackupRec := assertStatus(t, handler, http.MethodPost, "/api/admin/backups", nil, cookie, http.StatusCreated)
	var secondBackupMetadata map[string]any
	decodeResponse(t, secondBackupRec, &secondBackupMetadata)
	secondBackupPath, _ := secondBackupMetadata["backup_path"].(string)
	secondBackupName := filepath.Base(filepath.FromSlash(secondBackupPath))
	if secondBackupName == "." || secondBackupName == "" || secondBackupName == backupName {
		t.Fatalf("consecutive backups should have unique names, first=%q second=%q metadata=%v", backupName, secondBackupName, secondBackupMetadata)
	}
	if _, err := os.Stat(filepath.FromSlash(secondBackupPath)); err != nil {
		t.Fatalf("second backup should exist: %v", err)
	}
	twoBackupListRec := assertStatus(t, handler, http.MethodGet, "/api/admin/backups", nil, cookie, http.StatusOK)
	if !strings.Contains(twoBackupListRec.Body.String(), backupName) || !strings.Contains(twoBackupListRec.Body.String(), secondBackupName) {
		t.Fatalf("backup list should include both consecutive backups: %s", twoBackupListRec.Body.String())
	}
	assertStatus(t, handler, http.MethodDelete, "/api/admin/backups/"+backupName, nil, cookie, http.StatusOK)
	if _, err := os.Stat(filepath.FromSlash(backupPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted backup still exists or stat failed unexpectedly: %v", err)
	}
	assertStatus(t, handler, http.MethodDelete, "/api/admin/backups/"+secondBackupName, nil, cookie, http.StatusOK)
	if _, err := os.Stat(filepath.FromSlash(secondBackupPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted second backup still exists or stat failed unexpectedly: %v", err)
	}
	assertStatus(t, handler, http.MethodDelete, "/api/admin/backups/not-a-zip.txt", nil, cookie, http.StatusBadRequest)
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, cookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), "backup.delete") {
		t.Fatal("backup delete did not write operation log")
	}

	backupDir := filepath.Join(srv.cfg.DataDir, "backups")
	if err := os.MkdirAll(backupDir, 0o770); err != nil {
		t.Fatalf("create backup dir: %v", err)
	}
	externalBackupContent := "external backup secret"
	externalBackupPath := filepath.Join(t.TempDir(), "external.zip")
	if err := os.WriteFile(externalBackupPath, []byte(externalBackupContent), 0o660); err != nil {
		t.Fatalf("write external backup target: %v", err)
	}
	linkedBackupName := "linked-outside.zip"
	linkedBackupPath := filepath.Join(backupDir, linkedBackupName)
	linkedBackupCreated := true
	if err := os.Symlink(externalBackupPath, linkedBackupPath); err != nil {
		linkedBackupCreated = false
		t.Logf("skip backup symlink assertion: %v", err)
	}
	if linkedBackupCreated {
		symlinkListRec := assertStatus(t, handler, http.MethodGet, "/api/admin/backups", nil, cookie, http.StatusOK)
		if strings.Contains(symlinkListRec.Body.String(), linkedBackupName) {
			t.Fatalf("backup list exposed symlink archive: %s", symlinkListRec.Body.String())
		}
		symlinkDownload := assertStatus(t, handler, http.MethodGet, "/api/admin/backups/"+linkedBackupName+"/download", nil, cookie, http.StatusBadRequest)
		if strings.Contains(symlinkDownload.Body.String(), externalBackupContent) {
			t.Fatalf("backup symlink download leaked external content: %s", symlinkDownload.Body.String())
		}
		symlinkDelete := assertStatus(t, handler, http.MethodDelete, "/api/admin/backups/"+linkedBackupName, nil, cookie, http.StatusBadRequest)
		if strings.Contains(symlinkDelete.Body.String(), externalBackupContent) {
			t.Fatalf("backup symlink delete leaked external content: %s", symlinkDelete.Body.String())
		}
		data, err := os.ReadFile(externalBackupPath)
		if err != nil || string(data) != externalBackupContent {
			t.Fatalf("external backup symlink target changed: content=%q err=%v", string(data), err)
		}
	}
	oldName := "backup-20000101-000000-000000000.zip"
	oldPath := filepath.Join(backupDir, oldName)
	if err := os.WriteFile(oldPath, []byte("old backup"), 0o660); err != nil {
		t.Fatalf("write old backup: %v", err)
	}
	oldTime := time.Now().UTC().AddDate(0, 0, -3)
	if err := os.Chtimes(oldPath, oldTime, oldTime); err != nil {
		t.Fatalf("age old backup: %v", err)
	}
	assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks", map[string]any{
		"name":     "Disabled retention backup",
		"type":     "backup",
		"status":   "disabled",
		"metadata": map[string]any{"retention_days": 1},
	}, cookie, http.StatusCreated)
	disabledRetentionRec := assertStatus(t, handler, http.MethodPost, "/api/admin/backups", nil, cookie, http.StatusCreated)
	if strings.Contains(disabledRetentionRec.Body.String(), `"retention_deleted":1`) {
		t.Fatalf("disabled backup retention task deleted backups: %s", disabledRetentionRec.Body.String())
	}
	if _, err := os.Stat(oldPath); err != nil {
		t.Fatalf("disabled backup retention task should not delete old backup: %v", err)
	}
	assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks", map[string]any{
		"name":     "Retained backup",
		"type":     "backup",
		"status":   "enabled",
		"metadata": map[string]any{"retention_days": 1},
	}, cookie, http.StatusCreated)
	retainedRec := assertStatus(t, handler, http.MethodPost, "/api/admin/backups", nil, cookie, http.StatusCreated)
	if !strings.Contains(retainedRec.Body.String(), `"retention_deleted":1`) {
		t.Fatalf("backup creation did not report retained deletion: %s", retainedRec.Body.String())
	}
	if _, err := os.Stat(oldPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired backup was not deleted: %v", err)
	}
	if linkedBackupCreated {
		if info, err := os.Lstat(linkedBackupPath); err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("backup retention removed or changed symlink archive: info=%v err=%v", info, err)
		}
		data, err := os.ReadFile(externalBackupPath)
		if err != nil || string(data) != externalBackupContent {
			t.Fatalf("backup retention changed external symlink target: content=%q err=%v", string(data), err)
		}
	}
	listRec := assertStatus(t, handler, http.MethodGet, "/api/admin/backups", nil, cookie, http.StatusOK)
	if strings.Contains(listRec.Body.String(), oldName) {
		t.Fatal("expired backup still appears in backup list")
	}
	if linkedBackupCreated && strings.Contains(listRec.Body.String(), linkedBackupName) {
		t.Fatal("symlink backup still appears in backup list")
	}
}

func TestCreateBackupSnapshotRemovesArchiveOnPostCreateFailure(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	backupDir := filepath.Join(srv.cfg.DataDir, "backups")
	beforeFailure, err := filepath.Glob(filepath.Join(backupDir, "*.zip"))
	if err != nil {
		t.Fatalf("glob backups before snapshot failure: %v", err)
	}
	forcedErr := errors.New("forced backup retention failure")
	cleanupCalls := 0
	_, err = srv.createBackupSnapshotWithRetentionCleanup(func(time.Time) (backupRetentionResult, error) {
		cleanupCalls++
		return backupRetentionResult{}, forcedErr
	})
	if !errors.Is(err, forcedErr) {
		t.Fatalf("create backup snapshot error = %v, want %v", err, forcedErr)
	}
	if cleanupCalls != 1 {
		t.Fatalf("retention cleanup calls = %d, want 1", cleanupCalls)
	}
	afterFailure, err := filepath.Glob(filepath.Join(backupDir, "*.zip"))
	if err != nil {
		t.Fatalf("glob backups after snapshot failure: %v", err)
	}
	if len(afterFailure) != len(beforeFailure) {
		t.Fatalf("snapshot post-create failure left an archive: before=%v after=%v", beforeFailure, afterFailure)
	}
}

func TestBackupOperationLogPersistenceFailures(t *testing.T) {
	srv, cookie := newTestServer(t, nil)
	handler := http.Handler(srv)

	createBackupRec := assertStatus(t, handler, http.MethodPost, "/api/admin/backups", nil, cookie, http.StatusCreated)
	var backupMetadata map[string]any
	decodeResponse(t, createBackupRec, &backupMetadata)
	backupPath, _ := backupMetadata["backup_path"].(string)
	backupName := filepath.Base(filepath.FromSlash(backupPath))
	if backupName == "." || backupName == "" {
		t.Fatalf("backup path missing from metadata: %v", backupMetadata)
	}
	backupRaw, err := os.ReadFile(filepath.FromSlash(backupPath))
	if err != nil {
		t.Fatalf("read backup archive: %v", err)
	}
	backupDir := filepath.Join(srv.cfg.DataDir, "backups")
	beforeCreateFailure, err := filepath.Glob(filepath.Join(backupDir, "*.zip"))
	if err != nil {
		t.Fatalf("glob backups before failure: %v", err)
	}

	removeCreateLogBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	createFailureRec := assertStatus(t, handler, http.MethodPost, "/api/admin/backups", nil, cookie, http.StatusInternalServerError)
	removeCreateLogBlocker()
	if !strings.Contains(createFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("backup create operation log failure was not reported: %s", createFailureRec.Body.String())
	}
	afterCreateFailure, err := filepath.Glob(filepath.Join(backupDir, "*.zip"))
	if err != nil {
		t.Fatalf("glob backups after failure: %v", err)
	}
	if len(afterCreateFailure) != len(beforeCreateFailure) {
		t.Fatalf("backup create left an unaudited archive: before=%v after=%v", beforeCreateFailure, afterCreateFailure)
	}

	removeDownloadLogBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	downloadFailureRec := assertStatus(t, handler, http.MethodGet, "/api/admin/backups/"+backupName+"/download", nil, cookie, http.StatusInternalServerError)
	removeDownloadLogBlocker()
	if !strings.Contains(downloadFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("backup download operation log failure was not reported: %s", downloadFailureRec.Body.String())
	}
	if downloadFailureRec.Header().Get("Content-Type") == "application/zip" || bytes.Equal(downloadFailureRec.Body.Bytes(), backupRaw) {
		t.Fatalf("backup download returned archive after operation log failure")
	}

	removeDeleteLogBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	deleteFailureRec := assertStatus(t, handler, http.MethodDelete, "/api/admin/backups/"+backupName, nil, cookie, http.StatusInternalServerError)
	removeDeleteLogBlocker()
	if !strings.Contains(deleteFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("backup delete operation log failure was not reported: %s", deleteFailureRec.Body.String())
	}
	if _, err := os.Stat(filepath.FromSlash(backupPath)); err != nil {
		t.Fatalf("backup delete removed archive before audit log persisted: %v", err)
	}
	restoredBackupRaw, err := os.ReadFile(filepath.FromSlash(backupPath))
	if err != nil {
		t.Fatalf("read restored backup archive after delete log failure: %v", err)
	}
	if !bytes.Equal(restoredBackupRaw, backupRaw) {
		t.Fatal("backup delete restored archive with different content after audit log failure")
	}

	removeDryRunLogBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	dryRunFailureRec := assertMultipartStatus(t, handler, "/api/admin/backups/restore?dry_run=1", nil, backupName, backupRaw, cookie, http.StatusInternalServerError)
	removeDryRunLogBlocker()
	if !strings.Contains(dryRunFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("backup restore dry-run operation log failure was not reported: %s", dryRunFailureRec.Body.String())
	}
	if strings.Contains(dryRunFailureRec.Body.String(), `"valid":true`) {
		t.Fatalf("backup restore dry-run returned success after operation log failure: %s", dryRunFailureRec.Body.String())
	}

	transientAssetRec := assertStatus(t, handler, http.MethodPost, "/api/admin/assets", map[string]any{
		"name":     "restore-rollback-kept",
		"type":     "linux",
		"status":   "active",
		"protocol": "ssh",
		"host":     "127.0.0.50",
		"port":     22,
	}, cookie, http.StatusCreated)
	var transientAsset model.PlatformItem
	decodeResponse(t, transientAssetRec, &transientAsset)
	removeRestoreLogBlocker := blockOperationLogName(t, srv.cfg.Store, "backup.restore")
	restoreFailureRec := assertMultipartStatus(t, handler, "/api/admin/backups/restore", nil, backupName, backupRaw, cookie, http.StatusInternalServerError)
	removeRestoreLogBlocker()
	if !strings.Contains(restoreFailureRec.Body.String(), "persist operation log failed") {
		t.Fatalf("backup restore operation log failure was not reported: %s", restoreFailureRec.Body.String())
	}
	if strings.Contains(restoreFailureRec.Body.String(), `"restored":true`) {
		t.Fatalf("backup restore returned success after operation log failure: %s", restoreFailureRec.Body.String())
	}
	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusOK)
	rollbackCookie := loginRec.Result().Cookies()[0]
	assetsAfterRollbackRec := assertStatus(t, handler, http.MethodGet, "/api/admin/assets", nil, rollbackCookie, http.StatusOK)
	if !strings.Contains(assetsAfterRollbackRec.Body.String(), transientAsset.ID) {
		t.Fatalf("backup restore was not rolled back after operation log failure: %s", assetsAfterRollbackRec.Body.String())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "operation.log.persist_failed") {
		t.Fatal("operation log persistence failure was not written to core audit logs")
	}
}

func TestScheduledTaskRunners(t *testing.T) {
	handler, cookie := newTestHandler(t)
	srv := handler.(*Server)

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
	backupDir := filepath.Join(srv.cfg.DataDir, "backups")
	beforeBackupLogFailure, err := filepath.Glob(filepath.Join(backupDir, "*.zip"))
	if err != nil {
		t.Fatalf("glob backups before scheduled task log failure: %v", err)
	}
	removeBackupTaskLogBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	backupLogFailureRec := assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks/"+backupTask.ID+"/run", nil, cookie, http.StatusInternalServerError)
	removeBackupTaskLogBlocker()
	if !strings.Contains(backupLogFailureRec.Body.String(), "persist scheduled task log failed") {
		t.Fatalf("scheduled backup task log failure was not reported: %s", backupLogFailureRec.Body.String())
	}
	afterBackupLogFailure, err := filepath.Glob(filepath.Join(backupDir, "*.zip"))
	if err != nil {
		t.Fatalf("glob backups after scheduled task log failure: %v", err)
	}
	if len(afterBackupLogFailure) != len(beforeBackupLogFailure) {
		t.Fatalf("scheduled backup task left unaudited archive: before=%v after=%v", beforeBackupLogFailure, afterBackupLogFailure)
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "scheduled_task.log.persist_failed") {
		t.Fatal("scheduled task log persistence failure was not written to core audit logs")
	}

	beforeStateFailureLogs := len(scheduledTaskLogsForTest(t, srv, backupTask.ID))
	removeBackupTaskStateBlocker := blockPlatformItemSave(t, srv.cfg.Store, "scheduled_tasks", backupTask.ID)
	backupStateFailureRec := assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks/"+backupTask.ID+"/run", nil, cookie, http.StatusInternalServerError)
	removeBackupTaskStateBlocker()
	if !strings.Contains(backupStateFailureRec.Body.String(), "persist scheduled task state failed") {
		t.Fatalf("scheduled backup task state failure was not reported: %s", backupStateFailureRec.Body.String())
	}
	afterStateFailureLogs := scheduledTaskLogsForTest(t, srv, backupTask.ID)
	if len(afterStateFailureLogs) != beforeStateFailureLogs+1 {
		t.Fatalf("scheduled task state failure should keep the execution log: before=%d after=%#v", beforeStateFailureLogs, afterStateFailureLogs)
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "scheduled_task.state.persist_failed") {
		t.Fatal("scheduled task state persistence failure was not written to core audit logs")
	}

	disabledTaskRec := assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks", map[string]any{
		"name":   "Disabled manual backup",
		"type":   "backup",
		"status": "disabled",
	}, cookie, http.StatusCreated)
	var disabledTask model.PlatformItem
	decodeResponse(t, disabledTaskRec, &disabledTask)
	assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks/"+disabledTask.ID+"/run", nil, cookie, http.StatusConflict)
	if logs := scheduledTaskLogsForTest(t, srv, disabledTask.ID); len(logs) != 0 {
		t.Fatalf("disabled manual scheduled task should not run, got logs: %#v", logs)
	}
	unsupportedTaskRec := assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks", map[string]any{
		"name":   "Unsupported scheduled task",
		"type":   "custom-runner",
		"status": "enabled",
	}, cookie, http.StatusCreated)
	var unsupportedTask model.PlatformItem
	decodeResponse(t, unsupportedTaskRec, &unsupportedTask)
	unsupportedRunRec := assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks/"+unsupportedTask.ID+"/run", nil, cookie, http.StatusUnprocessableEntity)
	if !strings.Contains(unsupportedRunRec.Body.String(), "scheduled task type is not supported") || !strings.Contains(unsupportedRunRec.Body.String(), `"status":"failed"`) || !strings.Contains(unsupportedRunRec.Body.String(), `"supported":false`) {
		t.Fatalf("unsupported scheduled task did not return failed log context: %s", unsupportedRunRec.Body.String())
	}
	unsupportedLogs := scheduledTaskLogsForTest(t, srv, unsupportedTask.ID)
	if len(unsupportedLogs) != 1 || unsupportedLogs[0].Status != "failed" || firstMetadataString(unsupportedLogs[0].Metadata, "error") == "" {
		t.Fatalf("unsupported scheduled task did not persist failed log: %#v", unsupportedLogs)
	}
	storedUnsupportedTask, ok, err := srv.cfg.Store.GetPlatformItem("scheduled_tasks", unsupportedTask.ID)
	if err != nil || !ok {
		t.Fatalf("load unsupported scheduled task: ok=%v err=%v", ok, err)
	}
	if firstMetadataString(storedUnsupportedTask.Metadata, "last_run_status") != "failed" || firstMetadataString(storedUnsupportedTask.Metadata, "last_run_error") == "" {
		t.Fatalf("unsupported scheduled task did not persist failed metadata: %#v", storedUnsupportedTask.Metadata)
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
	oldSession, err := srv.cfg.Store.CreateSession(model.ConnectionSession{
		Protocol:     model.ProtocolRDP,
		ServerID:     "old-rdp-asset",
		CredentialID: "old-rdp-credential",
		UserID:       "admin",
		ClientIP:     "198.51.100.10",
	})
	if err != nil {
		t.Fatalf("create old session: %v", err)
	}
	oldRecordingPath := filepath.Join(srv.cfg.DataDir, "recordings", oldSession.ID)
	if err := os.MkdirAll(oldRecordingPath, 0o770); err != nil {
		t.Fatalf("create old recording dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(oldRecordingPath, "recording.guac"), []byte("expired frames"), 0o660); err != nil {
		t.Fatalf("write old recording: %v", err)
	}
	oldEndedAt := time.Now().UTC().AddDate(0, 0, -2)
	oldStartedAt := oldEndedAt.Add(-time.Hour)
	if _, err := srv.cfg.Store.UpdateSession(oldSession.ID, func(session *model.ConnectionSession) {
		session.Status = model.SessionClosed
		session.StartedAt = oldStartedAt
		session.EndedAt = &oldEndedAt
		session.RecordingPath = oldRecordingPath
	}); err != nil {
		t.Fatalf("close old session: %v", err)
	}
	activeSession, err := srv.cfg.Store.CreateSession(model.ConnectionSession{
		Protocol:     model.ProtocolSSH,
		ServerID:     "active-ssh-asset",
		CredentialID: "active-ssh-credential",
		UserID:       "admin",
		ClientIP:     "198.51.100.11",
	})
	if err != nil {
		t.Fatalf("create active session: %v", err)
	}
	if _, err := srv.cfg.Store.UpdateSession(activeSession.ID, func(session *model.ConnectionSession) {
		session.Status = model.SessionActive
		session.StartedAt = oldStartedAt
	}); err != nil {
		t.Fatalf("activate retained session: %v", err)
	}
	cleanupTaskRec := assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks", map[string]any{
		"name":     "Cleanup logs",
		"type":     "log-cleanup",
		"status":   "enabled",
		"metadata": map[string]any{"retention_days": 0},
	}, cookie, http.StatusCreated)
	var cleanupTask model.PlatformItem
	decodeResponse(t, cleanupTaskRec, &cleanupTask)

	removeCleanupLogBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	blockedCleanupRec := assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks/"+cleanupTask.ID+"/run", nil, cookie, http.StatusInternalServerError)
	removeCleanupLogBlocker()
	if !strings.Contains(blockedCleanupRec.Body.String(), "persist scheduled task log failed") {
		t.Fatalf("cleanup task log persistence failure was not reported: %s", blockedCleanupRec.Body.String())
	}
	blockedAccessLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/access-logs", nil, cookie, http.StatusOK)
	if !strings.Contains(blockedAccessLogsRec.Body.String(), oldAccess.ID) {
		t.Fatalf("cleanup task removed access log before scheduled log persisted: %s", blockedAccessLogsRec.Body.String())
	}
	blockedSQLLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/sql-logs", nil, cookie, http.StatusOK)
	if !strings.Contains(blockedSQLLogsRec.Body.String(), oldSQL.ID) {
		t.Fatalf("cleanup task removed sql log before scheduled log persisted: %s", blockedSQLLogsRec.Body.String())
	}
	removeCleanupFinalizeBlocker := blockPlatformCollectionSavePayloadFragment(t, srv.cfg.Store, "operation_logs", `"description":"log cleanup completed"`)
	finalizeCleanupRec := assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks/"+cleanupTask.ID+"/run", nil, cookie, http.StatusInternalServerError)
	removeCleanupFinalizeBlocker()
	if !strings.Contains(finalizeCleanupRec.Body.String(), "persist scheduled task log failed") {
		t.Fatalf("cleanup task final log persistence failure was not reported: %s", finalizeCleanupRec.Body.String())
	}
	finalizeAccessLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/access-logs", nil, cookie, http.StatusOK)
	if !strings.Contains(finalizeAccessLogsRec.Body.String(), oldAccess.ID) {
		t.Fatalf("cleanup task did not restore access log after final log failure: %s", finalizeAccessLogsRec.Body.String())
	}
	finalizeSQLLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/sql-logs", nil, cookie, http.StatusOK)
	if !strings.Contains(finalizeSQLLogsRec.Body.String(), oldSQL.ID) {
		t.Fatalf("cleanup task did not restore sql log after final log failure: %s", finalizeSQLLogsRec.Body.String())
	}
	if _, ok := srv.cfg.Store.GetSession(oldSession.ID); !ok {
		t.Fatal("cleanup task did not restore expired connection session after final log failure")
	}
	if info, err := os.Stat(oldRecordingPath); err != nil || !info.IsDir() {
		t.Fatalf("cleanup task did not restore expired recording directory after final log failure: info=%#v err=%v", info, err)
	}
	if data, err := os.ReadFile(filepath.Join(oldRecordingPath, "recording.guac")); err != nil || string(data) != "expired frames" {
		t.Fatalf("cleanup task did not restore recording content after final log failure: data=%q err=%v", string(data), err)
	}

	cleanupRunRec := assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks/"+cleanupTask.ID+"/run", nil, cookie, http.StatusAccepted)
	if !strings.Contains(cleanupRunRec.Body.String(), "deleted_count") {
		t.Fatal("cleanup task did not report deleted count")
	}
	var cleanupLog model.PlatformItem
	decodeResponse(t, cleanupRunRec, &cleanupLog)
	cleanupLogs := scheduledTaskLogsForTest(t, srv, cleanupTask.ID)
	if len(cleanupLogs) != 1 || cleanupLogs[0].ID != cleanupLog.ID || cleanupLogs[0].Status != "success" {
		t.Fatalf("cleanup task should preserve its own completed scheduled log, got %#v", cleanupLogs)
	}
	deleted, _ := cleanupLog.Metadata["deleted"].(map[string]any)
	if got, ok := metadataInt(deleted["connection_sessions"]); !ok || got != 1 {
		t.Fatalf("cleanup deleted connection_sessions = %v/%v, want 1 in %#v", got, ok, cleanupLog.Metadata)
	}
	if got, ok := metadataInt(cleanupLog.Metadata["recordings_deleted"]); !ok || got != 1 {
		t.Fatalf("cleanup recordings_deleted = %v/%v, want 1 in %#v", got, ok, cleanupLog.Metadata)
	}
	accessLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/access-logs", nil, cookie, http.StatusOK)
	if strings.Contains(accessLogsRec.Body.String(), oldAccess.ID) {
		t.Fatal("log cleanup did not delete old access log")
	}
	sqlLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/sql-logs", nil, cookie, http.StatusOK)
	if strings.Contains(sqlLogsRec.Body.String(), oldSQL.ID) {
		t.Fatal("log cleanup did not delete old sql log")
	}
	if _, ok := srv.cfg.Store.GetSession(oldSession.ID); ok {
		t.Fatal("log cleanup did not delete expired closed connection session")
	}
	if _, ok := srv.cfg.Store.GetSession(activeSession.ID); !ok {
		t.Fatal("log cleanup deleted active connection session")
	}
	if _, err := os.Stat(oldRecordingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("log cleanup did not delete expired recording directory: %v", err)
	}
	offlineSessionsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/offline-sessions", nil, cookie, http.StatusOK)
	if strings.Contains(offlineSessionsRec.Body.String(), oldSession.ID) {
		t.Fatal("log cleanup did not delete expired offline session index")
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
	headlessUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer headlessUpstream.Close()
	headlessWebRec := assertStatus(t, handler, http.MethodPost, "/api/admin/websites", map[string]any{
		"name":     "status web without head",
		"type":     "http",
		"status":   "enabled",
		"metadata": map[string]any{"target_url": headlessUpstream.URL},
	}, cookie, http.StatusCreated)
	var headlessWebAsset model.PlatformItem
	decodeResponse(t, headlessWebRec, &headlessWebAsset)
	legacyListener, closeLegacyListener := startAppTestTCPListener(t)
	defer closeLegacyListener()
	legacyHost, legacyPortText, err := net.SplitHostPort(legacyListener.Addr().String())
	if err != nil {
		t.Fatalf("split legacy listener address: %v", err)
	}
	legacyPort, err := strconv.Atoi(legacyPortText)
	if err != nil {
		t.Fatalf("parse legacy listener port: %v", err)
	}
	legacyServer, err := srv.cfg.Store.CreateServer(model.Server{
		Name:    "legacy status server",
		Host:    legacyHost,
		OS:      model.ServerOSLinux,
		SSHPort: legacyPort,
	})
	if err != nil {
		t.Fatalf("create legacy core server: %v", err)
	}
	if err := srv.cfg.Store.DeletePlatformItem("assets", legacyServer.ID); err != nil {
		t.Fatalf("remove writable platform asset mirror: %v", err)
	}
	missingSQLitePath := filepath.Join(srv.cfg.DataDir, "database-assets", "status-missing.db")
	databaseStatusRec := assertStatus(t, handler, http.MethodPost, "/api/admin/database-assets", map[string]any{
		"name":     "status missing sqlite",
		"type":     "sqlite",
		"status":   "enabled",
		"protocol": "database",
		"metadata": map[string]any{"sqlite_path": "status-missing.db"},
	}, cookie, http.StatusCreated)
	var databaseStatusAsset model.PlatformItem
	decodeResponse(t, databaseStatusRec, &databaseStatusAsset)
	existingSQLitePath := filepath.Join(srv.cfg.DataDir, "database-assets", "status-existing.db")
	if err := os.MkdirAll(filepath.Dir(existingSQLitePath), 0o770); err != nil {
		t.Fatalf("create database asset directory: %v", err)
	}
	existingSQLiteDB, err := sql.Open("sqlite", existingSQLitePath)
	if err != nil {
		t.Fatalf("open existing sqlite status fixture: %v", err)
	}
	if _, err := existingSQLiteDB.Exec("CREATE TABLE status_check(id INTEGER PRIMARY KEY)"); err != nil {
		_ = existingSQLiteDB.Close()
		t.Fatalf("prepare existing sqlite status fixture: %v", err)
	}
	if err := existingSQLiteDB.Close(); err != nil {
		t.Fatalf("close existing sqlite status fixture: %v", err)
	}
	existingDatabaseStatusRec := assertStatus(t, handler, http.MethodPost, "/api/admin/database-assets", map[string]any{
		"name":     "status existing sqlite",
		"type":     "sqlite",
		"status":   "enabled",
		"protocol": "database",
		"metadata": map[string]any{"sqlite_path": "status-existing.db"},
	}, cookie, http.StatusCreated)
	var existingDatabaseStatusAsset model.PlatformItem
	decodeResponse(t, existingDatabaseStatusRec, &existingDatabaseStatusAsset)
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
	if !strings.Contains(statusRunRec.Body.String(), legacyServer.ID) || !strings.Contains(statusRunRec.Body.String(), `"source":"legacy_server"`) || !strings.Contains(statusRunRec.Body.String(), `"persisted":false`) {
		t.Fatalf("asset status task did not include read-only legacy asset result: %s", statusRunRec.Body.String())
	}
	if !strings.Contains(statusRunRec.Body.String(), databaseStatusAsset.ID) || !strings.Contains(statusRunRec.Body.String(), "sqlite database file not found") {
		t.Fatalf("asset status task did not report missing sqlite asset without creation: %s", statusRunRec.Body.String())
	}
	if _, err := os.Stat(missingSQLitePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("asset status task created missing sqlite database file: %v", err)
	}
	if !strings.Contains(statusRunRec.Body.String(), existingDatabaseStatusAsset.ID) || !strings.Contains(statusRunRec.Body.String(), "sqlite reachable") {
		t.Fatalf("asset status task did not report existing sqlite asset as reachable: %s", statusRunRec.Body.String())
	}
	webListRec := assertStatus(t, handler, http.MethodGet, "/api/admin/websites", nil, cookie, http.StatusOK)
	if !strings.Contains(webListRec.Body.String(), webAsset.ID) || !strings.Contains(webListRec.Body.String(), "last_check_status") {
		t.Fatal("asset status task did not update web asset check metadata")
	}
	storedHeadlessWebAsset, ok, err := srv.cfg.Store.GetPlatformItem("web_assets", headlessWebAsset.ID)
	if err != nil || !ok {
		t.Fatalf("load headless web asset after status task: ok=%v err=%v", ok, err)
	}
	if storedHeadlessWebAsset.Status != "active" || firstMetadataString(storedHeadlessWebAsset.Metadata, "last_check_status") != "active" {
		t.Fatalf("asset status task did not fall back to GET after HEAD rejection: %#v", storedHeadlessWebAsset)
	}
	blockedStatusUpstreamHit := false
	blockedStatusUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		blockedStatusUpstreamHit = true
		_, _ = w.Write([]byte("ok"))
	}))
	defer blockedStatusUpstream.Close()
	blockedStatusWebRec := assertStatus(t, handler, http.MethodPost, "/api/admin/websites", map[string]any{
		"name":     "blocked status web",
		"type":     "http",
		"status":   "enabled",
		"metadata": map[string]any{"target_url": blockedStatusUpstream.URL},
	}, cookie, http.StatusCreated)
	var blockedStatusWeb model.PlatformItem
	decodeResponse(t, blockedStatusWebRec, &blockedStatusWeb)
	removeStatusLogBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	blockedStatusRunRec := assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks/"+statusTask.ID+"/run", nil, cookie, http.StatusInternalServerError)
	removeStatusLogBlocker()
	if !strings.Contains(blockedStatusRunRec.Body.String(), "persist scheduled task log failed") {
		t.Fatalf("asset status scheduled log failure was not reported: %s", blockedStatusRunRec.Body.String())
	}
	if blockedStatusUpstreamHit {
		t.Fatal("asset status task contacted upstream before scheduled task log was persisted")
	}
	storedBlockedStatusWeb, ok, err := srv.cfg.Store.GetPlatformItem("web_assets", blockedStatusWeb.ID)
	if err != nil || !ok {
		t.Fatalf("load blocked status web asset: ok=%v err=%v", ok, err)
	}
	if storedBlockedStatusWeb.Status != "enabled" || storedBlockedStatusWeb.Metadata["last_check_status"] != nil {
		t.Fatalf("asset status task changed asset before scheduled task log was persisted: %#v", storedBlockedStatusWeb)
	}
	finalizeStatusUpstreamHit := false
	finalizeStatusUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		finalizeStatusUpstreamHit = true
		_, _ = w.Write([]byte("ok"))
	}))
	defer finalizeStatusUpstream.Close()
	finalizeStatusWebRec := assertStatus(t, handler, http.MethodPost, "/api/admin/websites", map[string]any{
		"name":     "finalize status web",
		"type":     "http",
		"status":   "enabled",
		"metadata": map[string]any{"target_url": finalizeStatusUpstream.URL},
	}, cookie, http.StatusCreated)
	var finalizeStatusWeb model.PlatformItem
	decodeResponse(t, finalizeStatusWebRec, &finalizeStatusWeb)
	finalizeStatusBefore, ok, err := srv.cfg.Store.GetPlatformItem("web_assets", finalizeStatusWeb.ID)
	if err != nil || !ok {
		t.Fatalf("load finalize status web before task: ok=%v err=%v", ok, err)
	}
	removeStatusFinalizeBlocker := blockPlatformItemCollectionStatusUpdate(t, srv.cfg.Store, "operation_logs", "success")
	finalizeStatusRunRec := assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks/"+statusTask.ID+"/run", nil, cookie, http.StatusInternalServerError)
	removeStatusFinalizeBlocker()
	if !strings.Contains(finalizeStatusRunRec.Body.String(), "persist scheduled task log failed") {
		t.Fatalf("asset status final log failure was not reported: %s", finalizeStatusRunRec.Body.String())
	}
	if !finalizeStatusUpstreamHit {
		t.Fatal("asset status task did not execute before final log update failure")
	}
	finalizeStatusAfter, ok, err := srv.cfg.Store.GetPlatformItem("web_assets", finalizeStatusWeb.ID)
	if err != nil || !ok {
		t.Fatalf("load finalize status web after rollback: ok=%v err=%v", ok, err)
	}
	if finalizeStatusAfter.Status != finalizeStatusBefore.Status || finalizeStatusAfter.Metadata["last_check_status"] != finalizeStatusBefore.Metadata["last_check_status"] {
		t.Fatalf("asset status task did not roll back asset after final log failure: before=%#v after=%#v", finalizeStatusBefore, finalizeStatusAfter)
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
	disabledCertRec := assertStatus(t, handler, http.MethodPost, "/api/admin/certificates/self-signed", map[string]any{
		"name":   "disabled-renew-cert",
		"domain": "disabled-renew.example.test",
		"days":   1,
	}, cookie, http.StatusCreated)
	var disabledCert model.PlatformItem
	decodeResponse(t, disabledCertRec, &disabledCert)
	disabledCert.Metadata["expires_at"] = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	assertStatus(t, handler, http.MethodPatch, "/api/admin/certificates/"+disabledCert.ID, map[string]any{
		"name":     disabledCert.Name,
		"status":   "disabled",
		"metadata": disabledCert.Metadata,
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
	if strings.Contains(renewRunRec.Body.String(), disabledCert.ID) {
		t.Fatal("certificate renewal task renewed a disabled certificate")
	}
	storedDisabledCert, ok, err := srv.cfg.Store.GetPlatformItem("certificates", disabledCert.ID)
	if err != nil || !ok {
		t.Fatalf("load disabled certificate after renewal: ok=%v err=%v", ok, err)
	}
	if storedDisabledCert.Status != "disabled" || storedDisabledCert.Metadata["renewed_at"] != nil {
		t.Fatalf("disabled certificate was changed by renewal task: %#v", storedDisabledCert)
	}
	blockedCertRec := assertStatus(t, handler, http.MethodPost, "/api/admin/certificates/self-signed", map[string]any{
		"name":   "blocked-renew-cert",
		"domain": "blocked-renew.example.test",
		"days":   1,
	}, cookie, http.StatusCreated)
	var blockedCert model.PlatformItem
	decodeResponse(t, blockedCertRec, &blockedCert)
	blockedCert.Metadata["expires_at"] = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	assertStatus(t, handler, http.MethodPatch, "/api/admin/certificates/"+blockedCert.ID, map[string]any{
		"name":     blockedCert.Name,
		"status":   blockedCert.Status,
		"metadata": blockedCert.Metadata,
	}, cookie, http.StatusOK)
	blockedCertBefore, ok, err := srv.cfg.Store.GetPlatformItem("certificates", blockedCert.ID)
	if err != nil || !ok {
		t.Fatalf("load blocked certificate before renewal failure: ok=%v err=%v", ok, err)
	}
	removeRenewLogBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	blockedRenewRunRec := assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks/"+renewTask.ID+"/run", nil, cookie, http.StatusInternalServerError)
	removeRenewLogBlocker()
	if !strings.Contains(blockedRenewRunRec.Body.String(), "persist scheduled task log failed") {
		t.Fatalf("certificate renewal scheduled log failure was not reported: %s", blockedRenewRunRec.Body.String())
	}
	blockedCertAfter, ok, err := srv.cfg.Store.GetPlatformItem("certificates", blockedCert.ID)
	if err != nil || !ok {
		t.Fatalf("load blocked certificate after renewal failure: ok=%v err=%v", ok, err)
	}
	if blockedCertAfter.Status != blockedCertBefore.Status || fmt.Sprint(blockedCertAfter.Metadata["expires_at"]) != fmt.Sprint(blockedCertBefore.Metadata["expires_at"]) || blockedCertAfter.Metadata["renewed_at"] != nil {
		t.Fatalf("certificate renewal changed certificate before scheduled task log was persisted: before=%#v after=%#v", blockedCertBefore, blockedCertAfter)
	}
	finalizeCertRec := assertStatus(t, handler, http.MethodPost, "/api/admin/certificates/self-signed", map[string]any{
		"name":   "finalize-renew-cert",
		"domain": "finalize-renew.example.test",
		"days":   1,
	}, cookie, http.StatusCreated)
	var finalizeCert model.PlatformItem
	decodeResponse(t, finalizeCertRec, &finalizeCert)
	finalizeCert.Metadata["expires_at"] = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	assertStatus(t, handler, http.MethodPatch, "/api/admin/certificates/"+finalizeCert.ID, map[string]any{
		"name":     finalizeCert.Name,
		"status":   finalizeCert.Status,
		"metadata": finalizeCert.Metadata,
	}, cookie, http.StatusOK)
	finalizeCertBefore, ok, err := srv.cfg.Store.GetPlatformItem("certificates", finalizeCert.ID)
	if err != nil || !ok {
		t.Fatalf("load finalize certificate before renewal failure: ok=%v err=%v", ok, err)
	}
	removeRenewFinalizeBlocker := blockPlatformItemCollectionStatusUpdate(t, srv.cfg.Store, "operation_logs", "success")
	finalizeRenewRunRec := assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks/"+renewTask.ID+"/run", nil, cookie, http.StatusInternalServerError)
	removeRenewFinalizeBlocker()
	if !strings.Contains(finalizeRenewRunRec.Body.String(), "persist scheduled task log failed") {
		t.Fatalf("certificate renewal final log failure was not reported: %s", finalizeRenewRunRec.Body.String())
	}
	finalizeCertAfter, ok, err := srv.cfg.Store.GetPlatformItem("certificates", finalizeCert.ID)
	if err != nil || !ok {
		t.Fatalf("load finalize certificate after rollback: ok=%v err=%v", ok, err)
	}
	if finalizeCertAfter.Status != finalizeCertBefore.Status || fmt.Sprint(finalizeCertAfter.Metadata["expires_at"]) != fmt.Sprint(finalizeCertBefore.Metadata["expires_at"]) || finalizeCertAfter.Metadata["renewed_at"] != nil {
		t.Fatalf("certificate renewal did not roll back certificate after final log failure: before=%#v after=%#v", finalizeCertBefore, finalizeCertAfter)
	}
}

func TestScheduledTaskScheduleParsing(t *testing.T) {
	now := time.Date(2026, 7, 6, 12, 4, 30, 0, time.UTC)
	next, ok := nextCronRun("0 0/10 * * * ?", now)
	if !ok {
		t.Fatal("expected every-ten-minutes cron to parse")
	}
	want := time.Date(2026, 7, 6, 12, 10, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("next cron run = %s, want %s", next, want)
	}

	next, ok = nextCronRun("*/20 * * * * ?", now)
	if !ok {
		t.Fatal("expected seconds-step cron to parse")
	}
	want = time.Date(2026, 7, 6, 12, 4, 40, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("seconds-step cron run = %s, want %s", next, want)
	}

	next, ok = nextCronRun("*/15 * * * *", now)
	if !ok {
		t.Fatal("expected five-field unix cron to parse")
	}
	want = time.Date(2026, 7, 6, 12, 15, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("five-field cron run = %s, want %s", next, want)
	}

	next, ok = nextCronRun("0 0-30/15 9 * * ?", time.Date(2026, 7, 6, 9, 0, 1, 0, time.UTC))
	if !ok {
		t.Fatal("expected range-step cron to parse")
	}
	want = time.Date(2026, 7, 6, 9, 15, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("range-step cron run = %s, want %s", next, want)
	}

	next, ok = nextCronRun("0 0 2 * * ?", time.Date(2026, 7, 6, 2, 0, 1, 0, time.UTC))
	if !ok {
		t.Fatal("expected daily cron to parse")
	}
	want = time.Date(2026, 7, 7, 2, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("daily cron run = %s, want %s", next, want)
	}

	next, ok = nextCronRun("0 0 0 1 * ?", now)
	if !ok {
		t.Fatal("expected monthly cron to parse")
	}
	want = time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("monthly cron run = %s, want %s", next, want)
	}

	next, ok = nextCronRun("0 0 0 1 9 ?", now)
	if !ok {
		t.Fatal("expected month-filtered cron to parse")
	}
	want = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("month-filtered cron run = %s, want %s", next, want)
	}

	next, ok = nextCronRun("0 0 0 1 JAN ?", now)
	if !ok {
		t.Fatal("expected named-month cron to parse")
	}
	want = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("named-month cron run = %s, want %s", next, want)
	}

	next, ok = nextCronRun("0 30 9 ? * 1", time.Date(2026, 7, 7, 8, 0, 0, 0, time.UTC))
	if !ok {
		t.Fatal("expected weekday cron to parse")
	}
	want = time.Date(2026, 7, 13, 9, 30, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("weekday cron run = %s, want %s", next, want)
	}

	next, ok = nextCronRun("0 0 9 ? * MON-FRI", time.Date(2026, 7, 10, 9, 1, 0, 0, time.UTC))
	if !ok {
		t.Fatal("expected named-weekday range cron to parse")
	}
	want = time.Date(2026, 7, 13, 9, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("named-weekday cron run = %s, want %s", next, want)
	}

	next, ok = nextCronRun("0 0 8 ? * 7", time.Date(2026, 7, 4, 9, 0, 0, 0, time.UTC))
	if !ok {
		t.Fatal("expected sunday cron to parse")
	}
	want = time.Date(2026, 7, 5, 8, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("sunday cron run = %s, want %s", next, want)
	}

	if _, ok := nextCronRun("0 0 0 32 * ?", now); ok {
		t.Fatal("invalid day-of-month cron unexpectedly parsed")
	}
	if _, ok := nextCronRun("0 0 9 ? * FUNDAY", now); ok {
		t.Fatal("invalid day-of-week cron unexpectedly parsed")
	}

	intervalNext, ok := nextScheduledTaskRunAfter(model.PlatformItem{Metadata: map[string]any{"interval_seconds": 30}}, now)
	if !ok {
		t.Fatal("expected interval schedule to parse")
	}
	if want := now.Add(30 * time.Second); !intervalNext.Equal(want) {
		t.Fatalf("interval next run = %s, want %s", intervalNext, want)
	}
}

func TestScheduledTaskSchedulerRunsEnabledTasks(t *testing.T) {
	handler, cookie := newTestHandler(t)
	srv := handler.(*Server)
	due := time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)

	taskRec := assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks", map[string]any{
		"name":   "Scheduled backup",
		"type":   "backup",
		"status": "enabled",
		"metadata": map[string]any{
			"interval_ms": 5000,
			"next_run_at": due,
		},
	}, cookie, http.StatusCreated)
	var task model.PlatformItem
	decodeResponse(t, taskRec, &task)

	disabledRec := assertStatus(t, handler, http.MethodPost, "/api/admin/scheduled-tasks", map[string]any{
		"name":   "Disabled scheduled backup",
		"type":   "backup",
		"status": "disabled",
		"metadata": map[string]any{
			"interval_ms": 10,
			"next_run_at": due,
		},
	}, cookie, http.StatusCreated)
	var disabled model.PlatformItem
	decodeResponse(t, disabledRec, &disabled)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scheduler := srv.StartScheduler(ctx, SchedulerConfig{
		PollInterval: 10 * time.Millisecond,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	defer scheduler.Stop()

	waitForCondition(t, 2*time.Second, func() bool {
		if len(scheduledTaskLogsForTest(t, srv, task.ID)) == 0 {
			return false
		}
		savedTask, ok, err := srv.cfg.Store.GetPlatformItem("scheduled_tasks", task.ID)
		return err == nil && ok && firstMetadataString(savedTask.Metadata, "last_run_status") == "success"
	})
	logs := scheduledTaskLogsForTest(t, srv, task.ID)
	if len(logs) == 0 {
		t.Fatal("scheduler did not write operation log")
	}
	log := logs[0]
	if log.OwnerID != "system" || log.Status != "success" || firstMetadataString(log.Metadata, "trigger") != "scheduled" {
		t.Fatalf("unexpected scheduled task log: %#v", log)
	}
	backupPath := firstMetadataString(log.Metadata, "backup_path")
	if backupPath == "" {
		t.Fatalf("scheduled backup log missing backup path: %#v", log.Metadata)
	}
	if info, err := os.Stat(filepath.FromSlash(backupPath)); err != nil || info.Size() == 0 {
		t.Fatalf("scheduled backup file missing or empty: %v", err)
	}
	savedTask, ok, err := srv.cfg.Store.GetPlatformItem("scheduled_tasks", task.ID)
	if err != nil || !ok {
		t.Fatalf("load scheduled task: ok=%v err=%v", ok, err)
	}
	if firstMetadataString(savedTask.Metadata, "last_run_status") != "success" || firstMetadataString(savedTask.Metadata, "last_trigger") != "scheduled" {
		t.Fatalf("scheduled task metadata was not updated: %#v", savedTask.Metadata)
	}
	if _, ok := metadataTime(savedTask.Metadata["next_run_at"]); !ok {
		t.Fatalf("scheduled task next_run_at was not updated: %#v", savedTask.Metadata)
	}

	time.Sleep(80 * time.Millisecond)
	if logs := scheduledTaskLogsForTest(t, srv, disabled.ID); len(logs) != 0 {
		t.Fatalf("disabled scheduled task should not run, got logs: %#v", logs)
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
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": `windows\style.txt`, "content": "slash"}, userCookie, http.StatusCreated)
	uploadRec := assertMultipartStatus(t, handler, "/api/admin/storages/"+storage.ID+"/files-upload", map[string]string{"path": "docs"}, `C:\Users\ops\Downloads\uploaded.txt`, []byte("uploaded"), userCookie, http.StatusCreated)
	if !strings.Contains(uploadRec.Body.String(), `"name":"uploaded.txt"`) || strings.Contains(uploadRec.Body.String(), `C:\Users\ops`) {
		t.Fatalf("storage upload response did not sanitize filename: %s", uploadRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-copy", map[string]any{"path": "docs/a.txt", "destination": "docs/b.txt"}, userCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-rename", map[string]any{"path": "docs/b.txt", "destination": "docs/c.txt"}, userCookie, http.StatusOK)
	uploadDownloadRec := assertStatus(t, handler, http.MethodGet, "/api/admin/storages/"+storage.ID+"/files-download?path=docs/uploaded.txt", nil, userCookie, http.StatusOK)
	if strings.TrimSpace(uploadDownloadRec.Body.String()) != "uploaded" {
		t.Fatalf("uploaded file body = %q, want uploaded", uploadDownloadRec.Body.String())
	}
	windowsPathDownloadRec := assertStatus(t, handler, http.MethodGet, "/api/admin/storages/"+storage.ID+"/files-download?path=windows/style.txt", nil, userCookie, http.StatusOK)
	if strings.TrimSpace(windowsPathDownloadRec.Body.String()) != "slash" {
		t.Fatalf("backslash-normalized file body = %q, want slash", windowsPathDownloadRec.Body.String())
	}
	downloadRec := assertStatus(t, handler, http.MethodGet, "/api/admin/storages/"+storage.ID+"/files-download?path=docs/c.txt", nil, userCookie, http.StatusOK)
	if strings.TrimSpace(downloadRec.Body.String()) != "alpha" {
		t.Fatalf("download body = %q, want alpha", downloadRec.Body.String())
	}
	if contentDisposition := downloadRec.Header().Get("Content-Disposition"); !strings.Contains(contentDisposition, `filename="c.txt"`) {
		t.Fatalf("storage download missing attachment filename: %s", contentDisposition)
	}
	assertStatus(t, handler, http.MethodDelete, "/api/admin/storages/"+storage.ID+"/files?path=docs/c.txt", nil, userCookie, http.StatusForbidden)
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/file-logs", nil, userCookie, http.StatusOK)
	logsBody := logsRec.Body.String()
	for _, want := range []string{"copy", "rename", "download", "denied"} {
		if !strings.Contains(logsBody, want) {
			t.Fatalf("file logs did not include %q operation", want)
		}
	}
	for _, want := range []string{
		`"source_path":"docs/a.txt"`,
		`"destination_path":"docs/b.txt"`,
		`"source_path":"docs/b.txt"`,
		`"destination_path":"docs/c.txt"`,
		`"filename":"uploaded.txt"`,
		`"path":"docs/uploaded.txt"`,
		`"path":"docs/c.txt"`,
		`"size":5`,
		`"storage_id":"` + storage.ID + `"`,
		`"client_ip":"192.0.2.1"`,
		`"reason":"authorization_strategy"`,
	} {
		if !strings.Contains(logsBody, want) {
			t.Fatalf("file logs missing audit metadata %s: %s", want, logsBody)
		}
	}
	if strings.Contains(logsBody, `C:\Users\ops`) || strings.Contains(logsBody, `Downloads\`) {
		t.Fatalf("storage upload audit leaked client path: %s", logsBody)
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

	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "open/rename-source.txt", "content": "rename"}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/strategies", map[string]any{
		"name":        "deny strategy-drive paste into safe",
		"type":        "file",
		"status":      "enabled",
		"target_id":   storage.ID,
		"permissions": map[string]bool{"paste": false},
		"metadata":    map[string]any{"path_prefix": "safe"},
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-rename", map[string]any{"path": "open/rename-source.txt", "destination": "safe/rename-blocked.txt"}, userCookie, http.StatusForbidden)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-rename", map[string]any{"path": "open/rename-source.txt", "destination": "open/rename-ok.txt"}, userCookie, http.StatusOK)

	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "open/copy-source.txt", "content": "copy"}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "open/rename-overwrite-source.txt", "content": "rename"}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "safe/existing-copy.txt", "content": "existing"}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "safe/existing-rename.txt", "content": "existing"}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "open/existing-copy.txt", "content": "existing"}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "open/existing-rename.txt", "content": "existing"}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/strategies", map[string]any{
		"name":        "deny strategy-drive edit safe",
		"type":        "file",
		"status":      "enabled",
		"target_id":   storage.ID,
		"permissions": map[string]bool{"edit": false},
		"metadata":    map[string]any{"path_prefix": "safe"},
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-copy", map[string]any{"path": "open/copy-source.txt", "destination": "safe/existing-copy.txt", "overwrite": true}, userCookie, http.StatusForbidden)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-rename", map[string]any{"path": "open/rename-overwrite-source.txt", "destination": "safe/existing-rename.txt", "overwrite": true}, userCookie, http.StatusForbidden)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-copy", map[string]any{"path": "open/copy-source.txt", "destination": "open/existing-copy.txt", "overwrite": true}, userCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-rename", map[string]any{"path": "open/rename-overwrite-source.txt", "destination": "open/existing-rename.txt", "overwrite": true}, userCookie, http.StatusOK)
}

func TestStorageFileLogPersistenceFailureReturnsServerError(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)

	storageRec := assertStatus(t, handler, http.MethodPost, "/api/admin/storages", map[string]any{
		"name":   "persist-file-log-drive",
		"type":   "local",
		"status": "enabled",
	}, adminCookie, http.StatusCreated)
	var storage model.PlatformItem
	decodeResponse(t, storageRec, &storage)
	storageRoot := filepath.Join(srv.cfg.DataDir, "drives", storage.ID)
	assertStorageMissing := func(rel string) {
		t.Helper()
		if _, err := os.Stat(filepath.Join(storageRoot, filepath.FromSlash(rel))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("storage path %s exists after failed audited operation: %v", rel, err)
		}
	}
	assertStorageContent := func(rel, want string) {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(storageRoot, filepath.FromSlash(rel)))
		if err != nil || string(data) != want {
			t.Fatalf("storage file %s = %q/%v, want %q", rel, string(data), err, want)
		}
	}

	removeBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "file_logs")
	writeRec := assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "audit.txt", "content": "audit"}, adminCookie, http.StatusInternalServerError)
	removeBlocker()
	if !strings.Contains(writeRec.Body.String(), "persist file log failed") {
		t.Fatalf("storage file log persistence failure was not reported: %s", writeRec.Body.String())
	}
	assertStorageMissing("audit.txt")
	operationLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(operationLogsRec.Body.String(), "file.log.persist_failed") {
		t.Fatalf("storage file log persistence failure was not audited: %s", operationLogsRec.Body.String())
	}

	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "overwrite.txt", "content": "old"}, adminCookie, http.StatusCreated)
	removeOverwriteBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "file_logs")
	overwriteRec := assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "overwrite.txt", "content": "new"}, adminCookie, http.StatusInternalServerError)
	removeOverwriteBlocker()
	if !strings.Contains(overwriteRec.Body.String(), "persist file log failed") {
		t.Fatalf("storage overwrite file log persistence failure was not reported: %s", overwriteRec.Body.String())
	}
	assertStorageContent("overwrite.txt", "old")

	removeUploadBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "file_logs")
	uploadRec := assertMultipartStatus(t, handler, "/api/admin/storages/"+storage.ID+"/files-upload", nil, "upload-new.txt", []byte("upload"), adminCookie, http.StatusInternalServerError)
	removeUploadBlocker()
	if !strings.Contains(uploadRec.Body.String(), "persist file log failed") {
		t.Fatalf("storage upload file log persistence failure was not reported: %s", uploadRec.Body.String())
	}
	assertStorageMissing("upload-new.txt")

	removeMkdirBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "file_logs")
	mkdirRec := assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-mkdir", map[string]any{"path": "audit-dir/nested"}, adminCookie, http.StatusInternalServerError)
	removeMkdirBlocker()
	if !strings.Contains(mkdirRec.Body.String(), "persist file log failed") {
		t.Fatalf("storage mkdir file log persistence failure was not reported: %s", mkdirRec.Body.String())
	}
	assertStorageMissing("audit-dir")

	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "rename-source.txt", "content": "rename source"}, adminCookie, http.StatusCreated)
	removeRenameBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "file_logs")
	renameRec := assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-rename", map[string]any{"path": "rename-source.txt", "destination": "renamed.txt"}, adminCookie, http.StatusInternalServerError)
	removeRenameBlocker()
	if !strings.Contains(renameRec.Body.String(), "persist file log failed") {
		t.Fatalf("storage rename file log persistence failure was not reported: %s", renameRec.Body.String())
	}
	assertStorageContent("rename-source.txt", "rename source")
	assertStorageMissing("renamed.txt")

	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "rename-overwrite-source.txt", "content": "rename new"}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "rename-overwrite-target.txt", "content": "rename old"}, adminCookie, http.StatusCreated)
	removeRenameOverwriteBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "file_logs")
	renameOverwriteRec := assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-rename", map[string]any{"path": "rename-overwrite-source.txt", "destination": "rename-overwrite-target.txt", "overwrite": true}, adminCookie, http.StatusInternalServerError)
	removeRenameOverwriteBlocker()
	if !strings.Contains(renameOverwriteRec.Body.String(), "persist file log failed") {
		t.Fatalf("storage rename overwrite file log persistence failure was not reported: %s", renameOverwriteRec.Body.String())
	}
	assertStorageContent("rename-overwrite-source.txt", "rename new")
	assertStorageContent("rename-overwrite-target.txt", "rename old")

	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "rename-dir/source.txt", "content": "rename dir"}, adminCookie, http.StatusCreated)
	removeRenameDirBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "file_logs")
	renameDirRec := assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-rename", map[string]any{"path": "rename-dir", "destination": "renamed-dir"}, adminCookie, http.StatusInternalServerError)
	removeRenameDirBlocker()
	if !strings.Contains(renameDirRec.Body.String(), "persist file log failed") {
		t.Fatalf("storage rename directory file log persistence failure was not reported: %s", renameDirRec.Body.String())
	}
	assertStorageContent("rename-dir/source.txt", "rename dir")
	assertStorageMissing("renamed-dir")

	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "copy-source.txt", "content": "copy source"}, adminCookie, http.StatusCreated)
	removeCopyBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "file_logs")
	copyRec := assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-copy", map[string]any{"path": "copy-source.txt", "destination": "copy-new.txt"}, adminCookie, http.StatusInternalServerError)
	removeCopyBlocker()
	if !strings.Contains(copyRec.Body.String(), "persist file log failed") {
		t.Fatalf("storage copy file log persistence failure was not reported: %s", copyRec.Body.String())
	}
	assertStorageContent("copy-source.txt", "copy source")
	assertStorageMissing("copy-new.txt")

	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "copy-overwrite-source.txt", "content": "copy new"}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "copy-overwrite-target.txt", "content": "copy old"}, adminCookie, http.StatusCreated)
	removeCopyOverwriteBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "file_logs")
	copyOverwriteRec := assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-copy", map[string]any{"path": "copy-overwrite-source.txt", "destination": "copy-overwrite-target.txt", "overwrite": true}, adminCookie, http.StatusInternalServerError)
	removeCopyOverwriteBlocker()
	if !strings.Contains(copyOverwriteRec.Body.String(), "persist file log failed") {
		t.Fatalf("storage copy overwrite file log persistence failure was not reported: %s", copyOverwriteRec.Body.String())
	}
	assertStorageContent("copy-overwrite-source.txt", "copy new")
	assertStorageContent("copy-overwrite-target.txt", "copy old")

	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "copy-dir/source.txt", "content": "copy dir"}, adminCookie, http.StatusCreated)
	removeCopyDirBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "file_logs")
	copyDirRec := assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-copy", map[string]any{"path": "copy-dir", "destination": "copy-dir-new"}, adminCookie, http.StatusInternalServerError)
	removeCopyDirBlocker()
	if !strings.Contains(copyDirRec.Body.String(), "persist file log failed") {
		t.Fatalf("storage copy directory file log persistence failure was not reported: %s", copyDirRec.Body.String())
	}
	assertStorageContent("copy-dir/source.txt", "copy dir")
	assertStorageMissing("copy-dir-new")

	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "delete-me.txt", "content": "keep me"}, adminCookie, http.StatusCreated)
	removeDeleteBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "file_logs")
	deleteRec := assertStatus(t, handler, http.MethodDelete, "/api/admin/storages/"+storage.ID+"/files?path=delete-me.txt", nil, adminCookie, http.StatusInternalServerError)
	removeDeleteBlocker()
	if !strings.Contains(deleteRec.Body.String(), "persist file log failed") {
		t.Fatalf("storage delete file log persistence failure was not reported: %s", deleteRec.Body.String())
	}
	assertStorageContent("delete-me.txt", "keep me")

	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "delete-usage.txt", "content": "keep usage"}, adminCookie, http.StatusCreated)
	removeDeleteUsageBlocker := blockPlatformItemSave(t, srv.cfg.Store, "storages", storage.ID)
	deleteUsageRec := assertStatus(t, handler, http.MethodDelete, "/api/admin/storages/"+storage.ID+"/files?path=delete-usage.txt", nil, adminCookie, http.StatusInternalServerError)
	removeDeleteUsageBlocker()
	if !strings.Contains(deleteUsageRec.Body.String(), "forced platform item save failure") {
		t.Fatalf("storage delete usage persistence failure was not reported: %s", deleteUsageRec.Body.String())
	}
	assertStorageContent("delete-usage.txt", "keep usage")
}

func TestStorageQuotaEnforcedAndUsageUpdated(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)

	storageRec := assertStatus(t, handler, http.MethodPost, "/api/admin/storages", map[string]any{
		"name":     "quota-drive",
		"type":     "local",
		"status":   "enabled",
		"metadata": map[string]any{"limit_bytes": 8},
	}, adminCookie, http.StatusCreated)
	var storage model.PlatformItem
	decodeResponse(t, storageRec, &storage)

	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "a.txt", "content": "12345"}, adminCookie, http.StatusCreated)
	listRec := assertStatus(t, handler, http.MethodGet, "/api/admin/storages/"+storage.ID+"/files", nil, adminCookie, http.StatusOK)
	var listPayload struct {
		Usage storageUsageInfo `json:"usage"`
	}
	decodeResponse(t, listRec, &listPayload)
	if listPayload.Usage.Bytes != 5 || listPayload.Usage.LimitBytes != 8 || listPayload.Usage.AvailableBytes != 3 {
		t.Fatalf("usage after first write = %#v, want 5/8/3 bytes", listPayload.Usage)
	}

	quotaRec := assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "b.txt", "content": "1234"}, adminCookie, http.StatusRequestEntityTooLarge)
	if !strings.Contains(quotaRec.Body.String(), "quota") {
		t.Fatalf("quota denial body = %q, want quota detail", quotaRec.Body.String())
	}
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/file-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), "storage quota exceeded") || !strings.Contains(logsRec.Body.String(), "denied") {
		t.Fatal("quota denial was not written to file logs")
	}

	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "a.txt", "content": "12"}, adminCookie, http.StatusCreated)
	assertMultipartStatus(t, handler, "/api/admin/storages/"+storage.ID+"/files-upload", map[string]string{}, "c.bin", []byte("3456"), adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-copy", map[string]any{"path": "c.bin", "destination": "d.bin"}, adminCookie, http.StatusRequestEntityTooLarge)
	assertStatus(t, handler, http.MethodDelete, "/api/admin/storages/"+storage.ID+"/files?path=c.bin", nil, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "b.txt", "content": "123456"}, adminCookie, http.StatusCreated)

	saved, ok, err := srv.cfg.Store.GetPlatformItem("storages", storage.ID)
	if err != nil || !ok {
		t.Fatalf("get saved storage: ok=%v err=%v", ok, err)
	}
	if used, ok := parseStorageByteSize(saved.Metadata["used_bytes"]); !ok || used != 8 {
		t.Fatalf("saved used_bytes = %#v, want 8", saved.Metadata["used_bytes"])
	}
	if files, ok := metadataInt(saved.Metadata["files"]); !ok || files != 2 {
		t.Fatalf("saved files = %#v, want 2", saved.Metadata["files"])
	}
}

func TestStorageUsageIgnoresInternalRollbackBackups(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)

	storageRec := assertStatus(t, handler, http.MethodPost, "/api/admin/storages", map[string]any{
		"name":   "rollback-usage-drive",
		"type":   "local",
		"status": "enabled",
	}, adminCookie, http.StatusCreated)
	var storage model.PlatformItem
	decodeResponse(t, storageRec, &storage)

	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "source.txt", "content": "new"}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "target.txt", "content": "old-data"}, adminCookie, http.StatusCreated)
	copyRec := assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-copy", map[string]any{"path": "source.txt", "destination": "target.txt", "overwrite": true}, adminCookie, http.StatusCreated)
	var copyPayload struct {
		Usage storageUsageInfo `json:"usage"`
	}
	decodeResponse(t, copyRec, &copyPayload)
	if copyPayload.Usage.Bytes != 6 || copyPayload.Usage.Files != 2 {
		t.Fatalf("copy overwrite usage = %#v, want 6 bytes across 2 files", copyPayload.Usage)
	}

	saved, ok, err := srv.cfg.Store.GetPlatformItem("storages", storage.ID)
	if err != nil || !ok {
		t.Fatalf("get saved storage: ok=%v err=%v", ok, err)
	}
	if used, ok := parseStorageByteSize(saved.Metadata["used_bytes"]); !ok || used != 6 {
		t.Fatalf("saved used_bytes after rollback-backed copy = %#v, want 6", saved.Metadata["used_bytes"])
	}
}

func TestStorageFileOperationsRejectDisabledStorage(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	storageRec := assertStatus(t, handler, http.MethodPost, "/api/admin/storages", map[string]any{
		"name":   "disabled-drive",
		"type":   "local",
		"status": "enabled",
	}, adminCookie, http.StatusCreated)
	var storage model.PlatformItem
	decodeResponse(t, storageRec, &storage)

	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{
		"path":    "docs/keep.txt",
		"content": "keep",
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPatch, "/api/admin/storages/"+storage.ID, map[string]any{
		"status": "disabled",
	}, adminCookie, http.StatusOK)

	assertStatus(t, handler, http.MethodGet, "/api/admin/storages/"+storage.ID+"/files", nil, adminCookie, http.StatusNotFound)
	assertStatus(t, handler, http.MethodGet, "/api/admin/storages/"+storage.ID+"/files-download?path=docs/keep.txt", nil, adminCookie, http.StatusNotFound)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{
		"path":    "docs/blocked.txt",
		"content": "blocked",
	}, adminCookie, http.StatusNotFound)
	assertStatus(t, handler, http.MethodDelete, "/api/admin/storages/"+storage.ID+"/files?path=docs/keep.txt", nil, adminCookie, http.StatusNotFound)

	assertStatus(t, handler, http.MethodPatch, "/api/admin/storages/"+storage.ID, map[string]any{
		"status": "enabled",
	}, adminCookie, http.StatusOK)
	downloadRec := assertStatus(t, handler, http.MethodGet, "/api/admin/storages/"+storage.ID+"/files-download?path=docs/keep.txt", nil, adminCookie, http.StatusOK)
	if strings.TrimSpace(downloadRec.Body.String()) != "keep" {
		t.Fatalf("storage content after re-enable = %q, want keep", downloadRec.Body.String())
	}
}

func TestStorageFileOperationsRejectSymlinkTargets(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)

	storageRec := assertStatus(t, handler, http.MethodPost, "/api/admin/storages", map[string]any{
		"name":   "symlink-drive",
		"type":   "local",
		"status": "enabled",
	}, adminCookie, http.StatusCreated)
	var storage model.PlatformItem
	decodeResponse(t, storageRec, &storage)

	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "safe.txt", "content": "safe"}, adminCookie, http.StatusCreated)
	root := filepath.Join(srv.cfg.DataDir, "drives", storage.ID)
	externalContent := "external storage secret"
	externalPath := filepath.Join(t.TempDir(), "outside-storage.txt")
	if err := os.WriteFile(externalPath, []byte(externalContent), 0o660); err != nil {
		t.Fatalf("write external storage fixture: %v", err)
	}
	if err := os.Symlink(externalPath, filepath.Join(root, "linked.txt")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := os.Symlink(externalPath, filepath.Join(root, "destination-link.txt")); err != nil {
		t.Fatalf("create destination symlink: %v", err)
	}
	externalDir := filepath.Join(t.TempDir(), "outside-dir")
	if err := os.MkdirAll(externalDir, 0o770); err != nil {
		t.Fatalf("create external directory fixture: %v", err)
	}
	externalDirFile := filepath.Join(externalDir, "inside.txt")
	if err := os.WriteFile(externalDirFile, []byte("external dir file"), 0o660); err != nil {
		t.Fatalf("write external directory file fixture: %v", err)
	}
	if err := os.Symlink(externalDir, filepath.Join(root, "linked-dir")); err != nil {
		t.Fatalf("create directory symlink: %v", err)
	}

	normalDownload := assertStatus(t, handler, http.MethodGet, "/api/admin/storages/"+storage.ID+"/files-download?path=safe.txt", nil, adminCookie, http.StatusOK)
	if strings.TrimSpace(normalDownload.Body.String()) != "safe" {
		t.Fatalf("normal storage download body = %q", normalDownload.Body.String())
	}
	symlinkDownload := assertStatus(t, handler, http.MethodGet, "/api/admin/storages/"+storage.ID+"/files-download?path=linked.txt", nil, adminCookie, http.StatusBadRequest)
	if strings.Contains(symlinkDownload.Body.String(), externalContent) {
		t.Fatalf("symlink download leaked external content: %s", symlinkDownload.Body.String())
	}
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "linked.txt", "content": "overwrite"}, adminCookie, http.StatusBadRequest)
	assertMultipartStatus(t, handler, "/api/admin/storages/"+storage.ID+"/files-upload", map[string]string{}, "linked.txt", []byte("upload"), adminCookie, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-copy", map[string]any{"path": "linked.txt", "destination": "copied.txt"}, adminCookie, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-rename", map[string]any{"path": "linked.txt", "destination": "renamed.txt"}, adminCookie, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-copy", map[string]any{"path": "safe.txt", "destination": "destination-link.txt", "overwrite": true}, adminCookie, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-rename", map[string]any{"path": "safe.txt", "destination": "destination-link.txt", "overwrite": true}, adminCookie, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodGet, "/api/admin/storages/"+storage.ID+"/files?path=linked-dir", nil, adminCookie, http.StatusBadRequest)
	nestedSymlinkDownload := assertStatus(t, handler, http.MethodGet, "/api/admin/storages/"+storage.ID+"/files-download?path=linked-dir/inside.txt", nil, adminCookie, http.StatusBadRequest)
	if strings.Contains(nestedSymlinkDownload.Body.String(), "external dir file") {
		t.Fatalf("directory symlink nested download leaked external content: %s", nestedSymlinkDownload.Body.String())
	}
	assertStatus(t, handler, http.MethodDelete, "/api/admin/storages/"+storage.ID+"/files?path=linked-dir/inside.txt", nil, adminCookie, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-copy", map[string]any{"path": "linked-dir/inside.txt", "destination": "nested-copy.txt"}, adminCookie, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-rename", map[string]any{"path": "linked-dir/inside.txt", "destination": "nested-rename.txt"}, adminCookie, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "linked-dir/escaped.txt", "content": "escape"}, adminCookie, http.StatusBadRequest)
	assertMultipartStatus(t, handler, "/api/admin/storages/"+storage.ID+"/files-upload", map[string]string{"path": "linked-dir"}, "escaped-upload.txt", []byte("escape"), adminCookie, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-mkdir", map[string]any{"path": "linked-dir/new-dir"}, adminCookie, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-copy", map[string]any{"path": "safe.txt", "destination": "linked-dir/copied.txt"}, adminCookie, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-rename", map[string]any{"path": "safe.txt", "destination": "linked-dir/renamed.txt"}, adminCookie, http.StatusBadRequest)
	if data, err := os.ReadFile(externalPath); err != nil || string(data) != externalContent {
		t.Fatalf("external symlink target changed: content=%q err=%v", string(data), err)
	}
	if data, err := os.ReadFile(externalDirFile); err != nil || string(data) != "external dir file" {
		t.Fatalf("external symlink directory file changed: content=%q err=%v", string(data), err)
	}
	for _, name := range []string{"escaped.txt", "escaped-upload.txt", "new-dir", "copied.txt", "renamed.txt", "nested-copy.txt", "nested-rename.txt"} {
		if _, err := os.Stat(filepath.Join(externalDir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("directory symlink operation created %s outside storage: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "copied.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("copy from symlink unexpectedly created file: %v", err)
	}
}

func TestStorageListFiltersDeniedDownloadPaths(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	storageRec := assertStatus(t, handler, http.MethodPost, "/api/admin/storages", map[string]any{
		"name":   "list-filter-drive",
		"type":   "local",
		"status": "enabled",
	}, adminCookie, http.StatusCreated)
	var storage model.PlatformItem
	decodeResponse(t, storageRec, &storage)

	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "safe/secret.txt", "content": "secret"}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": "open/readme.txt", "content": "open"}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/roles", map[string]any{
		"name":   "storage-list-operator",
		"type":   "custom",
		"status": "enabled",
		"metadata": map[string]any{
			"api_permissions": []string{
				"GET /api/admin/storages/*",
				"GET /api/admin/audit/file-logs",
			},
		},
	}, adminCookie, http.StatusCreated)
	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "storage-list-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "storage-list-operator"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)
	assertStatus(t, handler, http.MethodPost, "/api/admin/strategies", map[string]any{
		"name":        "deny list-filter safe download",
		"type":        "file",
		"status":      "enabled",
		"target_id":   storage.ID,
		"owner_id":    user.ID,
		"permissions": map[string]bool{"download": false},
		"metadata":    map[string]any{"path_prefix": "safe"},
	}, adminCookie, http.StatusCreated)

	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "storage-list-user", "password": "password123"}, nil, http.StatusOK)
	userCookie := loginRec.Result().Cookies()[0]

	userListRec := assertStatus(t, handler, http.MethodGet, "/api/admin/storages/"+storage.ID+"/files", nil, userCookie, http.StatusOK)
	userListBody := userListRec.Body.String()
	if !strings.Contains(userListBody, `"name":"open"`) || strings.Contains(userListBody, `"name":"safe"`) {
		t.Fatalf("filtered storage list body = %s", userListBody)
	}
	assertStatus(t, handler, http.MethodGet, "/api/admin/storages/"+storage.ID+"/files?path=safe", nil, userCookie, http.StatusForbidden)
	assertStatus(t, handler, http.MethodGet, "/api/admin/storages/"+storage.ID+"/files-download?path=safe/secret.txt", nil, userCookie, http.StatusForbidden)

	adminListRec := assertStatus(t, handler, http.MethodGet, "/api/admin/storages/"+storage.ID+"/files", nil, adminCookie, http.StatusOK)
	if !strings.Contains(adminListRec.Body.String(), `"name":"safe"`) {
		t.Fatalf("admin storage list should include denied user path: %s", adminListRec.Body.String())
	}
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/file-logs", nil, userCookie, http.StatusOK)
	logsBody := logsRec.Body.String()
	if !strings.Contains(logsBody, "safe") || !strings.Contains(logsBody, "denied") || !strings.Contains(logsBody, "list") {
		t.Fatalf("storage list denial was not logged: %s", logsBody)
	}
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

func TestStorageAuthorizationStrategyPreventsDirectoryBypass(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	storageRec := assertStatus(t, handler, http.MethodPost, "/api/admin/storages", map[string]any{
		"name":   "recursive-policy-drive",
		"type":   "local",
		"status": "enabled",
	}, adminCookie, http.StatusCreated)
	var storage model.PlatformItem
	decodeResponse(t, storageRec, &storage)

	assertStatus(t, handler, http.MethodPost, "/api/admin/roles", map[string]any{
		"name":   "recursive-storage-operator",
		"type":   "custom",
		"status": "enabled",
		"metadata": map[string]any{
			"api_permissions": []string{
				"GET /api/admin/storages/*",
				"POST /api/admin/storages/*",
				"DELETE /api/admin/storages/*",
			},
		},
	}, adminCookie, http.StatusCreated)
	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "recursive-storage-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "recursive-storage-operator"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)
	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "recursive-storage-user", "password": "password123"}, nil, http.StatusOK)
	userCookie := loginRec.Result().Cookies()[0]

	writeFile := func(path, content string) {
		t.Helper()
		assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-write", map[string]any{"path": path, "content": content}, adminCookie, http.StatusCreated)
	}
	deny := func(name, action, pathPrefix string) {
		t.Helper()
		assertStatus(t, handler, http.MethodPost, "/api/admin/strategies", map[string]any{
			"name":        name,
			"type":        "file",
			"status":      "enabled",
			"target_id":   storage.ID,
			"owner_id":    user.ID,
			"permissions": map[string]bool{action: false},
			"metadata":    map[string]any{"path_prefix": pathPrefix},
		}, adminCookie, http.StatusCreated)
	}
	download := func(path string, want int) {
		t.Helper()
		assertStatus(t, handler, http.MethodGet, "/api/admin/storages/"+storage.ID+"/files-download?path="+path, nil, adminCookie, want)
	}

	writeFile("delete-tree/protected/blocked.txt", "blocked")
	writeFile("delete-tree/open.txt", "open")
	deny("deny recursive delete protected child", "delete", "delete-tree/protected")
	assertStatus(t, handler, http.MethodDelete, "/api/admin/storages/"+storage.ID+"/files?path=delete-tree", nil, userCookie, http.StatusForbidden)
	download("delete-tree/protected/blocked.txt", http.StatusOK)

	writeFile("copy-source/protected/blocked.txt", "blocked")
	deny("deny recursive copy protected child", "copy", "copy-source/protected")
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-copy", map[string]any{"path": "copy-source", "destination": "copy-target"}, userCookie, http.StatusForbidden)
	download("copy-target/protected/blocked.txt", http.StatusNotFound)

	writeFile("paste-source/protected/blocked.txt", "blocked")
	deny("deny recursive paste protected target child", "paste", "paste-target/protected")
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-copy", map[string]any{"path": "paste-source", "destination": "paste-target"}, userCookie, http.StatusForbidden)
	download("paste-target/protected/blocked.txt", http.StatusNotFound)

	writeFile("overwrite-source/protected/new.txt", "new")
	writeFile("overwrite-target/protected/existing.txt", "existing")
	deny("deny recursive copy overwrite protected child", "edit", "overwrite-target/protected")
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-copy", map[string]any{"path": "overwrite-source", "destination": "overwrite-target", "overwrite": true}, userCookie, http.StatusForbidden)
	download("overwrite-target/protected/existing.txt", http.StatusOK)

	writeFile("rename-source/protected/blocked.txt", "blocked")
	deny("deny recursive rename protected source child", "rename", "rename-source/protected")
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-rename", map[string]any{"path": "rename-source", "destination": "renamed-source"}, userCookie, http.StatusForbidden)
	download("rename-source/protected/blocked.txt", http.StatusOK)
	download("renamed-source/protected/blocked.txt", http.StatusNotFound)

	writeFile("rename-paste-source/protected/blocked.txt", "blocked")
	deny("deny recursive rename paste protected target child", "paste", "rename-paste-target/protected")
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-rename", map[string]any{"path": "rename-paste-source", "destination": "rename-paste-target"}, userCookie, http.StatusForbidden)
	download("rename-paste-source/protected/blocked.txt", http.StatusOK)
	download("rename-paste-target/protected/blocked.txt", http.StatusNotFound)

	writeFile("rename-overwrite-source/new.txt", "new")
	writeFile("rename-overwrite-target/protected/existing.txt", "existing")
	deny("deny recursive rename overwrite protected child", "edit", "rename-overwrite-target/protected")
	assertStatus(t, handler, http.MethodPost, "/api/admin/storages/"+storage.ID+"/files-rename", map[string]any{"path": "rename-overwrite-source", "destination": "rename-overwrite-target", "overwrite": true}, userCookie, http.StatusForbidden)
	download("rename-overwrite-source/new.txt", http.StatusOK)
	download("rename-overwrite-target/protected/existing.txt", http.StatusOK)
}

func TestPlatformOnlineSessionCloseEndpoint(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)

	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "platform-close-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)

	webRec := assertStatus(t, handler, http.MethodPost, "/api/admin/websites", map[string]any{
		"name":   "platform close web",
		"type":   "http",
		"status": "enabled",
		"metadata": map[string]any{
			"target_url": "http://127.0.0.1",
		},
	}, adminCookie, http.StatusCreated)
	var webAsset model.PlatformItem
	decodeResponse(t, webRec, &webAsset)
	assertStatus(t, handler, http.MethodPost, "/api/admin/authorizations/websites", map[string]any{
		"name":      "platform-close-user web",
		"owner_id":  user.ID,
		"target_id": webAsset.ID,
		"status":    "enabled",
	}, adminCookie, http.StatusCreated)

	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "platform-close-user", "password": "password123"}, nil, http.StatusOK)
	userCookie := loginRec.Result().Cookies()[0]
	createRec := assertStatus(t, handler, http.MethodPost, "/api/access/http/"+webAsset.ID, nil, userCookie, http.StatusAccepted)
	var online model.PlatformItem
	decodeResponse(t, createRec, &online)
	if online.ID == "" || online.OwnerID != user.ID || online.Protocol != model.ProtocolHTTP {
		t.Fatalf("platform online session = %#v", online)
	}

	recordingPath := filepath.Join(srv.cfg.DataDir, "recordings", online.ID)
	if err := os.MkdirAll(recordingPath, 0o770); err != nil {
		t.Fatalf("create platform recording path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(recordingPath, "recording.guac"), []byte("platform frames"), 0o660); err != nil {
		t.Fatalf("write platform recording: %v", err)
	}
	online.Metadata["recording_path"] = recordingPath
	if _, err := srv.cfg.Store.SavePlatformItem("online_sessions", online); err != nil {
		t.Fatalf("save platform online recording metadata: %v", err)
	}

	removePlatformCloseLogBlocker := blockOperationLogName(t, srv.cfg.Store, "connection.close")
	blockedPlatformCloseRec := assertStatus(t, handler, http.MethodPost, "/api/connections/"+online.ID+"/close", nil, userCookie, http.StatusInternalServerError)
	removePlatformCloseLogBlocker()
	if !strings.Contains(blockedPlatformCloseRec.Body.String(), "persist operation log failed") {
		t.Fatalf("platform close operation log failure was not reported: %s", blockedPlatformCloseRec.Body.String())
	}
	blockedOnlineRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/online-sessions", nil, adminCookie, http.StatusOK)
	if !strings.Contains(blockedOnlineRec.Body.String(), online.ID) {
		t.Fatalf("platform close removed online session after operation log failure: %s", blockedOnlineRec.Body.String())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "operation.log.persist_failed") {
		t.Fatal("platform close operation log failure was not audited")
	}

	closeRec := assertStatus(t, handler, http.MethodPost, "/api/connections/"+online.ID+"/close", nil, userCookie, http.StatusOK)
	var closed model.PlatformItem
	decodeResponse(t, closeRec, &closed)
	if closed.Status != string(model.SessionClosed) || firstMetadataString(closed.Metadata, "close_reason") != "closed by user" {
		t.Fatalf("closed platform session did not include close status/reason: %#v", closed)
	}
	if got, ok := metadataInt(closed.Metadata["recording_size"]); !ok || got != len("platform frames") {
		t.Fatalf("closed platform recording size = %v/%v, want %d in %#v", got, ok, len("platform frames"), closed.Metadata)
	}
	onlineRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/online-sessions", nil, adminCookie, http.StatusOK)
	if strings.Contains(onlineRec.Body.String(), online.ID) {
		t.Fatalf("closed platform session still appears online: %s", onlineRec.Body.String())
	}
	offlineRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/offline-sessions", nil, adminCookie, http.StatusOK)
	if !strings.Contains(offlineRec.Body.String(), online.ID) || !strings.Contains(offlineRec.Body.String(), `"recording_size":15`) {
		t.Fatalf("closed platform session missing from offline index: %s", offlineRec.Body.String())
	}
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), "connection.close") || !strings.Contains(logsRec.Body.String(), online.ID) {
		t.Fatalf("platform close was not audited: %s", logsRec.Body.String())
	}

	secondRec := assertStatus(t, handler, http.MethodPost, "/api/access/http/"+webAsset.ID, nil, userCookie, http.StatusAccepted)
	var second model.PlatformItem
	decodeResponse(t, secondRec, &second)
	assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "platform-close-other",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	otherLogin := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "platform-close-other", "password": "password123"}, nil, http.StatusOK)
	otherCookie := otherLogin.Result().Cookies()[0]
	assertStatus(t, handler, http.MethodPost, "/api/connections/"+second.ID+"/close", nil, otherCookie, http.StatusForbidden)
	stillOnlineRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/online-sessions", nil, adminCookie, http.StatusOK)
	if !strings.Contains(stillOnlineRec.Body.String(), second.ID) {
		t.Fatalf("forbidden close removed platform session from online list: %s", stillOnlineRec.Body.String())
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
	removeDisconnectLogBlocker := blockOperationLogName(t, handler.(*Server).cfg.Store, "audit.session.disconnect")
	blockedDisconnectRec := assertStatus(t, handler, http.MethodPost, "/api/admin/audit/online-sessions/"+sshSession.ID+"/disconnect", nil, adminCookie, http.StatusInternalServerError)
	removeDisconnectLogBlocker()
	if !strings.Contains(blockedDisconnectRec.Body.String(), "persist operation log failed") {
		t.Fatalf("audit disconnect operation log failure was not reported: %s", blockedDisconnectRec.Body.String())
	}
	blockedDisconnectOnlineRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/online-sessions", nil, adminCookie, http.StatusOK)
	if !strings.Contains(blockedDisconnectOnlineRec.Body.String(), sshSession.ID) {
		t.Fatalf("audit disconnect removed session after operation log failure: %s", blockedDisconnectOnlineRec.Body.String())
	}
	if !coreAuditLogsContainAction(handler.(*Server).cfg.Store, "operation.log.persist_failed") {
		t.Fatal("audit disconnect operation log failure was not audited")
	}
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
	removeConnectionCloseLogBlocker := blockOperationLogName(t, handler.(*Server).cfg.Store, "connection.close")
	blockedConnectionCloseRec := assertStatus(t, handler, http.MethodPost, "/api/connections/"+rdpSession.ID+"/close", nil, adminCookie, http.StatusInternalServerError)
	removeConnectionCloseLogBlocker()
	if !strings.Contains(blockedConnectionCloseRec.Body.String(), "persist operation log failed") {
		t.Fatalf("connection close operation log failure was not reported: %s", blockedConnectionCloseRec.Body.String())
	}
	blockedConnectionOnlineRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/online-sessions", nil, adminCookie, http.StatusOK)
	if !strings.Contains(blockedConnectionOnlineRec.Body.String(), rdpSession.ID) {
		t.Fatalf("connection close removed session after operation log failure: %s", blockedConnectionOnlineRec.Body.String())
	}
	closeRDPRec := assertStatus(t, handler, http.MethodPost, "/api/connections/"+rdpSession.ID+"/close", nil, adminCookie, http.StatusOK)
	var closedRDP model.ConnectionSession
	decodeResponse(t, closeRDPRec, &closedRDP)
	if closedRDP.RecordingSize != int64(len("frames")) {
		t.Fatalf("closed rdp recording size = %d, want %d", closedRDP.RecordingSize, len("frames"))
	}
	offlineSessionsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/offline-sessions", nil, adminCookie, http.StatusOK)
	if !strings.Contains(offlineSessionsRec.Body.String(), `"recording_size":6`) {
		t.Fatalf("offline session index did not include recording size: %s", offlineSessionsRec.Body.String())
	}
	externalRecordingContent := "external recording frames"
	externalRecordingPath := filepath.Join(t.TempDir(), "outside-recording.guac")
	if err := os.WriteFile(externalRecordingPath, []byte(externalRecordingContent), 0o660); err != nil {
		t.Fatalf("write external recording fixture: %v", err)
	}
	recordingSymlinkName := "linked-outside.guac"
	recordingSymlinkCreated := true
	if err := os.Symlink(externalRecordingPath, filepath.Join(rdpSession.RecordingPath, recordingSymlinkName)); err != nil {
		recordingSymlinkCreated = false
		t.Logf("skip recording symlink assertion: %v", err)
	}

	rdpAuditSessionRec := assertStatus(t, handler, http.MethodPost, "/api/connections/rdp", map[string]any{
		"server_id":         windows.ID,
		"credential_id":     rdpCred.ID,
		"recording_enabled": true,
	}, adminCookie, http.StatusCreated)
	var rdpAuditSession model.ConnectionSession
	decodeResponse(t, rdpAuditSessionRec, &rdpAuditSession)
	if err := os.WriteFile(filepath.Join(rdpAuditSession.RecordingPath, "recording.guac"), []byte("auditor frames"), 0o660); err != nil {
		t.Fatalf("write auditor recording: %v", err)
	}
	forceDisconnectRec := assertStatus(t, handler, http.MethodPost, "/api/admin/audit/online-sessions/"+rdpAuditSession.ID+"/disconnect", nil, adminCookie, http.StatusOK)
	var forceDisconnected model.ConnectionSession
	decodeResponse(t, forceDisconnectRec, &forceDisconnected)
	if forceDisconnected.RecordingSize != int64(len("auditor frames")) {
		t.Fatalf("auditor-disconnected recording size = %d, want %d", forceDisconnected.RecordingSize, len("auditor frames"))
	}

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
	if recordingSymlinkCreated {
		assertZipOmitsEntryAndContent(t, auditorDownload.Body.Bytes(), recordingSymlinkName, externalRecordingContent)
	}
	assertStatus(t, handler, http.MethodPost, "/api/admin/audit/online-sessions/"+rdpSession.ID+"/disconnect", nil, auditorCookie, http.StatusForbidden)
	assertStatus(t, handler, http.MethodPost, "/api/admin/roles", map[string]any{
		"name":   "recording-limited",
		"type":   "custom",
		"status": "enabled",
		"metadata": map[string]any{
			"api_permissions": []string{"GET /api/admin/audit/offline-sessions/*"},
		},
	}, adminCookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "recording-limited-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "recording-limited"},
	}, adminCookie, http.StatusCreated)
	limitedLogin := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "recording-limited-user", "password": "password123"}, nil, http.StatusOK)
	limitedCookie := limitedLogin.Result().Cookies()[0]
	assertStatus(t, handler, http.MethodGet, "/api/admin/audit/offline-sessions/"+rdpSession.ID+"/recording", nil, limitedCookie, http.StatusForbidden)
	deniedRecordingLogs := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(deniedRecordingLogs.Body.String(), "audit.recording.access.denied") || !strings.Contains(deniedRecordingLogs.Body.String(), rdpSession.ID) {
		t.Fatalf("denied recording access was not audited: %s", deniedRecordingLogs.Body.String())
	}

	adminDownload := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/offline-sessions/"+rdpSession.ID+"/recording", nil, adminCookie, http.StatusOK)
	assertZipContains(t, adminDownload.Body.Bytes(), "recording.guac", "frames")
	if recordingSymlinkCreated {
		assertZipOmitsEntryAndContent(t, adminDownload.Body.Bytes(), recordingSymlinkName, externalRecordingContent)
	}
	legacyDownload := assertStatus(t, handler, http.MethodGet, "/api/connections/"+rdpSession.ID+"/recording.zip", nil, adminCookie, http.StatusOK)
	assertZipContains(t, legacyDownload.Body.Bytes(), "recording.guac", "frames")
	if recordingSymlinkCreated {
		assertZipOmitsEntryAndContent(t, legacyDownload.Body.Bytes(), recordingSymlinkName, externalRecordingContent)
	}
	assertStatus(t, handler, http.MethodDelete, "/api/admin/audit/offline-sessions/"+rdpSession.ID+"/recording", nil, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodGet, "/api/admin/audit/offline-sessions/"+rdpSession.ID+"/recording", nil, adminCookie, http.StatusNotFound)
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), "audit.recording.delete") {
		t.Fatal("recording delete did not write operation log")
	}
}

func TestRecordingOperationLogPersistenceFailures(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)

	windowsRec := assertStatus(t, handler, http.MethodPost, "/api/servers", map[string]any{
		"name":     "recording-log-windows",
		"host":     "127.0.0.1",
		"os":       "windows",
		"rdp_port": 3389,
	}, adminCookie, http.StatusCreated)
	var windows model.Server
	decodeResponse(t, windowsRec, &windows)
	rdpCredRec := assertStatus(t, handler, http.MethodPost, "/api/credentials", map[string]any{
		"name":      "recording-log-rdp-admin",
		"server_id": windows.ID,
		"type":      "rdp_password",
		"username":  "Administrator",
		"password":  "secret",
	}, adminCookie, http.StatusCreated)
	var rdpCred model.CredentialPublic
	decodeResponse(t, rdpCredRec, &rdpCred)
	sessionRec := assertStatus(t, handler, http.MethodPost, "/api/connections/rdp", map[string]any{
		"server_id":         windows.ID,
		"credential_id":     rdpCred.ID,
		"recording_enabled": true,
	}, adminCookie, http.StatusCreated)
	var session model.ConnectionSession
	decodeResponse(t, sessionRec, &session)
	if session.RecordingPath == "" {
		t.Fatal("recording path was not created")
	}
	recordingFile := filepath.Join(session.RecordingPath, "recording.guac")
	if err := os.WriteFile(recordingFile, []byte("audit frames"), 0o660); err != nil {
		t.Fatalf("write recording fixture: %v", err)
	}

	removeLegacyDownloadBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	legacyDownloadRec := assertStatus(t, handler, http.MethodGet, "/api/connections/"+session.ID+"/recording.zip", nil, adminCookie, http.StatusInternalServerError)
	removeLegacyDownloadBlocker()
	if !strings.Contains(legacyDownloadRec.Body.String(), "persist operation log failed") {
		t.Fatalf("legacy recording download operation log failure was not reported: %s", legacyDownloadRec.Body.String())
	}
	if strings.Contains(legacyDownloadRec.Body.String(), "audit frames") {
		t.Fatalf("legacy recording download returned recording content after operation log failure: %s", legacyDownloadRec.Body.String())
	}

	removeAuditDownloadBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	auditDownloadRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/offline-sessions/"+session.ID+"/recording", nil, adminCookie, http.StatusInternalServerError)
	removeAuditDownloadBlocker()
	if !strings.Contains(auditDownloadRec.Body.String(), "persist operation log failed") {
		t.Fatalf("audit recording download operation log failure was not reported: %s", auditDownloadRec.Body.String())
	}
	if strings.Contains(auditDownloadRec.Body.String(), "audit frames") {
		t.Fatalf("audit recording download returned recording content after operation log failure: %s", auditDownloadRec.Body.String())
	}

	removeDeleteBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	deleteRec := assertStatus(t, handler, http.MethodDelete, "/api/admin/audit/offline-sessions/"+session.ID+"/recording", nil, adminCookie, http.StatusInternalServerError)
	removeDeleteBlocker()
	if !strings.Contains(deleteRec.Body.String(), "persist operation log failed") {
		t.Fatalf("recording delete operation log failure was not reported: %s", deleteRec.Body.String())
	}
	if data, err := os.ReadFile(recordingFile); err != nil || string(data) != "audit frames" {
		t.Fatalf("recording delete removed or changed recording before operation log persisted: data=%q err=%v", string(data), err)
	}
	storedSession, ok := srv.cfg.Store.GetSession(session.ID)
	if !ok || storedSession.RecordingPath == "" || storedSession.RecordingSize != 0 {
		t.Fatalf("recording delete changed session metadata before operation log persisted: ok=%v session=%#v", ok, storedSession)
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "operation.log.persist_failed") {
		t.Fatal("recording operation log persistence failure was not written to core audit logs")
	}

	if _, err := srv.cfg.Store.CloseSession(session.ID, "closed before recording state failure test"); err != nil {
		t.Fatalf("close recording state failure fixture session: %v", err)
	}
	removeStateBlocker := blockPlatformItemSave(t, srv.cfg.Store, "offline_sessions", session.ID)
	stateFailureRec := assertStatus(t, handler, http.MethodDelete, "/api/admin/audit/offline-sessions/"+session.ID+"/recording", nil, adminCookie, http.StatusInternalServerError)
	removeStateBlocker()
	if !strings.Contains(stateFailureRec.Body.String(), "persist recording deletion offline state failed") {
		t.Fatalf("recording state persistence failure was not reported: %s", stateFailureRec.Body.String())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "audit.recording.state.persist_failed") {
		t.Fatal("recording state persistence failure was not written to core audit logs")
	}
	if _, err := os.Stat(recordingFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recording file state after metadata failure = %v, want removed", err)
	}
	offline, ok, err := srv.cfg.Store.GetPlatformItem("offline_sessions", session.ID)
	if err != nil || !ok {
		t.Fatalf("load offline recording fixture after metadata failure: ok=%v err=%v", ok, err)
	}
	if firstMetadataString(offline.Metadata, "recording_path") == "" {
		t.Fatalf("offline recording metadata unexpectedly changed after forced persistence failure: %#v", offline.Metadata)
	}
}

func TestRecordingAuditRejectsSymlinkRecordingRoot(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)

	recordingsRoot := filepath.Join(srv.cfg.DataDir, "recordings")
	if err := os.MkdirAll(recordingsRoot, 0o770); err != nil {
		t.Fatalf("create recordings root: %v", err)
	}
	externalDir := filepath.Join(t.TempDir(), "external-recording-root")
	if err := os.MkdirAll(externalDir, 0o770); err != nil {
		t.Fatalf("create external recording dir: %v", err)
	}
	externalFile := filepath.Join(externalDir, "recording.guac")
	externalContent := "external recording root frames"
	if err := os.WriteFile(externalFile, []byte(externalContent), 0o660); err != nil {
		t.Fatalf("write external recording file: %v", err)
	}
	linkPath := filepath.Join(recordingsRoot, "linked-root")
	if err := os.Symlink(externalDir, linkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	session, err := srv.cfg.Store.CreateSession(model.ConnectionSession{
		Protocol:      model.ProtocolRDP,
		UserID:        "admin",
		RecordingPath: linkPath,
	})
	if err != nil {
		t.Fatalf("create session with linked recording root: %v", err)
	}
	legacyDownload := assertStatus(t, handler, http.MethodGet, "/api/connections/"+session.ID+"/recording.zip", nil, adminCookie, http.StatusBadRequest)
	if strings.Contains(legacyDownload.Body.String(), externalContent) {
		t.Fatalf("legacy recording download leaked external content: %s", legacyDownload.Body.String())
	}

	offlineID := "offline-linked-recording-root"
	if _, err := srv.cfg.Store.SavePlatformItem("offline_sessions", model.PlatformItem{
		ID:          offlineID,
		Name:        "linked recording root",
		Type:        "rdp",
		Status:      string(model.SessionClosed),
		Protocol:    model.ProtocolRDP,
		OwnerID:     "admin",
		Description: "linked recording root fixture",
		Metadata: map[string]any{
			"recording_path": linkPath,
		},
	}); err != nil {
		t.Fatalf("save offline linked recording root: %v", err)
	}
	auditDownload := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/offline-sessions/"+offlineID+"/recording", nil, adminCookie, http.StatusBadRequest)
	if strings.Contains(auditDownload.Body.String(), externalContent) {
		t.Fatalf("audit recording download leaked external content: %s", auditDownload.Body.String())
	}
	assertStatus(t, handler, http.MethodDelete, "/api/admin/audit/offline-sessions/"+offlineID+"/recording", nil, adminCookie, http.StatusBadRequest)
	if data, err := os.ReadFile(externalFile); err != nil || string(data) != externalContent {
		t.Fatalf("external recording file changed after rejected delete: content=%q err=%v", string(data), err)
	}
	if _, err := os.Lstat(linkPath); err != nil {
		t.Fatalf("rejected recording delete removed local symlink: %v", err)
	}
	deleted, bytes, err := srv.deleteSessionRecordingPath(linkPath)
	if err != nil || deleted || bytes != 0 {
		t.Fatalf("cleanup linked recording root = deleted %v bytes %d err %v, want no-op", deleted, bytes, err)
	}
	if data, err := os.ReadFile(externalFile); err != nil || string(data) != externalContent {
		t.Fatalf("external recording file changed after cleanup: content=%q err=%v", string(data), err)
	}
}

func TestDesktopSessionDriveFiles(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)

	windowsRec := assertStatus(t, handler, http.MethodPost, "/api/servers", map[string]any{
		"name":     "windows-drive",
		"host":     "127.0.0.1",
		"os":       "windows",
		"rdp_port": 3389,
	}, adminCookie, http.StatusCreated)
	var windows model.Server
	decodeResponse(t, windowsRec, &windows)
	rdpCredRec := assertStatus(t, handler, http.MethodPost, "/api/credentials", map[string]any{
		"name":      "rdp-drive-admin",
		"server_id": windows.ID,
		"type":      "rdp_password",
		"username":  "Administrator",
		"password":  "secret",
	}, adminCookie, http.StatusCreated)
	var rdpCred model.CredentialPublic
	decodeResponse(t, rdpCredRec, &rdpCred)
	sessionRec := assertStatus(t, handler, http.MethodPost, "/api/connections/rdp", map[string]any{
		"server_id":     windows.ID,
		"credential_id": rdpCred.ID,
	}, adminCookie, http.StatusCreated)
	var session model.ConnectionSession
	decodeResponse(t, sessionRec, &session)

	driveRoot := filepath.Join(srv.cfg.DataDir, "drives", session.ID, "reports")
	if err := os.MkdirAll(driveRoot, 0o770); err != nil {
		t.Fatalf("create session drive: %v", err)
	}
	if err := os.WriteFile(filepath.Join(driveRoot, "download.txt"), []byte("desktop file"), 0o660); err != nil {
		t.Fatalf("write drive download file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(driveRoot, "remove.txt"), []byte("delete me"), 0o660); err != nil {
		t.Fatalf("write drive delete file: %v", err)
	}
	externalDriveContent := "external desktop drive secret"
	externalDrivePath := filepath.Join(t.TempDir(), "outside-drive.txt")
	if err := os.WriteFile(externalDrivePath, []byte(externalDriveContent), 0o660); err != nil {
		t.Fatalf("write external drive fixture: %v", err)
	}
	driveSymlinkCreated := true
	if err := os.Symlink(externalDrivePath, filepath.Join(driveRoot, "linked.txt")); err != nil {
		driveSymlinkCreated = false
		t.Logf("skip desktop drive symlink assertion: %v", err)
	}
	externalDriveDir := filepath.Join(t.TempDir(), "outside-drive-dir")
	if err := os.MkdirAll(externalDriveDir, 0o770); err != nil {
		t.Fatalf("create external drive directory fixture: %v", err)
	}
	externalDriveDirFile := filepath.Join(externalDriveDir, "inside.txt")
	if err := os.WriteFile(externalDriveDirFile, []byte("external desktop dir file"), 0o660); err != nil {
		t.Fatalf("write external drive directory file fixture: %v", err)
	}
	driveDirSymlinkCreated := true
	if err := os.Symlink(externalDriveDir, filepath.Join(driveRoot, "linked-dir")); err != nil {
		driveDirSymlinkCreated = false
		t.Logf("skip desktop drive directory symlink assertion: %v", err)
	}

	assertMultipartStatus(t, handler, "/api/connections/"+session.ID+"/drive/upload", map[string]string{"path": "../secret"}, "escape.txt", []byte("escape"), adminCookie, http.StatusForbidden)
	uploadRec := assertMultipartStatus(t, handler, "/api/connections/"+session.ID+"/drive/upload", map[string]string{"path": "reports"}, `C:\Users\ops\Downloads\uploaded.bin`, []byte{4, 5, 6}, adminCookie, http.StatusCreated)
	if !strings.Contains(uploadRec.Body.String(), `"name":"uploaded.bin"`) || strings.Contains(uploadRec.Body.String(), `C:\Users\ops`) {
		t.Fatalf("drive upload leaked unsafe filename: %s", uploadRec.Body.String())
	}

	rootList := assertStatus(t, handler, http.MethodGet, "/api/connections/"+session.ID+"/drive", nil, adminCookie, http.StatusOK)
	if !strings.Contains(rootList.Body.String(), `"name":"reports"`) {
		t.Fatalf("drive root did not list reports directory: %s", rootList.Body.String())
	}
	reportsList := assertStatus(t, handler, http.MethodGet, "/api/connections/"+session.ID+"/drive?path=reports", nil, adminCookie, http.StatusOK)
	if !strings.Contains(reportsList.Body.String(), `"name":"download.txt"`) || !strings.Contains(reportsList.Body.String(), `"name":"remove.txt"`) || !strings.Contains(reportsList.Body.String(), `"name":"uploaded.bin"`) {
		t.Fatalf("drive reports did not list files: %s", reportsList.Body.String())
	}
	downloadRec := assertStatus(t, handler, http.MethodGet, "/api/connections/"+session.ID+"/drive/download?path=reports/download.txt", nil, adminCookie, http.StatusOK)
	if strings.TrimSpace(downloadRec.Body.String()) != "desktop file" {
		t.Fatalf("drive download body = %q", downloadRec.Body.String())
	}
	if contentDisposition := downloadRec.Header().Get("Content-Disposition"); !strings.Contains(contentDisposition, `filename="download.txt"`) {
		t.Fatalf("drive download missing safe attachment filename: %s", contentDisposition)
	}
	uploadDownloadRec := assertStatus(t, handler, http.MethodGet, "/api/connections/"+session.ID+"/drive/download?path=reports/uploaded.bin", nil, adminCookie, http.StatusOK)
	if !bytes.Equal(uploadDownloadRec.Body.Bytes(), []byte{4, 5, 6}) {
		t.Fatalf("drive uploaded download body = %v", uploadDownloadRec.Body.Bytes())
	}
	assertStatus(t, handler, http.MethodGet, "/api/connections/"+session.ID+"/drive/download?path=../secret.txt", nil, adminCookie, http.StatusForbidden)
	if driveSymlinkCreated {
		symlinkDownload := assertStatus(t, handler, http.MethodGet, "/api/connections/"+session.ID+"/drive/download?path=reports/linked.txt", nil, adminCookie, http.StatusBadRequest)
		if strings.Contains(symlinkDownload.Body.String(), externalDriveContent) {
			t.Fatalf("desktop drive symlink download leaked external content: %s", symlinkDownload.Body.String())
		}
		assertMultipartStatus(t, handler, "/api/connections/"+session.ID+"/drive/upload", map[string]string{"path": "reports"}, "linked.txt", []byte("overwrite"), adminCookie, http.StatusBadRequest)
		assertStatus(t, handler, http.MethodDelete, "/api/connections/"+session.ID+"/drive?path=reports/linked.txt", nil, adminCookie, http.StatusBadRequest)
		if _, err := os.Lstat(filepath.Join(driveRoot, "linked.txt")); err != nil {
			t.Fatalf("desktop drive symlink was removed by rejected delete: %v", err)
		}
		if data, err := os.ReadFile(externalDrivePath); err != nil || string(data) != externalDriveContent {
			t.Fatalf("external desktop drive symlink target changed: content=%q err=%v", string(data), err)
		}
	}
	if driveDirSymlinkCreated {
		linkedDirList := assertStatus(t, handler, http.MethodGet, "/api/connections/"+session.ID+"/drive?path=reports/linked-dir", nil, adminCookie, http.StatusBadRequest)
		if strings.Contains(linkedDirList.Body.String(), "inside.txt") {
			t.Fatalf("desktop drive symlink directory list leaked external entries: %s", linkedDirList.Body.String())
		}
		nestedSymlinkDownload := assertStatus(t, handler, http.MethodGet, "/api/connections/"+session.ID+"/drive/download?path=reports/linked-dir/inside.txt", nil, adminCookie, http.StatusBadRequest)
		if strings.Contains(nestedSymlinkDownload.Body.String(), "external desktop dir file") {
			t.Fatalf("desktop drive symlink nested download leaked external content: %s", nestedSymlinkDownload.Body.String())
		}
		assertStatus(t, handler, http.MethodDelete, "/api/connections/"+session.ID+"/drive?path=reports/linked-dir/inside.txt", nil, adminCookie, http.StatusBadRequest)
		assertStatus(t, handler, http.MethodDelete, "/api/connections/"+session.ID+"/drive?path=reports/linked-dir", nil, adminCookie, http.StatusBadRequest)
		if _, err := os.Lstat(filepath.Join(driveRoot, "linked-dir")); err != nil {
			t.Fatalf("desktop drive directory symlink was removed by rejected delete: %v", err)
		}
		if data, err := os.ReadFile(externalDriveDirFile); err != nil || string(data) != "external desktop dir file" {
			t.Fatalf("external desktop drive directory file changed: content=%q err=%v", string(data), err)
		}
		assertMultipartStatus(t, handler, "/api/connections/"+session.ID+"/drive/upload", map[string]string{"path": "reports/linked-dir"}, "escaped.txt", []byte("escape"), adminCookie, http.StatusBadRequest)
		if _, err := os.Stat(filepath.Join(externalDriveDir, "escaped.txt")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("desktop drive directory symlink upload created outside file: %v", err)
		}
	}
	assertStatus(t, handler, http.MethodDelete, "/api/connections/"+session.ID+"/drive?path=reports/remove.txt", nil, adminCookie, http.StatusOK)
	if _, err := os.Stat(filepath.Join(driveRoot, "remove.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("drive delete did not remove file: %v", err)
	}

	assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name":     "drive-other-user",
		"type":     "local",
		"status":   "enabled",
		"password": "password123",
		"metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	otherLogin := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": "drive-other-user", "password": "password123"}, nil, http.StatusOK)
	otherCookie := otherLogin.Result().Cookies()[0]
	assertStatus(t, handler, http.MethodGet, "/api/connections/"+session.ID+"/drive", nil, otherCookie, http.StatusForbidden)

	disabled := false
	if _, err := srv.cfg.Store.UpdateSession(session.ID, func(item *model.ConnectionSession) {
		item.FileTransferEnabled = &disabled
	}); err != nil {
		t.Fatalf("disable file transfer: %v", err)
	}
	assertStatus(t, handler, http.MethodGet, "/api/connections/"+session.ID+"/drive", nil, adminCookie, http.StatusForbidden)
	assertMultipartStatus(t, handler, "/api/connections/"+session.ID+"/drive/upload", map[string]string{"path": "reports"}, "blocked.txt", []byte("blocked"), adminCookie, http.StatusForbidden)

	fileLogs := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/file-logs", nil, adminCookie, http.StatusOK)
	for _, want := range []string{session.ID, "upload", "download", "delete", "denied", "session_access", "file_transfer_disabled"} {
		if !strings.Contains(fileLogs.Body.String(), want) {
			t.Fatalf("drive file log missing %q: %s", want, fileLogs.Body.String())
		}
	}
	if !strings.Contains(fileLogs.Body.String(), `"filename":"uploaded.bin"`) || strings.Contains(fileLogs.Body.String(), `C:\Users\ops`) || strings.Contains(fileLogs.Body.String(), `Downloads\`) {
		t.Fatalf("drive file log leaked unsafe filename: %s", fileLogs.Body.String())
	}
	operationLogs := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	for _, want := range []string{"connection.drive.list.denied", "connection.drive.upload.denied"} {
		if !strings.Contains(operationLogs.Body.String(), want) {
			t.Fatalf("drive denied operation log missing %q: %s", want, operationLogs.Body.String())
		}
	}
}

func TestDesktopDriveFileLogPersistenceFailureReturnsServerError(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)

	windowsRec := assertStatus(t, handler, http.MethodPost, "/api/servers", map[string]any{
		"name":     "windows-drive-log",
		"host":     "127.0.0.1",
		"os":       "windows",
		"rdp_port": 3389,
	}, adminCookie, http.StatusCreated)
	var windows model.Server
	decodeResponse(t, windowsRec, &windows)
	rdpCredRec := assertStatus(t, handler, http.MethodPost, "/api/credentials", map[string]any{
		"name":      "rdp-drive-log-admin",
		"server_id": windows.ID,
		"type":      "rdp_password",
		"username":  "Administrator",
		"password":  "secret",
	}, adminCookie, http.StatusCreated)
	var rdpCred model.CredentialPublic
	decodeResponse(t, rdpCredRec, &rdpCred)
	sessionRec := assertStatus(t, handler, http.MethodPost, "/api/connections/rdp", map[string]any{
		"server_id":     windows.ID,
		"credential_id": rdpCred.ID,
	}, adminCookie, http.StatusCreated)
	var session model.ConnectionSession
	decodeResponse(t, sessionRec, &session)

	driveRoot := filepath.Join(srv.cfg.DataDir, "drives", session.ID, "reports")
	if err := os.MkdirAll(driveRoot, 0o770); err != nil {
		t.Fatalf("create session drive: %v", err)
	}
	if err := os.WriteFile(filepath.Join(driveRoot, "download.txt"), []byte("desktop file"), 0o660); err != nil {
		t.Fatalf("write drive download file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(driveRoot, "delete.txt"), []byte("desktop delete"), 0o660); err != nil {
		t.Fatalf("write drive delete file: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(driveRoot, "delete-dir"), 0o770); err != nil {
		t.Fatalf("create drive delete directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(driveRoot, "delete-dir", "nested.txt"), []byte("desktop delete dir"), 0o660); err != nil {
		t.Fatalf("write drive delete directory file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(driveRoot, "overwrite.txt"), []byte("desktop old"), 0o660); err != nil {
		t.Fatalf("write drive overwrite file: %v", err)
	}

	removeBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "file_logs")
	downloadRec := assertStatus(t, handler, http.MethodGet, "/api/connections/"+session.ID+"/drive/download?path=reports/download.txt", nil, adminCookie, http.StatusInternalServerError)
	removeBlocker()
	if !strings.Contains(downloadRec.Body.String(), "persist file log failed") {
		t.Fatalf("desktop drive file log persistence failure was not reported: %s", downloadRec.Body.String())
	}
	if strings.Contains(downloadRec.Body.String(), "desktop file") {
		t.Fatalf("desktop drive download returned file content after audit log failure: %s", downloadRec.Body.String())
	}
	operationLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(operationLogsRec.Body.String(), "file.log.persist_failed") {
		t.Fatalf("desktop drive file log persistence failure was not audited: %s", operationLogsRec.Body.String())
	}

	removeUploadBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "file_logs")
	uploadRec := assertMultipartStatus(t, handler, "/api/connections/"+session.ID+"/drive/upload", map[string]string{"path": "reports"}, "upload-new.txt", []byte("desktop upload"), adminCookie, http.StatusInternalServerError)
	removeUploadBlocker()
	if !strings.Contains(uploadRec.Body.String(), "persist file log failed") {
		t.Fatalf("desktop drive upload file log persistence failure was not reported: %s", uploadRec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(driveRoot, "upload-new.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("desktop drive upload left a new file before file log persisted: %v", err)
	}

	removeOverwriteBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "file_logs")
	overwriteRec := assertMultipartStatus(t, handler, "/api/connections/"+session.ID+"/drive/upload", map[string]string{"path": "reports"}, "overwrite.txt", []byte("desktop new"), adminCookie, http.StatusInternalServerError)
	removeOverwriteBlocker()
	if !strings.Contains(overwriteRec.Body.String(), "persist file log failed") {
		t.Fatalf("desktop drive overwrite file log persistence failure was not reported: %s", overwriteRec.Body.String())
	}
	if data, err := os.ReadFile(filepath.Join(driveRoot, "overwrite.txt")); err != nil || string(data) != "desktop old" {
		t.Fatalf("desktop drive overwrite did not restore old content after file log failure: data=%q err=%v", string(data), err)
	}

	removeDeleteBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "file_logs")
	deleteRec := assertStatus(t, handler, http.MethodDelete, "/api/connections/"+session.ID+"/drive?path=reports/delete.txt", nil, adminCookie, http.StatusInternalServerError)
	removeDeleteBlocker()
	if !strings.Contains(deleteRec.Body.String(), "persist file log failed") {
		t.Fatalf("desktop drive delete file log persistence failure was not reported: %s", deleteRec.Body.String())
	}
	if data, err := os.ReadFile(filepath.Join(driveRoot, "delete.txt")); err != nil || string(data) != "desktop delete" {
		t.Fatalf("desktop drive delete removed file before file log persisted: data=%q err=%v", string(data), err)
	}

	removeDeleteDirBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "file_logs")
	deleteDirRec := assertStatus(t, handler, http.MethodDelete, "/api/connections/"+session.ID+"/drive?path=reports/delete-dir", nil, adminCookie, http.StatusInternalServerError)
	removeDeleteDirBlocker()
	if !strings.Contains(deleteDirRec.Body.String(), "persist file log failed") {
		t.Fatalf("desktop drive directory delete file log persistence failure was not reported: %s", deleteDirRec.Body.String())
	}
	if data, err := os.ReadFile(filepath.Join(driveRoot, "delete-dir", "nested.txt")); err != nil || string(data) != "desktop delete dir" {
		t.Fatalf("desktop drive directory delete did not restore content after file log failure: data=%q err=%v", string(data), err)
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

type testPasskeyCreationOptionsResponse struct {
	ChallengeID string                 `json:"challenge_id"`
	PublicKey   passkeyCreationOptions `json:"publicKey"`
}

type testPasskeyRequestOptionsResponse struct {
	ChallengeID string                `json:"challenge_id"`
	PublicKey   passkeyRequestOptions `json:"publicKey"`
}

func registerTestPasskey(t *testing.T, handler http.Handler, cookie *http.Cookie, username string) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	privateKey, credentialID, _ := registerTestPasskeyWithCredentialID(t, handler, cookie, username, []byte("test-passkey-credential"))
	return privateKey, credentialID
}

func registerTestPasskeyWithCredentialID(t *testing.T, handler http.Handler, cookie *http.Cookie, username string, credentialID []byte) (*ecdsa.PrivateKey, []byte, passkeyPublicItem) {
	t.Helper()
	optionsRec := assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/register/options", map[string]any{}, cookie, http.StatusOK)
	var options testPasskeyCreationOptionsResponse
	decodeResponse(t, optionsRec, &options)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate passkey key: %v", err)
	}
	payload := testPasskeyRegistrationPayload(t, options, username, credentialID, privateKey)
	verifyRec := assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/register/verify", payload, cookie, http.StatusCreated)
	assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/register/verify", payload, cookie, http.StatusUnauthorized)
	var item passkeyPublicItem
	decodeResponse(t, verifyRec, &item)
	return privateKey, credentialID, item
}

func testPasskeyRegistrationPayload(t *testing.T, options testPasskeyCreationOptionsResponse, username string, credentialID []byte, privateKey *ecdsa.PrivateKey) map[string]any {
	t.Helper()
	clientData := testPasskeyClientData(t, "webauthn.create", options.PublicKey.Challenge)
	attestation := testPasskeyAttestation(t, options.PublicKey.RP.ID, credentialID, privateKey, 1)
	return map[string]any{
		"challenge_id": options.ChallengeID,
		"name":         username + " test passkey",
		"id":           passkeyBase64Encode(credentialID),
		"raw_id":       passkeyBase64Encode(credentialID),
		"type":         "public-key",
		"response": map[string]any{
			"client_data_json":   passkeyBase64Encode(clientData),
			"attestation_object": passkeyBase64Encode(attestation),
		},
	}
}

func testPasskeyLoginOptions(t *testing.T, handler http.Handler, username string) testPasskeyRequestOptionsResponse {
	t.Helper()
	rec := assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/login/options", map[string]any{"username": username}, nil, http.StatusOK)
	var options testPasskeyRequestOptionsResponse
	decodeResponse(t, rec, &options)
	if options.ChallengeID == "" || options.PublicKey.Challenge == "" || len(options.PublicKey.AllowCredentials) == 0 {
		t.Fatalf("invalid passkey login options: %#v", options)
	}
	return options
}

func testPasskeyClientData(t *testing.T, typ, challenge string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"type":      typ,
		"challenge": challenge,
		"origin":    "http://example.com",
	})
	if err != nil {
		t.Fatalf("marshal client data: %v", err)
	}
	return raw
}

func testPasskeyAttestation(t *testing.T, rpID string, credentialID []byte, privateKey *ecdsa.PrivateKey, signCount uint32) []byte {
	t.Helper()
	x := privateKey.PublicKey.X.FillBytes(make([]byte, 32))
	y := privateKey.PublicKey.Y.FillBytes(make([]byte, 32))
	coseKey, err := cbor.Marshal(map[int]any{
		1:  2,
		3:  -7,
		-1: 1,
		-2: x,
		-3: y,
	})
	if err != nil {
		t.Fatalf("marshal cose key: %v", err)
	}
	rpHash := sha256.Sum256([]byte(rpID))
	authData := make([]byte, 0, 37+16+2+len(credentialID)+len(coseKey))
	authData = append(authData, rpHash[:]...)
	authData = append(authData, 0x41)
	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, signCount)
	authData = append(authData, counter...)
	authData = append(authData, make([]byte, 16)...)
	credentialLen := make([]byte, 2)
	binary.BigEndian.PutUint16(credentialLen, uint16(len(credentialID)))
	authData = append(authData, credentialLen...)
	authData = append(authData, credentialID...)
	authData = append(authData, coseKey...)
	attestation, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"authData": authData,
		"attStmt":  map[string]any{},
	})
	if err != nil {
		t.Fatalf("marshal attestation: %v", err)
	}
	return attestation
}

func testPasskeyAssertionPayload(t *testing.T, challengeID, challenge, rpID string, credentialID []byte, privateKey *ecdsa.PrivateKey, signCount uint32, corruptSignature bool) map[string]any {
	t.Helper()
	clientData := testPasskeyClientData(t, "webauthn.get", challenge)
	authenticatorData := testPasskeyAssertionAuthData(t, rpID, signCount)
	clientHash := sha256.Sum256(clientData)
	signed := append(append([]byte{}, authenticatorData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	if corruptSignature && len(signature) > 0 {
		signature[len(signature)-1] ^= 0xff
	}
	return map[string]any{
		"challenge_id": challengeID,
		"id":           passkeyBase64Encode(credentialID),
		"raw_id":       passkeyBase64Encode(credentialID),
		"type":         "public-key",
		"response": map[string]any{
			"client_data_json":   passkeyBase64Encode(clientData),
			"authenticator_data": passkeyBase64Encode(authenticatorData),
			"signature":          passkeyBase64Encode(signature),
		},
	}
}

func testPasskeyAssertionAuthData(t *testing.T, rpID string, signCount uint32) []byte {
	t.Helper()
	rpHash := sha256.Sum256([]byte(rpID))
	authData := make([]byte, 0, 37)
	authData = append(authData, rpHash[:]...)
	authData = append(authData, 0x01)
	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, signCount)
	authData = append(authData, counter...)
	return authData
}

func testMTLSMaterials(t *testing.T) ([]byte, []byte, []byte, tls.Certificate) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          testSerialNumber(t),
		Subject:               pkix.Name{CommonName: "owm-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: testSerialNumber(t),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:     []string{"localhost"},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server certificate: %v", err)
	}
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("parse server key pair: %v", err)
	}

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: testSerialNumber(t),
		Subject:      pkix.Name{CommonName: "owm-mtls-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client certificate: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})
	return caPEM, clientCertPEM, clientKeyPEM, serverCert
}

func testSerialNumber(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	return serial
}

func newTestHandler(t *testing.T) (http.Handler, *http.Cookie) {
	server, cookie := newTestServer(t, nil)
	return server, cookie
}

func newTestServer(t *testing.T, configure func(*Config)) (*Server, *http.Cookie) {
	t.Helper()
	server := newUnconfiguredTestServer(t, configure)
	rec := assertStatus(t, server, http.MethodPost, "/api/auth/setup", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusCreated)
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("setup did not set auth cookie")
	}
	return server, cookies[0]
}

func newUnconfiguredTestServer(t *testing.T, configure func(*Config)) *Server {
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
	cfg := Config{
		Store:    st,
		Guacd:    guac.NewManager(guac.ManagerConfig{}),
		StaticFS: fstest.MapFS{"static/index.html": &fstest.MapFile{Data: []byte("<html></html>")}},
		DataDir:  t.TempDir(),
	}
	if configure != nil {
		configure(&cfg)
	}
	return NewServer(cfg)
}

func blockSQLWorkOrderStatusUpdate(t *testing.T, st *store.Store, orderID, status string) func() {
	t.Helper()
	return blockPlatformItemStatusUpdate(t, st, "sql_work_orders", orderID, status)
}

func insertRawPlatformRecord(t *testing.T, st *store.Store, collection, id, payload string) func() {
	t.Helper()
	db, err := sql.Open("sqlite", st.DatabasePath())
	if err != nil {
		t.Fatalf("open store database for raw platform record: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT OR REPLACE INTO platform_records(collection, id, payload, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`, collection, id, payload, now, now); err != nil {
		_ = db.Close()
		t.Fatalf("insert raw platform record: %v", err)
	}
	return func() {
		_, _ = db.Exec(`DELETE FROM platform_records WHERE collection = ? AND id = ?`, collection, id)
		_ = db.Close()
	}
}

func deletePlatformRecordsPayloadFragment(t *testing.T, st *store.Store, collection, fragment string) {
	t.Helper()
	db, err := sql.Open("sqlite", st.DatabasePath())
	if err != nil {
		t.Fatalf("open store database for payload cleanup: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`DELETE FROM platform_records WHERE collection = ? AND instr(payload, ?) > 0`, collection, fragment); err != nil {
		t.Fatalf("delete platform payload cleanup: %v", err)
	}
}

func blockPlatformItemCreate(t *testing.T, st *store.Store, collection string) func() {
	t.Helper()
	db, err := sql.Open("sqlite", st.DatabasePath())
	if err != nil {
		t.Fatalf("open store database for create blocker: %v", err)
	}
	triggerName := "block_platform_item_create"
	if _, err := db.Exec(`DROP TRIGGER IF EXISTS ` + triggerName); err != nil {
		_ = db.Close()
		t.Fatalf("drop stale create blocker trigger: %v", err)
	}
	triggerSQL := `CREATE TRIGGER ` + triggerName + ` BEFORE INSERT ON platform_records
WHEN NEW.collection = ` + sqliteTestStringLiteral(collection) + `
BEGIN
  SELECT RAISE(ABORT, 'forced platform item create failure');
END`
	if _, err := db.Exec(triggerSQL); err != nil {
		_ = db.Close()
		t.Fatalf("create platform item blocker trigger: %v", err)
	}
	return func() {
		_, _ = db.Exec(`DROP TRIGGER IF EXISTS ` + triggerName)
		_ = db.Close()
	}
}

func blockPlatformItemSave(t *testing.T, st *store.Store, collection, itemID string) func() {
	t.Helper()
	db, err := sql.Open("sqlite", st.DatabasePath())
	if err != nil {
		t.Fatalf("open store database for save blocker: %v", err)
	}
	triggerName := "block_platform_item_save"
	if _, err := db.Exec(`DROP TRIGGER IF EXISTS ` + triggerName); err != nil {
		_ = db.Close()
		t.Fatalf("drop stale save blocker trigger: %v", err)
	}
	triggerSQL := `CREATE TRIGGER ` + triggerName + ` BEFORE INSERT ON platform_records
WHEN NEW.collection = ` + sqliteTestStringLiteral(collection) + `
  AND NEW.id = ` + sqliteTestStringLiteral(itemID) + `
BEGIN
  SELECT RAISE(ABORT, 'forced platform item save failure');
END`
	if _, err := db.Exec(triggerSQL); err != nil {
		_ = db.Close()
		t.Fatalf("create platform item save blocker trigger: %v", err)
	}
	return func() {
		_, _ = db.Exec(`DROP TRIGGER IF EXISTS ` + triggerName)
		_ = db.Close()
	}
}

func blockPlatformItemSavePayloadFragment(t *testing.T, st *store.Store, collection, itemID, fragment string) func() {
	t.Helper()
	db, err := sql.Open("sqlite", st.DatabasePath())
	if err != nil {
		t.Fatalf("open store database for payload save blocker: %v", err)
	}
	triggerName := "block_platform_item_save_payload_fragment"
	if _, err := db.Exec(`DROP TRIGGER IF EXISTS ` + triggerName); err != nil {
		_ = db.Close()
		t.Fatalf("drop stale payload save blocker trigger: %v", err)
	}
	triggerSQL := `CREATE TRIGGER ` + triggerName + ` BEFORE INSERT ON platform_records
WHEN NEW.collection = ` + sqliteTestStringLiteral(collection) + `
  AND NEW.id = ` + sqliteTestStringLiteral(itemID) + `
  AND instr(NEW.payload, ` + sqliteTestStringLiteral(fragment) + `) > 0
BEGIN
  SELECT RAISE(ABORT, 'forced platform item payload save failure');
END`
	if _, err := db.Exec(triggerSQL); err != nil {
		_ = db.Close()
		t.Fatalf("create platform item payload save blocker trigger: %v", err)
	}
	return func() {
		_, _ = db.Exec(`DROP TRIGGER IF EXISTS ` + triggerName)
		_ = db.Close()
	}
}

func blockPlatformCollectionSavePayloadFragment(t *testing.T, st *store.Store, collection, fragment string) func() {
	t.Helper()
	db, err := sql.Open("sqlite", st.DatabasePath())
	if err != nil {
		t.Fatalf("open store database for collection payload save blocker: %v", err)
	}
	triggerName := "block_platform_collection_save_payload_fragment"
	if _, err := db.Exec(`DROP TRIGGER IF EXISTS ` + triggerName); err != nil {
		_ = db.Close()
		t.Fatalf("drop stale collection payload save blocker trigger: %v", err)
	}
	triggerSQL := `CREATE TRIGGER ` + triggerName + ` BEFORE INSERT ON platform_records
WHEN NEW.collection = ` + sqliteTestStringLiteral(collection) + `
  AND instr(NEW.payload, ` + sqliteTestStringLiteral(fragment) + `) > 0
BEGIN
  SELECT RAISE(ABORT, 'forced platform collection payload save failure');
END`
	if _, err := db.Exec(triggerSQL); err != nil {
		_ = db.Close()
		t.Fatalf("create platform collection payload save blocker trigger: %v", err)
	}
	return func() {
		_, _ = db.Exec(`DROP TRIGGER IF EXISTS ` + triggerName)
		_ = db.Close()
	}
}

func blockPlatformItemDeletePayloadFragment(t *testing.T, st *store.Store, collection, fragment string) func() {
	t.Helper()
	db, err := sql.Open("sqlite", st.DatabasePath())
	if err != nil {
		t.Fatalf("open store database for payload delete blocker: %v", err)
	}
	triggerName := "block_platform_item_delete_payload_fragment"
	if _, err := db.Exec(`DROP TRIGGER IF EXISTS ` + triggerName); err != nil {
		_ = db.Close()
		t.Fatalf("drop stale payload delete blocker trigger: %v", err)
	}
	triggerSQL := `CREATE TRIGGER ` + triggerName + ` BEFORE DELETE ON platform_records
WHEN OLD.collection = ` + sqliteTestStringLiteral(collection) + `
  AND instr(OLD.payload, ` + sqliteTestStringLiteral(fragment) + `) > 0
BEGIN
  SELECT RAISE(ABORT, 'forced platform item payload delete failure');
END`
	if _, err := db.Exec(triggerSQL); err != nil {
		_ = db.Close()
		t.Fatalf("create platform item payload delete blocker trigger: %v", err)
	}
	return func() {
		_, _ = db.Exec(`DROP TRIGGER IF EXISTS ` + triggerName)
		_ = db.Close()
	}
}

func blockOperationLogName(t *testing.T, st *store.Store, name string) func() {
	t.Helper()
	db, err := sql.Open("sqlite", st.DatabasePath())
	if err != nil {
		t.Fatalf("open store database for operation log name blocker: %v", err)
	}
	triggerName := "block_operation_log_name"
	if _, err := db.Exec(`DROP TRIGGER IF EXISTS ` + triggerName); err != nil {
		_ = db.Close()
		t.Fatalf("drop stale operation log name blocker trigger: %v", err)
	}
	nameFragment := `"name":"` + name + `"`
	triggerSQL := `CREATE TRIGGER ` + triggerName + ` BEFORE INSERT ON platform_records
WHEN NEW.collection = 'operation_logs'
  AND instr(NEW.payload, ` + sqliteTestStringLiteral(nameFragment) + `) > 0
BEGIN
  SELECT RAISE(ABORT, 'forced operation log name create failure');
END`
	if _, err := db.Exec(triggerSQL); err != nil {
		_ = db.Close()
		t.Fatalf("create operation log name blocker trigger: %v", err)
	}
	return func() {
		_, _ = db.Exec(`DROP TRIGGER IF EXISTS ` + triggerName)
		_ = db.Close()
	}
}

func blockPlatformItemStatusUpdate(t *testing.T, st *store.Store, collection, itemID, status string) func() {
	t.Helper()
	db, err := sql.Open("sqlite", st.DatabasePath())
	if err != nil {
		t.Fatalf("open store database for status blocker: %v", err)
	}
	triggerName := "block_platform_item_status_update"
	if _, err := db.Exec(`DROP TRIGGER IF EXISTS ` + triggerName); err != nil {
		_ = db.Close()
		t.Fatalf("drop stale status blocker trigger: %v", err)
	}
	statusFragment := `"status":"` + status + `"`
	triggerSQL := `CREATE TRIGGER ` + triggerName + ` BEFORE INSERT ON platform_records
WHEN NEW.collection = ` + sqliteTestStringLiteral(collection) + `
  AND NEW.id = ` + sqliteTestStringLiteral(itemID) + `
  AND instr(NEW.payload, ` + sqliteTestStringLiteral(statusFragment) + `) > 0
BEGIN
  SELECT RAISE(ABORT, 'forced platform item status update failure');
END`
	if _, err := db.Exec(triggerSQL); err != nil {
		_ = db.Close()
		t.Fatalf("create status blocker trigger: %v", err)
	}
	return func() {
		_, _ = db.Exec(`DROP TRIGGER IF EXISTS ` + triggerName)
		_ = db.Close()
	}
}

func blockPlatformItemCollectionStatusUpdate(t *testing.T, st *store.Store, collection, status string) func() {
	t.Helper()
	db, err := sql.Open("sqlite", st.DatabasePath())
	if err != nil {
		t.Fatalf("open store database for collection status blocker: %v", err)
	}
	triggerName := "block_platform_item_collection_status_update"
	if _, err := db.Exec(`DROP TRIGGER IF EXISTS ` + triggerName); err != nil {
		_ = db.Close()
		t.Fatalf("drop stale collection status blocker trigger: %v", err)
	}
	statusFragment := `"status":"` + status + `"`
	triggerSQL := `CREATE TRIGGER ` + triggerName + ` BEFORE INSERT ON platform_records
WHEN NEW.collection = ` + sqliteTestStringLiteral(collection) + `
  AND instr(NEW.payload, ` + sqliteTestStringLiteral(statusFragment) + `) > 0
BEGIN
  SELECT RAISE(ABORT, 'forced platform item collection status update failure');
END`
	if _, err := db.Exec(triggerSQL); err != nil {
		_ = db.Close()
		t.Fatalf("create collection status blocker trigger: %v", err)
	}
	return func() {
		_, _ = db.Exec(`DROP TRIGGER IF EXISTS ` + triggerName)
		_ = db.Close()
	}
}

func sqliteTestStringLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

type fakeSSHGatewayRuntime struct {
	address string
	errText string
	reloads int
}

func (f *fakeSSHGatewayRuntime) Address() string {
	return f.address
}

func (f *fakeSSHGatewayRuntime) Reload() error {
	f.reloads++
	return nil
}

func (f *fakeSSHGatewayRuntime) LastError() string {
	return f.errText
}

func startAppTestTCPListener(t *testing.T) (net.Listener, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp test server: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	return listener, func() {
		_ = listener.Close()
		<-done
	}
}

func startEchoTCPServer(t *testing.T) (string, <-chan string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo tcp server: %v", err)
	}
	received := make(chan string, 10)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				line, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					return
				}
				received <- line
				_, _ = conn.Write([]byte("echo:" + line))
			}(conn)
		}
	}()
	return listener.Addr().String(), received, func() {
		_ = listener.Close()
		<-done
	}
}

func freeLocalTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen free tcp address: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("close free tcp listener: %v", err)
	}
	return address
}

func waitForCondition(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	if condition() {
		return
	}
	t.Fatalf("condition was not met within %s", timeout)
}

func scheduledTaskLogsForTest(t *testing.T, srv *Server, taskID string) []model.PlatformItem {
	t.Helper()
	items, err := srv.cfg.Store.ListPlatformItems("operation_logs")
	if err != nil {
		t.Fatalf("list operation logs: %v", err)
	}
	result := []model.PlatformItem{}
	for _, item := range items {
		if item.Type == "scheduled_task" && item.TargetID == taskID {
			result = append(result, item)
		}
	}
	return result
}

func connectionSessionsForTarget(t *testing.T, srv *Server, targetID string) int {
	t.Helper()
	_, _, sessions, _ := srv.cfg.Store.Bootstrap()
	count := 0
	for _, session := range sessions {
		if session.ServerID == targetID {
			count++
		}
	}
	return count
}

func platformItemsForTarget(t *testing.T, srv *Server, collection, targetID string) int {
	t.Helper()
	items, err := srv.cfg.Store.ListPlatformItems(collection)
	if err != nil {
		t.Fatalf("list %s: %v", collection, err)
	}
	count := 0
	for _, item := range items {
		if item.TargetID == targetID {
			count++
		}
	}
	return count
}

func recordingDirCountForTest(t *testing.T, srv *Server) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(srv.cfg.DataDir, "recordings"))
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		t.Fatalf("read recordings dir: %v", err)
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			count++
		}
	}
	return count
}

type fakeLDAPUser struct {
	password string
	claims   externalLDAPClaims
}

type fakeLDAPAuthenticator struct {
	users        map[string]fakeLDAPUser
	err          error
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
	if f.err != nil {
		return externalLDAPClaims{}, false, f.err
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
	auths    chan string
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
		auths:    make(chan string, 4),
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
			go handleFakeSMTPConnection(conn, server.messages, server.auths)
		}
	}()
	return server
}

func newFailingSMTPAuthServer(t *testing.T, failure string) fakeSMTPServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failing smtp: %v", err)
	}
	server := fakeSMTPServer{
		addr:     listener.Addr().String(),
		messages: make(chan string, 1),
		auths:    make(chan string, 1),
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
			go handleFailingSMTPAuthConnection(conn, failure)
		}
	}()
	return server
}

func handleFakeSMTPConnection(conn net.Conn, messages chan<- string, auths chan<- string) {
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
			select {
			case auths <- trimmed:
			default:
			}
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

func handleFailingSMTPAuthConnection(conn net.Conn, failure string) {
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
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		trimmed := strings.TrimRight(line, "\r\n")
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
			_ = writeLine("535 " + failure)
			return
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

func assertRawStatus(t *testing.T, handler http.Handler, method, path, contentType, body string, cookie *http.Cookie, want int) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
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

func assertZipOmitsEntryAndContent(t *testing.T, raw []byte, filename, content string) {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	for _, file := range reader.File {
		if file.Name == filename {
			t.Fatalf("zip entry %q should have been omitted", filename)
		}
		rc, err := file.Open()
		if err != nil {
			t.Fatalf("open zip entry: %v", err)
		}
		data, err := io.ReadAll(rc)
		closeErr := rc.Close()
		if err != nil {
			t.Fatalf("read zip entry: %v", err)
		}
		if closeErr != nil {
			t.Fatalf("close zip entry: %v", closeErr)
		}
		if content != "" && strings.Contains(string(data), content) {
			t.Fatalf("zip entry %q leaked omitted content", file.Name)
		}
	}
}

func zipEntryText(t *testing.T, reader *zip.Reader, filename string) string {
	t.Helper()
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
		return string(data)
	}
	t.Fatalf("zip entry %q not found", filename)
	return ""
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

func rawPlatformUserByName(t *testing.T, srv *Server, username string) model.PlatformItem {
	t.Helper()
	items, err := srv.cfg.Store.ListPlatformItems("users")
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	for _, item := range items {
		if item.Name == username {
			return item
		}
	}
	t.Fatalf("user %s not found", username)
	return model.PlatformItem{}
}

func assertNoAuthSessionForUsername(t *testing.T, srv *Server, username string) {
	t.Helper()
	srv.auth.mu.RLock()
	defer srv.auth.mu.RUnlock()
	for token, session := range srv.auth.sessions {
		if session.Username == username {
			t.Fatalf("auth session remained for %q under token %q", username, token)
		}
	}
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
