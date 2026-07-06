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
	"encoding/json"
	"encoding/pem"
	"errors"
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
		case "/root/redirect":
			http.SetCookie(w, &http.Cookie{Name: "upstream_session", Value: "abc", Domain: "upstream.internal", Path: "/root", HttpOnly: true})
			http.Redirect(w, r, "/root/dashboard?tab=1", http.StatusFound)
		case "/root/fail":
			if r.URL.Query().Get("x") != "2" {
				t.Fatalf("upstream fail query = %q, want x=2", r.URL.RawQuery)
			}
			http.Error(w, "upstream failed", http.StatusInternalServerError)
		default:
			t.Fatalf("upstream path = %q, want /root/hello, /root/redirect or /root/fail", r.URL.Path)
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
		"Connection":  "X-Remove-Me",
		"Cookie":      "upstream_theme=dark",
		"Referer":     "https://docs.example.test/start",
		"User-Agent":  "openwebservermanager-test",
		"X-Remove-Me": "secret",
	}, http.StatusOK)
	if proxyRec.Body.String() != "proxied ok" || proxyRec.Header().Get("X-Upstream") != "ok" {
		t.Fatalf("proxy response body/header = %q/%q", proxyRec.Body.String(), proxyRec.Header().Get("X-Upstream"))
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
	assertStatus(t, handler, http.MethodPost, "/api/admin/sql-work-orders/"+rejectedOrder.ID+"/reject", map[string]any{"note": "not allowed"}, adminCookie, http.StatusOK)
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

	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/sql-logs", nil, adminCookie, http.StatusOK)
	logsBody := logsRec.Body.String()
	for _, want := range []string{databaseAsset.ID, "database_access", "alpha", "missing_table", "failed", "work_order", workOrder.ID, "work_order_hosts", failingOrder.ID, "missing_work_order_table"} {
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

func TestExternalOIDCCallbackTokenFailureIsAuditedAndRedacted(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)
	var tokenEndpointCalls int
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		tokenEndpointCalls++
		http.Error(w, "provider down with openweb-secret", http.StatusBadGateway)
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
			"oidc_client_secret":          "openweb-secret",
			"oidc_scopes":                 []string{"openid", "profile"},
		},
	}, adminCookie, http.StatusCreated)
	state, _, err := srv.auth.createExternalOIDCState("broken-sso", "/app/access")
	if err != nil {
		t.Fatalf("create external oidc state: %v", err)
	}
	failedRec := assertStatus(t, handler, http.MethodGet, "/api/auth/oidc/callback?state="+url.QueryEscape(state)+"&code=broken-code", nil, nil, http.StatusBadGateway)
	if !strings.Contains(failedRec.Body.String(), "provider down") || strings.Contains(failedRec.Body.String(), "openweb-secret") {
		t.Fatalf("oidc token failure response missing sanitized reason or leaked secret: %s", failedRec.Body.String())
	}
	if tokenEndpointCalls != 1 {
		t.Fatalf("oidc token endpoint calls = %d, want 1", tokenEndpointCalls)
	}
	loginLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/login-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(loginLogsRec.Body.String(), `"type":"oidc"`) || !strings.Contains(loginLogsRec.Body.String(), `"status":"failed"`) || !strings.Contains(loginLogsRec.Body.String(), "broken-sso") || !strings.Contains(loginLogsRec.Body.String(), "provider down") || strings.Contains(loginLogsRec.Body.String(), "openweb-secret") {
		t.Fatalf("oidc token failure log missing details or leaked secret: %s", loginLogsRec.Body.String())
	}
	operationLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(operationLogsRec.Body.String(), "auth.oidc.login_failed") || strings.Contains(operationLogsRec.Body.String(), "openweb-secret") {
		t.Fatalf("oidc token failure audit missing or leaked secret: %s", operationLogsRec.Body.String())
	}
}

func TestOIDCIntegrationAuthorizationEndpointTest(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
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
			http.Error(w, "invalid client secret openweb-secret", http.StatusBadRequest)
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
			"oidc_client_secret":          "openweb-secret",
			"oidc_scopes":                 []string{"openid", "profile", "email"},
			"oidc_role":                   "user",
		},
	}, adminCookie, http.StatusCreated)
	var setting model.PlatformItem
	decodeResponse(t, settingRec, &setting)

	settingsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/system-settings", nil, adminCookie, http.StatusOK)
	for _, leaked := range []string{"openweb-secret", "oidc_client_secret_encrypted", "client_secret_encrypted"} {
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
	for _, leaked := range []string{"openweb-secret", "client_secret", "oidc_client_secret_encrypted", "client_secret_encrypted"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("oidc test response leaked sensitive value %q: %s", leaked, body)
		}
	}
	usersRec := assertStatus(t, handler, http.MethodGet, "/api/admin/users", nil, adminCookie, http.StatusOK)
	if strings.Contains(usersRec.Body.String(), `"type":"oidc"`) {
		t.Fatalf("oidc authorization test unexpectedly created a user: %s", usersRec.Body.String())
	}
	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+setting.ID, map[string]any{
		"status": "disabled",
	}, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/oidc/test", map[string]any{
		"setting_id": setting.ID,
	}, adminCookie, http.StatusNotFound)
	if authorizeCalls != 1 {
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
			"oidc_client_secret":          "openweb-secret",
		},
	}, adminCookie, http.StatusCreated)
	var badSetting model.PlatformItem
	decodeResponse(t, badSettingRec, &badSetting)
	failedRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/oidc/test", map[string]any{
		"setting_id": badSetting.ID,
	}, adminCookie, http.StatusBadGateway)
	if strings.Contains(failedRec.Body.String(), "openweb-secret") {
		t.Fatalf("oidc failed test leaked secret: %s", failedRec.Body.String())
	}
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), "system_settings.oidc_test") || !strings.Contains(logsRec.Body.String(), "system_settings.oidc_test.failed") || strings.Contains(logsRec.Body.String(), "openweb-secret") {
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

	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/ldap/test", map[string]any{
		"setting_id": setting.ID,
		"username":   "ldap-probe",
		"password":   "wrong-password",
	}, adminCookie, http.StatusUnauthorized)
	if fakeLDAP.calls != 2 {
		t.Fatalf("ldap authenticator calls after failed probe = %d, want 2", fakeLDAP.calls)
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
	if fakeLDAP.calls != 2 {
		t.Fatalf("disabled ldap setting should not call authenticator, calls=%d", fakeLDAP.calls)
	}
}

func TestWeComIntegrationTokenTest(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
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
			writeJSON(w, http.StatusOK, map[string]any{"errcode": 40014, "errmsg": "invalid " + gotSecret})
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
	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+setting.ID, map[string]any{
		"status": "disabled",
	}, adminCookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/wecom/test", map[string]any{
		"setting_id": setting.ID,
	}, adminCookie, http.StatusNotFound)
	if tokenCalls != 1 {
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
			"wecom_agent_secret":      "bad-secret",
			"wecom_token_endpoint":    provider.URL + "/gettoken",
			"wecom_userinfo_endpoint": provider.URL + "/getuserinfo",
		},
	}, adminCookie, http.StatusCreated)
	var badSetting model.PlatformItem
	decodeResponse(t, badSettingRec, &badSetting)
	failedRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/wecom/test", map[string]any{
		"setting_id": badSetting.ID,
	}, adminCookie, http.StatusBadGateway)
	if strings.Contains(failedRec.Body.String(), "bad-secret") {
		t.Fatalf("wecom failed test leaked secret: %s", failedRec.Body.String())
	}
	logsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(logsRec.Body.String(), "system_settings.wecom_test") || !strings.Contains(logsRec.Body.String(), "system_settings.wecom_test.failed") || strings.Contains(logsRec.Body.String(), "bad-secret") {
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

func TestExternalWeComCallbackTokenFailureIsAuditedAndRedacted(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)
	var tokenEndpointCalls int
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gettoken" {
			http.NotFound(w, r)
			return
		}
		tokenEndpointCalls++
		writeJSON(w, http.StatusOK, map[string]any{"errcode": 40001, "errmsg": "bad corpsecret wecom-secret"})
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
			"wecom_agent_secret":       "wecom-secret",
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
	if !strings.Contains(failedRec.Body.String(), "bad corpsecret") || strings.Contains(failedRec.Body.String(), "wecom-secret") {
		t.Fatalf("wecom token failure response missing sanitized reason or leaked secret: %s", failedRec.Body.String())
	}
	if tokenEndpointCalls != 1 {
		t.Fatalf("wecom token endpoint calls = %d, want 1", tokenEndpointCalls)
	}
	loginLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/login-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(loginLogsRec.Body.String(), `"type":"wecom"`) || !strings.Contains(loginLogsRec.Body.String(), `"status":"failed"`) || !strings.Contains(loginLogsRec.Body.String(), "broken-wecom") || !strings.Contains(loginLogsRec.Body.String(), "bad corpsecret") || strings.Contains(loginLogsRec.Body.String(), "wecom-secret") {
		t.Fatalf("wecom token failure log missing details or leaked secret: %s", loginLogsRec.Body.String())
	}
	operationLogsRec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, adminCookie, http.StatusOK)
	if !strings.Contains(operationLogsRec.Body.String(), "auth.wecom.login_failed") || strings.Contains(operationLogsRec.Body.String(), "wecom-secret") {
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
	adminBootstrapRec := assertStatus(t, handler, http.MethodGet, "/api/bootstrap", nil, adminCookie, http.StatusOK)
	if !strings.Contains(adminBootstrapRec.Body.String(), `"guacd"`) {
		t.Fatalf("admin bootstrap missing runtime guacd state: %s", adminBootstrapRec.Body.String())
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
	limitedBootstrapRec := assertStatus(t, handler, http.MethodGet, "/api/bootstrap", nil, userCookie, http.StatusOK)
	if strings.Contains(limitedBootstrapRec.Body.String(), `"guacd"`) {
		t.Fatalf("limited user bootstrap leaked runtime guacd state: %s", limitedBootstrapRec.Body.String())
	}
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
	if !strings.Contains(logsRec.Body.String(), "agent.gateway.register") || !strings.Contains(logsRec.Body.String(), "agent_gateway.token") {
		t.Fatal("agent gateway token/register operations were not audited")
	}
}

func TestResourceOperationEndpoints(t *testing.T) {
	handler, cookie := newTestHandler(t)
	server := handler.(*Server)

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
	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+setting.ID, map[string]any{
		"status": "disabled",
	}, cookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/smtp/test", map[string]any{
		"setting_id": setting.ID,
		"to":         "receiver@example.test",
	}, cookie, http.StatusNotFound)
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
	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+setting.ID, map[string]any{
		"status": "disabled",
	}, cookie, http.StatusOK)
	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/llm/test", map[string]any{
		"setting_id": setting.ID,
		"prompt":     "ping",
	}, cookie, http.StatusNotFound)
	if llmCalls != 1 {
		t.Fatalf("disabled llm setting should not call provider endpoint, calls=%d", llmCalls)
	}

	failingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "provider down", http.StatusBadGateway)
	}))
	defer failingServer.Close()
	failingSettingRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "Failing LLM integrations",
		"type":   "integration",
		"status": "enabled",
		"metadata": map[string]any{
			"llm_base_url": failingServer.URL + "/v1",
			"llm_model":    "test-model",
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
	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/llm/test", map[string]any{
		"setting_id": "missing",
	}, cookie, http.StatusNotFound)
}

func TestProxyServiceSettingsPersistStatusAndSyncSSHGateway(t *testing.T) {
	handler, cookie := newTestHandler(t)
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

	sshGatewayRec := assertStatus(t, handler, http.MethodGet, "/api/admin/ssh-gateways", nil, cookie, http.StatusOK)
	sshGatewayBody := sshGatewayRec.Body.String()
	for _, want := range []string{`"status":"enabled"`, `"host":"127.0.0.1"`, `"port":22022`, "db.internal:5432", "proxy_services"} {
		if !strings.Contains(sshGatewayBody, want) {
			t.Fatalf("ssh gateway sync missing %s: %s", want, sshGatewayBody)
		}
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
	for _, leaked := range []string{"restore-secret", "restore-smtp-secret", "restore-llm-secret", "restore-dns-secret", "postgres://restore_user", "PRIVATE KEY"} {
		if strings.Contains(restoreBody, leaked) {
			t.Fatalf("backup restore response leaked %q: %s", leaked, restoreBody)
		}
	}
	if !strings.Contains(restoreBody, `"restored":true`) || !strings.Contains(restoreBody, `"migrated_platform_secrets":3`) {
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
	assertStatus(t, handler, http.MethodDelete, "/api/admin/backups/"+backupName, nil, cookie, http.StatusOK)
	if _, err := os.Stat(filepath.FromSlash(backupPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted backup still exists or stat failed unexpectedly: %v", err)
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
	listRec := assertStatus(t, handler, http.MethodGet, "/api/admin/backups", nil, cookie, http.StatusOK)
	if strings.Contains(listRec.Body.String(), oldName) {
		t.Fatal("expired backup still appears in backup list")
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

	next, ok = nextCronRun("0 0 2 * * ?", time.Date(2026, 7, 6, 2, 0, 1, 0, time.UTC))
	if !ok {
		t.Fatal("expected daily cron to parse")
	}
	want = time.Date(2026, 7, 7, 2, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("daily cron run = %s, want %s", next, want)
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
	server := NewServer(cfg)
	rec := assertStatus(t, server, http.MethodPost, "/api/auth/setup", map[string]any{"username": "admin", "password": "password123"}, nil, http.StatusCreated)
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("setup did not set auth cookie")
	}
	return server, cookies[0]
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
