package app

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"openwebservermanager/internal/guac"
	"openwebservermanager/internal/model"
	sshrunner "openwebservermanager/internal/ssh"
	"openwebservermanager/internal/store"
	"openwebservermanager/internal/ws"
)

type Config struct {
	Store             *store.Store
	Guacd             *guac.Manager
	StaticFS          fs.FS
	DataDir           string
	Public            PublicConfig
	TrustProxyHeaders bool
	LDAPAuthenticator ldapAuthenticator
}

type PublicConfig struct {
	SiteName  string          `json:"site_name"`
	Version   string          `json:"version"`
	GitHubURL string          `json:"github_url"`
	Copyright string          `json:"copyright"`
	NavLinks  []PublicNavLink `json:"nav_links"`
}

type PublicNavLink struct {
	Title    string `json:"title"`
	Href     string `json:"href"`
	External bool   `json:"external,omitempty"`
}

type Server struct {
	cfg      Config
	static   http.Handler
	staticFS fs.FS
	auth     *authManager
	oidc     *oidcManager
	ldap     ldapAuthenticator
}

func New(cfg Config) http.Handler {
	sub, err := fs.Sub(cfg.StaticFS, "static")
	if err != nil {
		panic(err)
	}
	ldapAuth := cfg.LDAPAuthenticator
	if ldapAuth == nil {
		ldapAuth = realLDAPAuthenticator{}
	}
	return &Server{
		cfg:      cfg,
		static:   http.FileServer(http.FS(sub)),
		staticFS: sub,
		auth:     newAuthManager(),
		oidc:     newOIDCManager(),
		ldap:     ldapAuth,
	}
}

type ldapAuthenticator interface {
	Authenticate(context.Context, externalLDAPProvider, string, string) (externalLDAPClaims, bool, error)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	writeBaseSecurityHeaders(w)
	if r.Method == http.MethodGet && r.URL.Path == "/.well-known/openid-configuration" {
		s.handleOIDCDiscovery(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		s.serveAPI(w, r)
		return
	}
	if r.Method == http.MethodGet && shouldServeIndex(r.URL.Path) {
		index, err := fs.ReadFile(s.staticFS, "index.html")
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(index)
		return
	}
	s.static.ServeHTTP(w, r)
}

func (s *Server) serveAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if isUnsafeMethod(r.Method) && !s.sameOriginRequest(r) {
		writeError(w, http.StatusForbidden, "cross-origin request rejected")
		return
	}

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/auth/status":
		s.handleAuthStatus(w, r)
		return
	case r.Method == http.MethodGet && r.URL.Path == "/api/auth/captcha":
		s.handleCaptcha(w, r)
		return
	case r.Method == http.MethodGet && r.URL.Path == "/api/public/config":
		s.handlePublicConfig(w, r)
		return
	case r.Method == http.MethodPost && r.URL.Path == "/api/auth/setup":
		s.handleSetup(w, r)
		return
	case r.Method == http.MethodPost && r.URL.Path == "/api/auth/login":
		s.handleLogin(w, r)
		return
	case r.Method == http.MethodPost && r.URL.Path == "/api/auth/mfa/complete-login":
		s.handleMFACompleteLogin(w, r)
		return
	case r.Method == http.MethodPost && r.URL.Path == "/api/auth/logout":
		s.handleLogout(w, r)
		return
	case r.Method == http.MethodGet && r.URL.Path == "/api/auth/me":
		s.handleMe(w, r)
		return
	case strings.HasPrefix(r.URL.Path, "/api/auth/oidc/"):
		s.handleExternalOIDCAPI(w, r)
		return
	case strings.HasPrefix(r.URL.Path, "/api/oidc/"):
		s.handleOIDCAPI(w, r)
		return
	case strings.HasPrefix(r.URL.Path, "/api/agent/"):
		s.handleAgentAPI(w, r)
		return
	}

	if !s.requireAuth(w, r) {
		return
	}

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/bootstrap":
		s.handleBootstrap(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/auth/mfa/"):
		s.handleAuthenticatedMFA(w, r)
	case !s.authorizeAPI(w, r):
		return
	case s.handlePlatformAPI(w, r):
		return
	case r.Method == http.MethodPost && r.URL.Path == "/api/servers":
		s.handleCreateServer(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/credentials":
		s.handleCreateCredential(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/connections/ssh":
		s.handleCreateSSH(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/connections/ssh/") && strings.HasSuffix(r.URL.Path, "/ws"):
		s.handleSSHWebSocket(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/connections/rdp":
		s.handleCreateRDP(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/connections/rdp/") && strings.HasSuffix(r.URL.Path, "/tunnel"):
		s.handleRDPTunnel(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/connections/vnc":
		s.handleCreateVNC(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/connections/vnc/") && strings.HasSuffix(r.URL.Path, "/tunnel"):
		s.handleVNCTunnel(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/connections/") && strings.HasSuffix(r.URL.Path, "/recording.zip"):
		s.handleRecordingDownload(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/connections/") && strings.HasSuffix(r.URL.Path, "/close"):
		s.handleClose(w, r)
	default:
		writeError(w, http.StatusNotFound, "endpoint not found")
	}
}

func (s *Server) handlePublicConfig(w http.ResponseWriter, _ *http.Request) {
	cfg := s.cfg.Public
	if cfg.SiteName == "" {
		cfg.SiteName = "Open Web Server Manager"
	}
	if cfg.Version == "" {
		cfg.Version = "dev"
	}
	if cfg.GitHubURL == "" {
		cfg.GitHubURL = "https://github.com/weige2008/openwebservermanager"
	}
	if cfg.Copyright == "" {
		cfg.Copyright = "Copyright (c) 2026 weige2008. All rights reserved."
	}
	if len(cfg.NavLinks) == 0 {
		cfg.NavLinks = []PublicNavLink{
			{Title: "product", Href: "/#product"},
			{Title: "connections", Href: "/#connections"},
			{Title: "security", Href: "/#security"},
			{Title: "deploy", Href: "/#deploy"},
			{Title: "about", Href: "/about"},
		}
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	servers, credentials, sessions, auditLogs := s.cfg.Store.Bootstrap()
	platform, err := s.cfg.Store.PlatformBootstrap()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	platform["departments"] = departmentTreeItems(platform)
	_, session, _ := s.auth.session(r)
	decision := s.roleDecision(session.Role)
	switch decision.Kind {
	case roleSuperAdmin, roleAdmin:
	case roleAuditor:
		servers = nil
		credentials = nil
		sessions = nil
		platform = auditBootstrapPlatform(platform)
	case roleCustom:
		servers = nil
		credentials = nil
		sessions = nil
		auditLogs = nil
		platform = customRoleBootstrapPlatform(platform, session.UserID, decision)
	default:
		servers = nil
		credentials = nil
		sessions = nil
		auditLogs = nil
		platform = accessBootstrapPlatform(platform, session.UserID)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"servers":     servers,
		"credentials": credentials,
		"sessions":    sessions,
		"audit_logs":  auditLogs,
		"platform":    platform,
		"guacd": map[string]any{
			"address": s.cfg.Guacd.Address(),
		},
	})
}

func (s *Server) handleCreateServer(w http.ResponseWriter, r *http.Request) {
	var req model.Server
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Host = strings.TrimSpace(req.Host)
	req.Group = strings.TrimSpace(req.Group)
	req.Description = strings.TrimSpace(req.Description)
	if req.Name == "" || req.Host == "" {
		writeError(w, http.StatusBadRequest, "name and host are required")
		return
	}
	if err := validateServer(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.OS == "" {
		req.OS = model.ServerOSLinux
	}
	server, err := s.cfg.Store.CreateServer(req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "server.create", server.ID, "", "created server "+server.Name)
	writeJSON(w, http.StatusCreated, server)
}

type credentialRequest struct {
	Name       string               `json:"name"`
	ServerID   string               `json:"server_id"`
	Type       model.CredentialType `json:"type"`
	Username   string               `json:"username"`
	Domain     string               `json:"domain"`
	Password   string               `json:"password"`
	PrivateKey string               `json:"private_key"`
	Passphrase string               `json:"passphrase"`
}

func (s *Server) handleCreateCredential(w http.ResponseWriter, r *http.Request) {
	var req credentialRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Username = strings.TrimSpace(req.Username)
	req.Domain = strings.TrimSpace(req.Domain)
	if req.Name == "" || req.Username == "" || req.Type == "" {
		writeError(w, http.StatusBadRequest, "name, username and type are required")
		return
	}
	if err := validateCredentialRequest(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.ServerID != "" {
		server, ok := s.cfg.Store.GetServer(req.ServerID)
		if !ok {
			writeError(w, http.StatusNotFound, "server not found")
			return
		}
		if err := validateCredentialForServer(req.Type, server); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	credential, err := s.cfg.Store.CreateCredential(model.Credential{
		ServerID: req.ServerID,
		Name:     req.Name,
		Type:     req.Type,
		Username: req.Username,
		Domain:   req.Domain,
	}, store.CredentialSecret{
		Password:   req.Password,
		PrivateKey: req.PrivateKey,
		Passphrase: req.Passphrase,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "credential.create", credential.ID, "", "created credential "+credential.Name)
	writeJSON(w, http.StatusCreated, credential)
}

func (s *Server) handleCreateSSH(w http.ResponseWriter, r *http.Request) {
	var req model.SSHCreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	server, ok := s.cfg.Store.GetServer(req.ServerID)
	if !ok {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	credential, _, ok, err := s.cfg.Store.GetCredential(req.CredentialID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "credential not found")
		return
	}
	if credential.Type != model.CredentialSSHPassword && credential.Type != model.CredentialSSHKey {
		writeError(w, http.StatusBadRequest, "credential is not ssh compatible")
		return
	}
	if credential.ServerID != "" && credential.ServerID != server.ID {
		writeError(w, http.StatusBadRequest, "credential is bound to another server")
		return
	}
	if server.OS != model.ServerOSLinux {
		writeError(w, http.StatusBadRequest, "ssh is only supported for linux servers")
		return
	}
	if !s.requireAssetAuthorization(w, r, model.ProtocolSSH, server.ID) {
		return
	}
	req.Cols = clampInt(req.Cols, 40, 300, 120)
	req.Rows = clampInt(req.Rows, 10, 120, 32)

	session, err := s.cfg.Store.CreateSession(model.ConnectionSession{
		Protocol:     model.ProtocolSSH,
		ServerID:     server.ID,
		CredentialID: credential.ID,
		UserID:       s.currentUserID(r),
		ClientIP:     s.clientIP(r),
		Width:        req.Cols,
		Height:       req.Rows,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "connection.ssh.create", session.ID, model.ProtocolSSH, "created ssh session")
	writeJSON(w, http.StatusCreated, session)
}

func (s *Server) handleSSHWebSocket(w http.ResponseWriter, r *http.Request) {
	if !s.sameOriginRequest(r) {
		writeError(w, http.StatusForbidden, "cross-origin websocket rejected")
		return
	}
	id := pathSegment(r.URL.Path, 3)
	session, server, credential, secret, ok := s.connectionParts(w, r, id, model.ProtocolSSH)
	if !ok {
		return
	}
	conn, err := ws.Upgrade(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	term := r.URL.Query().Get("term")
	cols, _ := strconv.Atoi(r.URL.Query().Get("cols"))
	rows, _ := strconv.Atoi(r.URL.Query().Get("rows"))
	_ = s.audit(r, "connection.ssh.open", session.ID, model.ProtocolSSH, "opened ssh websocket")
	sshrunner.Runner{Store: s.cfg.Store, Logger: slog.Default(), KnownHostsPath: filepath.Join(s.cfg.DataDir, "known_hosts")}.Run(conn, session, server, credential, secret, term, cols, rows)
}

func (s *Server) handleCreateRDP(w http.ResponseWriter, r *http.Request) {
	var req model.RDPCreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	server, ok := s.cfg.Store.GetServer(req.ServerID)
	if !ok {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	credential, _, ok, err := s.cfg.Store.GetCredential(req.CredentialID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "credential not found")
		return
	}
	if credential.Type != model.CredentialRDPPassword {
		writeError(w, http.StatusBadRequest, "credential is not rdp compatible")
		return
	}
	if credential.ServerID != "" && credential.ServerID != server.ID {
		writeError(w, http.StatusBadRequest, "credential is bound to another server")
		return
	}
	if server.OS != model.ServerOSWindows {
		writeError(w, http.StatusBadRequest, "rdp is only supported for windows servers")
		return
	}
	if !s.requireAssetAuthorization(w, r, model.ProtocolRDP, server.ID) {
		return
	}
	policy := s.desktopAccessPolicy(model.ProtocolRDP)
	req.Width = clampInt(req.Width, 640, 7680, policy.Width)
	req.Height = clampInt(req.Height, 480, 4320, policy.Height)
	req.DPI = clampInt(req.DPI, 72, 240, policy.DPI)

	session, err := s.cfg.Store.CreateSession(model.ConnectionSession{
		Protocol:            model.ProtocolRDP,
		ServerID:            server.ID,
		CredentialID:        credential.ID,
		UserID:              s.currentUserID(r),
		ClientIP:            s.clientIP(r),
		Width:               req.Width,
		Height:              req.Height,
		DPI:                 req.DPI,
		ColorDepth:          policy.ColorDepth,
		ResizeMethod:        policy.ResizeMethod,
		ClipboardEnabled:    boolPtr(policy.ClipboardEnabled),
		FileTransferEnabled: boolPtr(policy.FileTransferEnabled),
		IgnoreCert:          boolPtr(policy.IgnoreCert),
		ReadOnly:            boolPtr(policy.ReadOnly),
		WatermarkEnabled:    boolPtr(policy.WatermarkEnabled),
		WatermarkText:       policy.WatermarkText,
		WatermarkColor:      policy.WatermarkColor,
		WatermarkFontSize:   policy.WatermarkFontSize,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if req.RecordingEnabled || policy.RecordingEnabled {
		recordingPath := filepath.Join(s.cfg.DataDir, "recordings", session.ID)
		if err := os.MkdirAll(recordingPath, 0o770); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = os.Chmod(recordingPath, 0o770)
		_, _ = s.cfg.Store.UpdateSession(session.ID, func(item *model.ConnectionSession) {
			item.RecordingPath = recordingPath
		})
		session.RecordingPath = recordingPath
	}
	_ = s.audit(r, "connection.rdp.create", session.ID, model.ProtocolRDP, "created rdp session")
	writeJSON(w, http.StatusCreated, session)
}

func (s *Server) handleRDPTunnel(w http.ResponseWriter, r *http.Request) {
	s.handleDesktopTunnel(w, r, model.ProtocolRDP)
}

func (s *Server) handleRecordingDownload(w http.ResponseWriter, r *http.Request) {
	id := pathSegment(r.URL.Path, 2)
	session, ok := s.cfg.Store.GetSession(id)
	if !ok {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	if (session.Protocol != model.ProtocolRDP && session.Protocol != model.ProtocolVNC) || session.RecordingPath == "" {
		writeError(w, http.StatusNotFound, "recording not found")
		return
	}
	if !s.canAccessSession(r, session) {
		writeError(w, http.StatusForbidden, "session access denied")
		return
	}
	if err := ensureChildPath(filepath.Join(s.cfg.DataDir, "recordings"), session.RecordingPath); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if _, err := os.Stat(session.RecordingPath); err != nil {
		writeError(w, http.StatusNotFound, "recording not found")
		return
	}
	_ = s.audit(r, "recording.download", session.ID, session.Protocol, "downloaded recording")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+session.ID+".zip\"")
	archive := zip.NewWriter(w)
	defer archive.Close()
	_ = filepath.WalkDir(session.RecordingPath, func(filePath string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(session.RecordingPath, filePath)
		if err != nil {
			return nil
		}
		writer, err := archive.Create(filepath.ToSlash(rel))
		if err != nil {
			return nil
		}
		file, err := os.Open(filePath)
		if err != nil {
			return nil
		}
		defer file.Close()
		_, _ = io.Copy(writer, file)
		return nil
	})
}
func (s *Server) handleClose(w http.ResponseWriter, r *http.Request) {
	id := pathSegment(r.URL.Path, 2)
	existing, ok := s.cfg.Store.GetSession(id)
	if !ok {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	if !s.canAccessSession(r, existing) {
		writeError(w, http.StatusForbidden, "session access denied")
		return
	}
	session, err := s.cfg.Store.CloseSession(id, "closed by user")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "connection.close", session.ID, session.Protocol, "closed session")
	writeJSON(w, http.StatusOK, session)
}

func (s *Server) connectionParts(w http.ResponseWriter, r *http.Request, sessionID string, protocol model.Protocol) (model.ConnectionSession, model.Server, model.Credential, store.CredentialSecret, bool) {
	session, ok := s.cfg.Store.GetSession(sessionID)
	if !ok {
		writeError(w, http.StatusNotFound, "session not found")
		return model.ConnectionSession{}, model.Server{}, model.Credential{}, store.CredentialSecret{}, false
	}
	if session.Protocol != protocol {
		writeError(w, http.StatusBadRequest, "session protocol mismatch")
		return model.ConnectionSession{}, model.Server{}, model.Credential{}, store.CredentialSecret{}, false
	}
	if !s.canAccessSession(r, session) {
		writeError(w, http.StatusForbidden, "session access denied")
		return model.ConnectionSession{}, model.Server{}, model.Credential{}, store.CredentialSecret{}, false
	}
	server, ok := s.cfg.Store.GetServer(session.ServerID)
	if !ok {
		if protocol == model.ProtocolSSH {
			asset, platformCredential, secret, ok := s.platformSSHConnectionParts(w, session)
			if !ok {
				return model.ConnectionSession{}, model.Server{}, model.Credential{}, store.CredentialSecret{}, false
			}
			return session, platformSSHServer(asset), platformSSHCredential(platformCredential), secret, true
		}
		writeError(w, http.StatusNotFound, "server not found")
		return model.ConnectionSession{}, model.Server{}, model.Credential{}, store.CredentialSecret{}, false
	}
	credential, secret, ok, err := s.cfg.Store.GetCredential(session.CredentialID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return model.ConnectionSession{}, model.Server{}, model.Credential{}, store.CredentialSecret{}, false
	}
	if !ok {
		writeError(w, http.StatusNotFound, "credential not found")
		return model.ConnectionSession{}, model.Server{}, model.Credential{}, store.CredentialSecret{}, false
	}
	return session, server, credential, secret, true
}

func (s *Server) platformSSHConnectionParts(w http.ResponseWriter, session model.ConnectionSession) (model.PlatformItem, model.PlatformItem, store.CredentialSecret, bool) {
	asset, ok, err := s.cfg.Store.GetPlatformItem("assets", session.ServerID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return model.PlatformItem{}, model.PlatformItem{}, store.CredentialSecret{}, false
	}
	if !ok || asset.Protocol != model.ProtocolSSH {
		writeError(w, http.StatusNotFound, "server not found")
		return model.PlatformItem{}, model.PlatformItem{}, store.CredentialSecret{}, false
	}
	credential, secret, ok, err := s.cfg.Store.GetPlatformCredentialSecret(session.CredentialID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return model.PlatformItem{}, model.PlatformItem{}, store.CredentialSecret{}, false
	}
	if !ok {
		writeError(w, http.StatusNotFound, "credential not found")
		return model.PlatformItem{}, model.PlatformItem{}, store.CredentialSecret{}, false
	}
	if !platformCredentialCompatible(credential, model.ProtocolSSH) || !credentialTargetsAsset(credential, asset, false) {
		writeError(w, http.StatusBadRequest, "credential is not ssh compatible")
		return model.PlatformItem{}, model.PlatformItem{}, store.CredentialSecret{}, false
	}
	if !sshSecretPresent(credential, secret) {
		writeError(w, http.StatusBadRequest, "credential secret is missing")
		return model.PlatformItem{}, model.PlatformItem{}, store.CredentialSecret{}, false
	}
	return asset, credential, secret, true
}

func (s *Server) requireAssetAuthorization(w http.ResponseWriter, r *http.Request, protocol model.Protocol, assetID string) bool {
	platform, err := s.cfg.Store.PlatformBootstrap()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return false
	}
	userID, isAdmin := s.accessUser(r)
	if isAccessAuthorized(platform, protocol, assetID, userID, isAdmin) {
		return true
	}
	_ = s.audit(r, "connection."+string(protocol)+".denied", assetID, protocol, "asset access denied")
	writeError(w, http.StatusForbidden, "asset access denied")
	return false
}

func (s *Server) audit(r *http.Request, action, targetID string, protocol model.Protocol, detail string) error {
	return s.cfg.Store.Audit(model.AuditLog{
		UserID:   s.currentUserID(r),
		Action:   action,
		TargetID: targetID,
		Protocol: protocol,
		Detail:   detail,
		ClientIP: s.clientIP(r),
	})
}

func validateCredentialForServer(credentialType model.CredentialType, server model.Server) error {
	if server.OS == model.ServerOSWindows {
		if credentialType == model.CredentialRDPPassword {
			return nil
		}
		return errors.New("windows servers only support rdp credentials")
	}
	if server.OS == model.ServerOSLinux {
		if credentialType == model.CredentialSSHPassword || credentialType == model.CredentialSSHKey {
			return nil
		}
		return errors.New("linux servers only support ssh credentials")
	}
	return errors.New("unsupported server os")
}

func shouldServeIndex(path string) bool {
	if path == "/" {
		return true
	}
	base := filepath.Base(path)
	return !strings.Contains(base, ".")
}

func ensureChildPath(root, child string) error {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	childAbs, err := filepath.Abs(child)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(rootAbs, childAbs)
	if err != nil {
		return err
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return errors.New("recording path escapes data directory")
	}
	return nil
}
func decodeJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeError(w, http.StatusBadRequest, "request body must contain a single JSON object")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxyHeaders {
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			return strings.TrimSpace(strings.Split(forwarded, ",")[0])
		}
		if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
			return realIP
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func writeBaseSecurityHeaders(w http.ResponseWriter) {
	header := w.Header()
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	header.Set("Cross-Origin-Opener-Policy", "same-origin")
	header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
}

func isUnsafeMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func (s *Server) sameOriginRequest(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	return canonicalHost(parsed.Host) == canonicalHost(effectiveHost(r, s.cfg.TrustProxyHeaders))
}

func effectiveHost(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0]); forwarded != "" {
			return forwarded
		}
	}
	return r.Host
}

func canonicalHost(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if host, port, err := net.SplitHostPort(value); err == nil {
		if port == "80" || port == "443" {
			return strings.ToLower(host)
		}
		return strings.ToLower(net.JoinHostPort(host, port))
	}
	return strings.TrimSuffix(value, ".")
}

func (s *Server) canAccessSession(r *http.Request, session model.ConnectionSession) bool {
	if r == nil {
		return true
	}
	_, authSession, ok := s.auth.session(r)
	if !ok {
		return false
	}
	kind := s.roleDecision(authSession.Role).Kind
	return kind == roleSuperAdmin || kind == roleAdmin || kind == roleAuditor || session.UserID == authSession.UserID
}

func validateServer(server model.Server) error {
	if len(server.Name) > 120 {
		return errors.New("server name is too long")
	}
	if len(server.Host) > 255 || strings.ContainsAny(server.Host, "/\\\x00\r\n\t") {
		return errors.New("server host is invalid")
	}
	if server.OS != "" && server.OS != model.ServerOSLinux && server.OS != model.ServerOSWindows {
		return errors.New("unsupported server os")
	}
	if server.SSHPort != 0 && !validPort(server.SSHPort) {
		return errors.New("ssh port must be between 1 and 65535")
	}
	if server.RDPPort != 0 && !validPort(server.RDPPort) {
		return errors.New("rdp port must be between 1 and 65535")
	}
	return nil
}

func validateCredentialRequest(req credentialRequest) error {
	if len(req.Name) > 120 || len(req.Username) > 120 || len(req.Domain) > 120 {
		return errors.New("credential metadata is too long")
	}
	switch req.Type {
	case model.CredentialSSHPassword, model.CredentialRDPPassword:
		if req.Password == "" {
			return errors.New("password is required")
		}
	case model.CredentialSSHKey:
		if req.PrivateKey == "" {
			return errors.New("private key is required")
		}
	default:
		return errors.New("unsupported credential type")
	}
	if len(req.Password) > 32*1024 || len(req.PrivateKey) > 128*1024 || len(req.Passphrase) > 32*1024 {
		return errors.New("credential secret is too large")
	}
	return nil
}

func validPort(port int) bool {
	return port >= 1 && port <= 65535
}

func clampInt(value, min, max, fallback int) int {
	if value == 0 {
		return fallback
	}
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func pathSegment(value string, index int) string {
	parts := strings.Split(strings.Trim(value, "/"), "/")
	if index < 0 || index >= len(parts) {
		return ""
	}
	return parts[index]
}
