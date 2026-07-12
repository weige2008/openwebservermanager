package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"time"

	"openwebservermanager/internal/agentrelay"
	"openwebservermanager/internal/guac"
	"openwebservermanager/internal/model"
	sshrunner "openwebservermanager/internal/ssh"
	"openwebservermanager/internal/store"
	"openwebservermanager/internal/ws"
)

type Config struct {
	Store               *store.Store
	Guacd               *guac.Manager
	SSHGatewayAddress   string
	SSHGateway          sshGatewayRuntime
	RDPProxy            rdpProxyRuntime
	DatabaseProxy       databaseProxyRuntime
	StaticFS            fs.FS
	DataDir             string
	Public              PublicConfig
	TrustProxyHeaders   bool
	LDAPAuthenticator   ldapAuthenticator
	AgentRelay          *agentrelay.Manager
	RecordingTranscoder RecordingTranscoder
	ACMEIssuer          ACMEIssuer
	DNSProviderFactory  DNSChallengeProviderFactory
}

type sshGatewayRuntime interface {
	Address() string
	Reload() error
	LastError() string
}

type databaseProxyRuntime interface {
	Address() string
	Target() string
	Routes() []proxyRouteStatus
	Reload() error
	LastError() string
	ActiveConnections() int
}

type rdpProxyRuntime interface {
	Address() string
	Target() string
	Routes() []proxyRouteStatus
	Reload() error
	LastError() string
	ActiveConnections() int
}

type PublicConfig struct {
	SiteName         string          `json:"site_name"`
	Version          string          `json:"version"`
	Commit           string          `json:"commit,omitempty"`
	GitHubURL        string          `json:"github_url"`
	Copyright        string          `json:"copyright"`
	LogoURL          string          `json:"logo_url,omitempty"`
	AssetLogoURL     string          `json:"asset_logo_url,omitempty"`
	ICPNumber        string          `json:"icp_number,omitempty"`
	AboutTitle       string          `json:"about_title,omitempty"`
	AboutDescription string          `json:"about_description,omitempty"`
	AboutBody        string          `json:"about_body,omitempty"`
	FooterText       string          `json:"footer_text,omitempty"`
	NavLinks         []PublicNavLink `json:"nav_links"`
}

type PublicNavLink struct {
	Title    string `json:"title"`
	Href     string `json:"href"`
	External bool   `json:"external,omitempty"`
}

var errStoragePathEscape = errors.New("recording path escapes data directory")

type Server struct {
	cfg                 Config
	static              http.Handler
	staticFS            fs.FS
	auth                *authManager
	oidc                *oidcManager
	ldap                ldapAuthenticator
	activeConnections   activeConnectionRegistry
	agentRelay          *agentrelay.Manager
	recordingTranscodes recordingTranscodeRegistry
	recordingTranscoder RecordingTranscoder
	acmeIssuer          ACMEIssuer
	acmeChallenges      acmeChallengeRegistry
	dnsProviderFactory  DNSChallengeProviderFactory
	started             time.Time
}

func New(cfg Config) http.Handler {
	return NewServer(cfg)
}

func NewServer(cfg Config) *Server {
	sub, err := fs.Sub(cfg.StaticFS, "static")
	if err != nil {
		panic(err)
	}
	ldapAuth := cfg.LDAPAuthenticator
	if ldapAuth == nil {
		ldapAuth = realLDAPAuthenticator{}
	}
	relay := cfg.AgentRelay
	if relay == nil {
		relay = agentrelay.NewManager(cfg.Store)
	}
	transcoder := cfg.RecordingTranscoder
	if transcoder == nil {
		transcoder = newGuacencTranscoderFromEnvironment()
	}
	acmeIssuer := cfg.ACMEIssuer
	if acmeIssuer == nil {
		acmeIssuer = realACMEIssuer{}
	}
	dnsProviderFactory := cfg.DNSProviderFactory
	if dnsProviderFactory == nil {
		dnsProviderFactory = realDNSChallengeProviderFactory{}
	}
	server := &Server{
		cfg:                 cfg,
		static:              http.FileServer(http.FS(sub)),
		staticFS:            sub,
		auth:                newAuthManager(cfg.Store),
		oidc:                newOIDCManager(cfg.Store),
		ldap:                ldapAuth,
		agentRelay:          relay,
		recordingTranscoder: transcoder,
		acmeIssuer:          acmeIssuer,
		dnsProviderFactory:  dnsProviderFactory,
		started:             time.Now().UTC(),
	}
	server.migrateLegacyRecordingPaths()
	server.reconcileInterruptedRecordingTranscodes()
	server.reconcileInterruptedScheduledTaskLogs()
	return server
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
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		s.handleACMEHTTPChallenge(w, r)
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
	case strings.HasPrefix(r.URL.Path, "/api/auth/wecom/"):
		s.handleExternalWeComAPI(w, r)
		return
	case strings.HasPrefix(r.URL.Path, "/api/auth/passkeys/login/"):
		s.handlePasskeyLoginAPI(w, r)
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
	case r.Method == http.MethodGet && r.URL.Path == "/api/notifications":
		s.handleNotifications(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/notifications/read":
		s.handleNotificationRead(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/auth/mfa/"):
		s.handleAuthenticatedMFA(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/auth/passkeys"):
		s.handleAuthenticatedPasskeys(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/auth/ssh-keys"):
		s.handleAuthenticatedSSHPublicKeys(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/auth/password":
		s.handlePasswordChange(w, r)
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
	case strings.HasPrefix(r.URL.Path, "/api/connections/") && strings.Contains(r.URL.Path, "/drive"):
		s.handleDesktopDrive(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/connections/") && strings.Contains(r.URL.Path, "/sftp"):
		s.handleSSHFiles(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/connections/") && strings.HasSuffix(r.URL.Path, "/close"):
		s.handleClose(w, r)
	default:
		writeError(w, http.StatusNotFound, "endpoint not found")
	}
}

func (s *Server) handlePublicConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.publicConfig())
}

func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	servers, credentials, sessions, auditLogs := s.cfg.Store.Bootstrap()
	platform, err := s.cfg.Store.PlatformBootstrap()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	platform["departments"] = departmentTreeItems(platform)
	_, session, _ := s.authSession(r)
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
	payload := map[string]any{
		"servers":     servers,
		"credentials": credentials,
		"sessions":    sessions,
		"audit_logs":  auditLogs,
		"platform":    platform,
	}
	if notificationCanSeeSystem(decision) {
		payload["guacd"] = map[string]any{
			"address": s.cfg.Guacd.Address(),
		}
	}
	writeJSON(w, http.StatusOK, payload)
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
	if err := s.createLegacyServerCreateOperationLog(r, server); err != nil {
		if rollbackErr := s.cfg.Store.DeleteServer(server.ID); rollbackErr != nil && !errors.Is(rollbackErr, os.ErrNotExist) {
			err = fmt.Errorf("%w; additionally failed to roll back created server: %v", err, rollbackErr)
		}
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
	if err := s.createLegacyCredentialCreateOperationLog(r, credential); err != nil {
		if rollbackErr := s.cfg.Store.DeleteCredential(credential.ID); rollbackErr != nil && !errors.Is(rollbackErr, os.ErrNotExist) {
			err = fmt.Errorf("%w; additionally failed to roll back created credential: %v", err, rollbackErr)
		}
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
	if !s.requireAccessMFA(w, r, accessMFAInput{MFACode: req.MFACode, RecoveryCode: req.RecoveryCode}) {
		return
	}
	if !s.validateReconnectSource(w, r, req.ReconnectFrom, model.ProtocolSSH, server.ID, credential.ID) {
		return
	}
	req.Cols = clampInt(req.Cols, 40, 300, 120)
	req.Rows = clampInt(req.Rows, 10, 120, 32)

	sshPolicy := s.sshAccessPolicy()
	sessionRequest := model.ConnectionSession{
		Protocol:      model.ProtocolSSH,
		ServerID:      server.ID,
		CredentialID:  credential.ID,
		UserID:        s.currentUserID(r),
		ClientIP:      s.clientIP(r),
		ReconnectFrom: strings.TrimSpace(req.ReconnectFrom),
		Width:         req.Cols,
		Height:        req.Rows,
	}
	applySSHAccessPolicy(&sessionRequest, sshPolicy)
	session, err := s.cfg.Store.CreateSession(sessionRequest)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.createConnectionSessionCreateOperationLog(r, session, connectionSessionCreateDescription(session)); err != nil {
		err = rollbackCreatedConnectionSessionError(s.cfg.Store.DeleteSession(session.ID), err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, connectionSessionCreateAction(session), session.ID, model.ProtocolSSH, connectionSessionCreateDescription(session))
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
	term := r.URL.Query().Get("term")
	cols, _ := strconv.Atoi(r.URL.Query().Get("cols"))
	rows, _ := strconv.Atoi(r.URL.Query().Get("rows"))
	if err := s.createConnectionSessionOpenOperationLog(r, session, "opened ssh websocket", map[string]any{
		"term": term,
		"cols": cols,
		"rows": rows,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	conn, err := ws.Upgrade(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	unregister := s.activeConnections.register(session.ID, conn.Close)
	defer unregister()
	if !s.sessionStillOpen(session.ID) {
		_ = conn.Close()
		return
	}
	_ = s.audit(r, "connection.ssh.open", session.ID, model.ProtocolSSH, "opened ssh websocket")
	sshrunner.Runner{Store: s.cfg.Store, Logger: slog.Default(), KnownHostsPath: filepath.Join(s.cfg.DataDir, "known_hosts"), DialContext: s.sshSessionDialContext(session)}.Run(conn, session, server, credential, secret, term, cols, rows)
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
	if !s.requireAccessMFA(w, r, accessMFAInput{MFACode: req.MFACode, RecoveryCode: req.RecoveryCode}) {
		return
	}
	if !s.validateReconnectSource(w, r, req.ReconnectFrom, model.ProtocolRDP, server.ID, credential.ID) {
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
		ReconnectFrom:       strings.TrimSpace(req.ReconnectFrom),
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
			err = rollbackCreatedConnectionSessionError(s.cfg.Store.DeleteSession(session.ID), err)
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = os.Chmod(recordingPath, 0o770)
		updated, err := s.cfg.Store.UpdateSession(session.ID, func(item *model.ConnectionSession) {
			item.RecordingPath = recordingPath
		})
		if err != nil {
			err = rollbackCreatedConnectionSessionError(s.rollbackCreatedConnectionSession(session.ID, recordingPath), err)
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		session = updated
	}
	if err := s.createConnectionSessionCreateOperationLog(r, session, connectionSessionCreateDescription(session)); err != nil {
		err = rollbackCreatedConnectionSessionError(s.rollbackCreatedConnectionSession(session.ID, session.RecordingPath), err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, connectionSessionCreateAction(session), session.ID, model.ProtocolRDP, connectionSessionCreateDescription(session))
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
	if !s.canViewSession(r, session) {
		if err := s.createRecordingOperationLog(r, "recording.access.denied", "denied", session.ID, session.Protocol, "recording access denied", nil); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeError(w, http.StatusForbidden, "session access denied")
		return
	}
	recording, ok := s.validateRecordingPath(w, session.RecordingPath, session.Protocol)
	if !ok {
		return
	}
	if err := s.createRecordingOperationLog(r, "recording.download", "success", session.ID, session.Protocol, "downloaded recording", map[string]any{
		"recording_path": recording.path,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "recording.download", session.ID, session.Protocol, "downloaded recording")
	s.serveRecordingZip(w, r, session.ID, recording.path)
}
func (s *Server) handleClose(w http.ResponseWriter, r *http.Request) {
	id := pathSegment(r.URL.Path, 2)
	existing, ok := s.cfg.Store.GetSession(id)
	if !ok {
		item, platformOK, err := s.cfg.Store.GetPlatformItem("online_sessions", id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !platformOK {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}
		if !s.canControlPlatformSession(r, item) {
			writeError(w, http.StatusForbidden, "session access denied")
			return
		}
		if err := s.createSessionLifecycleOperationLog(r, "connection.close", "requested", id, item.Protocol, "close platform session requested", map[string]any{
			"session_collection": "online_sessions",
			"close_reason":       "closed by user",
		}); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		closed, err := s.closePlatformOnlineSession(r, id, "closed by user")
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.audit(r, "connection.close", closed.ID, closed.Protocol, "closed platform session")
		writeJSON(w, http.StatusOK, closed)
		return
	}
	if !s.canControlSession(r, existing) {
		writeError(w, http.StatusForbidden, "session access denied")
		return
	}
	if err := s.createSessionLifecycleOperationLog(r, "connection.close", "requested", id, existing.Protocol, "close session requested", map[string]any{
		"session_collection": "connection_sessions",
		"close_reason":       "closed by user",
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.refreshSessionRecordingSize(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
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
	s.activeConnections.disconnect(id)
	_ = s.audit(r, "connection.close", session.ID, session.Protocol, "closed session")
	writeJSON(w, http.StatusOK, session)
}

func (s *Server) closePlatformOnlineSession(r *http.Request, id, reason string) (model.PlatformItem, error) {
	item, ok, err := s.cfg.Store.GetPlatformItem("online_sessions", id)
	if err != nil {
		return model.PlatformItem{}, err
	}
	if !ok {
		return model.PlatformItem{}, os.ErrNotExist
	}
	previousOnline := item
	previousOnline.Metadata = cloneMetadata(item.Metadata)
	now := time.Now().UTC()
	item.Status = string(model.SessionClosed)
	item.Description = strings.TrimSpace(reason)
	item.Metadata = cloneMetadata(item.Metadata)
	item.Metadata["ended_at"] = now
	if reason != "" {
		item.Metadata["close_reason"] = reason
	}
	if size, ok := s.recordingSizeFromMetadata(item.Metadata); ok {
		item.Metadata["recording_size"] = size
	}
	if err := s.cfg.Store.DeletePlatformItem("online_sessions", id); err != nil && !errors.Is(err, os.ErrNotExist) {
		return model.PlatformItem{}, s.platformSessionCloseStateError(r, id, item.Protocol, "delete platform online session failed", err)
	}
	saved, err := s.cfg.Store.SavePlatformItem("offline_sessions", item)
	if err != nil {
		stateErr := s.platformSessionCloseStateError(r, id, item.Protocol, "persist platform offline session failed", err)
		if _, restoreErr := s.cfg.Store.SavePlatformItem("online_sessions", previousOnline); restoreErr != nil {
			detail := "restore platform online session failed after offline persistence failure: " + restoreErr.Error()
			_ = s.audit(r, "connection.close.restore_failed", id, item.Protocol, detail)
			return model.PlatformItem{}, fmt.Errorf("%w; additionally %s", stateErr, detail)
		}
		return model.PlatformItem{}, stateErr
	}
	return saved, nil
}

func (s *Server) platformSessionCloseStateError(r *http.Request, id string, protocol model.Protocol, message string, err error) error {
	detail := message + ": " + err.Error()
	_ = s.audit(r, "connection.close.state.persist_failed", id, protocol, detail)
	return errors.New(detail)
}

func (s *Server) refreshSessionRecordingSize(id string) error {
	session, ok := s.cfg.Store.GetSession(id)
	if !ok || strings.TrimSpace(session.RecordingPath) == "" {
		return nil
	}
	size, sizeOK, err := s.recordingDirectorySize(session.RecordingPath)
	if err != nil {
		return err
	}
	if !sizeOK {
		return nil
	}
	_, err = s.cfg.Store.UpdateSession(id, func(item *model.ConnectionSession) {
		item.RecordingSize = size
	})
	return err
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
	if !s.canControlSession(r, session) {
		writeError(w, http.StatusForbidden, "session access denied")
		return model.ConnectionSession{}, model.Server{}, model.Credential{}, store.CredentialSecret{}, false
	}
	if !sessionStatusOpen(session.Status) {
		writeError(w, http.StatusConflict, "session is closed")
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
	if !platformAccessItemEnabled(asset) {
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
	if !platformCredentialEnabled(credential) {
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

func (s *Server) createOperationLog(r *http.Request, req model.PlatformItemRequest) error {
	if _, err := s.cfg.Store.CreatePlatformItem("operation_logs", req); err != nil {
		detail := "persist operation log failed: " + err.Error()
		if r != nil {
			_ = s.audit(r, "operation.log.persist_failed", req.TargetID, req.Protocol, detail)
		}
		return errors.New(detail)
	}
	return nil
}

func (s *Server) createLegacyServerCreateOperationLog(r *http.Request, server model.Server) error {
	return s.createOperationLog(r, model.PlatformItemRequest{
		Name:        "server.create",
		Type:        "server",
		Status:      "success",
		Protocol:    legacyServerProtocol(server),
		TargetID:    server.ID,
		OwnerID:     s.currentUserID(r),
		Description: "created server " + server.Name,
		Metadata: map[string]any{
			"server_id": server.ID,
			"host":      server.Host,
			"ssh_port":  server.SSHPort,
			"rdp_port":  server.RDPPort,
			"os":        server.OS,
			"group":     server.Group,
			"client_ip": s.clientIP(r),
			"source":    "legacy_api",
		},
	})
}

func (s *Server) createLegacyCredentialCreateOperationLog(r *http.Request, credential model.CredentialPublic) error {
	return s.createOperationLog(r, model.PlatformItemRequest{
		Name:        "credential.create",
		Type:        "credential",
		Status:      "success",
		Protocol:    legacyCredentialProtocol(credential.Type),
		TargetID:    credential.ID,
		OwnerID:     s.currentUserID(r),
		Description: "created credential " + credential.Name,
		Metadata: map[string]any{
			"credential_id": credential.ID,
			"server_id":     credential.ServerID,
			"type":          credential.Type,
			"username":      credential.Username,
			"domain":        credential.Domain,
			"client_ip":     s.clientIP(r),
			"source":        "legacy_api",
		},
	})
}

func (s *Server) createSessionLifecycleOperationLog(r *http.Request, name, status, id string, protocol model.Protocol, description string, metadata map[string]any) error {
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["session_id"] = id
	metadata["client_ip"] = s.clientIP(r)
	return s.createOperationLog(r, model.PlatformItemRequest{
		Name:        name,
		Type:        "connection_session",
		Status:      status,
		Protocol:    protocol,
		TargetID:    id,
		OwnerID:     s.currentUserID(r),
		Description: description,
		Metadata:    metadata,
	})
}

func (s *Server) createConnectionSessionCreateOperationLog(r *http.Request, session model.ConnectionSession, description string) error {
	name := connectionSessionCreateAction(session)
	metadata := map[string]any{
		"session_id":    session.ID,
		"server_id":     session.ServerID,
		"credential_id": session.CredentialID,
		"client_ip":     s.clientIP(r),
		"width":         session.Width,
		"height":        session.Height,
		"dpi":           session.DPI,
	}
	if session.ReconnectFrom != "" {
		metadata["reconnect_from"] = session.ReconnectFrom
	}
	return s.createOperationLog(r, model.PlatformItemRequest{
		Name:        name,
		Type:        "connection_session",
		Status:      "success",
		Protocol:    session.Protocol,
		TargetID:    session.ID,
		OwnerID:     s.currentUserID(r),
		Description: description,
		Metadata:    metadata,
	})
}

func (s *Server) createConnectionSessionOpenOperationLog(r *http.Request, session model.ConnectionSession, description string, metadata map[string]any) error {
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["session_id"] = session.ID
	metadata["server_id"] = session.ServerID
	metadata["credential_id"] = session.CredentialID
	metadata["client_ip"] = s.clientIP(r)
	return s.createOperationLog(r, model.PlatformItemRequest{
		Name:        "connection." + string(session.Protocol) + ".open",
		Type:        "connection_session",
		Status:      "success",
		Protocol:    session.Protocol,
		TargetID:    session.ID,
		OwnerID:     s.currentUserID(r),
		Description: description,
		Metadata:    metadata,
	})
}

func (s *Server) createPlatformOnlineSessionCreateOperationLog(r *http.Request, item model.PlatformItem, description string) error {
	return s.createOperationLog(r, model.PlatformItemRequest{
		Name:        "access." + string(item.Protocol) + ".create",
		Type:        "online_session",
		Status:      "success",
		Protocol:    item.Protocol,
		TargetID:    item.ID,
		OwnerID:     s.currentUserID(r),
		Description: description,
		Metadata: map[string]any{
			"session_id": item.ID,
			"asset_id":   item.TargetID,
			"client_ip":  s.clientIP(r),
			"source":     "access_portal",
		},
	})
}

func (s *Server) rollbackCreatedConnectionSession(sessionID, recordingPath string) error {
	var errs []error
	if strings.TrimSpace(recordingPath) != "" {
		if err := os.RemoveAll(recordingPath); err != nil {
			errs = append(errs, fmt.Errorf("remove recording path: %w", err))
		}
	}
	if err := s.cfg.Store.DeleteSession(sessionID); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func rollbackCreatedConnectionSessionError(rollbackErr, err error) error {
	if rollbackErr != nil {
		return fmt.Errorf("%w; additionally failed to roll back created session: %v", err, rollbackErr)
	}
	return err
}

func legacyServerProtocol(server model.Server) model.Protocol {
	if server.OS == model.ServerOSWindows {
		return model.ProtocolRDP
	}
	return model.ProtocolSSH
}

func legacyCredentialProtocol(credentialType model.CredentialType) model.Protocol {
	switch credentialType {
	case model.CredentialRDPPassword:
		return model.ProtocolRDP
	case model.CredentialVNCPassword:
		return model.ProtocolVNC
	case model.CredentialDatabase:
		return model.ProtocolDatabase
	default:
		return model.ProtocolSSH
	}
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
		return errStoragePathEscape
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

func (s *Server) canViewSession(r *http.Request, session model.ConnectionSession) bool {
	if r == nil {
		return true
	}
	_, authSession, ok := s.authSession(r)
	if !ok {
		return false
	}
	kind := s.roleDecision(authSession.Role).Kind
	return kind == roleSuperAdmin || kind == roleAdmin || kind == roleAuditor || session.UserID == authSession.UserID
}

func (s *Server) canControlSession(r *http.Request, session model.ConnectionSession) bool {
	if r == nil {
		return true
	}
	_, authSession, ok := s.authSession(r)
	if !ok {
		return false
	}
	kind := s.roleDecision(authSession.Role).Kind
	return kind == roleSuperAdmin || kind == roleAdmin || session.UserID == authSession.UserID
}

func sessionStatusOpen(status model.SessionStatus) bool {
	return status == model.SessionPending || status == model.SessionActive
}

func (s *Server) sessionStillOpen(id string) bool {
	session, ok := s.cfg.Store.GetSession(id)
	return ok && sessionStatusOpen(session.Status)
}

func (s *Server) validateReconnectSource(w http.ResponseWriter, r *http.Request, sourceID string, protocol model.Protocol, assetID, credentialID string) bool {
	sourceID = strings.TrimSpace(sourceID)
	if sourceID == "" {
		return true
	}
	source, ok := s.cfg.Store.GetSession(sourceID)
	if !ok {
		writeError(w, http.StatusNotFound, "reconnect source session not found")
		return false
	}
	if !s.canControlSession(r, source) {
		_ = s.audit(r, "connection."+string(protocol)+".reconnect.denied", sourceID, protocol, "reconnect source session access denied")
		writeError(w, http.StatusForbidden, "reconnect source session access denied")
		return false
	}
	if sessionStatusOpen(source.Status) {
		writeError(w, http.StatusConflict, "reconnect source session is still active")
		return false
	}
	if source.Protocol != protocol || source.ServerID != strings.TrimSpace(assetID) || (credentialID != "" && source.CredentialID != strings.TrimSpace(credentialID)) {
		_ = s.audit(r, "connection."+string(protocol)+".reconnect.denied", sourceID, protocol, "reconnect source session does not match target")
		writeError(w, http.StatusBadRequest, "reconnect source session does not match target")
		return false
	}
	return true
}

func connectionSessionCreateAction(session model.ConnectionSession) string {
	action := "create"
	if session.ReconnectFrom != "" {
		action = "reconnect"
	}
	return "connection." + string(session.Protocol) + "." + action
}

func connectionSessionCreateDescription(session model.ConnectionSession) string {
	if session.ReconnectFrom != "" {
		return "reconnected " + string(session.Protocol) + " session from " + session.ReconnectFrom
	}
	return "created " + string(session.Protocol) + " session"
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
