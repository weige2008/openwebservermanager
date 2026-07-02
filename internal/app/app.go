package app

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"servermanager/internal/guac"
	"servermanager/internal/model"
	sshrunner "servermanager/internal/ssh"
	"servermanager/internal/store"
	"servermanager/internal/ws"
)

type Config struct {
	Store    *store.Store
	Guacd    *guac.Manager
	StaticFS fs.FS
	DataDir  string
}

type Server struct {
	cfg    Config
	static http.Handler
}

func New(cfg Config) http.Handler {
	sub, err := fs.Sub(cfg.StaticFS, "static")
	if err != nil {
		panic(err)
	}
	return &Server{
		cfg:    cfg,
		static: http.FileServer(http.FS(sub)),
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		s.serveAPI(w, r)
		return
	}
	if r.URL.Path == "/" {
		r.URL.Path = "/index.html"
	}
	s.static.ServeHTTP(w, r)
}

func (s *Server) serveAPI(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/bootstrap":
		s.handleBootstrap(w, r)
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
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/connections/") && strings.HasSuffix(r.URL.Path, "/recording.zip"):
		s.handleRecordingDownload(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/connections/") && strings.HasSuffix(r.URL.Path, "/close"):
		s.handleClose(w, r)
	default:
		writeError(w, http.StatusNotFound, "endpoint not found")
	}
}

func (s *Server) handleBootstrap(w http.ResponseWriter, _ *http.Request) {
	servers, credentials, sessions, auditLogs := s.cfg.Store.Bootstrap()
	writeJSON(w, http.StatusOK, map[string]any{
		"servers":     servers,
		"credentials": credentials,
		"sessions":    sessions,
		"audit_logs":  auditLogs,
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
	if req.Name == "" || req.Host == "" {
		writeError(w, http.StatusBadRequest, "name and host are required")
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
	if req.Name == "" || req.Username == "" || req.Type == "" {
		writeError(w, http.StatusBadRequest, "name, username and type are required")
		return
	}
	credential, err := s.cfg.Store.CreateCredential(model.Credential{
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

	session, err := s.cfg.Store.CreateSession(model.ConnectionSession{
		Protocol:     model.ProtocolSSH,
		ServerID:     server.ID,
		CredentialID: credential.ID,
		UserID:       "local-admin",
		ClientIP:     clientIP(r),
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
	id := pathSegment(r.URL.Path, 3)
	session, server, credential, secret, ok := s.connectionParts(w, id, model.ProtocolSSH)
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
	sshrunner.Runner{Store: s.cfg.Store, Logger: slog.Default()}.Run(conn, session, server, credential, secret, term, cols, rows)
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

	session, err := s.cfg.Store.CreateSession(model.ConnectionSession{
		Protocol:     model.ProtocolRDP,
		ServerID:     server.ID,
		CredentialID: credential.ID,
		UserID:       "local-admin",
		ClientIP:     clientIP(r),
		Width:        req.Width,
		Height:       req.Height,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	recordingPath := filepath.Join(s.cfg.DataDir, "recordings", session.ID)
	_, _ = s.cfg.Store.UpdateSession(session.ID, func(item *model.ConnectionSession) {
		item.RecordingPath = recordingPath
	})
	if err := os.MkdirAll(recordingPath, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	session.RecordingPath = recordingPath
	_ = s.audit(r, "connection.rdp.create", session.ID, model.ProtocolRDP, "created rdp session")
	writeJSON(w, http.StatusCreated, session)
}

func (s *Server) handleRDPTunnel(w http.ResponseWriter, r *http.Request) {
	id := pathSegment(r.URL.Path, 3)
	session, server, credential, secret, ok := s.connectionParts(w, id, model.ProtocolRDP)
	if !ok {
		return
	}
	conn, err := ws.Upgrade(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	width, _ := strconv.Atoi(r.URL.Query().Get("width"))
	height, _ := strconv.Atoi(r.URL.Query().Get("height"))
	dpi, _ := strconv.Atoi(r.URL.Query().Get("dpi"))
	_ = s.audit(r, "connection.rdp.open", session.ID, model.ProtocolRDP, "opened rdp tunnel")
	guac.Tunnel{Manager: s.cfg.Guacd, Store: s.cfg.Store, Logger: slog.Default(), DataDir: s.cfg.DataDir}.Run(r.Context(), conn, guac.RDPConfig{
		Session:    session,
		Server:     server,
		Credential: credential,
		Secret:     secret,
		Width:      width,
		Height:     height,
		DPI:        dpi,
	})
}

func (s *Server) handleRecordingDownload(w http.ResponseWriter, r *http.Request) {
	id := pathSegment(r.URL.Path, 2)
	session, ok := s.cfg.Store.GetSession(id)
	if !ok {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	if session.Protocol != model.ProtocolRDP || session.RecordingPath == "" {
		writeError(w, http.StatusNotFound, "recording not found")
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

func (s *Server) connectionParts(w http.ResponseWriter, sessionID string, protocol model.Protocol) (model.ConnectionSession, model.Server, model.Credential, store.CredentialSecret, bool) {
	session, ok := s.cfg.Store.GetSession(sessionID)
	if !ok {
		writeError(w, http.StatusNotFound, "session not found")
		return model.ConnectionSession{}, model.Server{}, model.Credential{}, store.CredentialSecret{}, false
	}
	if session.Protocol != protocol {
		writeError(w, http.StatusBadRequest, "session protocol mismatch")
		return model.ConnectionSession{}, model.Server{}, model.Credential{}, store.CredentialSecret{}, false
	}
	server, ok := s.cfg.Store.GetServer(session.ServerID)
	if !ok {
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

func (s *Server) audit(r *http.Request, action, targetID string, protocol model.Protocol, detail string) error {
	return s.cfg.Store.Audit(model.AuditLog{
		UserID:   "local-admin",
		Action:   action,
		TargetID: targetID,
		Protocol: protocol,
		Detail:   detail,
		ClientIP: clientIP(r),
	})
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
	if rel == "." || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return errors.New("recording path escapes data directory")
	}
	return nil
}
func decodeJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
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

func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func pathSegment(value string, index int) string {
	parts := strings.Split(strings.Trim(value, "/"), "/")
	if index < 0 || index >= len(parts) {
		return ""
	}
	return parts[index]
}

