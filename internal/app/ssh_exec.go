package app

import (
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"openwebservermanager/internal/model"
	sshrunner "openwebservermanager/internal/ssh"
)

type sshExecRequest struct {
	Command        string `json:"command"`
	CredentialID   string `json:"credential_id"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	MFACode        string `json:"mfa_code"`
	RecoveryCode   string `json:"recovery_code"`
}

func (s *Server) handleSSHExec(w http.ResponseWriter, r *http.Request, asset model.PlatformItem, userID string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req sshExecRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !s.requireAccessMFA(w, r, accessMFAInput{MFACode: req.MFACode, RecoveryCode: req.RecoveryCode}) {
		return
	}
	req.Command = strings.TrimSpace(req.Command)
	if req.Command == "" {
		writeError(w, http.StatusBadRequest, "command is required")
		return
	}
	if len(req.Command) > 8192 {
		writeError(w, http.StatusBadRequest, "command is too large")
		return
	}
	credential, secret, ok, err := s.resolvePlatformCredential(asset, model.ProtocolSSH, req.CredentialID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusBadRequest, "compatible credential not found")
		return
	}
	if !sshSecretPresent(credential, secret) {
		writeError(w, http.StatusBadRequest, "credential secret is missing")
		return
	}
	session, err := s.cfg.Store.CreateSession(model.ConnectionSession{
		Protocol:     model.ProtocolSSH,
		ServerID:     asset.ID,
		CredentialID: credential.ID,
		UserID:       userID,
		ClientIP:     s.clientIP(r),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	timeout := time.Duration(clampInt(req.TimeoutSeconds, 1, 600, 30)) * time.Second
	result, err := sshrunner.Runner{
		Store:          s.cfg.Store,
		Logger:         slog.Default(),
		KnownHostsPath: filepath.Join(s.cfg.DataDir, "known_hosts"),
	}.RunCommand(session, platformSSHServer(asset), platformSSHCredential(credential), secret, req.Command, timeout)
	if errors.Is(err, sshrunner.ErrCommandBlocked) {
		_ = s.audit(r, "connection.ssh.exec.denied", session.ID, model.ProtocolSSH, "blocked ssh exec command")
		writeJSON(w, http.StatusForbidden, result)
		return
	}
	if errors.Is(err, sshrunner.ErrCommandTimeout) {
		_ = s.audit(r, "connection.ssh.exec.timeout", session.ID, model.ProtocolSSH, "timed out ssh exec command")
		writeJSON(w, http.StatusGatewayTimeout, result)
		return
	}
	if err != nil {
		_ = s.audit(r, "connection.ssh.exec.failed", session.ID, model.ProtocolSSH, "failed ssh exec command")
		writeJSON(w, http.StatusBadGateway, result)
		return
	}
	_ = s.audit(r, "connection.ssh.exec", session.ID, model.ProtocolSSH, "executed ssh command")
	writeJSON(w, http.StatusOK, result)
}
