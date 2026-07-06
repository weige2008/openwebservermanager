package app

import (
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"openwebservermanager/internal/guac"
	"openwebservermanager/internal/model"
	"openwebservermanager/internal/store"
	"openwebservermanager/internal/ws"
)

type desktopCreateRequest struct {
	AssetID          string `json:"asset_id"`
	CredentialID     string `json:"credential_id"`
	Width            int    `json:"width"`
	Height           int    `json:"height"`
	DPI              int    `json:"dpi"`
	RecordingEnabled bool   `json:"recording_enabled"`
	MFACode          string `json:"mfa_code"`
	RecoveryCode     string `json:"recovery_code"`
}

type sshAccessCreateRequest struct {
	AssetID      string `json:"asset_id"`
	CredentialID string `json:"credential_id"`
	Cols         int    `json:"cols"`
	Rows         int    `json:"rows"`
	Term         string `json:"term"`
	MFACode      string `json:"mfa_code"`
	RecoveryCode string `json:"recovery_code"`
}

func (s *Server) handleCreateVNC(w http.ResponseWriter, r *http.Request) {
	var req model.VNCCreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	s.createPlatformDesktopSession(w, r, model.ProtocolVNC, desktopCreateRequest{
		AssetID:          req.AssetID,
		CredentialID:     req.CredentialID,
		Width:            req.Width,
		Height:           req.Height,
		DPI:              req.DPI,
		RecordingEnabled: req.RecordingEnabled,
	}, http.StatusCreated)
}

func (s *Server) handleVNCTunnel(w http.ResponseWriter, r *http.Request) {
	s.handleDesktopTunnel(w, r, model.ProtocolVNC)
}

func (s *Server) handleDesktopTunnel(w http.ResponseWriter, r *http.Request, protocol model.Protocol) {
	if !s.sameOriginRequest(r) {
		writeError(w, http.StatusForbidden, "cross-origin websocket rejected")
		return
	}
	id := pathSegment(r.URL.Path, 3)
	cfg, ok := s.desktopTunnelConfig(w, r, id, protocol)
	if !ok {
		return
	}
	conn, err := ws.Upgrade(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if width, _ := strconv.Atoi(r.URL.Query().Get("width")); width > 0 {
		cfg.Width = width
	}
	if height, _ := strconv.Atoi(r.URL.Query().Get("height")); height > 0 {
		cfg.Height = height
	}
	if dpi, _ := strconv.Atoi(r.URL.Query().Get("dpi")); dpi > 0 {
		cfg.DPI = dpi
	}
	_ = s.audit(r, "connection."+string(protocol)+".open", cfg.Session.ID, protocol, "opened "+string(protocol)+" tunnel")
	guac.Tunnel{Manager: s.cfg.Guacd, Store: s.cfg.Store, Logger: slog.Default(), DataDir: s.cfg.DataDir}.RunDesktop(r.Context(), conn, cfg)
}

func (s *Server) desktopTunnelConfig(w http.ResponseWriter, r *http.Request, sessionID string, protocol model.Protocol) (guac.DesktopConfig, bool) {
	session, ok := s.cfg.Store.GetSession(sessionID)
	if !ok {
		writeError(w, http.StatusNotFound, "session not found")
		return guac.DesktopConfig{}, false
	}
	if session.Protocol != protocol {
		writeError(w, http.StatusBadRequest, "session protocol mismatch")
		return guac.DesktopConfig{}, false
	}
	if !s.canAccessSession(r, session) {
		writeError(w, http.StatusForbidden, "session access denied")
		return guac.DesktopConfig{}, false
	}
	if protocol == model.ProtocolRDP {
		if server, ok := s.cfg.Store.GetServer(session.ServerID); ok {
			credential, secret, ok, err := s.cfg.Store.GetCredential(session.CredentialID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return guac.DesktopConfig{}, false
			}
			if !ok {
				writeError(w, http.StatusNotFound, "credential not found")
				return guac.DesktopConfig{}, false
			}
			port := server.RDPPort
			if port == 0 {
				port = 3389
			}
			policy := s.desktopAccessPolicy(model.ProtocolRDP)
			return guac.DesktopConfig{
				Protocol:         model.ProtocolRDP,
				Session:          session,
				Host:             server.Host,
				Port:             port,
				Username:         credential.Username,
				Password:         secret.Password,
				Domain:           credential.Domain,
				Width:            session.Width,
				Height:           session.Height,
				DPI:              clampInt(session.DPI, 72, 240, policy.DPI),
				ColorDepth:       clampInt(session.ColorDepth, 8, 32, policy.ColorDepth),
				IgnoreCert:       boolPtrValue(session.IgnoreCert, policy.IgnoreCert),
				EnableDrive:      boolPtrValue(session.FileTransferEnabled, policy.FileTransferEnabled),
				ClipboardEnabled: boolPtrValue(session.ClipboardEnabled, policy.ClipboardEnabled),
				ReadOnly:         boolPtrValue(session.ReadOnly, policy.ReadOnly),
				ResizeMethod:     valueOrDefault(session.ResizeMethod, policy.ResizeMethod),
			}, true
		}
	}
	asset, credential, secret, ok := s.platformDesktopParts(w, session, protocol)
	if !ok {
		return guac.DesktopConfig{}, false
	}
	return platformDesktopConfig(session, asset, credential, secret, protocol), true
}

func (s *Server) platformDesktopParts(w http.ResponseWriter, session model.ConnectionSession, protocol model.Protocol) (model.PlatformItem, model.PlatformItem, store.CredentialSecret, bool) {
	asset, ok, err := s.cfg.Store.GetPlatformItem("assets", session.ServerID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return model.PlatformItem{}, model.PlatformItem{}, store.CredentialSecret{}, false
	}
	if !ok || asset.Protocol != protocol {
		writeError(w, http.StatusNotFound, "desktop asset not found")
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
	if !platformCredentialCompatible(credential, protocol) {
		writeError(w, http.StatusBadRequest, "credential is not compatible with "+string(protocol))
		return model.PlatformItem{}, model.PlatformItem{}, store.CredentialSecret{}, false
	}
	return asset, credential, secret, true
}

func (s *Server) createPlatformDesktopSession(w http.ResponseWriter, r *http.Request, protocol model.Protocol, req desktopCreateRequest, statusCode int) {
	if protocol != model.ProtocolRDP && protocol != model.ProtocolVNC {
		writeError(w, http.StatusBadRequest, "unsupported desktop protocol")
		return
	}
	req.AssetID = strings.TrimSpace(req.AssetID)
	if req.AssetID == "" {
		writeError(w, http.StatusBadRequest, "asset_id is required")
		return
	}
	platform, err := s.cfg.Store.PlatformBootstrap()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	userID, isAdmin := s.accessUser(r)
	asset, ok := findAccessAsset(platform, protocol, req.AssetID)
	if !ok {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}
	if !isAccessAuthorized(platform, protocol, asset.ID, userID, isAdmin) {
		writeError(w, http.StatusForbidden, "asset access denied")
		return
	}
	credential, secret, ok, err := s.resolvePlatformDesktopCredential(asset, protocol, req.CredentialID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusBadRequest, "compatible credential not found")
		return
	}
	if !desktopSecretPresent(protocol, secret) {
		writeError(w, http.StatusBadRequest, "credential secret is missing")
		return
	}
	policy := s.desktopAccessPolicy(protocol)
	req.Width = clampInt(req.Width, 640, 7680, policy.Width)
	req.Height = clampInt(req.Height, 480, 4320, policy.Height)
	req.DPI = clampInt(req.DPI, 72, 240, policy.DPI)
	session, err := s.cfg.Store.CreateSession(model.ConnectionSession{
		Protocol:            protocol,
		ServerID:            asset.ID,
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
	_ = s.audit(r, "connection."+string(protocol)+".create", session.ID, protocol, "created "+string(protocol)+" session")
	writeJSON(w, statusCode, session)
}

func (s *Server) createPlatformSSHSession(w http.ResponseWriter, r *http.Request, req sshAccessCreateRequest, statusCode int) {
	req.AssetID = strings.TrimSpace(req.AssetID)
	if req.AssetID == "" {
		writeError(w, http.StatusBadRequest, "asset_id is required")
		return
	}
	platform, err := s.cfg.Store.PlatformBootstrap()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	userID, isAdmin := s.accessUser(r)
	asset, ok := findAccessAsset(platform, model.ProtocolSSH, req.AssetID)
	if !ok {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}
	if !isAccessAuthorized(platform, model.ProtocolSSH, asset.ID, userID, isAdmin) {
		writeError(w, http.StatusForbidden, "asset access denied")
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
	req.Cols = clampInt(req.Cols, 40, 300, 120)
	req.Rows = clampInt(req.Rows, 10, 120, 32)
	session, err := s.cfg.Store.CreateSession(model.ConnectionSession{
		Protocol:     model.ProtocolSSH,
		ServerID:     asset.ID,
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
	writeJSON(w, statusCode, session)
}

func (s *Server) resolvePlatformDesktopCredential(asset model.PlatformItem, protocol model.Protocol, requestedID string) (model.PlatformItem, store.CredentialSecret, bool, error) {
	return s.resolvePlatformCredential(asset, protocol, requestedID)
}

func (s *Server) resolvePlatformCredential(asset model.PlatformItem, protocol model.Protocol, requestedID string) (model.PlatformItem, store.CredentialSecret, bool, error) {
	requestedID = strings.TrimSpace(requestedID)
	if requestedID != "" {
		credential, secret, ok, err := s.cfg.Store.GetPlatformCredentialSecret(requestedID)
		if err != nil || !ok {
			return model.PlatformItem{}, store.CredentialSecret{}, false, err
		}
		if platformCredentialCompatible(credential, protocol) && credentialTargetsAsset(credential, asset, true) {
			return credential, secret, true, nil
		}
		return model.PlatformItem{}, store.CredentialSecret{}, false, nil
	}
	candidateIDs := metadataStrings(asset.Metadata["credential_id"])
	candidateIDs = append(candidateIDs, metadataStrings(asset.Metadata["credential_ids"])...)
	seen := map[string]bool{}
	for _, id := range candidateIDs {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		credential, secret, ok, err := s.cfg.Store.GetPlatformCredentialSecret(id)
		if err != nil || !ok {
			return model.PlatformItem{}, store.CredentialSecret{}, false, err
		}
		if platformCredentialCompatible(credential, protocol) && credentialTargetsAsset(credential, asset, false) {
			return credential, secret, true, nil
		}
	}
	credentials, err := s.cfg.Store.ListPlatformItems("credentials")
	if err != nil {
		return model.PlatformItem{}, store.CredentialSecret{}, false, err
	}
	for _, credential := range credentials {
		if !platformCredentialCompatible(credential, protocol) || !credentialTargetsAsset(credential, asset, false) {
			continue
		}
		raw, secret, ok, err := s.cfg.Store.GetPlatformCredentialSecret(credential.ID)
		if err != nil || !ok {
			return model.PlatformItem{}, store.CredentialSecret{}, false, err
		}
		return raw, secret, true, nil
	}
	return model.PlatformItem{}, store.CredentialSecret{}, false, nil
}

func platformCredentialCompatible(credential model.PlatformItem, protocol model.Protocol) bool {
	credentialType := strings.ToLower(strings.TrimSpace(credential.Type))
	switch protocol {
	case model.ProtocolSSH:
		return credentialType == string(model.CredentialSSHPassword) || credentialType == string(model.CredentialSSHKey)
	case model.ProtocolRDP:
		return credentialType == string(model.CredentialRDPPassword)
	case model.ProtocolVNC:
		return credentialType == string(model.CredentialVNCPassword)
	default:
		return false
	}
}

func credentialTargetsAsset(credential, asset model.PlatformItem, strict bool) bool {
	if credential.TargetID == asset.ID || credential.TargetID == asset.Name {
		return true
	}
	for _, value := range metadataStrings(credential.Metadata["asset_id"]) {
		if value == asset.ID || value == asset.Name {
			return true
		}
	}
	for _, value := range metadataStrings(credential.Metadata["asset_ids"]) {
		for _, part := range splitCriteria(value) {
			if part == asset.ID || part == asset.Name {
				return true
			}
		}
	}
	return !strict && credential.TargetID == "" && len(metadataStrings(credential.Metadata["asset_id"])) == 0 && len(metadataStrings(credential.Metadata["asset_ids"])) == 0
}

func platformDesktopConfig(session model.ConnectionSession, asset, credential model.PlatformItem, secret store.CredentialSecret, protocol model.Protocol) guac.DesktopConfig {
	port := asset.Port
	if port == 0 {
		if protocol == model.ProtocolVNC {
			port = 5900
		} else {
			port = 3389
		}
	}
	colorDepth := session.ColorDepth
	if colorDepth == 0 {
		colorDepth = 24
	}
	if configured, ok := metadataInt(asset.Metadata["color_depth"]); ok {
		colorDepth = clampInt(configured, 8, 32, 24)
	}
	return guac.DesktopConfig{
		Protocol:         protocol,
		Session:          session,
		Host:             asset.Host,
		Port:             port,
		Username:         credential.Username,
		Password:         secret.Password,
		Domain:           firstMetadataString(credential.Metadata, "domain", "workgroup"),
		Width:            session.Width,
		Height:           session.Height,
		DPI:              clampInt(session.DPI, 72, 240, 96),
		ColorDepth:       colorDepth,
		IgnoreCert:       boolPtrValue(session.IgnoreCert, true),
		EnableDrive:      boolPtrValue(session.FileTransferEnabled, protocol == model.ProtocolRDP),
		ClipboardEnabled: boolPtrValue(session.ClipboardEnabled, true),
		ReadOnly:         boolPtrValue(session.ReadOnly, false),
		ResizeMethod:     session.ResizeMethod,
	}
}

func desktopSecretPresent(protocol model.Protocol, secret store.CredentialSecret) bool {
	switch protocol {
	case model.ProtocolRDP, model.ProtocolVNC:
		return strings.TrimSpace(secret.Password) != ""
	default:
		return false
	}
}

func sshSecretPresent(credential model.PlatformItem, secret store.CredentialSecret) bool {
	switch model.CredentialType(strings.ToLower(strings.TrimSpace(credential.Type))) {
	case model.CredentialSSHPassword:
		return strings.TrimSpace(secret.Password) != ""
	case model.CredentialSSHKey:
		return strings.TrimSpace(secret.PrivateKey) != ""
	default:
		return false
	}
}

func decodeOptionalDesktopCreateRequest(w http.ResponseWriter, r *http.Request) (desktopCreateRequest, bool) {
	if r.Body == nil || r.ContentLength == 0 {
		return desktopCreateRequest{}, true
	}
	var req desktopCreateRequest
	if !decodeJSON(w, r, &req) {
		return desktopCreateRequest{}, false
	}
	return req, true
}

func decodeOptionalSSHAccessCreateRequest(w http.ResponseWriter, r *http.Request) (sshAccessCreateRequest, bool) {
	if r.Body == nil || r.ContentLength == 0 {
		return sshAccessCreateRequest{}, true
	}
	var req sshAccessCreateRequest
	if !decodeJSON(w, r, &req) {
		return sshAccessCreateRequest{}, false
	}
	return req, true
}

func platformSSHServer(asset model.PlatformItem) model.Server {
	port := asset.Port
	if port == 0 {
		port = 22
	}
	return model.Server{
		ID:      asset.ID,
		Name:    asset.Name,
		Host:    asset.Host,
		SSHPort: port,
		OS:      model.ServerOSLinux,
		Group:   asset.Group,
	}
}

func platformSSHCredential(credential model.PlatformItem) model.Credential {
	return model.Credential{
		ID:       credential.ID,
		Name:     credential.Name,
		Type:     model.CredentialType(strings.ToLower(strings.TrimSpace(credential.Type))),
		Username: credential.Username,
	}
}
