package app

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"openwebservermanager/internal/model"
	sshrunner "openwebservermanager/internal/ssh"
)

type commandApprovalExecuteRequest struct {
	TimeoutSeconds int    `json:"timeout_seconds"`
	MFACode        string `json:"mfa_code"`
	RecoveryCode   string `json:"recovery_code"`
}

func (s *Server) handleCommandApprovalDecision(w http.ResponseWriter, r *http.Request, id, nextStatus string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	approval, ok, err := s.cfg.Store.GetPlatformItem("command_approvals", id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "command approval not found")
		return
	}
	status := strings.ToLower(strings.TrimSpace(approval.Status))
	if status == "" {
		status = "pending"
	}
	if status != "pending" {
		writeError(w, http.StatusConflict, "command approval decisions can only be made while pending")
		return
	}
	var req workOrderDecisionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	userID, isAdmin := s.accessUser(r)
	if nextStatus == "approved" && !isAdmin && commandApprovalRequesterMatches(approval, userID) {
		_ = s.audit(r, "command_approval.approve.denied", id, model.ProtocolSSH, "command approval cannot be self-approved")
		writeError(w, http.StatusForbidden, "command approval cannot be self-approved")
		return
	}
	if _, _, ok := s.commandApprovalSSHAsset(w, r, approval); !ok {
		return
	}
	nextMetadata := cloneMetadata(approval.Metadata)
	now := time.Now().UTC()
	if nextStatus == "approved" {
		nextMetadata["approved_by"] = userID
		nextMetadata["approved_at"] = now
		nextMetadata["approval_note"] = strings.TrimSpace(req.Note)
	} else {
		nextMetadata["rejected_by"] = userID
		nextMetadata["rejected_at"] = now
		nextMetadata["rejection_note"] = strings.TrimSpace(req.Note)
	}
	item, err := s.cfg.Store.UpdatePlatformItem("command_approvals", id, model.PlatformItemRequest{
		Status:   nextStatus,
		Protocol: model.ProtocolSSH,
		Metadata: nextMetadata,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.createCommandApprovalDecisionOperationLog(r, nextStatus, item, "set command approval "+nextStatus); err != nil {
		if _, restoreErr := s.cfg.Store.SavePlatformItem("command_approvals", approval); restoreErr != nil {
			err = fmt.Errorf("%w; additionally failed to restore command approval: %v", err, restoreErr)
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "command_approval."+nextStatus, id, model.ProtocolSSH, "set command approval "+nextStatus)
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) createCommandApprovalDecisionOperationLog(r *http.Request, status string, item model.PlatformItem, description string) error {
	return s.createOperationLog(r, model.PlatformItemRequest{
		Name:        "command_approval." + status,
		Type:        "command_approvals",
		Status:      "success",
		Protocol:    model.ProtocolSSH,
		TargetID:    item.ID,
		OwnerID:     s.currentUserID(r),
		Description: description,
		Metadata: map[string]any{
			"collection": "command_approvals",
			"item_id":    item.ID,
			"decision":   status,
			"client_ip":  s.clientIP(r),
		},
	})
}

func (s *Server) handleCommandApprovalExecute(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	approval, ok, err := s.cfg.Store.GetPlatformItem("command_approvals", id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "command approval not found")
		return
	}
	if !strings.EqualFold(strings.TrimSpace(approval.Status), "approved") {
		writeError(w, http.StatusConflict, "command approval must be approved before execution")
		return
	}
	var req commandApprovalExecuteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !s.requireAccessMFA(w, r, accessMFAInput{MFACode: req.MFACode, RecoveryCode: req.RecoveryCode}) {
		return
	}
	command := strings.TrimSpace(firstMetadataString(approval.Metadata, "command"))
	if command == "" {
		writeError(w, http.StatusBadRequest, "command approval is missing command")
		return
	}
	asset, _, ok := s.commandApprovalSSHAsset(w, r, approval)
	if !ok {
		return
	}
	credentialID := firstMetadataString(approval.Metadata, "credential_id")
	credential, secret, ok, err := s.resolvePlatformCredential(asset, model.ProtocolSSH, credentialID)
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
	gatewayRoute, ok := s.requireAssetGatewayRoute(w, asset)
	if !ok {
		return
	}
	requestedBy := commandApprovalRequesterID(approval)
	if requestedBy == "" {
		requestedBy = s.currentUserID(r)
	}
	sessionRequest := model.ConnectionSession{
		Protocol:     model.ProtocolSSH,
		ServerID:     asset.ID,
		CredentialID: credential.ID,
		UserID:       requestedBy,
		ClientIP:     s.clientIP(r),
	}
	applyGatewayRouteSession(&sessionRequest, gatewayRoute)
	session, err := s.cfg.Store.CreateSession(sessionRequest)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	timeout := time.Duration(clampInt(req.TimeoutSeconds, 1, 600, 30)) * time.Second
	result, runErr := sshrunner.Runner{
		Store:          s.cfg.Store,
		Logger:         slog.Default(),
		KnownHostsPath: filepath.Join(s.cfg.DataDir, "known_hosts"),
	}.RunApprovedCommand(session, platformSSHServer(asset), platformSSHCredential(credential), secret, command, timeout, approval.ID)
	if errors.Is(runErr, sshrunner.ErrExecCommandLogPersist) {
		s.handleExecCommandLogPersistFailure(w, r, approval.ID, runErr)
		return
	}

	nextMetadata := commandApprovalExecutionMetadata(approval, session, result, s.currentUserID(r))
	nextStatus := "executed"
	statusCode := http.StatusOK
	auditAction := "command_approval.execute"
	auditMessage := "executed approved ssh command"
	switch {
	case errors.Is(runErr, sshrunner.ErrCommandBlocked):
		nextStatus = "denied"
		statusCode = http.StatusForbidden
		auditAction = "command_approval.execute.denied"
		auditMessage = "approved ssh command was blocked by a deny rule"
	case errors.Is(runErr, sshrunner.ErrCommandTimeout):
		nextStatus = "failed"
		statusCode = http.StatusGatewayTimeout
		auditAction = "command_approval.execute.timeout"
		auditMessage = "approved ssh command timed out"
	case runErr != nil:
		nextStatus = "failed"
		statusCode = http.StatusBadGateway
		auditAction = "command_approval.execute.failed"
		auditMessage = "approved ssh command failed"
	}
	if runErr != nil {
		nextMetadata["execution_error"] = result.Error
	}
	if _, ok := s.updateCommandApprovalExecutionState(w, r, id, nextStatus, nextMetadata); !ok {
		return
	}
	_ = s.audit(r, auditAction, id, model.ProtocolSSH, auditMessage)
	writeJSON(w, statusCode, result)
}

func (s *Server) updateCommandApprovalExecutionState(w http.ResponseWriter, r *http.Request, id, status string, metadata map[string]any) (model.PlatformItem, bool) {
	item, err := s.cfg.Store.UpdatePlatformItem("command_approvals", id, model.PlatformItemRequest{
		Status:   status,
		Protocol: model.ProtocolSSH,
		Metadata: metadata,
	})
	if err != nil {
		detail := "persist command approval " + status + " state failed: " + err.Error()
		_ = s.audit(r, "command_approval.execute.persist_failed", id, model.ProtocolSSH, detail)
		writeError(w, http.StatusInternalServerError, detail)
		return model.PlatformItem{}, false
	}
	return item, true
}

func commandApprovalExecutionMetadata(approval model.PlatformItem, session model.ConnectionSession, result sshrunner.ExecResult, userID string) map[string]any {
	nextMetadata := cloneMetadata(approval.Metadata)
	nextMetadata["session_id"] = session.ID
	nextMetadata["executed_session_id"] = session.ID
	nextMetadata["executed_by"] = userID
	nextMetadata["executed_at"] = time.Now().UTC()
	nextMetadata["execution_status"] = result.Status
	nextMetadata["exit_code"] = result.ExitCode
	nextMetadata["duration_ms"] = result.DurationMs
	nextMetadata["stdout"] = result.Stdout
	nextMetadata["stderr"] = result.Stderr
	nextMetadata["error"] = result.Error
	nextMetadata["approved_execution"] = result.ApprovedExecution
	return nextMetadata
}

func commandApprovalRequesterID(approval model.PlatformItem) string {
	return firstNonEmpty(
		firstMetadataString(approval.Metadata, "requested_by", "requester", "requester_id", "applicant_id", "applicant"),
		approval.OwnerID,
		approval.Username,
	)
}

func commandApprovalRequesterMatches(approval model.PlatformItem, userID string) bool {
	requester := commandApprovalRequesterID(approval)
	return requester != "" && strings.EqualFold(strings.TrimSpace(requester), strings.TrimSpace(userID))
}

func commandApprovalAssetID(approval model.PlatformItem) string {
	return firstNonEmpty(
		strings.TrimSpace(approval.TargetID),
		firstMetadataString(approval.Metadata, "server_id", "asset_id", "target_id"),
	)
}

func (s *Server) commandApprovalSSHAsset(w http.ResponseWriter, r *http.Request, approval model.PlatformItem) (model.PlatformItem, string, bool) {
	assetID := commandApprovalAssetID(approval)
	if assetID == "" {
		writeError(w, http.StatusBadRequest, "command approval is missing ssh asset")
		return model.PlatformItem{}, "", false
	}
	platform, err := s.cfg.Store.PlatformBootstrap()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return model.PlatformItem{}, "", false
	}
	asset, ok := findAccessAsset(platform, model.ProtocolSSH, assetID)
	if !ok {
		writeError(w, http.StatusNotFound, "ssh asset not found")
		return model.PlatformItem{}, "", false
	}
	userID, isAdmin := s.accessUser(r)
	if !isAccessAuthorized(platform, model.ProtocolSSH, asset.ID, userID, isAdmin) {
		_ = s.audit(r, "command_approval.asset_access.denied", approval.ID, model.ProtocolSSH, "ssh asset access denied: "+asset.ID)
		writeError(w, http.StatusForbidden, "ssh asset access denied")
		return model.PlatformItem{}, "", false
	}
	return asset, userID, true
}
