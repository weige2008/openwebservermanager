package app

import (
	"net/http"
	"strings"
	"time"
)

const defaultAccessMFATTL = 10 * time.Minute

type accessMFAInput struct {
	MFACode      string
	RecoveryCode string
}

func accessMFAInputFromRequest(r *http.Request) accessMFAInput {
	query := r.URL.Query()
	code := strings.TrimSpace(r.Header.Get("X-OpenWebServerManager-MFA-Code"))
	if code == "" {
		code = strings.TrimSpace(query.Get("mfa_code"))
	}
	recovery := strings.TrimSpace(r.Header.Get("X-OpenWebServerManager-Recovery-Code"))
	if recovery == "" {
		recovery = strings.TrimSpace(query.Get("recovery_code"))
	}
	return accessMFAInput{MFACode: code, RecoveryCode: recovery}
}

func (s *Server) requireAccessMFA(w http.ResponseWriter, r *http.Request, input accessMFAInput) bool {
	enabled, ttl := s.accessMFASettings()
	if !enabled {
		return true
	}
	token, session, ok := s.auth.session(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return false
	}
	if s.auth.accessMFAValid(token, session.UserID) {
		return true
	}
	profile, _, err := s.cfg.Store.UserMFAProfile(session.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return false
	}
	if !profile.Enabled {
		_ = s.audit(r, "access.mfa.setup_required", session.UserID, "", "access MFA requires user MFA enrollment")
		s.writeAccessMFARequired(w, ttl, true)
		return false
	}
	if strings.TrimSpace(input.MFACode) == "" && strings.TrimSpace(input.RecoveryCode) == "" {
		s.writeAccessMFARequired(w, ttl, false)
		return false
	}
	verified, method, err := s.verifyMFAInput(session.UserID, profile, input.MFACode, input.RecoveryCode)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return false
	}
	if !verified {
		_ = s.audit(r, "access.mfa.failed", session.UserID, "", "invalid access MFA code")
		writeError(w, http.StatusUnauthorized, "access MFA code is invalid")
		return false
	}
	s.auth.grantAccessMFA(token, session.UserID, ttl)
	_ = s.audit(r, "access.mfa.verify", session.UserID, "", "verified access MFA with "+method)
	return true
}

func (s *Server) writeAccessMFARequired(w http.ResponseWriter, ttl time.Duration, setupRequired bool) {
	message := "access MFA required"
	if setupRequired {
		message = "access MFA setup required"
	}
	writeJSON(w, http.StatusPreconditionRequired, map[string]any{
		"error":              message,
		"mfa_required":       true,
		"mfa_scope":          "access",
		"mfa_setup_required": setupRequired,
		"expires_in":         int(ttl.Seconds()),
	})
}

func (s *Server) accessMFASettings() (bool, time.Duration) {
	ttl := defaultAccessMFATTL
	items, err := s.cfg.Store.ListPlatformItems("system_settings")
	if err != nil {
		return false, ttl
	}
	for _, item := range items {
		if !platformItemEnabled(item) {
			continue
		}
		itemType := strings.ToLower(strings.TrimSpace(item.Type))
		if itemType != "access" && itemType != "security" && itemType != "mfa" {
			continue
		}
		ttl = accessMFATTLFromMetadata(item.Metadata, ttl)
		if enabled, ok := metadataBoolByKeys(item.Metadata,
			"access_mfa_enabled",
			"accessMfaEnabled",
			"access_mfa_required",
			"accessMfaRequired",
			"access_mfa",
			"accessMFA",
			"mfa_required",
			"require_mfa",
		); ok {
			return enabled, ttl
		}
	}
	return false, ttl
}

func accessMFATTLFromMetadata(metadata map[string]any, fallback time.Duration) time.Duration {
	if metadata == nil {
		return fallback
	}
	if seconds, ok := metadataIntByKeys(metadata, "access_mfa_ttl_seconds", "mfa_valid_seconds", "access_mfa_valid_seconds"); ok {
		return time.Duration(clampInt(seconds, 60, 86400, int(fallback.Seconds()))) * time.Second
	}
	if minutes, ok := metadataIntByKeys(metadata, "access_mfa_valid_minutes", "mfa_valid_minutes", "access_mfa_ttl_minutes"); ok {
		return time.Duration(clampInt(minutes, 1, 1440, int(fallback.Minutes()))) * time.Minute
	}
	return fallback
}
