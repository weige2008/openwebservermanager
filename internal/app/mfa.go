package app

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"openwebservermanager/internal/model"
	"openwebservermanager/internal/security"
	"openwebservermanager/internal/store"
)

const (
	totpDigits = security.TOTPDigits
	totpPeriod = security.TOTPPeriod
)

type mfaCompleteLoginRequest struct {
	Token        string `json:"token"`
	MFACode      string `json:"mfa_code"`
	RecoveryCode string `json:"recovery_code"`
}

type mfaEnableRequest struct {
	Secret  string `json:"secret"`
	MFACode string `json:"mfa_code"`
}

type mfaDisableRequest struct {
	CurrentPassword string `json:"current_password"`
	MFACode         string `json:"mfa_code"`
	RecoveryCode    string `json:"recovery_code"`
}

type mfaRecoveryCodesRequest struct {
	CurrentPassword string `json:"current_password"`
	MFACode         string `json:"mfa_code"`
	RecoveryCode    string `json:"recovery_code"`
}

func (s *Server) handleLoginMFA(w http.ResponseWriter, r *http.Request, user store.AdminPublic, username, clientIP, failureKey, loginType string, req loginRequest) (bool, bool, model.PlatformItem, bool) {
	profile, _, err := s.cfg.Store.UserMFAProfile(user.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return false, true, model.PlatformItem{}, false
	}
	if profile.Enabled {
		if strings.TrimSpace(req.MFACode) == "" && strings.TrimSpace(req.RecoveryCode) == "" {
			s.writeMFAChallenge(w, r, user, username, clientIP, failureKey, loginType, false, "", nil)
			return false, true, model.PlatformItem{}, false
		}
		previous, ok, err := s.userMFASnapshot(user.UserID)
		if err != nil || !ok {
			if err == nil {
				err = fmt.Errorf("user not found")
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return false, true, model.PlatformItem{}, false
		}
		ok, method, err := s.verifyMFAInput(user.UserID, profile, req.MFACode, req.RecoveryCode)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return false, true, model.PlatformItem{}, false
		}
		if !ok {
			s.recordMFAFailure(w, r, username, clientIP, failureKey, "invalid MFA code")
			return false, true, model.PlatformItem{}, false
		}
		_ = s.audit(r, "auth.mfa.verify", user.UserID, "", "verified login MFA with "+method)
		return true, false, previous, mfaVerificationMutates(method)
	}
	if s.forceMFAEnabled() {
		secret, err := generateTOTPSecret()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return false, true, model.PlatformItem{}, false
		}
		s.writeMFAChallenge(w, r, user, username, clientIP, failureKey, loginType, true, secret, nil)
		return false, true, model.PlatformItem{}, false
	}
	return true, false, model.PlatformItem{}, false
}

func (s *Server) handleMFACompleteLogin(w http.ResponseWriter, r *http.Request) {
	var req mfaCompleteLoginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	token := strings.TrimSpace(req.Token)
	challenge, ok, err := s.auth.consumeMFAChallenge(token)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if token == "" || !ok {
		writeError(w, http.StatusUnauthorized, "MFA challenge expired")
		return
	}
	currentUser, userOK, err := s.authUserByID(challenge.User.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !userOK {
		s.recordMFAFailure(w, r, challenge.Username, challenge.ClientIP, challenge.FailureKey, "MFA account is disabled or no longer exists")
		return
	}
	challenge.User = currentUser
	previous, ok, err := s.userMFASnapshot(challenge.User.UserID)
	if err != nil || !ok {
		if err == nil {
			err = fmt.Errorf("user not found")
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	mfaMutated := false
	var recoveryCodes []string
	var method string
	if challenge.SetupRequired {
		if !verifyTOTP(challenge.Secret, req.MFACode, time.Now().UTC()) {
			s.recordMFAFailure(w, r, challenge.Username, challenge.ClientIP, challenge.FailureKey, "invalid MFA enrollment code")
			return
		}
		var err error
		recoveryCodes, err = generateRecoveryCodes(8)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if _, err := s.cfg.Store.EnableUserMFA(challenge.User.UserID, challenge.Secret, recoveryCodes); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		mfaMutated = true
		method = "totp_setup"
		_ = s.audit(r, "auth.mfa.enable", challenge.User.UserID, "", "enabled MFA during forced enrollment")
	} else {
		profile, _, err := s.cfg.Store.UserMFAProfile(challenge.User.UserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		verified, verifiedMethod, err := s.verifyMFAInput(challenge.User.UserID, profile, req.MFACode, req.RecoveryCode)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !verified {
			s.recordMFAFailure(w, r, challenge.Username, challenge.ClientIP, challenge.FailureKey, "invalid MFA code")
			return
		}
		method = verifiedMethod
		mfaMutated = mfaVerificationMutates(method)
		_ = s.audit(r, "auth.mfa.verify", challenge.User.UserID, "", "verified login MFA with "+method)
	}

	loginType := strings.TrimSpace(challenge.LoginType)
	if loginType == "" {
		loginType = "mfa"
	}
	loginMetadata := cloneMetadata(challenge.LoginMetadata)
	loginMetadata["client_ip"] = challenge.ClientIP
	loginMetadata["account"] = challenge.Username
	loginMetadata["mfa_method"] = method
	if err := s.createLoginLog(r, model.PlatformItemRequest{
		Name:        challenge.Username,
		Type:        loginType,
		Status:      "success",
		OwnerID:     challenge.User.UserID,
		Description: "signed in with " + loginType + " and MFA",
		Metadata:    loginMetadata,
	}); err != nil {
		if mfaMutated {
			err = s.restoreMFASnapshotAfterFailure(r, challenge.User.UserID, previous, err)
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.auth.resetLoginFailures(challenge.FailureKey); err != nil {
		if mfaMutated {
			err = s.restoreMFASnapshotAfterFailure(r, challenge.User.UserID, previous, err)
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	authToken, session, err := s.auth.create(challenge.User)
	if err != nil {
		if mfaMutated {
			err = s.restoreMFASnapshotAfterFailure(r, challenge.User.UserID, previous, err)
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.recordUserLoginState(r, authToken, session, challenge.ClientIP); err != nil {
		if mfaMutated {
			err = s.restoreMFASnapshotAfterFailure(r, challenge.User.UserID, previous, err)
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "auth.login", session.UserID, "", "signed in with "+loginType+" and MFA")
	http.SetCookie(w, s.authCookie(r, authToken, int(authSessionTTL.Seconds())))
	writeJSON(w, http.StatusOK, map[string]any{"user": s.authUserPayload(session), "recovery_codes": recoveryCodes})
}

func (s *Server) handleAuthenticatedMFA(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/auth/mfa/status":
		s.handleMFAStatus(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/auth/mfa/setup":
		s.handleMFASetup(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/auth/mfa/enable":
		s.handleMFAEnable(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/auth/mfa/disable":
		s.handleMFADisable(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/auth/mfa/recovery-codes":
		s.handleMFARegenerateRecoveryCodes(w, r)
	default:
		writeError(w, http.StatusNotFound, "MFA endpoint not found")
	}
}

func (s *Server) handleMFAStatus(w http.ResponseWriter, r *http.Request) {
	_, session, _ := s.authSession(r)
	profile, _, err := s.cfg.Store.UserMFAProfile(session.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	passwordRequired, err := s.cfg.Store.UserHasLocalPassword(session.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":           profile.Enabled,
		"forced":            s.forceMFAEnabled(),
		"password_required": passwordRequired,
		"recovery_count":    profile.RecoveryCount,
	})
}

func (s *Server) handleMFASetup(w http.ResponseWriter, r *http.Request) {
	_, session, _ := s.authSession(r)
	profile, _, err := s.cfg.Store.UserMFAProfile(session.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if profile.Enabled {
		writeError(w, http.StatusConflict, "MFA is already enabled")
		return
	}
	secret, err := generateTOTPSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"secret":      secret,
		"otpauth_url": otpauthURL(s.mfaIssuer(), session.Username, secret),
		"digits":      totpDigits,
		"period":      totpPeriod,
	})
}

func (s *Server) handleMFAEnable(w http.ResponseWriter, r *http.Request) {
	var req mfaEnableRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	_, session, _ := s.authSession(r)
	profile, _, err := s.cfg.Store.UserMFAProfile(session.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if profile.Enabled {
		writeError(w, http.StatusConflict, "MFA is already enabled")
		return
	}
	secret := normalizeTOTPSecret(req.Secret)
	if secret == "" || !verifyTOTP(secret, req.MFACode, time.Now().UTC()) {
		writeError(w, http.StatusBadRequest, "invalid MFA setup code")
		return
	}
	recoveryCodes, err := generateRecoveryCodes(8)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	previous, ok, err := s.userMFASnapshot(session.UserID)
	if err != nil || !ok {
		if err == nil {
			err = fmt.Errorf("user not found")
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	profile, err = s.cfg.Store.EnableUserMFA(session.UserID, secret, recoveryCodes)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			writeError(w, http.StatusConflict, "MFA is already enabled")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.createMFAOperationLog(r, "auth.mfa.enable", session.UserID, "enabled MFA", nil); err != nil {
		err = s.restoreMFASnapshotAfterFailure(r, session.UserID, previous, err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "auth.mfa.enable", session.UserID, "", "enabled MFA")
	writeJSON(w, http.StatusOK, map[string]any{"enabled": profile.Enabled, "recovery_count": profile.RecoveryCount, "recovery_codes": recoveryCodes})
}

func (s *Server) handleMFADisable(w http.ResponseWriter, r *http.Request) {
	var req mfaDisableRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	_, session, _ := s.authSession(r)
	passwordOK, err := s.verifyMFAAccountPassword(session.UserID, req.CurrentPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !passwordOK {
		writeError(w, http.StatusUnauthorized, "current password is invalid")
		return
	}
	profile, _, err := s.cfg.Store.UserMFAProfile(session.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	previous, ok, err := s.userMFASnapshot(session.UserID)
	if err != nil || !ok {
		if err == nil {
			err = fmt.Errorf("user not found")
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	verificationMutated := false
	if profile.Enabled {
		verified, method, err := s.verifyMFAInput(session.UserID, profile, req.MFACode, req.RecoveryCode)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !verified {
			writeError(w, http.StatusUnauthorized, "MFA code is invalid")
			return
		}
		verificationMutated = mfaVerificationMutates(method)
	}
	if err := s.cfg.Store.DisableUserMFA(session.UserID); err != nil {
		if verificationMutated {
			err = s.restoreMFASnapshotAfterFailure(r, session.UserID, previous, err)
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.createMFAOperationLog(r, "auth.mfa.disable", session.UserID, "disabled MFA", nil); err != nil {
		err = s.restoreMFASnapshotAfterFailure(r, session.UserID, previous, err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "auth.mfa.disable", session.UserID, "", "disabled MFA")
	writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
}

func (s *Server) handleMFARegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	var req mfaRecoveryCodesRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	_, session, _ := s.authSession(r)
	passwordOK, err := s.verifyMFAAccountPassword(session.UserID, req.CurrentPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !passwordOK {
		writeError(w, http.StatusUnauthorized, "current password is invalid")
		return
	}
	profile, _, err := s.cfg.Store.UserMFAProfile(session.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !profile.Enabled {
		writeError(w, http.StatusConflict, "MFA is not enabled")
		return
	}
	previous, ok, err := s.userMFASnapshot(session.UserID)
	if err != nil || !ok {
		if err == nil {
			err = fmt.Errorf("user not found")
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	verified, method, err := s.verifyMFAInput(session.UserID, profile, req.MFACode, req.RecoveryCode)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !verified {
		writeError(w, http.StatusUnauthorized, "MFA code is invalid")
		return
	}
	verificationMutated := mfaVerificationMutates(method)
	recoveryCodes, err := generateRecoveryCodes(8)
	if err != nil {
		if verificationMutated {
			err = s.restoreMFASnapshotAfterFailure(r, session.UserID, previous, err)
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	nextProfile, err := s.cfg.Store.ReplaceUserMFARecoveryCodes(session.UserID, recoveryCodes)
	if err != nil {
		if verificationMutated {
			err = s.restoreMFASnapshotAfterFailure(r, session.UserID, previous, err)
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.createMFAOperationLog(r, "auth.mfa.recovery_codes.regenerate", session.UserID, "regenerated MFA recovery codes", nil); err != nil {
		err = s.restoreMFASnapshotAfterFailure(r, session.UserID, previous, err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "auth.mfa.recovery_codes.regenerate", session.UserID, "", "regenerated MFA recovery codes")
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":        nextProfile.Enabled,
		"recovery_count": nextProfile.RecoveryCount,
		"recovery_codes": recoveryCodes,
	})
}

func (s *Server) userMFASnapshot(userID string) (model.PlatformItem, bool, error) {
	item, ok, err := s.cfg.Store.GetPlatformItem("users", userID)
	if err != nil || !ok {
		return item, ok, err
	}
	item.Metadata = cloneMetadata(item.Metadata)
	return item, true, nil
}

func (s *Server) restoreMFASnapshotAfterFailure(r *http.Request, userID string, previous model.PlatformItem, err error) error {
	if _, restoreErr := s.cfg.Store.SavePlatformItem("users", previous); restoreErr != nil {
		detail := "failed to restore MFA state: " + restoreErr.Error()
		_ = s.audit(r, "auth.mfa.restore_failed", userID, "", detail)
		return fmt.Errorf("%w; additionally %s", err, detail)
	}
	return err
}

func (s *Server) createMFAOperationLog(r *http.Request, name, userID, description string, metadata map[string]any) error {
	if metadata == nil {
		metadata = map[string]any{}
	} else {
		metadata = cloneMetadata(metadata)
	}
	metadata["client_ip"] = s.clientIP(r)
	return s.createOperationLog(r, model.PlatformItemRequest{
		Name:        name,
		Type:        "mfa",
		Status:      "success",
		OwnerID:     userID,
		TargetID:    userID,
		Description: description,
		Metadata:    metadata,
	})
}

func (s *Server) writeMFAChallenge(w http.ResponseWriter, r *http.Request, user store.AdminPublic, username, clientIP, failureKey, loginType string, setupRequired bool, secret string, loginMetadata map[string]any) bool {
	loginType = strings.TrimSpace(loginType)
	if loginType == "" {
		loginType = "password"
	}
	token, err := s.auth.createMFAChallenge(mfaChallenge{
		User:          user,
		Username:      username,
		ClientIP:      clientIP,
		FailureKey:    failureKey,
		LoginType:     loginType,
		LoginMetadata: cloneMetadata(loginMetadata),
		SetupRequired: setupRequired,
		Secret:        secret,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return false
	}
	metadata := cloneMetadata(loginMetadata)
	metadata["client_ip"] = clientIP
	metadata["account"] = username
	metadata["login_type"] = loginType
	metadata["setup_required"] = setupRequired
	payload := map[string]any{"mfa_required": !setupRequired, "mfa_setup_required": setupRequired, "mfa_token": token}
	if setupRequired {
		metadata["method"] = "totp_setup"
		payload["secret"] = secret
		payload["otpauth_url"] = otpauthURL(s.mfaIssuer(), username, secret)
		payload["digits"] = totpDigits
		payload["period"] = totpPeriod
	}
	if err := s.createLoginLog(r, model.PlatformItemRequest{
		Name:        username,
		Type:        "mfa",
		Status:      "challenge",
		Description: "MFA verification required",
		Metadata:    metadata,
	}); err != nil {
		if _, consumed, cleanupErr := s.auth.consumeMFAChallenge(token); cleanupErr != nil || !consumed {
			detail := "failed to remove MFA challenge after login log failure"
			if cleanupErr != nil {
				detail += ": " + cleanupErr.Error()
			}
			_ = s.audit(r, "auth.mfa.challenge.restore_failed", user.UserID, "", detail)
			err = fmt.Errorf("%w; additionally %s", err, detail)
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return false
	}
	writeJSON(w, http.StatusAccepted, payload)
	return true
}

func (s *Server) verifyMFAInput(userID string, profile store.MFAProfile, code, recoveryCode string) (bool, string, error) {
	if profile.Enabled && profile.Secret != "" && strings.TrimSpace(code) != "" {
		ok, err := s.cfg.Store.ConsumeUserMFATOTP(userID, code, time.Now().UTC())
		if err != nil {
			return false, "totp", err
		}
		if ok {
			return true, "totp", nil
		}
	}
	recovery := strings.TrimSpace(recoveryCode)
	if recovery == "" {
		recovery = strings.TrimSpace(code)
	}
	if recovery != "" {
		ok, err := s.cfg.Store.ConsumeUserMFARecoveryCode(userID, recovery)
		if err != nil || !ok {
			return ok, "recovery_code", err
		}
		return true, "recovery_code", nil
	}
	return false, "", nil
}

func mfaVerificationMutates(method string) bool {
	return method == "totp" || method == "recovery_code"
}

func (s *Server) recordMFAFailure(w http.ResponseWriter, r *http.Request, username, clientIP, failureKey, detail string) {
	failure, err := s.auth.recordLoginFailure(failureKey, s.loginFailurePolicy())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !failure.LockedUntil.IsZero() {
		if err := s.createLoginLock(username, clientIP, failure); err != nil {
			lockDetail := "persist login lock failed: " + err.Error()
			_ = s.audit(r, "auth.login.lock.persist_failed", "", "", lockDetail)
			writeError(w, http.StatusInternalServerError, lockDetail)
			return
		}
	}
	if err := s.createLoginLog(r, model.PlatformItemRequest{
		Name:        username,
		Type:        "mfa",
		Status:      "failed",
		Description: detail,
		Metadata:    map[string]any{"client_ip": clientIP, "account": username},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeError(w, http.StatusUnauthorized, detail)
}

func (s *Server) forceMFAEnabled() bool {
	items, err := s.cfg.Store.ListPlatformItems("system_settings")
	if err != nil {
		return false
	}
	for _, item := range items {
		if !platformItemEnabled(item) {
			continue
		}
		itemType := strings.ToLower(strings.TrimSpace(item.Type))
		if itemType != "security" && itemType != "identity" && itemType != "access" && itemType != "mfa" {
			continue
		}
		for _, key := range []string{"force_mfa", "forceMFA", "mfa_required", "require_mfa", "access_mfa"} {
			if metadataBoolForMFA(item.Metadata[key]) {
				return true
			}
		}
	}
	return false
}

func (s *Server) verifyMFAAccountPassword(userID, password string) (bool, error) {
	required, err := s.cfg.Store.UserHasLocalPassword(userID)
	if err != nil || !required {
		return !required, err
	}
	return s.cfg.Store.VerifyUserPassword(userID, password)
}

func (s *Server) mfaIssuer() string {
	issuer := strings.TrimSpace(s.cfg.Public.SiteName)
	if issuer == "" {
		issuer = "Open Web Server Manager"
	}
	return issuer
}

func generateTOTPSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

func normalizeTOTPSecret(secret string) string {
	return security.NormalizeTOTPSecret(secret)
}

func verifyTOTP(secret, code string, now time.Time) bool {
	return security.VerifyTOTP(secret, code, now)
}

func totpCode(secret string, now time.Time) string {
	code, _ := totpCodeAt(secret, now)
	return code
}

func totpCodeAt(secret string, now time.Time) (string, bool) {
	return security.TOTPCodeAt(secret, now)
}

func generateRecoveryCodes(count int) ([]string, error) {
	codes := make([]string, 0, count)
	encoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	for len(codes) < count {
		buf := make([]byte, 6)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		raw := encoder.EncodeToString(buf)
		if len(raw) > 10 {
			raw = raw[:10]
		}
		codes = append(codes, raw[:5]+"-"+raw[5:])
	}
	return codes, nil
}

func otpauthURL(issuer, account, secret string) string {
	values := url.Values{}
	values.Set("secret", normalizeTOTPSecret(secret))
	values.Set("issuer", issuer)
	values.Set("algorithm", "SHA1")
	values.Set("digits", strconv.Itoa(totpDigits))
	values.Set("period", strconv.Itoa(totpPeriod))
	label := issuer + ":" + account
	return "otpauth://totp/" + url.PathEscape(label) + "?" + values.Encode()
}

func metadataBoolForMFA(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		text := strings.ToLower(strings.TrimSpace(typed))
		return text == "true" || text == "1" || text == "yes" || text == "enabled" || text == "required"
	case float64:
		return typed != 0
	case int:
		return typed != 0
	default:
		return false
	}
}
