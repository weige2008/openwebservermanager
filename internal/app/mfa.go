package app

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"openwebservermanager/internal/model"
	"openwebservermanager/internal/store"
)

const (
	totpDigits = 6
	totpPeriod = 30
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

func (s *Server) handleLoginMFA(w http.ResponseWriter, r *http.Request, user store.AdminPublic, username, clientIP, failureKey string, req loginRequest) (bool, bool) {
	profile, _, err := s.cfg.Store.UserMFAProfile(user.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return false, true
	}
	if profile.Enabled {
		if strings.TrimSpace(req.MFACode) == "" && strings.TrimSpace(req.RecoveryCode) == "" {
			s.writeMFAChallenge(w, r, user, username, clientIP, failureKey, false, "")
			return false, true
		}
		ok, method, err := s.verifyMFAInput(user.UserID, profile, req.MFACode, req.RecoveryCode)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return false, true
		}
		if !ok {
			s.recordMFAFailure(w, r, username, clientIP, failureKey, "invalid MFA code")
			return false, true
		}
		_ = s.audit(r, "auth.mfa.verify", user.UserID, "", "verified login MFA with "+method)
		return true, false
	}
	if s.forceMFAEnabled() {
		secret, err := generateTOTPSecret()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return false, true
		}
		s.writeMFAChallenge(w, r, user, username, clientIP, failureKey, true, secret)
		return false, true
	}
	return true, false
}

func (s *Server) handleMFACompleteLogin(w http.ResponseWriter, r *http.Request) {
	var req mfaCompleteLoginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	token := strings.TrimSpace(req.Token)
	challenge, ok := s.auth.mfaChallenge(token)
	if token == "" || !ok {
		writeError(w, http.StatusUnauthorized, "MFA challenge expired")
		return
	}
	defer s.auth.deleteMFAChallenge(token)
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
		mfaMutated = method == "recovery_code"
		_ = s.audit(r, "auth.mfa.verify", challenge.User.UserID, "", "verified login MFA with "+method)
	}

	if err := s.createLoginLog(r, model.PlatformItemRequest{
		Name:        challenge.Username,
		Type:        "mfa",
		Status:      "success",
		OwnerID:     challenge.User.UserID,
		Description: "signed in with MFA",
		Metadata:    map[string]any{"client_ip": challenge.ClientIP, "account": challenge.Username, "method": method},
	}); err != nil {
		if mfaMutated {
			_, _ = s.cfg.Store.SavePlatformItem("users", previous)
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auth.resetLoginFailures(challenge.FailureKey)
	authToken, session, err := s.auth.create(challenge.User)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.cfg.Store.RecordUserLogin(session.UserID, challenge.ClientIP, r.UserAgent())
	_ = s.audit(r, "auth.login", session.UserID, "", "signed in with MFA")
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
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":        profile.Enabled,
		"forced":         s.forceMFAEnabled(),
		"recovery_count": profile.RecoveryCount,
	})
}

func (s *Server) handleMFASetup(w http.ResponseWriter, r *http.Request) {
	_, session, _ := s.authSession(r)
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
	profile, err := s.cfg.Store.EnableUserMFA(session.UserID, secret, recoveryCodes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.createMFAOperationLog(r, "auth.mfa.enable", session.UserID, "enabled MFA", nil); err != nil {
		_, _ = s.cfg.Store.SavePlatformItem("users", previous)
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
	if !s.verifyCurrentPassword(session.Username, req.CurrentPassword) {
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
	if profile.Enabled {
		verified, _, err := s.verifyMFAInput(session.UserID, profile, req.MFACode, req.RecoveryCode)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !verified {
			writeError(w, http.StatusUnauthorized, "MFA code is invalid")
			return
		}
	}
	if err := s.cfg.Store.DisableUserMFA(session.UserID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.createMFAOperationLog(r, "auth.mfa.disable", session.UserID, "disabled MFA", nil); err != nil {
		_, _ = s.cfg.Store.SavePlatformItem("users", previous)
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
	if !s.verifyCurrentPassword(session.Username, req.CurrentPassword) {
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
	verified, _, err := s.verifyMFAInput(session.UserID, profile, req.MFACode, req.RecoveryCode)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !verified {
		writeError(w, http.StatusUnauthorized, "MFA code is invalid")
		return
	}
	recoveryCodes, err := generateRecoveryCodes(8)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	nextProfile, err := s.cfg.Store.ReplaceUserMFARecoveryCodes(session.UserID, recoveryCodes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.createMFAOperationLog(r, "auth.mfa.recovery_codes.regenerate", session.UserID, "regenerated MFA recovery codes", nil); err != nil {
		_, _ = s.cfg.Store.SavePlatformItem("users", previous)
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

func (s *Server) writeMFAChallenge(w http.ResponseWriter, r *http.Request, user store.AdminPublic, username, clientIP, failureKey string, setupRequired bool, secret string) {
	token, err := s.auth.createMFAChallenge(mfaChallenge{
		User:          user,
		Username:      username,
		ClientIP:      clientIP,
		FailureKey:    failureKey,
		SetupRequired: setupRequired,
		Secret:        secret,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	metadata := map[string]any{"client_ip": clientIP, "account": username, "setup_required": setupRequired}
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
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, payload)
}

func (s *Server) verifyMFAInput(userID string, profile store.MFAProfile, code, recoveryCode string) (bool, string, error) {
	if profile.Enabled && profile.Secret != "" && verifyTOTP(profile.Secret, code, time.Now().UTC()) {
		return true, "totp", nil
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

func (s *Server) recordMFAFailure(w http.ResponseWriter, r *http.Request, username, clientIP, failureKey, detail string) {
	failure := s.auth.recordLoginFailure(failureKey, s.loginFailurePolicy())
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

func (s *Server) verifyCurrentPassword(username, password string) bool {
	if strings.TrimSpace(password) == "" {
		return false
	}
	if _, ok, err := s.cfg.Store.VerifyAdmin(username, password); err == nil && ok {
		return true
	}
	if _, ok, err := s.cfg.Store.VerifyPlatformUser(username, password); err == nil && ok {
		return true
	}
	return false
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
	return strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""), "-", ""))
}

func verifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(strings.ReplaceAll(code, " ", ""))
	if len(code) != totpDigits {
		return false
	}
	for offset := -1; offset <= 1; offset++ {
		if expected, ok := totpCodeAt(secret, now.Add(time.Duration(offset*totpPeriod)*time.Second)); ok && expected == code {
			return true
		}
	}
	return false
}

func totpCode(secret string, now time.Time) string {
	code, _ := totpCodeAt(secret, now)
	return code
}

func totpCodeAt(secret string, now time.Time) (string, bool) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normalizeTOTPSecret(secret))
	if err != nil || len(key) == 0 {
		return "", false
	}
	counter := uint64(now.Unix() / totpPeriod)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)
	modulo := uint32(1)
	for i := 0; i < totpDigits; i++ {
		modulo *= 10
	}
	return fmt.Sprintf("%0"+strconv.Itoa(totpDigits)+"d", value%modulo), true
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
