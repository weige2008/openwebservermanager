package app

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"openwebservermanager/internal/model"
	"openwebservermanager/internal/store"
)

const (
	authCookieName = "openwebservermanager_session"
	authSessionTTL = 24 * time.Hour
)

type authManager struct {
	mu                   sync.RWMutex
	sessions             map[string]authSession
	failures             map[string]loginFailure
	mfaChallenges        map[string]mfaChallenge
	captchas             map[string]captchaChallenge
	accessMFAGrants      map[string]accessMFAGrant
	oidcStates           map[string]externalOIDCState
	wecomStates          map[string]externalWeComState
	passkeyRegistrations map[string]passkeyChallenge
	passkeyLogins        map[string]passkeyChallenge
}

type authSession struct {
	UserID    string    `json:"id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

type authUserPayload struct {
	UserID          string    `json:"id"`
	Username        string    `json:"username"`
	Role            string    `json:"role"`
	ExpiresAt       time.Time `json:"expires_at"`
	APIPermissions  []string  `json:"api_permissions,omitempty"`
	MenuPermissions []string  `json:"menu_permissions,omitempty"`
}

type loginFailure struct {
	Count       int
	LastFailure time.Time
	LockedUntil time.Time
}

type mfaChallenge struct {
	User          store.AdminPublic
	Username      string
	ClientIP      string
	FailureKey    string
	SetupRequired bool
	Secret        string
	ExpiresAt     time.Time
}

type accessMFAGrant struct {
	UserID    string
	ExpiresAt time.Time
}

type authStatus struct {
	Configured            bool `json:"configured"`
	CaptchaRequired       bool `json:"captcha_required"`
	PasswordLoginDisabled bool `json:"password_login_disabled"`
	LDAPLoginEnabled      bool `json:"ldap_login_enabled"`
}

type setupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginRequest struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	MFACode       string `json:"mfa_code"`
	RecoveryCode  string `json:"recovery_code"`
	CaptchaID     string `json:"captcha_id"`
	CaptchaAnswer string `json:"captcha_answer"`
}

func newAuthManager() *authManager {
	return &authManager{
		sessions:             map[string]authSession{},
		failures:             map[string]loginFailure{},
		mfaChallenges:        map[string]mfaChallenge{},
		captchas:             map[string]captchaChallenge{},
		accessMFAGrants:      map[string]accessMFAGrant{},
		oidcStates:           map[string]externalOIDCState{},
		wecomStates:          map[string]externalWeComState{},
		passkeyRegistrations: map[string]passkeyChallenge{},
		passkeyLogins:        map[string]passkeyChallenge{},
	}
}

func (m *authManager) create(admin store.AdminPublic) (string, authSession, error) {
	token, err := randomToken()
	if err != nil {
		return "", authSession{}, err
	}
	session := authSession{
		UserID:    admin.UserID,
		Username:  admin.Username,
		Role:      admin.Role,
		ExpiresAt: time.Now().Add(authSessionTTL).UTC(),
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[token] = session
	return token, session, nil
}

func (m *authManager) delete(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, token)
	delete(m.accessMFAGrants, token)
}

func (m *authManager) hasUserSession(userID string) bool {
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	for token, session := range m.sessions {
		if now.After(session.ExpiresAt) {
			delete(m.sessions, token)
			continue
		}
		if session.UserID == userID {
			return true
		}
	}
	return false
}

func (m *authManager) session(r *http.Request) (string, authSession, bool) {
	cookie, err := r.Cookie(authCookieName)
	if err != nil || cookie.Value == "" {
		return "", authSession{}, false
	}
	token := cookie.Value
	now := time.Now().UTC()

	m.mu.RLock()
	session, ok := m.sessions[token]
	m.mu.RUnlock()
	if !ok {
		return "", authSession{}, false
	}
	if now.After(session.ExpiresAt) {
		m.delete(token)
		return "", authSession{}, false
	}
	return token, session, true
}

func (m *authManager) checkLoginAllowed(key string, policy loginFailurePolicy) (time.Duration, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	failure := m.failures[key]
	now := time.Now().UTC()
	if !failure.LockedUntil.IsZero() && now.Before(failure.LockedUntil) {
		return time.Until(failure.LockedUntil).Round(time.Second), false
	}
	if !failure.LastFailure.IsZero() && now.Sub(failure.LastFailure) > policy.Window {
		delete(m.failures, key)
	}
	return 0, true
}

func (m *authManager) recordLoginFailure(key string, policy loginFailurePolicy) loginFailure {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	failure := m.failures[key]
	if !failure.LastFailure.IsZero() && now.Sub(failure.LastFailure) > policy.Window {
		failure = loginFailure{}
	}
	failure.Count++
	failure.LastFailure = now
	if failure.Count >= policy.Threshold {
		failure.LockedUntil = now.Add(policy.LockDuration)
	}
	m.failures[key] = failure
	return failure
}

func (m *authManager) resetLoginFailures(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.failures, key)
}

func (m *authManager) clearSessions() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions = map[string]authSession{}
	m.mfaChallenges = map[string]mfaChallenge{}
	m.captchas = map[string]captchaChallenge{}
	m.accessMFAGrants = map[string]accessMFAGrant{}
	m.oidcStates = map[string]externalOIDCState{}
	m.wecomStates = map[string]externalWeComState{}
	m.passkeyRegistrations = map[string]passkeyChallenge{}
	m.passkeyLogins = map[string]passkeyChallenge{}
}

func (m *authManager) grantAccessMFA(token, userID string, ttl time.Duration) {
	if strings.TrimSpace(token) == "" || strings.TrimSpace(userID) == "" || ttl <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accessMFAGrants[token] = accessMFAGrant{
		UserID:    userID,
		ExpiresAt: time.Now().Add(ttl).UTC(),
	}
}

func (m *authManager) accessMFAValid(token, userID string) bool {
	if strings.TrimSpace(token) == "" || strings.TrimSpace(userID) == "" {
		return false
	}
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	grant, ok := m.accessMFAGrants[token]
	if !ok {
		return false
	}
	if now.After(grant.ExpiresAt) {
		delete(m.accessMFAGrants, token)
		return false
	}
	return grant.UserID == userID
}

func (m *authManager) createMFAChallenge(challenge mfaChallenge) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	challenge.ExpiresAt = time.Now().Add(5 * time.Minute).UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mfaChallenges[token] = challenge
	return token, nil
}

func (m *authManager) mfaChallenge(token string) (mfaChallenge, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	challenge, ok := m.mfaChallenges[token]
	if !ok {
		return mfaChallenge{}, false
	}
	if time.Now().UTC().After(challenge.ExpiresAt) {
		delete(m.mfaChallenges, token)
		return mfaChallenge{}, false
	}
	return challenge, true
}

func (m *authManager) deleteMFAChallenge(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.mfaChallenges, token)
}

func (m *authManager) createPasskeyRegistrationChallenge(challenge passkeyChallenge) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	challenge.ExpiresAt = time.Now().Add(5 * time.Minute).UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.passkeyRegistrations[token] = challenge
	return token, nil
}

func (m *authManager) passkeyRegistrationChallenge(token string) (passkeyChallenge, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	challenge, ok := m.passkeyRegistrations[token]
	if !ok {
		return passkeyChallenge{}, false
	}
	if time.Now().UTC().After(challenge.ExpiresAt) {
		delete(m.passkeyRegistrations, token)
		return passkeyChallenge{}, false
	}
	return challenge, true
}

func (m *authManager) deletePasskeyRegistrationChallenge(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.passkeyRegistrations, token)
}

func (m *authManager) createPasskeyLoginChallenge(challenge passkeyChallenge) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	challenge.ExpiresAt = time.Now().Add(5 * time.Minute).UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.passkeyLogins[token] = challenge
	return token, nil
}

func (m *authManager) passkeyLoginChallenge(token string) (passkeyChallenge, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	challenge, ok := m.passkeyLogins[token]
	if !ok {
		return passkeyChallenge{}, false
	}
	if time.Now().UTC().After(challenge.ExpiresAt) {
		delete(m.passkeyLogins, token)
		return passkeyChallenge{}, false
	}
	return challenge, true
}

func (m *authManager) deletePasskeyLoginChallenge(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.passkeyLogins, token)
}

func (s *Server) requireAuth(w http.ResponseWriter, r *http.Request) bool {
	if !s.cfg.Store.AdminConfigured() {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error":          "admin setup required",
			"setup_required": true,
		})
		return false
	}
	_, _, ok := s.auth.session(r)
	if ok {
		return true
	}
	writeError(w, http.StatusUnauthorized, "authentication required")
	return false
}

func (s *Server) currentUserID(r *http.Request) string {
	_, session, ok := s.auth.session(r)
	if !ok || session.UserID == "" {
		return "anonymous"
	}
	return session.UserID
}

func (s *Server) authUserPayload(session authSession) authUserPayload {
	decision := s.roleDecision(session.Role)
	return authUserPayload{
		UserID:          session.UserID,
		Username:        session.Username,
		Role:            session.Role,
		ExpiresAt:       session.ExpiresAt,
		APIPermissions:  decision.Permissions,
		MenuPermissions: decision.MenuPermissions,
	}
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, authStatus{
		Configured:            s.cfg.Store.AdminConfigured(),
		CaptchaRequired:       s.captchaRequired(),
		PasswordLoginDisabled: s.passwordLoginDisabled(),
		LDAPLoginEnabled:      s.ldapLoginConfigured(),
	})
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	var req setupRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	username := strings.TrimSpace(req.Username)
	if username == "" {
		username = "admin"
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	admin, err := s.cfg.Store.SetupAdmin(username, req.Password)
	if err != nil {
		if errors.Is(err, store.ErrAdminAlreadyConfigured) {
			writeError(w, http.StatusConflict, "admin already configured")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	token, session, err := s.auth.create(admin)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	http.SetCookie(w, s.authCookie(r, token, int(authSessionTTL.Seconds())))
	_ = s.cfg.Store.RecordUserLogin(session.UserID, s.clientIP(r), r.UserAgent())
	_ = s.audit(r, "auth.setup", session.UserID, "", "admin initialized")
	_, _ = s.cfg.Store.CreatePlatformItem("login_logs", model.PlatformItemRequest{
		Name:        username,
		Type:        "setup",
		Status:      "success",
		OwnerID:     session.UserID,
		Description: "administrator initialized",
		Metadata:    map[string]any{"client_ip": s.clientIP(r), "account": username},
	})
	writeJSON(w, http.StatusCreated, map[string]any{"user": s.authUserPayload(session)})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !s.cfg.Store.AdminConfigured() {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":          "admin setup required",
			"setup_required": true,
		})
		return
	}
	username := strings.TrimSpace(req.Username)
	clientIP := s.clientIP(r)
	passwordLoginDisabled := s.passwordLoginDisabled()
	if passwordLoginDisabled && !s.ldapLoginConfigured() {
		_, _ = s.cfg.Store.CreatePlatformItem("login_logs", model.PlatformItemRequest{
			Name:        username,
			Type:        "password",
			Status:      "denied",
			Description: "password login is disabled",
			Metadata:    map[string]any{"client_ip": clientIP, "account": username},
		})
		_ = s.audit(r, "auth.login.password_denied", "", "", "password login is disabled")
		writeError(w, http.StatusForbidden, "password login is disabled")
		return
	}
	if s.captchaRequired() && !s.verifyCaptcha(req.CaptchaID, req.CaptchaAnswer) {
		_, _ = s.cfg.Store.CreatePlatformItem("login_logs", model.PlatformItemRequest{
			Name:        username,
			Type:        "captcha",
			Status:      "failed",
			Description: "invalid captcha",
			Metadata:    map[string]any{"client_ip": clientIP, "account": username},
		})
		writeError(w, http.StatusBadRequest, "captcha is required or invalid")
		return
	}
	if ok, reason := s.loginPolicyAllows(username, clientIP); !ok {
		_, _ = s.cfg.Store.CreatePlatformItem("login_logs", model.PlatformItemRequest{
			Name:        username,
			Type:        "policy",
			Status:      "denied",
			Description: reason,
			Metadata:    map[string]any{"client_ip": clientIP, "account": username},
		})
		writeError(w, http.StatusForbidden, reason)
		return
	}
	if retryAfter, locked := s.activeLoginLock(username, clientIP); locked {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
		writeError(w, http.StatusTooManyRequests, "account or client ip is locked; try again later")
		return
	}
	failureKey := clientIP + ":" + strings.ToLower(username)
	failurePolicy := s.loginFailurePolicy()
	if retryAfter, ok := s.auth.checkLoginAllowed(failureKey, failurePolicy); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
		writeError(w, http.StatusTooManyRequests, "too many failed login attempts; try again later")
		return
	}

	var admin store.AdminPublic
	loginType := "password"
	ok := false
	var err error
	if !passwordLoginDisabled {
		admin, ok, err = s.cfg.Store.VerifyAdmin(username, req.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !ok {
			admin, ok, err = s.cfg.Store.VerifyPlatformUser(username, req.Password)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
	}
	if !ok {
		var providerID string
		admin, providerID, ok, err = s.authenticateExternalLDAP(r.Context(), username, req.Password)
		if err != nil {
			status := http.StatusBadGateway
			if errors.Is(err, errExternalLDAPUserDisabled) || errors.Is(err, errExternalLDAPUserNotAllowed) {
				status = http.StatusForbidden
			}
			_, _ = s.cfg.Store.CreatePlatformItem("login_logs", model.PlatformItemRequest{
				Name:        username,
				Type:        "ldap",
				Status:      "failed",
				Description: err.Error(),
				Metadata:    map[string]any{"client_ip": clientIP, "account": username, "provider_id": providerID},
			})
			writeError(w, status, err.Error())
			return
		}
		if ok {
			loginType = "ldap"
		}
	}
	if !ok {
		failure := s.auth.recordLoginFailure(failureKey, failurePolicy)
		if !failure.LockedUntil.IsZero() {
			s.createLoginLock(username, clientIP, failure)
		}
		_, _ = s.cfg.Store.CreatePlatformItem("login_logs", model.PlatformItemRequest{
			Name:        username,
			Type:        "password",
			Status:      "failed",
			Description: "invalid username or password",
			Metadata:    map[string]any{"client_ip": clientIP, "account": username},
		})
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	s.auth.resetLoginFailures(failureKey)

	if proceed, handled := s.handleLoginMFA(w, r, admin, username, clientIP, failureKey, req); handled {
		return
	} else if !proceed {
		return
	}

	token, session, err := s.auth.create(admin)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	http.SetCookie(w, s.authCookie(r, token, int(authSessionTTL.Seconds())))
	_ = s.cfg.Store.RecordUserLogin(session.UserID, clientIP, r.UserAgent())
	_ = s.audit(r, "auth.login", session.UserID, "", "signed in with "+loginType)
	_, _ = s.cfg.Store.CreatePlatformItem("login_logs", model.PlatformItemRequest{
		Name:        username,
		Type:        loginType,
		Status:      "success",
		OwnerID:     session.UserID,
		Description: "signed in",
		Metadata:    map[string]any{"client_ip": clientIP, "account": username},
	})
	writeJSON(w, http.StatusOK, map[string]any{"user": s.authUserPayload(session)})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if token, session, ok := s.auth.session(r); ok {
		s.auth.delete(token)
		if !s.auth.hasUserSession(session.UserID) {
			_ = s.cfg.Store.RecordUserLogout(session.UserID)
		}
		_ = s.audit(r, "auth.logout", session.UserID, "", "admin signed out")
	}
	http.SetCookie(w, s.authCookie(r, "", -1))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	_, session, ok := s.auth.session(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": s.authUserPayload(session)})
}

func (s *Server) authCookie(r *http.Request, value string, maxAge int) *http.Cookie {
	expires := time.Now().Add(authSessionTTL)
	if maxAge < 0 {
		expires = time.Unix(0, 0)
	}
	return &http.Cookie{
		Name:     authCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		Expires:  expires,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
	}
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
