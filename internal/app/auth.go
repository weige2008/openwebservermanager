package app

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
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
	store                *store.Store
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
	AuthTime  time.Time `json:"auth_time"`
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

type passwordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func newAuthManager(st *store.Store) *authManager {
	return &authManager{
		store:                st,
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
	now := time.Now().UTC()
	session := authSession{
		UserID:    admin.UserID,
		Username:  admin.Username,
		Role:      admin.Role,
		AuthTime:  now,
		ExpiresAt: now.Add(authSessionTTL),
	}
	if err := m.prunePersistedSessions(); err != nil {
		return "", authSession{}, err
	}
	if err := m.persistSession(token, session); err != nil {
		return "", authSession{}, err
	}
	m.mu.Lock()
	m.sessions[token] = session
	m.mu.Unlock()
	return token, session, nil
}

func (m *authManager) delete(token string) error {
	m.mu.Lock()
	delete(m.sessions, token)
	delete(m.accessMFAGrants, token)
	m.mu.Unlock()
	if m.store != nil {
		if err := m.store.DeletePlatformItem("auth_sessions", authSessionRecordID(token)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (m *authManager) refreshSession(token string, session authSession) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}
	if err := m.persistSession(token, session); err != nil {
		m.mu.Lock()
		delete(m.sessions, token)
		delete(m.accessMFAGrants, token)
		m.mu.Unlock()
		return err
	}
	m.mu.Lock()
	if _, ok := m.sessions[token]; ok {
		m.sessions[token] = session
	}
	m.mu.Unlock()
	return nil
}

func (m *authManager) deleteUserSessionsExcept(userID, keepToken string) error {
	userID = strings.TrimSpace(userID)
	keepToken = strings.TrimSpace(keepToken)
	if userID == "" {
		return nil
	}
	if m.store != nil {
		items, err := m.store.ListPlatformItems("auth_sessions")
		if err != nil {
			return err
		}
		keepID := authSessionRecordID(keepToken)
		for _, item := range items {
			if item.OwnerID == userID && item.ID != keepID {
				if err := m.store.DeletePlatformItem("auth_sessions", item.ID); err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
			}
		}
	}
	m.mu.Lock()
	for token, session := range m.sessions {
		if session.UserID != userID || token == keepToken {
			continue
		}
		delete(m.sessions, token)
		delete(m.accessMFAGrants, token)
	}
	m.mu.Unlock()
	return nil
}

func (m *authManager) hasUserSession(userID string) bool {
	if m.store != nil {
		return m.hasPersistedUserSession(userID, "")
	}
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

func (m *authManager) hasOtherUserSession(userID, currentToken string) bool {
	if m.store != nil {
		return m.hasPersistedUserSession(userID, authSessionRecordID(currentToken))
	}
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	for token, session := range m.sessions {
		if now.After(session.ExpiresAt) {
			delete(m.sessions, token)
			continue
		}
		if token != currentToken && session.UserID == userID {
			return true
		}
	}
	return false
}

func (m *authManager) session(r *http.Request) (string, authSession, bool) {
	now := time.Now().UTC()

	for _, cookie := range r.Cookies() {
		if !strings.EqualFold(cookie.Name, authCookieName) || cookie.Value == "" {
			continue
		}
		token := cookie.Value

		m.mu.RLock()
		session, ok := m.sessions[token]
		m.mu.RUnlock()
		if !ok {
			var err error
			session, ok, err = m.loadPersistedSession(token)
			if err != nil {
				continue
			}
			if ok {
				m.mu.Lock()
				m.sessions[token] = session
				m.mu.Unlock()
			}
		}
		if !ok {
			continue
		}
		if now.After(session.ExpiresAt) {
			_ = m.delete(token)
			continue
		}
		return token, session, true
	}
	return "", authSession{}, false
}

func authSessionRecordID(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (m *authManager) persistSession(token string, session authSession) error {
	if m.store == nil {
		return nil
	}
	payload, err := json.Marshal(session)
	if err != nil {
		return err
	}
	_, err = m.store.SavePlatformItem("auth_sessions", model.PlatformItem{
		ID: authSessionRecordID(token), Name: "auth session", Type: "auth-session", Status: "active", OwnerID: session.UserID,
		Metadata: map[string]any{"payload": string(payload), "expires_at": session.ExpiresAt.UTC().Format(time.RFC3339Nano)},
	})
	return err
}

func (m *authManager) loadPersistedSession(token string) (authSession, bool, error) {
	if m.store == nil {
		return authSession{}, false, nil
	}
	item, ok, err := m.store.GetPlatformItem("auth_sessions", authSessionRecordID(token))
	if err != nil || !ok {
		return authSession{}, ok, err
	}
	var session authSession
	payload, _ := item.Metadata["payload"].(string)
	if payload == "" || json.Unmarshal([]byte(payload), &session) != nil {
		_ = m.store.DeletePlatformItem("auth_sessions", item.ID)
		return authSession{}, false, nil
	}
	if !time.Now().UTC().Before(session.ExpiresAt) {
		_ = m.store.DeletePlatformItem("auth_sessions", item.ID)
		return authSession{}, false, nil
	}
	return session, true, nil
}

func (m *authManager) hasPersistedUserSession(userID, excludedID string) bool {
	items, err := m.store.ListPlatformItems("auth_sessions")
	if err != nil {
		return false
	}
	now := time.Now().UTC()
	for _, item := range items {
		var session authSession
		payload, _ := item.Metadata["payload"].(string)
		if payload == "" || json.Unmarshal([]byte(payload), &session) != nil || !now.Before(session.ExpiresAt) {
			_ = m.store.DeletePlatformItem("auth_sessions", item.ID)
			continue
		}
		if item.ID != excludedID && session.UserID == userID {
			return true
		}
	}
	return false
}

func (m *authManager) prunePersistedSessions() error {
	if m.store == nil {
		return nil
	}
	items, err := m.store.ListPlatformItems("auth_sessions")
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, item := range items {
		expiresAt, ok := metadataTime(item.Metadata["expires_at"])
		if ok && now.Before(expiresAt) {
			continue
		}
		if err := m.store.DeletePlatformItem("auth_sessions", item.ID); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (m *authManager) persistAuthRuntimeState(collection, token string, payload any, expiresAt time.Time) error {
	if m.store == nil {
		return nil
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = m.store.SavePlatformItem(collection, model.PlatformItem{
		ID: authSessionRecordID(token), Name: collection, Type: "auth-runtime", Status: "active",
		Metadata: map[string]any{"payload": string(encoded), "expires_at": expiresAt.UTC().Format(time.RFC3339Nano)},
	})
	return err
}

func (m *authManager) consumeAuthRuntimeState(collection, token string, target any) (bool, error) {
	if m.store == nil {
		return false, nil
	}
	id := authSessionRecordID(token)
	item, ok, err := m.store.GetPlatformItem(collection, id)
	if err != nil || !ok {
		return ok, err
	}
	if err := m.store.DeletePlatformItem(collection, id); err != nil {
		return false, err
	}
	payload, _ := item.Metadata["payload"].(string)
	if payload == "" {
		return false, errors.New("persisted authentication state is missing payload")
	}
	if err := json.Unmarshal([]byte(payload), target); err != nil {
		return false, fmt.Errorf("decode persisted authentication state: %w", err)
	}
	return true, nil
}

func (m *authManager) pruneAuthRuntimeStates(collection string) error {
	if m.store == nil {
		return nil
	}
	items, err := m.store.ListPlatformItems(collection)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, item := range items {
		expiresAt, ok := metadataTime(item.Metadata["expires_at"])
		if ok && now.Before(expiresAt) {
			continue
		}
		if err := m.store.DeletePlatformItem(collection, item.ID); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
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

func (m *authManager) resetLoginFailuresFor(username, clientIP string) {
	username = strings.ToLower(strings.TrimSpace(username))
	clientIP = strings.TrimSpace(clientIP)
	if username == "" && clientIP == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if username != "" && clientIP != "" {
		delete(m.failures, clientIP+":"+username)
		return
	}
	for key := range m.failures {
		if username != "" && strings.HasSuffix(key, ":"+username) {
			delete(m.failures, key)
			continue
		}
		if clientIP != "" && strings.HasPrefix(key, clientIP+":") {
			delete(m.failures, key)
		}
	}
}

func (m *authManager) clearSessions() error {
	m.mu.Lock()
	m.sessions = map[string]authSession{}
	m.mfaChallenges = map[string]mfaChallenge{}
	m.captchas = map[string]captchaChallenge{}
	m.accessMFAGrants = map[string]accessMFAGrant{}
	m.oidcStates = map[string]externalOIDCState{}
	m.wecomStates = map[string]externalWeComState{}
	m.passkeyRegistrations = map[string]passkeyChallenge{}
	m.passkeyLogins = map[string]passkeyChallenge{}
	m.mu.Unlock()
	if m.store == nil {
		return nil
	}
	items, err := m.store.ListPlatformItems("auth_sessions")
	if err != nil {
		return err
	}
	var errs []error
	for _, item := range items {
		if err := m.store.DeletePlatformItem("auth_sessions", item.ID); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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
	_, _, ok := s.authSession(r)
	if ok {
		return true
	}
	writeError(w, http.StatusUnauthorized, "authentication required")
	return false
}

func (s *Server) currentUserID(r *http.Request) string {
	_, session, ok := s.authSession(r)
	if !ok || session.UserID == "" {
		return "anonymous"
	}
	return session.UserID
}

func (s *Server) authSession(r *http.Request) (string, authSession, bool) {
	token, session, ok := s.auth.session(r)
	if !ok {
		return "", authSession{}, false
	}
	session, ok = s.refreshAuthSession(token, session)
	if !ok {
		return "", authSession{}, false
	}
	return token, session, true
}

func (s *Server) refreshAuthSession(token string, session authSession) (authSession, bool) {
	session.UserID = strings.TrimSpace(session.UserID)
	if session.UserID == "" {
		_ = s.auth.delete(token)
		return authSession{}, false
	}
	user, ok, err := s.authUserByID(session.UserID)
	if err != nil {
		return session, true
	}
	if !ok {
		_ = s.auth.delete(token)
		return authSession{}, false
	}
	refreshed := authSession{
		UserID:    user.UserID,
		Username:  strings.TrimSpace(user.Username),
		Role:      user.Role,
		AuthTime:  session.AuthTime,
		ExpiresAt: session.ExpiresAt,
	}
	if refreshed.Username == "" {
		refreshed.Username = session.Username
	}
	if refreshed.UserID == session.UserID && refreshed.Username == session.Username && refreshed.Role == session.Role {
		return session, true
	}
	if err := s.auth.refreshSession(token, refreshed); err != nil {
		return authSession{}, false
	}
	return refreshed, true
}

func (s *Server) authUserByID(userID string) (store.AdminPublic, bool, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return store.AdminPublic{}, false, nil
	}
	item, ok, err := s.cfg.Store.GetPlatformItem("users", userID)
	if err != nil {
		return store.AdminPublic{}, false, err
	}
	if ok {
		if !platformItemEnabled(item) {
			return store.AdminPublic{}, false, nil
		}
		return store.AdminPublic{
			UserID:    item.ID,
			Username:  item.Name,
			Role:      userRole(item),
			CreatedAt: item.CreatedAt,
			UpdatedAt: item.UpdatedAt,
		}, true, nil
	}
	admin, adminOK := s.cfg.Store.AdminUser()
	if adminOK && admin.UserID == userID {
		return admin, true, nil
	}
	return store.AdminPublic{}, false, nil
}

func userRole(user model.PlatformItem) string {
	if user.Metadata != nil {
		if role, ok := user.Metadata["role"].(string); ok && strings.TrimSpace(role) != "" {
			return strings.TrimSpace(role)
		}
	}
	return string(roleUser)
}

func (s *Server) authUserPayload(session authSession) authUserPayload {
	decision := s.roleDecision(session.Role)
	return authUserPayload{
		UserID:          session.UserID,
		Username:        session.Username,
		Role:            canonicalAuthRole(session.Role),
		ExpiresAt:       session.ExpiresAt,
		APIPermissions:  decision.Permissions,
		MenuPermissions: decision.MenuPermissions,
	}
}

func canonicalAuthRole(role string) string {
	trimmed := strings.TrimSpace(role)
	if kind := normalizeBuiltInRole(trimmed); kind != roleCustom {
		return string(kind)
	}
	return trimmed
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

	if err := s.createLoginLog(r, model.PlatformItemRequest{
		Name:        username,
		Type:        "setup",
		Status:      "success",
		OwnerID:     admin.UserID,
		Description: "administrator initialized",
		Metadata:    map[string]any{"client_ip": s.clientIP(r), "account": username},
	}); err != nil {
		if rollbackErr := s.cfg.Store.RollbackSetupAdmin(admin.UserID); rollbackErr != nil {
			_ = s.audit(r, "auth.setup.rollback_failed", admin.UserID, "", rollbackErr.Error())
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	token, session, err := s.auth.create(admin)
	if err != nil {
		if rollbackErr := s.cfg.Store.RollbackSetupAdmin(admin.UserID); rollbackErr != nil {
			_ = s.audit(r, "auth.setup.rollback_failed", admin.UserID, "", rollbackErr.Error())
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.recordUserLoginState(r, token, session, s.clientIP(r)); err != nil {
		if rollbackErr := s.cfg.Store.RollbackSetupAdmin(admin.UserID); rollbackErr != nil {
			_ = s.audit(r, "auth.setup.rollback_failed", admin.UserID, "", rollbackErr.Error())
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "auth.setup", session.UserID, "", "admin initialized")
	http.SetCookie(w, s.authCookie(r, token, int(authSessionTTL.Seconds())))
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
		if err := s.createLoginLog(r, model.PlatformItemRequest{
			Name:        username,
			Type:        "password",
			Status:      "denied",
			Description: "password login is disabled",
			Metadata:    map[string]any{"client_ip": clientIP, "account": username},
		}); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.audit(r, "auth.login.password_denied", "", "", "password login is disabled")
		writeError(w, http.StatusForbidden, "password login is disabled")
		return
	}
	if s.captchaRequired() && !s.verifyCaptcha(req.CaptchaID, req.CaptchaAnswer) {
		if err := s.createLoginLog(r, model.PlatformItemRequest{
			Name:        username,
			Type:        "captcha",
			Status:      "failed",
			Description: "invalid captcha",
			Metadata:    map[string]any{"client_ip": clientIP, "account": username},
		}); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, "captcha is required or invalid")
		return
	}
	if ok, reason := s.loginPolicyAllows(username, clientIP); !ok {
		if err := s.createLoginLog(r, model.PlatformItemRequest{
			Name:        username,
			Type:        "policy",
			Status:      "denied",
			Description: reason,
			Metadata:    map[string]any{"client_ip": clientIP, "account": username},
		}); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeError(w, http.StatusForbidden, reason)
		return
	}
	if retryAfter, locked := s.activeLoginLock(username, clientIP); locked {
		if err := s.createLoginLog(r, model.PlatformItemRequest{
			Name:        username,
			Type:        "lock",
			Status:      "denied",
			Description: "account or client ip is locked",
			Metadata:    map[string]any{"client_ip": clientIP, "account": username, "retry_after_seconds": int(retryAfter.Seconds())},
		}); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
		writeError(w, http.StatusTooManyRequests, "account or client ip is locked; try again later")
		return
	}
	failureKey := clientIP + ":" + strings.ToLower(username)
	failurePolicy := s.loginFailurePolicy()
	if retryAfter, ok := s.auth.checkLoginAllowed(failureKey, failurePolicy); !ok {
		if err := s.createLoginLog(r, model.PlatformItemRequest{
			Name:        username,
			Type:        "lock",
			Status:      "denied",
			Description: "too many failed login attempts",
			Metadata:    map[string]any{"client_ip": clientIP, "account": username, "retry_after_seconds": int(retryAfter.Seconds())},
		}); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
		writeError(w, http.StatusTooManyRequests, "too many failed login attempts; try again later")
		return
	}

	var admin store.AdminPublic
	loginType := "password"
	ok := false
	var ldapPreviousUser model.PlatformItem
	ldapHadPreviousUser := false
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
		admin, providerID, ok, ldapPreviousUser, ldapHadPreviousUser, err = s.authenticateExternalLDAP(r.Context(), username, req.Password)
		if err != nil {
			status := http.StatusBadGateway
			if errors.Is(err, errExternalLDAPUserDisabled) || errors.Is(err, errExternalLDAPUserNotAllowed) {
				status = http.StatusForbidden
			}
			if logErr := s.recordExternalLDAPLoginFailure(r, username, providerID, err); logErr != nil {
				writeError(w, http.StatusInternalServerError, logErr.Error())
				return
			}
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
			if err := s.createLoginLock(username, clientIP, failure); err != nil {
				detail := "persist login lock failed: " + err.Error()
				_ = s.audit(r, "auth.login.lock.persist_failed", "", "", detail)
				writeError(w, http.StatusInternalServerError, detail)
				return
			}
		}
		if err := s.createLoginLog(r, model.PlatformItemRequest{
			Name:        username,
			Type:        "password",
			Status:      "failed",
			Description: "invalid username or password",
			Metadata:    map[string]any{"client_ip": clientIP, "account": username},
		}); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	if proceed, handled := s.handleLoginMFA(w, r, admin, username, clientIP, failureKey, req); handled {
		return
	} else if !proceed {
		return
	}

	if err := s.createLoginLog(r, model.PlatformItemRequest{
		Name:        username,
		Type:        loginType,
		Status:      "success",
		OwnerID:     admin.UserID,
		Description: "signed in",
		Metadata:    map[string]any{"client_ip": clientIP, "account": username},
	}); err != nil {
		if loginType == "ldap" {
			err = s.restoreExternalUserAfterLoginLogFailure(r, admin.UserID, ldapPreviousUser, ldapHadPreviousUser, err)
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auth.resetLoginFailures(failureKey)
	token, session, err := s.auth.create(admin)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err := s.recordUserLoginState(r, token, session, clientIP); err != nil {
		if loginType == "ldap" {
			err = s.restoreExternalUserAfterLoginStateFailure(r, admin.UserID, ldapPreviousUser, ldapHadPreviousUser, err)
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "auth.login", session.UserID, "", "signed in with "+loginType)
	http.SetCookie(w, s.authCookie(r, token, int(authSessionTTL.Seconds())))
	writeJSON(w, http.StatusOK, map[string]any{"user": s.authUserPayload(session)})
}

func (s *Server) recordExternalLDAPLoginFailure(r *http.Request, username, providerID string, err error) error {
	detail := "external ldap login failed"
	if err != nil {
		detail = err.Error()
	}
	if logErr := s.createLoginLog(r, model.PlatformItemRequest{
		Name:        username,
		Type:        "ldap",
		Status:      "failed",
		Description: detail,
		Metadata:    map[string]any{"client_ip": s.clientIP(r), "account": username, "provider_id": providerID},
	}); logErr != nil {
		return logErr
	}
	_ = s.audit(r, "auth.ldap.login_failed", providerID, "ldap", detail)
	return nil
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if token, session, ok := s.authSession(r); ok {
		if err := s.revokeAuthSession(r, token, session); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.audit(r, "auth.logout", session.UserID, "", "admin signed out")
	}
	http.SetCookie(w, s.authCookie(r, "", -1))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) revokeAuthSession(r *http.Request, token string, session authSession) error {
	hasOtherSession := s.auth.hasOtherUserSession(session.UserID, token)
	if !hasOtherSession {
		if err := s.cfg.Store.RecordUserLogout(session.UserID); err != nil {
			detail := "persist user logout state failed: " + err.Error()
			_ = s.audit(r, "auth.logout.state.persist_failed", session.UserID, "", detail)
			return errors.New(detail)
		}
	}
	if err := s.auth.delete(token); err != nil {
		if !hasOtherSession {
			if rollbackErr := s.cfg.Store.RecordUserLogin(session.UserID, s.clientIP(r), r.UserAgent()); rollbackErr != nil {
				_ = s.audit(r, "auth.logout.state.rollback_failed", session.UserID, "", rollbackErr.Error())
			}
		}
		detail := "revoke persisted auth session failed: " + err.Error()
		_ = s.audit(r, "auth.logout.session.persist_failed", session.UserID, "", detail)
		return errors.New(detail)
	}
	return nil
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	_, session, ok := s.authSession(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": s.authUserPayload(session)})
}

func (s *Server) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req passwordChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	token, session, ok := s.authSession(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if ok, err := s.cfg.Store.VerifyUserPassword(session.UserID, req.CurrentPassword); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if !ok {
		_ = s.audit(r, "auth.password.change.failed", session.UserID, "", "current password is invalid")
		writeError(w, http.StatusUnauthorized, "current password is invalid")
		return
	}
	if len(req.NewPassword) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}
	snapshot, err := s.cfg.Store.SnapshotUserPassword(session.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	user, err := s.cfg.Store.UpdateUserPassword(session.UserID, req.NewPassword)
	if err != nil {
		if restoreErr := s.cfg.Store.RestoreUserPasswordSnapshot(snapshot); restoreErr != nil {
			err = fmt.Errorf("%w; additionally failed to restore password: %v", err, restoreErr)
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	passwordLog, err := s.createPasswordChangeOperationLog(r, session.UserID)
	if err != nil {
		if restoreErr := s.cfg.Store.RestoreUserPasswordSnapshot(snapshot); restoreErr != nil {
			err = fmt.Errorf("%w; additionally failed to restore password: %v", err, restoreErr)
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.auth.deleteUserSessionsExcept(session.UserID, token); err != nil {
		if restoreErr := s.cfg.Store.RestoreUserPasswordSnapshot(snapshot); restoreErr != nil {
			err = fmt.Errorf("%w; additionally failed to restore password: %v", err, restoreErr)
		}
		if deleteErr := s.cfg.Store.DeletePlatformItem("operation_logs", passwordLog.ID); deleteErr != nil && !errors.Is(deleteErr, os.ErrNotExist) {
			err = fmt.Errorf("%w; additionally failed to remove password change log: %v", err, deleteErr)
			_ = s.audit(r, "auth.password.session_revoke.rollback_failed", session.UserID, "", deleteErr.Error())
		}
		_ = s.audit(r, "auth.password.session_revoke_failed", session.UserID, "", err.Error())
		writeError(w, http.StatusInternalServerError, "revoke other auth sessions failed: "+err.Error())
		return
	}
	s.auth.resetLoginFailuresFor(session.Username, s.clientIP(r))
	_ = s.audit(r, "auth.password.change", session.UserID, "", "changed local password")
	writeJSON(w, http.StatusOK, map[string]any{"user": s.authUserPayload(authSession{
		UserID:    user.UserID,
		Username:  user.Username,
		Role:      user.Role,
		ExpiresAt: session.ExpiresAt,
	})})
}

func (s *Server) createPasswordChangeOperationLog(r *http.Request, userID string) (model.PlatformItem, error) {
	item, err := s.cfg.Store.CreatePlatformItem("operation_logs", model.PlatformItemRequest{
		Name:        "auth.password.change",
		Type:        "auth",
		Status:      "success",
		TargetID:    userID,
		OwnerID:     s.currentUserID(r),
		Description: "changed local password",
		Metadata: map[string]any{
			"user_id":   userID,
			"client_ip": s.clientIP(r),
		},
	})
	if err != nil {
		detail := "persist operation log failed: " + err.Error()
		_ = s.audit(r, "operation.log.persist_failed", userID, "", detail)
		return model.PlatformItem{}, errors.New(detail)
	}
	return item, nil
}

func (s *Server) recordUserLoginState(r *http.Request, token string, session authSession, clientIP string) error {
	if err := s.cfg.Store.RecordUserLogin(session.UserID, clientIP, r.UserAgent()); err != nil {
		_ = s.auth.delete(token)
		detail := "persist user login state failed: " + err.Error()
		_ = s.audit(r, "auth.login.state.persist_failed", session.UserID, "", detail)
		return errors.New(detail)
	}
	return nil
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
