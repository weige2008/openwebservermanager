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
	mu       sync.RWMutex
	sessions map[string]authSession
	failures map[string]loginFailure
}

type authSession struct {
	UserID    string    `json:"id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

type loginFailure struct {
	Count       int
	LastFailure time.Time
	LockedUntil time.Time
}

type authStatus struct {
	Configured bool `json:"configured"`
}

type setupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func newAuthManager() *authManager {
	return &authManager{
		sessions: map[string]authSession{},
		failures: map[string]loginFailure{},
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

func (m *authManager) checkLoginAllowed(key string) (time.Duration, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	failure := m.failures[key]
	now := time.Now().UTC()
	if !failure.LockedUntil.IsZero() && now.Before(failure.LockedUntil) {
		return time.Until(failure.LockedUntil).Round(time.Second), false
	}
	if !failure.LastFailure.IsZero() && now.Sub(failure.LastFailure) > 15*time.Minute {
		delete(m.failures, key)
	}
	return 0, true
}

func (m *authManager) recordLoginFailure(key string) loginFailure {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	failure := m.failures[key]
	if !failure.LastFailure.IsZero() && now.Sub(failure.LastFailure) > 15*time.Minute {
		failure = loginFailure{}
	}
	failure.Count++
	failure.LastFailure = now
	if failure.Count >= 5 {
		failure.LockedUntil = now.Add(5 * time.Minute)
	}
	m.failures[key] = failure
	return failure
}

func (m *authManager) resetLoginFailures(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.failures, key)
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

func (s *Server) handleAuthStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, authStatus{Configured: s.cfg.Store.AdminConfigured()})
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
	_ = s.audit(r, "auth.setup", session.UserID, "", "admin initialized")
	_, _ = s.cfg.Store.CreatePlatformItem("login_logs", model.PlatformItemRequest{
		Name:        username,
		Type:        "setup",
		Status:      "success",
		OwnerID:     session.UserID,
		Description: "administrator initialized",
		Metadata:    map[string]any{"client_ip": s.clientIP(r), "account": username},
	})
	writeJSON(w, http.StatusCreated, map[string]any{"user": session})
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
	if retryAfter, ok := s.auth.checkLoginAllowed(failureKey); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
		writeError(w, http.StatusTooManyRequests, "too many failed login attempts; try again later")
		return
	}

	admin, ok, err := s.cfg.Store.VerifyAdmin(username, req.Password)
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
		if !ok {
			failure := s.auth.recordLoginFailure(failureKey)
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
	}
	s.auth.resetLoginFailures(failureKey)

	token, session, err := s.auth.create(admin)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	http.SetCookie(w, s.authCookie(r, token, int(authSessionTTL.Seconds())))
	_ = s.audit(r, "auth.login", session.UserID, "", "admin signed in")
	_, _ = s.cfg.Store.CreatePlatformItem("login_logs", model.PlatformItemRequest{
		Name:        username,
		Type:        "password",
		Status:      "success",
		OwnerID:     session.UserID,
		Description: "signed in",
		Metadata:    map[string]any{"client_ip": clientIP, "account": username},
	})
	writeJSON(w, http.StatusOK, map[string]any{"user": session})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if token, session, ok := s.auth.session(r); ok {
		s.auth.delete(token)
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
	writeJSON(w, http.StatusOK, map[string]any{"user": session})
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
