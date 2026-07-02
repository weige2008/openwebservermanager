package app

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"servermanager/internal/store"
)

const (
	authCookieName = "servermanager_session"
	authSessionTTL = 24 * time.Hour
)

type authManager struct {
	mu       sync.RWMutex
	sessions map[string]authSession
}

type authSession struct {
	UserID    string    `json:"id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
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
	return &authManager{sessions: map[string]authSession{}}
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
	admin, ok, err := s.cfg.Store.VerifyAdmin(strings.TrimSpace(req.Username), req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	token, session, err := s.auth.create(admin)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	http.SetCookie(w, s.authCookie(r, token, int(authSessionTTL.Seconds())))
	_ = s.audit(r, "auth.login", session.UserID, "", "admin signed in")
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
