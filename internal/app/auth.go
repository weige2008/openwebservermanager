package app

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	authCookieName = "servermanager_session"
	authSessionTTL = 24 * time.Hour
	defaultAdmin   = "admin"
	defaultPass    = "admin123"
)

type authManager struct {
	mu       sync.RWMutex
	user     string
	password string
	sessions map[string]authSession
}

type authSession struct {
	UserID    string    `json:"id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func newAuthManager(user, password string) *authManager {
	user = strings.TrimSpace(user)
	if user == "" {
		user = defaultAdmin
	}
	if password == "" {
		password = defaultPass
	}
	return &authManager{
		user:     user,
		password: password,
		sessions: map[string]authSession{},
	}
}

func (m *authManager) authenticate(username, password string) bool {
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(m.user)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(password), []byte(m.password)) == 1
	return userOK && passOK
}

func (m *authManager) create(username string) (string, authSession, error) {
	token, err := randomToken()
	if err != nil {
		return "", authSession{}, err
	}
	session := authSession{
		UserID:    "local-admin",
		Username:  username,
		Role:      "admin",
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
		return "local-admin"
	}
	return session.UserID
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !s.auth.authenticate(req.Username, req.Password) {
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	token, session, err := s.auth.create(req.Username)
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
