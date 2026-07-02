package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"servermanager/internal/model"
	"servermanager/internal/security"

	"golang.org/x/crypto/bcrypt"
)

type Store struct {
	mu     sync.RWMutex
	path   string
	cipher *security.Cipher
	state  state
}

type state struct {
	Servers     map[string]model.Server            `json:"servers"`
	Credentials map[string]model.Credential        `json:"credentials"`
	Sessions    map[string]model.ConnectionSession `json:"sessions"`
	AuditLogs   []model.AuditLog                   `json:"audit_logs"`
	Admin       *AdminAuth                         `json:"admin,omitempty"`
}

type CredentialSecret struct {
	Password   string
	PrivateKey string
	Passphrase string
}

type AdminAuth struct {
	UserID       string    `json:"user_id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type AdminPublic struct {
	UserID    string    `json:"id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

var ErrAdminAlreadyConfigured = errors.New("admin already configured")

func Open(path string, cipher *security.Cipher) (*Store, error) {
	st := &Store{
		path:   path,
		cipher: cipher,
		state: state{
			Servers:     map[string]model.Server{},
			Credentials: map[string]model.Credential{},
			Sessions:    map[string]model.ConnectionSession{},
			AuditLogs:   []model.AuditLog{},
		},
	}

	raw, err := os.ReadFile(path)
	if err == nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, &st.state); err != nil {
			return nil, fmt.Errorf("load store: %w", err)
		}
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read store: %w", err)
	}
	st.ensureMaps()
	return st, nil
}

func (s *Store) AdminConfigured() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.Admin != nil && s.state.Admin.PasswordHash != ""
}

func (s *Store) SetupAdmin(username, password string) (AdminPublic, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state.Admin != nil && s.state.Admin.PasswordHash != "" {
		return AdminPublic{}, ErrAdminAlreadyConfigured
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return AdminPublic{}, err
	}

	now := time.Now().UTC()
	admin := AdminAuth{
		UserID:       newID("user"),
		Username:     username,
		PasswordHash: string(hash),
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	s.state.Admin = &admin
	if err := s.saveLocked(); err != nil {
		return AdminPublic{}, err
	}
	return admin.Public(), nil
}

func (s *Store) VerifyAdmin(username, password string) (AdminPublic, bool, error) {
	s.mu.RLock()
	admin := s.state.Admin
	s.mu.RUnlock()
	if admin == nil || admin.PasswordHash == "" {
		return AdminPublic{}, false, nil
	}
	if username != admin.Username {
		return AdminPublic{}, false, nil
	}
	if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(password)); err != nil {
		return AdminPublic{}, false, nil
	}
	return admin.Public(), true, nil
}

func (a AdminAuth) Public() AdminPublic {
	return AdminPublic{
		UserID:    a.UserID,
		Username:  a.Username,
		Role:      "admin",
		CreatedAt: a.CreatedAt,
		UpdatedAt: a.UpdatedAt,
	}
}

func (s *Store) ensureMaps() {
	if s.state.Servers == nil {
		s.state.Servers = map[string]model.Server{}
	}
	if s.state.Credentials == nil {
		s.state.Credentials = map[string]model.Credential{}
	}
	if s.state.Sessions == nil {
		s.state.Sessions = map[string]model.ConnectionSession{}
	}
	if s.state.AuditLogs == nil {
		s.state.AuditLogs = []model.AuditLog{}
	}
}

func (s *Store) Bootstrap() ([]model.Server, []model.CredentialPublic, []model.ConnectionSession, []model.AuditLog) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	servers := make([]model.Server, 0, len(s.state.Servers))
	for _, item := range s.state.Servers {
		servers = append(servers, item)
	}
	credentials := make([]model.CredentialPublic, 0, len(s.state.Credentials))
	for _, item := range s.state.Credentials {
		credentials = append(credentials, item.Public())
	}
	sessions := make([]model.ConnectionSession, 0, len(s.state.Sessions))
	for _, item := range s.state.Sessions {
		sessions = append(sessions, item)
	}
	logs := make([]model.AuditLog, len(s.state.AuditLogs))
	copy(logs, s.state.AuditLogs)
	return servers, credentials, sessions, logs
}

func (s *Store) CreateServer(server model.Server) (model.Server, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	server.ID = newID("srv")
	server.CreatedAt = now
	server.UpdatedAt = now
	if server.SSHPort == 0 {
		server.SSHPort = 22
	}
	if server.RDPPort == 0 {
		server.RDPPort = 3389
	}
	s.state.Servers[server.ID] = server
	return server, s.saveLocked()
}

func (s *Store) GetServer(id string) (model.Server, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	server, ok := s.state.Servers[id]
	return server, ok
}

func (s *Store) CreateCredential(credential model.Credential, secret CredentialSecret) (model.CredentialPublic, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err error
	credential.EncryptedPassword, err = s.cipher.EncryptString(secret.Password)
	if err != nil {
		return model.CredentialPublic{}, err
	}
	credential.EncryptedKey, err = s.cipher.EncryptString(secret.PrivateKey)
	if err != nil {
		return model.CredentialPublic{}, err
	}
	credential.EncryptedPhrase, err = s.cipher.EncryptString(secret.Passphrase)
	if err != nil {
		return model.CredentialPublic{}, err
	}

	now := time.Now().UTC()
	credential.ID = newID("cred")
	credential.CreatedAt = now
	credential.UpdatedAt = now
	s.state.Credentials[credential.ID] = credential
	return credential.Public(), s.saveLocked()
}

func (s *Store) GetCredential(id string) (model.Credential, CredentialSecret, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	credential, ok := s.state.Credentials[id]
	if !ok {
		return model.Credential{}, CredentialSecret{}, false, nil
	}
	password, err := s.cipher.DecryptString(credential.EncryptedPassword)
	if err != nil {
		return model.Credential{}, CredentialSecret{}, true, err
	}
	privateKey, err := s.cipher.DecryptString(credential.EncryptedKey)
	if err != nil {
		return model.Credential{}, CredentialSecret{}, true, err
	}
	passphrase, err := s.cipher.DecryptString(credential.EncryptedPhrase)
	if err != nil {
		return model.Credential{}, CredentialSecret{}, true, err
	}
	return credential, CredentialSecret{Password: password, PrivateKey: privateKey, Passphrase: passphrase}, true, nil
}

func (s *Store) CreateSession(session model.ConnectionSession) (model.ConnectionSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	session.ID = newID("sess")
	session.Status = model.SessionPending
	session.StartedAt = now
	session.LastActivityAt = now
	s.state.Sessions[session.ID] = session
	return session, s.saveLocked()
}

func (s *Store) GetSession(id string) (model.ConnectionSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.state.Sessions[id]
	return session, ok
}

func (s *Store) UpdateSession(id string, update func(*model.ConnectionSession)) (model.ConnectionSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.state.Sessions[id]
	if !ok {
		return model.ConnectionSession{}, os.ErrNotExist
	}
	update(&session)
	session.LastActivityAt = time.Now().UTC()
	s.state.Sessions[id] = session
	return session, s.saveLocked()
}

func (s *Store) CloseSession(id, reason string) (model.ConnectionSession, error) {
	now := time.Now().UTC()
	return s.UpdateSession(id, func(session *model.ConnectionSession) {
		session.Status = model.SessionClosed
		session.EndedAt = &now
		if reason != "" {
			session.Error = reason
		}
	})
}

func (s *Store) Audit(log model.AuditLog) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	log.ID = newID("audit")
	log.CreatedAt = time.Now().UTC()
	s.state.AuditLogs = append(s.state.AuditLogs, log)
	if len(s.state.AuditLogs) > 1000 {
		s.state.AuditLogs = s.state.AuditLogs[len(s.state.AuditLogs)-1000:]
	}
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func newID(prefix string) string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
	}
	return prefix + "_" + hex.EncodeToString(buf)
}
