package store

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"openwebservermanager/internal/model"
	"openwebservermanager/internal/security"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type Store struct {
	mu     sync.RWMutex
	path   string
	db     *sql.DB
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

type MFAProfile struct {
	Enabled       bool
	Secret        string
	RecoveryCount int
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

type RestoreSummary struct {
	LegacyStateRestored     bool           `json:"legacy_state_restored"`
	CoreStateRestored       bool           `json:"core_state_restored,omitempty"`
	PlatformRecords         int            `json:"platform_records"`
	CoreRecords             int            `json:"core_records,omitempty"`
	RecordsByCollection     map[string]int `json:"records_by_collection"`
	MigratedPlatformSecrets int            `json:"migrated_platform_secrets,omitempty"`
}

type platformRecordSnapshot struct {
	Collection string
	ID         string
	Payload    string
	CreatedAt  string
	UpdatedAt  string
	Migrated   bool
}

type coreRecordSnapshot struct {
	Kind      string
	ID        string
	Payload   string
	CreatedAt string
	UpdatedAt string
}

var ErrAdminAlreadyConfigured = errors.New("admin already configured")

func Open(path string, cipher *security.Cipher) (*Store, error) {
	db, err := openPlatformDB(path)
	if err != nil {
		return nil, err
	}
	st := &Store{
		path:   path,
		db:     db,
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
			_ = db.Close()
			return nil, fmt.Errorf("load store: %w", err)
		}
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = db.Close()
		return nil, fmt.Errorf("read store: %w", err)
	}
	st.ensureMaps()
	if err := st.migratePlatformDB(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := st.loadOrImportCoreState(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := st.seedPlatformData(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return st, nil
}

func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) Path() string {
	return s.path
}

func (s *Store) DatabasePath() string {
	return strings.TrimSuffix(s.path, filepath.Ext(s.path)) + ".db"
}

func (s *Store) DBStats() sql.DBStats {
	if s == nil || s.db == nil {
		return sql.DBStats{}
	}
	return s.db.Stats()
}

func (s *Store) AdminConfigured() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.Admin != nil && s.state.Admin.PasswordHash != ""
}

func (s *Store) AdminUser() (AdminPublic, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state.Admin == nil || s.state.Admin.UserID == "" {
		return AdminPublic{}, false
	}
	return s.state.Admin.Public(), true
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
	if _, err := s.createPlatformItem("users", model.PlatformItem{
		ID:          admin.UserID,
		Name:        admin.Username,
		Type:        "local",
		Status:      "enabled",
		Description: "首次初始化创建的管理员用户。",
		Metadata:    map[string]any{"role": "超级管理员"},
		CreatedAt:   admin.CreatedAt,
		UpdatedAt:   admin.UpdatedAt,
	}); err != nil {
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

func (s *Store) VerifyPlatformUser(username, password string) (AdminPublic, bool, error) {
	rows, err := s.db.Query(`SELECT payload FROM platform_records WHERE collection = ?`, "users")
	if err != nil {
		return AdminPublic{}, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return AdminPublic{}, false, err
		}
		var item model.PlatformItem
		if err := json.Unmarshal([]byte(payload), &item); err != nil {
			return AdminPublic{}, false, err
		}
		if item.Name != username || strings.EqualFold(strings.TrimSpace(item.Status), "disabled") {
			continue
		}
		hash, _ := item.Metadata["password_hash"].(string)
		if hash == "" {
			continue
		}
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
			return AdminPublic{}, false, nil
		}
		role, _ := item.Metadata["role"].(string)
		if role == "" {
			role = "user"
		}
		return AdminPublic{
			UserID:    item.ID,
			Username:  item.Name,
			Role:      role,
			CreatedAt: item.CreatedAt,
			UpdatedAt: item.UpdatedAt,
		}, true, nil
	}
	if err := rows.Err(); err != nil {
		return AdminPublic{}, false, err
	}
	return AdminPublic{}, false, nil
}

func (s *Store) VerifyUserPassword(userID, password string) (bool, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" || strings.TrimSpace(password) == "" {
		return false, nil
	}
	s.mu.RLock()
	admin := s.state.Admin
	s.mu.RUnlock()
	if admin != nil && admin.UserID == userID && admin.PasswordHash != "" {
		return bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(password)) == nil, nil
	}
	item, ok, err := s.GetPlatformItem("users", userID)
	if err != nil || !ok {
		return false, err
	}
	hash, _ := item.Metadata["password_hash"].(string)
	if hash == "" {
		return false, nil
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil, nil
}

func (s *Store) UpdateUserPassword(userID, password string) (AdminPublic, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return AdminPublic{}, errors.New("user id is required")
	}
	if len(password) < 8 {
		return AdminPublic{}, errors.New("password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return AdminPublic{}, err
	}
	passwordHash := string(hash)
	now := time.Now().UTC()

	var legacyAdmin AdminPublic
	updatedLegacy := false
	s.mu.Lock()
	if s.state.Admin != nil && s.state.Admin.UserID == userID {
		s.state.Admin.PasswordHash = passwordHash
		s.state.Admin.UpdatedAt = now
		legacyAdmin = s.state.Admin.Public()
		updatedLegacy = true
		if err := s.saveLocked(); err != nil {
			s.mu.Unlock()
			return AdminPublic{}, err
		}
	}
	s.mu.Unlock()

	item, ok, err := s.GetPlatformItem("users", userID)
	if err != nil {
		return AdminPublic{}, err
	}
	if !ok {
		if updatedLegacy {
			return legacyAdmin, nil
		}
		return AdminPublic{}, os.ErrNotExist
	}
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	item.Metadata["password_hash"] = passwordHash
	saved, err := s.SavePlatformItem("users", item)
	if err != nil {
		return AdminPublic{}, err
	}
	role, _ := saved.Metadata["role"].(string)
	if role == "" {
		role = "user"
	}
	if updatedLegacy && legacyAdmin.Role != "" {
		role = legacyAdmin.Role
	}
	return AdminPublic{
		UserID:    saved.ID,
		Username:  saved.Name,
		Role:      role,
		CreatedAt: saved.CreatedAt,
		UpdatedAt: saved.UpdatedAt,
	}, nil
}

func (s *Store) RecordUserLogin(userID, clientIP, userAgent string) error {
	item, ok, err := s.GetPlatformItem("users", userID)
	if err != nil || !ok {
		return err
	}
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	now := time.Now().UTC()
	item.Metadata["online"] = true
	item.Metadata["last_login_at"] = now.Format(time.RFC3339Nano)
	item.Metadata["last_seen_at"] = now.Format(time.RFC3339Nano)
	item.Metadata["login_count"] = metadataIntValue(item.Metadata["login_count"]) + 1
	if strings.TrimSpace(clientIP) != "" {
		item.Metadata["last_login_ip"] = strings.TrimSpace(clientIP)
	}
	if strings.TrimSpace(userAgent) != "" {
		item.Metadata["last_user_agent"] = trimMetadataText(userAgent, 512)
	}
	_, err = s.SavePlatformItem("users", item)
	return err
}

func (s *Store) RecordUserLogout(userID string) error {
	item, ok, err := s.GetPlatformItem("users", userID)
	if err != nil || !ok {
		return err
	}
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	now := time.Now().UTC()
	item.Metadata["online"] = false
	item.Metadata["last_logout_at"] = now.Format(time.RFC3339Nano)
	item.Metadata["last_seen_at"] = now.Format(time.RFC3339Nano)
	_, err = s.SavePlatformItem("users", item)
	return err
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

var platformCollections = []string{
	"users",
	"passkeys",
	"roles",
	"departments",
	"login_policies",
	"login_locks",
	"oidc_clients",
	"assets",
	"asset_groups",
	"credentials",
	"command_snippets",
	"storages",
	"web_assets",
	"certificates",
	"database_assets",
	"sql_work_orders",
	"ssh_gateways",
	"agent_gateways",
	"gateway_groups",
	"online_sessions",
	"offline_sessions",
	"exec_command_logs",
	"file_logs",
	"access_logs",
	"access_stats",
	"login_logs",
	"operation_logs",
	"sql_logs",
	"scheduled_tasks",
	"command_filters",
	"command_approvals",
	"authorization_strategies",
	"authorized_assets",
	"authorized_web_assets",
	"authorized_database_assets",
	"system_settings",
}

func openPlatformDB(jsonPath string) (*sql.DB, error) {
	dbPath := strings.TrimSuffix(jsonPath, filepath.Ext(jsonPath)) + ".db"
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite store: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping sqlite store: %w", err)
	}
	return db, nil
}

func (s *Store) migratePlatformDB() error {
	if s.db == nil {
		return nil
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS platform_records (
			collection TEXT NOT NULL,
			id TEXT NOT NULL,
			payload TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			PRIMARY KEY (collection, id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_platform_records_collection_created ON platform_records(collection, created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS core_records (
			kind TEXT NOT NULL,
			id TEXT NOT NULL,
			payload TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			PRIMARY KEY (kind, id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_core_records_kind_created ON core_records(kind, created_at DESC)`,
		`INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ','now'))`,
	}
	for _, statement := range statements {
		if _, err := s.db.Exec(statement); err != nil {
			return fmt.Errorf("migrate sqlite store: %w", err)
		}
	}
	return nil
}

func (s *Store) loadOrImportCoreState() error {
	if s.db == nil {
		return nil
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM core_records`).Scan(&count); err != nil {
		return fmt.Errorf("count core records: %w", err)
	}
	if count > 0 {
		next, err := s.readCoreStateFromDB()
		if err != nil {
			return err
		}
		s.state = next
		s.ensureMaps()
		return nil
	}
	if !s.hasLegacyState() {
		return nil
	}
	return s.syncCoreStateLocked()
}

func (s *Store) hasLegacyState() bool {
	return s.state.Admin != nil ||
		len(s.state.Servers) > 0 ||
		len(s.state.Credentials) > 0 ||
		len(s.state.Sessions) > 0 ||
		len(s.state.AuditLogs) > 0
}

func (s *Store) readCoreStateFromDB() (state, error) {
	records, err := s.readCoreRecordSnapshot(s.DatabasePath())
	if err != nil {
		return state{}, err
	}
	return stateFromCoreRecords(records)
}

func stateFromCoreRecords(records []coreRecordSnapshot) (state, error) {
	next := state{
		Servers:     map[string]model.Server{},
		Credentials: map[string]model.Credential{},
		Sessions:    map[string]model.ConnectionSession{},
		AuditLogs:   []model.AuditLog{},
	}
	for _, record := range records {
		switch record.Kind {
		case "admin":
			var admin AdminAuth
			if err := json.Unmarshal([]byte(record.Payload), &admin); err != nil {
				return state{}, fmt.Errorf("decode core admin record: %w", err)
			}
			next.Admin = &admin
		case "servers":
			var item model.Server
			if err := json.Unmarshal([]byte(record.Payload), &item); err != nil {
				return state{}, fmt.Errorf("decode core server record: %w", err)
			}
			next.Servers[item.ID] = item
		case "credentials":
			var item model.Credential
			if err := json.Unmarshal([]byte(record.Payload), &item); err != nil {
				return state{}, fmt.Errorf("decode core credential record: %w", err)
			}
			next.Credentials[item.ID] = item
		case "sessions":
			var item model.ConnectionSession
			if err := json.Unmarshal([]byte(record.Payload), &item); err != nil {
				return state{}, fmt.Errorf("decode core session record: %w", err)
			}
			next.Sessions[item.ID] = item
		case "audit_logs":
			var item model.AuditLog
			if err := json.Unmarshal([]byte(record.Payload), &item); err != nil {
				return state{}, fmt.Errorf("decode core audit record: %w", err)
			}
			next.AuditLogs = append(next.AuditLogs, item)
		default:
			return state{}, fmt.Errorf("unsupported core record kind %q", record.Kind)
		}
	}
	sort.Slice(next.AuditLogs, func(i, j int) bool {
		return next.AuditLogs[i].CreatedAt.Before(next.AuditLogs[j].CreatedAt)
	})
	return next, nil
}

func (s *Store) seedPlatformData() error {
	for collection, items := range defaultPlatformItems() {
		count, err := s.platformCount(collection)
		if err != nil {
			return err
		}
		if count > 0 {
			continue
		}
		for _, item := range items {
			item.Module = collection
			if _, err := s.createPlatformItem(collection, item); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) platformCount(collection string) (int, error) {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM platform_records WHERE collection = ?`, collection).Scan(&count); err != nil {
		return 0, fmt.Errorf("count platform records: %w", err)
	}
	return count, nil
}

func defaultPlatformItems() map[string][]model.PlatformItem {
	return map[string][]model.PlatformItem{
		"roles": {
			{Name: "超级管理员", Type: "builtin", Status: "enabled", Description: "拥有全部管理、审计和接入权限。"},
			{Name: "管理员", Type: "builtin", Status: "enabled", Description: "管理资产、凭据、授权和系统设置。"},
			{Name: "审计员", Type: "builtin", Status: "enabled", Description: "查看会话、录屏、登录和操作审计。"},
			{Name: "普通用户", Type: "builtin", Status: "enabled", Description: "通过接入门户访问授权资产。"},
		},
		"departments": {
			{Name: "默认部门", Type: "root", Status: "enabled", Description: "默认用户组织。"},
		},
		"asset_groups": {
			{Name: "文本协议", Type: "ssh", Status: "enabled", Protocol: model.ProtocolSSH, Description: "SSH 等文本协议资产。"},
			{Name: "图形协议", Type: "desktop", Status: "enabled", Protocol: model.ProtocolRDP, Description: "RDP/VNC 图形协议资产。"},
			{Name: "Web资产", Type: "web", Status: "enabled", Protocol: model.ProtocolHTTP, Description: "通过反向代理接入的 Web 资产。"},
			{Name: "数据库资产", Type: "database", Status: "enabled", Protocol: model.ProtocolDatabase, Description: "数据库代理与 SQL 审计资产。"},
		},
		"storages": {
			{Name: "Default", Type: "local", Status: "enabled", Description: "默认本地用户文件盘。", Metadata: map[string]any{"shared": false, "limit": "5 GB", "used": "0 B"}},
		},
		"scheduled_tasks": {
			{Name: "Auto renew Certificate", Type: "certificate-renewal", Status: "enabled", Description: "自动续签证书。", Metadata: map[string]any{"cron": "0 0/10 * * * ?"}},
			{Name: "Auto Remove History Log", Type: "log-cleanup", Status: "enabled", Description: "按保留策略清理历史日志。", Metadata: map[string]any{"cron": "0 0/10 * * * ?"}},
			{Name: "Asset Check Status", Type: "asset-status", Status: "enabled", Description: "定时检测资产连通状态。", Metadata: map[string]any{"cron": "0 0/10 * * * ?"}},
			{Name: "Auto Backup", Type: "backup", Status: "disabled", Description: "定时备份系统数据。", Metadata: map[string]any{"cron": "0 0 2 * * ?"}},
		},
		"system_settings": {
			{Name: "系统设置", Type: "branding", Status: "enabled", Description: "系统图标、名称、备案号、版权、资产 Logo 与关于页。"},
			{Name: "资产接入设置", Type: "access", Status: "enabled", Description: "接入页面、独立标签页、MFA、水印和录屏策略。"},
			{Name: "代理服务设置", Type: "proxy", Status: "enabled", Description: "SSH/RDP/数据库代理监听、私钥和转发白名单。"},
			{Name: "安全设置", Type: "security", Status: "enabled", Description: "验证码、强制 MFA、禁用密码登录、会话和密码策略。"},
			{Name: "身份认证设置", Type: "identity", Status: "enabled", Description: "Passkey、LDAP、企业微信、OIDC 登录。"},
			{Name: "身份提供服务", Type: "oidc-server", Status: "enabled", Description: "OIDC Server Discovery、JWKS、Authorize、Token、UserInfo。"},
			{Name: "通知与集成", Type: "integration", Status: "enabled", Description: "SMTP 邮件和 LLM 集成配置。"},
			{Name: "日志保留设置", Type: "retention", Status: "enabled", Description: "会话、登录、访问、SQL、任务日志保留天数。"},
			{Name: "系统维护", Type: "maintenance", Status: "enabled", Description: "备份恢复、授权许可、资产 Logo、关于。"},
		},
		"authorization_strategies": {
			{Name: "默认文件权限", Type: "file", Status: "enabled", Description: "上传、下载、编辑、删除、重命名、复制、粘贴权限矩阵。", Permissions: map[string]bool{"upload": true, "download": true, "edit": true, "delete": false, "rename": true, "copy": true, "paste": true}},
		},
		"ssh_gateways": {
			{Name: "内置 SSH 网关", Type: "builtin", Status: "disabled", Host: "0.0.0.0", Port: 2022, Description: "允许原生 SSH 客户端进入资产选择或直连资产。"},
		},
		"agent_gateways": {
			{Name: "默认安全网关", Type: "agent", Status: "offline", Description: "Agent/安全网关注册、令牌、延迟和资源指标。"},
		},
		"gateway_groups": {
			{Name: "默认网关分组", Type: "manual", Status: "enabled", Description: "手动选择网关成员用于资产接入路由。"},
		},
		"command_filters": {
			{Name: "高危命令拦截", Type: "deny", Status: "disabled", Description: "匹配高危命令并执行拒绝或审批动作。", Metadata: map[string]any{"risk": "high", "pattern": "rm -rf|mkfs|shutdown|reboot"}},
		},
	}
}

func (s *Store) PlatformBootstrap() (map[string][]model.PlatformItem, error) {
	result := map[string][]model.PlatformItem{}
	for _, collection := range platformCollections {
		result[collection] = []model.PlatformItem{}
	}
	rows, err := s.db.Query(`SELECT collection, payload FROM platform_records ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list platform records: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var collection string
		var payload string
		if err := rows.Scan(&collection, &payload); err != nil {
			return nil, err
		}
		var item model.PlatformItem
		if err := json.Unmarshal([]byte(payload), &item); err != nil {
			return nil, fmt.Errorf("decode platform record: %w", err)
		}
		sanitizePlatformItem(&item)
		result[collection] = append(result[collection], item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	s.appendLegacyPlatformData(result)
	return result, nil
}

func (s *Store) appendLegacyPlatformData(result map[string][]model.PlatformItem) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, server := range s.state.Servers {
		item := model.PlatformItem{
			ID:          server.ID,
			Module:      "assets",
			Name:        server.Name,
			Type:        string(server.OS),
			Status:      "active",
			Protocol:    serverProtocol(server),
			Host:        server.Host,
			Port:        serverPort(server),
			Group:       server.Group,
			Description: server.Description,
			Metadata: map[string]any{
				"source":      "legacy_server",
				"legacy_id":   server.ID,
				"ssh_port":    server.SSHPort,
				"rdp_port":    server.RDPPort,
				"os":          server.OS,
				"import_note": "从旧服务器资产镜像到平台资产视图",
			},
			CreatedAt: server.CreatedAt,
			UpdatedAt: server.UpdatedAt,
		}
		appendPlatformItem(result, "assets", item)
	}
	for _, credential := range s.state.Credentials {
		item := model.PlatformItem{
			ID:          credential.ID,
			Module:      "credentials",
			Name:        credential.Name,
			Type:        string(credential.Type),
			Status:      "encrypted",
			Username:    credential.Username,
			TargetID:    credential.ServerID,
			Description: "从旧凭据库镜像，敏感字段仅在服务端解密使用。",
			Metadata: map[string]any{
				"source":    "legacy_credential",
				"legacy_id": credential.ID,
				"domain":    credential.Domain,
			},
			CreatedAt: credential.CreatedAt,
			UpdatedAt: credential.UpdatedAt,
		}
		appendPlatformItem(result, "credentials", item)
	}
	for _, session := range s.state.Sessions {
		collection := "offline_sessions"
		if session.Status == model.SessionActive || session.Status == model.SessionPending {
			collection = "online_sessions"
		}
		item := model.PlatformItem{
			ID:          session.ID,
			Module:      collection,
			Name:        session.ID,
			Type:        string(session.Protocol),
			Status:      string(session.Status),
			Protocol:    session.Protocol,
			OwnerID:     session.UserID,
			TargetID:    session.ServerID,
			Description: session.Error,
			Metadata: map[string]any{
				"source":                "legacy_session",
				"credential_id":         session.CredentialID,
				"client_ip":             session.ClientIP,
				"recording_path":        session.RecordingPath,
				"recording_size":        session.RecordingSize,
				"gateway_group_id":      session.GatewayGroupID,
				"gateway_id":            session.GatewayID,
				"gateway_name":          session.GatewayName,
				"gateway_collection":    session.GatewayCollection,
				"workspace_width":       session.Width,
				"workspace_height":      session.Height,
				"workspace_dpi":         session.DPI,
				"color_depth":           session.ColorDepth,
				"resize_method":         session.ResizeMethod,
				"clipboard_enabled":     optionalBoolValue(session.ClipboardEnabled),
				"file_transfer_enabled": optionalBoolValue(session.FileTransferEnabled),
				"ignore_cert":           optionalBoolValue(session.IgnoreCert),
				"read_only":             optionalBoolValue(session.ReadOnly),
				"watermark_enabled":     optionalBoolValue(session.WatermarkEnabled),
				"watermark_text":        session.WatermarkText,
				"watermark_color":       session.WatermarkColor,
				"watermark_font_size":   session.WatermarkFontSize,
				"started_at":            session.StartedAt,
				"ended_at":              session.EndedAt,
			},
			CreatedAt: session.StartedAt,
			UpdatedAt: session.LastActivityAt,
		}
		appendPlatformItem(result, collection, item)
	}
	for _, log := range s.state.AuditLogs {
		item := model.PlatformItem{
			ID:          log.ID,
			Module:      "operation_logs",
			Name:        log.Action,
			Type:        string(log.Protocol),
			Status:      "recorded",
			OwnerID:     log.UserID,
			TargetID:    log.TargetID,
			Description: log.Detail,
			Metadata: map[string]any{
				"source":    "legacy_audit",
				"client_ip": log.ClientIP,
			},
			CreatedAt: log.CreatedAt,
			UpdatedAt: log.CreatedAt,
		}
		appendPlatformItem(result, "operation_logs", item)
	}
}

func appendPlatformItem(result map[string][]model.PlatformItem, collection string, item model.PlatformItem) {
	for _, existing := range result[collection] {
		if existing.ID == item.ID {
			return
		}
	}
	result[collection] = append(result[collection], item)
}

func serverProtocol(server model.Server) model.Protocol {
	if server.OS == model.ServerOSWindows {
		return model.ProtocolRDP
	}
	return model.ProtocolSSH
}

func serverPort(server model.Server) int {
	if server.OS == model.ServerOSWindows {
		if server.RDPPort == 0 {
			return 3389
		}
		return server.RDPPort
	}
	if server.SSHPort == 0 {
		return 22
	}
	return server.SSHPort
}

func (s *Store) ListPlatformItems(collection string) ([]model.PlatformItem, error) {
	items, err := s.PlatformBootstrap()
	if err != nil {
		return nil, err
	}
	return items[collection], nil
}

func (s *Store) CreatePlatformItem(collection string, req model.PlatformItemRequest) (model.PlatformItem, error) {
	item := model.PlatformItem{
		Name:        strings.TrimSpace(req.Name),
		Type:        strings.TrimSpace(req.Type),
		Status:      strings.TrimSpace(req.Status),
		Protocol:    req.Protocol,
		Host:        strings.TrimSpace(req.Host),
		Port:        req.Port,
		Username:    strings.TrimSpace(req.Username),
		Group:       strings.TrimSpace(req.Group),
		OwnerID:     strings.TrimSpace(req.OwnerID),
		ParentID:    strings.TrimSpace(req.ParentID),
		TargetID:    strings.TrimSpace(req.TargetID),
		Tags:        req.Tags,
		Permissions: req.Permissions,
		Description: strings.TrimSpace(req.Description),
		Metadata:    req.Metadata,
	}
	if err := s.applyPlatformSecrets(collection, req, &item, true); err != nil {
		return model.PlatformItem{}, err
	}
	if item.Name == "" {
		item.Name = "未命名"
	}
	if item.Status == "" {
		item.Status = "enabled"
	}
	return s.createPlatformItem(collection, item)
}

func (s *Store) createPlatformItem(collection string, item model.PlatformItem) (model.PlatformItem, error) {
	now := time.Now().UTC()
	if item.ID == "" {
		item.ID = newID(collectionPrefix(collection))
	}
	if item.Module == "" {
		item.Module = collection
	}
	if item.CreatedAt.IsZero() {
		item.CreatedAt = now
	}
	if item.UpdatedAt.IsZero() {
		item.UpdatedAt = item.CreatedAt
	}
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	if collection == "assets" {
		stripAssetSensitiveMetadata(item.Metadata)
	}
	payload, err := json.Marshal(item)
	if err != nil {
		return model.PlatformItem{}, err
	}
	_, err = s.db.Exec(
		`INSERT OR REPLACE INTO platform_records(collection, id, payload, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		collection,
		item.ID,
		string(payload),
		item.CreatedAt.Format(time.RFC3339Nano),
		item.UpdatedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return model.PlatformItem{}, fmt.Errorf("create platform record: %w", err)
	}
	sanitizePlatformItem(&item)
	return item, nil
}

func (s *Store) UpdatePlatformItem(collection, id string, req model.PlatformItemRequest) (model.PlatformItem, error) {
	item, ok, err := s.GetPlatformItem(collection, id)
	if err != nil {
		return model.PlatformItem{}, err
	}
	if !ok {
		return model.PlatformItem{}, os.ErrNotExist
	}
	if strings.TrimSpace(req.Name) != "" {
		item.Name = strings.TrimSpace(req.Name)
	}
	if req.Type != "" {
		item.Type = strings.TrimSpace(req.Type)
	}
	if req.Status != "" {
		item.Status = strings.TrimSpace(req.Status)
	}
	if req.Protocol != "" {
		item.Protocol = req.Protocol
	}
	if req.Host != "" {
		item.Host = strings.TrimSpace(req.Host)
	}
	if req.Port != 0 {
		item.Port = req.Port
	}
	if req.Username != "" {
		item.Username = strings.TrimSpace(req.Username)
	}
	if req.Group != "" {
		item.Group = strings.TrimSpace(req.Group)
	}
	if req.OwnerID != "" {
		item.OwnerID = strings.TrimSpace(req.OwnerID)
	}
	if req.ParentID != "" {
		item.ParentID = strings.TrimSpace(req.ParentID)
	}
	if req.TargetID != "" {
		item.TargetID = strings.TrimSpace(req.TargetID)
	}
	if req.Tags != nil {
		item.Tags = req.Tags
	}
	if req.Permissions != nil {
		item.Permissions = req.Permissions
	}
	if req.Description != "" {
		item.Description = strings.TrimSpace(req.Description)
	}
	existingPasswordHash, _ := item.Metadata["password_hash"].(string)
	existingClientSecretHash, _ := item.Metadata["client_secret_hash"].(string)
	existingAgentTokenHash, _ := item.Metadata["agent_token_hash"].(string)
	existingCredentialSecrets := copyMetadataSecrets(item.Metadata, "encrypted_password", "encrypted_private_key", "encrypted_passphrase")
	existingSystemSettingSecrets := copyMetadataSecrets(item.Metadata, "smtp_password_encrypted", "llm_api_key_encrypted", "oidc_client_secret_encrypted", "ldap_bind_password_encrypted", "wecom_agent_secret_encrypted", "dns_api_token_encrypted", "proxy_private_key_encrypted")
	existingCertificateSecrets := copyMetadataSecrets(item.Metadata, "certificate_private_key_encrypted")
	existingCertificatePlainPrivateKey := firstMetadataString(item.Metadata, certificatePrivateKeyPlainKeys...)
	existingCertificateSecretState := copyMetadataValues(item.Metadata, "has_private_key", "private_key_set", "private_key_updated_at", "private_key_filename")
	existingDatabaseAssetSecrets := copyMetadataSecrets(item.Metadata, "database_dsn_encrypted")
	existingDatabaseAssetPlainDSN := firstMetadataString(item.Metadata, databaseAssetDSNPlainKeys...)
	existingDatabaseAssetSecretState := copyMetadataValues(item.Metadata, "database_dsn_set", "database_dsn_updated_at")
	existingSystemSettingSecretState := copyMetadataValues(item.Metadata,
		"smtp_password_set",
		"smtp_password_updated_at",
		"llm_api_key_set",
		"llm_api_key_updated_at",
		"oidc_client_secret_set",
		"oidc_client_secret_updated_at",
		"ldap_bind_password_set",
		"ldap_bind_password_updated_at",
		"wecom_agent_secret_set",
		"wecom_agent_secret_updated_at",
		"dns_api_token_set",
		"dns_api_token_updated_at",
		"proxy_private_key_set",
		"proxy_private_key_updated_at",
	)
	existingUserMFA := copyMetadataSecrets(item.Metadata, "mfa_secret_encrypted")
	existingUserMFA["mfa_enabled"] = metadataStringValue(item.Metadata["mfa_enabled"])
	existingUserMFA["mfa_enabled_at"] = metadataStringValue(item.Metadata["mfa_enabled_at"])
	existingUserMFA["mfa_recovery_count"] = metadataStringValue(item.Metadata["mfa_recovery_count"])
	existingUserMFA["mfa_recovery_hashes"] = metadataStringValue(item.Metadata["mfa_recovery_hashes"])
	existingUserPresence := copyMetadataValues(item.Metadata,
		"online",
		"last_login_at",
		"last_logout_at",
		"last_seen_at",
		"last_login_ip",
		"last_user_agent",
		"login_count",
	)
	if req.Metadata != nil {
		item.Metadata = req.Metadata
		if collection == "users" {
			if existingPasswordHash != "" {
				item.Metadata["password_hash"] = existingPasswordHash
			}
			restoreMetadataValues(item.Metadata, existingUserMFA)
			restoreMetadataAnyValues(item.Metadata, existingUserPresence)
		}
		if collection == "oidc_clients" {
			delete(item.Metadata, "client_secret_hash")
			if existingClientSecretHash != "" {
				item.Metadata["client_secret_hash"] = existingClientSecretHash
			}
		}
		if collection == "agent_gateways" {
			delete(item.Metadata, "agent_token_hash")
			if existingAgentTokenHash != "" {
				item.Metadata["agent_token_hash"] = existingAgentTokenHash
			}
		}
		if collection == "credentials" {
			for key, value := range existingCredentialSecrets {
				delete(item.Metadata, key)
				if value != "" {
					item.Metadata[key] = value
				}
			}
		}
		if collection == "system_settings" {
			for key, value := range existingSystemSettingSecrets {
				delete(item.Metadata, key)
				if value != "" {
					item.Metadata[key] = value
				}
			}
			restoreMetadataAnyValues(item.Metadata, existingSystemSettingSecretState)
		}
		if collection == "certificates" {
			for key, value := range existingCertificateSecrets {
				delete(item.Metadata, key)
				if value != "" {
					item.Metadata[key] = value
				}
			}
			restoreMetadataAnyValues(item.Metadata, existingCertificateSecretState)
			if existingCertificateSecrets["certificate_private_key_encrypted"] == "" && existingCertificatePlainPrivateKey != "" && firstMetadataString(item.Metadata, certificatePrivateKeyPlainKeys...) == "" {
				item.Metadata["private_key"] = existingCertificatePlainPrivateKey
			}
		}
		if collection == "database_assets" {
			for key, value := range existingDatabaseAssetSecrets {
				delete(item.Metadata, key)
				if value != "" {
					item.Metadata[key] = value
				}
			}
			restoreMetadataAnyValues(item.Metadata, existingDatabaseAssetSecretState)
			if existingDatabaseAssetSecrets["database_dsn_encrypted"] == "" && existingDatabaseAssetPlainDSN != "" && firstMetadataString(item.Metadata, databaseAssetDSNPlainKeys...) == "" {
				item.Metadata["dsn"] = existingDatabaseAssetPlainDSN
			}
		}
	}
	if err := s.applyPlatformSecrets(collection, req, &item, false); err != nil {
		return model.PlatformItem{}, err
	}
	item.UpdatedAt = time.Now().UTC()
	return s.createPlatformItem(collection, item)
}

func (s *Store) GetPlatformItem(collection, id string) (model.PlatformItem, bool, error) {
	var payload string
	err := s.db.QueryRow(`SELECT payload FROM platform_records WHERE collection = ? AND id = ?`, collection, id).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return model.PlatformItem{}, false, nil
	}
	if err != nil {
		return model.PlatformItem{}, false, fmt.Errorf("get platform record: %w", err)
	}
	var item model.PlatformItem
	if err := json.Unmarshal([]byte(payload), &item); err != nil {
		return model.PlatformItem{}, false, err
	}
	return item, true, nil
}

func (s *Store) SavePlatformItem(collection string, item model.PlatformItem) (model.PlatformItem, error) {
	item.Module = collection
	item.UpdatedAt = time.Now().UTC()
	if item.CreatedAt.IsZero() {
		item.CreatedAt = item.UpdatedAt
	}
	if err := s.applyPlatformSecrets(collection, model.PlatformItemRequest{}, &item, false); err != nil {
		return model.PlatformItem{}, err
	}
	return s.createPlatformItem(collection, item)
}

func (s *Store) DeletePlatformItem(collection, id string) error {
	result, err := s.db.Exec(`DELETE FROM platform_records WHERE collection = ? AND id = ?`, collection, id)
	if err != nil {
		return fmt.Errorf("delete platform record: %w", err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return os.ErrNotExist
	}
	return nil
}

func (s *Store) RestoreSnapshot(legacyRaw []byte, sqlitePath string) (RestoreSummary, error) {
	var nextState *state
	legacyStateRestored := false
	coreStateRestored := false
	if len(legacyRaw) > 0 {
		parsed := state{}
		if err := json.Unmarshal(legacyRaw, &parsed); err != nil {
			return RestoreSummary{}, fmt.Errorf("decode legacy store: %w", err)
		}
		if parsed.Admin == nil || parsed.Admin.PasswordHash == "" {
			return RestoreSummary{}, errors.New("backup legacy store does not contain an administrator")
		}
		nextState = &parsed
		legacyStateRestored = true
	}

	var records []platformRecordSnapshot
	var coreRecords []coreRecordSnapshot
	var err error
	if sqlitePath != "" {
		records, err = s.readPlatformRecordSnapshot(sqlitePath)
		if err != nil {
			return RestoreSummary{}, err
		}
		coreRecords, err = s.readCoreRecordSnapshot(sqlitePath)
		if err != nil {
			return RestoreSummary{}, err
		}
		if len(coreRecords) > 0 {
			restoredState, err := stateFromCoreRecords(coreRecords)
			if err != nil {
				return RestoreSummary{}, err
			}
			nextState = &restoredState
			legacyStateRestored = false
			coreStateRestored = true
		}
	}
	if nextState == nil && len(records) == 0 {
		return RestoreSummary{}, errors.New("backup does not contain restoreable store data")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	summary := RestoreSummary{RecordsByCollection: map[string]int{}}
	if nextState != nil {
		s.state = *nextState
		s.ensureMaps()
		if err := s.saveLocked(); err != nil {
			return RestoreSummary{}, err
		}
		summary.LegacyStateRestored = legacyStateRestored
		summary.CoreStateRestored = coreStateRestored
		summary.CoreRecords = len(coreRecords)
	}
	if len(records) > 0 {
		tx, err := s.db.Begin()
		if err != nil {
			return RestoreSummary{}, err
		}
		if _, err := tx.Exec(`DELETE FROM platform_records`); err != nil {
			_ = tx.Rollback()
			return RestoreSummary{}, fmt.Errorf("clear platform records: %w", err)
		}
		stmt, err := tx.Prepare(`INSERT INTO platform_records(collection, id, payload, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`)
		if err != nil {
			_ = tx.Rollback()
			return RestoreSummary{}, fmt.Errorf("prepare platform restore: %w", err)
		}
		for _, record := range records {
			if _, err := stmt.Exec(record.Collection, record.ID, record.Payload, record.CreatedAt, record.UpdatedAt); err != nil {
				_ = stmt.Close()
				_ = tx.Rollback()
				return RestoreSummary{}, fmt.Errorf("restore platform record: %w", err)
			}
			summary.PlatformRecords++
			summary.RecordsByCollection[record.Collection]++
			if record.Migrated {
				summary.MigratedPlatformSecrets++
			}
		}
		if err := stmt.Close(); err != nil {
			_ = tx.Rollback()
			return RestoreSummary{}, err
		}
		if err := tx.Commit(); err != nil {
			return RestoreSummary{}, fmt.Errorf("commit platform restore: %w", err)
		}
	}
	return summary, nil
}

func (s *Store) readPlatformRecordSnapshot(sqlitePath string) ([]platformRecordSnapshot, error) {
	db, err := sql.Open("sqlite", sqlitePath)
	if err != nil {
		return nil, fmt.Errorf("open backup sqlite store: %w", err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT collection, id, payload, created_at, updated_at FROM platform_records ORDER BY collection, created_at`)
	if isMissingTableError(err) {
		return []platformRecordSnapshot{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read backup platform records: %w", err)
	}
	defer rows.Close()
	allowedCollections := platformCollectionSet()
	records := []platformRecordSnapshot{}
	for rows.Next() {
		var record platformRecordSnapshot
		if err := rows.Scan(&record.Collection, &record.ID, &record.Payload, &record.CreatedAt, &record.UpdatedAt); err != nil {
			return nil, err
		}
		if !allowedCollections[record.Collection] {
			return nil, fmt.Errorf("backup contains unsupported platform collection %q", record.Collection)
		}
		if record.Collection == "" || record.ID == "" || record.Payload == "" {
			return nil, errors.New("backup contains an invalid platform record")
		}
		var item model.PlatformItem
		if err := json.Unmarshal([]byte(record.Payload), &item); err != nil {
			return nil, fmt.Errorf("decode backup platform record %s/%s: %w", record.Collection, record.ID, err)
		}
		normalized, migrated, err := s.normalizeRestoredPlatformRecord(record.Collection, record.ID, item)
		if err != nil {
			return nil, err
		}
		record.Payload = normalized
		record.Migrated = migrated
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func (s *Store) readCoreRecordSnapshot(sqlitePath string) ([]coreRecordSnapshot, error) {
	db, err := sql.Open("sqlite", sqlitePath)
	if err != nil {
		return nil, fmt.Errorf("open core sqlite store: %w", err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT kind, id, payload, created_at, updated_at FROM core_records ORDER BY kind, created_at`)
	if isMissingTableError(err) {
		return []coreRecordSnapshot{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read core records: %w", err)
	}
	defer rows.Close()
	records := []coreRecordSnapshot{}
	for rows.Next() {
		var record coreRecordSnapshot
		if err := rows.Scan(&record.Kind, &record.ID, &record.Payload, &record.CreatedAt, &record.UpdatedAt); err != nil {
			return nil, err
		}
		if !allowedCoreRecordKind(record.Kind) {
			return nil, fmt.Errorf("backup contains unsupported core record kind %q", record.Kind)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func isMissingTableError(err error) bool {
	if err == nil {
		return false
	}
	value := strings.ToLower(err.Error())
	return strings.Contains(value, "no such table")
}

func allowedCoreRecordKind(kind string) bool {
	switch kind {
	case "admin", "servers", "credentials", "sessions", "audit_logs":
		return true
	default:
		return false
	}
}

func (s *Store) normalizeRestoredPlatformRecord(collection, id string, item model.PlatformItem) (string, bool, error) {
	if item.ID == "" {
		item.ID = id
	}
	if item.ID != id {
		return "", false, fmt.Errorf("backup platform record %s/%s payload id mismatch %q", collection, id, item.ID)
	}
	item.Module = collection
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	before, err := json.Marshal(item.Metadata)
	if err != nil {
		return "", false, fmt.Errorf("encode backup platform record metadata %s/%s: %w", collection, id, err)
	}
	if err := s.applyPlatformSecrets(collection, model.PlatformItemRequest{}, &item, false); err != nil {
		return "", false, fmt.Errorf("migrate backup platform record secrets %s/%s: %w", collection, id, err)
	}
	after, err := json.Marshal(item.Metadata)
	if err != nil {
		return "", false, fmt.Errorf("encode migrated backup platform record metadata %s/%s: %w", collection, id, err)
	}
	payload, err := json.Marshal(item)
	if err != nil {
		return "", false, fmt.Errorf("encode backup platform record %s/%s: %w", collection, id, err)
	}
	return string(payload), !bytes.Equal(before, after), nil
}

func platformCollectionSet() map[string]bool {
	result := map[string]bool{}
	for _, collection := range platformCollections {
		result[collection] = true
	}
	return result
}

func collectionPrefix(collection string) string {
	parts := strings.Split(collection, "_")
	prefix := "rec"
	if len(parts) > 0 && parts[0] != "" {
		prefix = parts[0]
	}
	if len(prefix) > 10 {
		prefix = prefix[:10]
	}
	return prefix
}

func (s *Store) applyPlatformSecrets(collection string, req model.PlatformItemRequest, item *model.PlatformItem, creating bool) error {
	switch collection {
	case "users":
		return applyUserPlatformSecret(req, item, creating)
	case "oidc_clients":
		return applyOIDCClientPlatformSecret(req, item, creating)
	case "agent_gateways":
		return applyAgentGatewayPlatformSecret(item, creating)
	case "credentials":
		return s.applyCredentialPlatformSecret(req, item, creating)
	case "certificates":
		return s.applyCertificatePlatformSecret(item, creating)
	case "database_assets":
		return s.applyDatabaseAssetPlatformSecret(item, creating)
	case "system_settings":
		return s.applySystemSettingPlatformSecret(req, item, creating)
	default:
		return nil
	}
}

func applyUserPlatformSecret(req model.PlatformItemRequest, item *model.PlatformItem, creating bool) error {
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	if item.Type == "" {
		item.Type = "local"
	}
	if _, ok := item.Metadata["role"]; !ok {
		item.Metadata["role"] = "user"
	}
	if req.Password == "" {
		if !strings.EqualFold(strings.TrimSpace(item.Type), "local") {
			return nil
		}
		if creating {
			return errors.New("password is required for local users")
		}
		return nil
	}
	if len(req.Password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	item.Metadata["password_hash"] = string(hash)
	return nil
}

func applyOIDCClientPlatformSecret(req model.PlatformItemRequest, item *model.PlatformItem, creating bool) error {
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	if item.Type == "" {
		item.Type = "confidential"
	}
	secret := strings.TrimSpace(req.Password)
	for _, key := range []string{"client_secret", "clientSecret", "secret"} {
		if secret == "" {
			if text, ok := item.Metadata[key].(string); ok {
				secret = strings.TrimSpace(text)
			}
		}
		delete(item.Metadata, key)
	}
	if secret == "" {
		if creating {
			delete(item.Metadata, "client_secret_hash")
		}
		return nil
	}
	delete(item.Metadata, "client_secret_hash")
	if len(secret) > 4096 {
		return errors.New("client secret is too large")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	item.Metadata["client_secret_hash"] = string(hash)
	return nil
}

func applyAgentGatewayPlatformSecret(item *model.PlatformItem, creating bool) error {
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	if item.Type == "" {
		item.Type = "agent"
	}
	for _, key := range []string{"registration_token", "agent_token", "gateway_token", "token"} {
		delete(item.Metadata, key)
	}
	if creating {
		delete(item.Metadata, "agent_token_hash")
	}
	return nil
}

func (s *Store) applyCredentialPlatformSecret(req model.PlatformItemRequest, item *model.PlatformItem, creating bool) error {
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	for _, key := range []string{"password", "private_key", "privateKey", "passphrase"} {
		delete(item.Metadata, key)
	}
	if item.Type == "" {
		item.Type = string(model.CredentialSSHPassword)
	}
	password := strings.TrimSpace(req.Password)
	privateKey := strings.TrimSpace(req.PrivateKey)
	passphrase := strings.TrimSpace(req.Passphrase)
	if password == "" {
		password = firstMetadataString(item.Metadata, "plain_password")
		delete(item.Metadata, "plain_password")
	}
	if privateKey == "" {
		privateKey = firstMetadataString(item.Metadata, "plain_private_key")
		delete(item.Metadata, "plain_private_key")
	}
	if passphrase == "" {
		passphrase = firstMetadataString(item.Metadata, "plain_passphrase")
		delete(item.Metadata, "plain_passphrase")
	}
	if password == "" && privateKey == "" && passphrase == "" {
		if creating {
			delete(item.Metadata, "encrypted_password")
			delete(item.Metadata, "encrypted_private_key")
			delete(item.Metadata, "encrypted_passphrase")
		}
		return nil
	}
	if len(password) > 32*1024 || len(privateKey) > 128*1024 || len(passphrase) > 32*1024 {
		return errors.New("credential secret is too large")
	}
	if password != "" {
		encrypted, err := s.cipher.EncryptString(password)
		if err != nil {
			return err
		}
		item.Metadata["encrypted_password"] = encrypted
	}
	if privateKey != "" {
		encrypted, err := s.cipher.EncryptString(privateKey)
		if err != nil {
			return err
		}
		item.Metadata["encrypted_private_key"] = encrypted
	}
	if passphrase != "" {
		encrypted, err := s.cipher.EncryptString(passphrase)
		if err != nil {
			return err
		}
		item.Metadata["encrypted_passphrase"] = encrypted
	}
	return nil
}

var certificatePrivateKeyPlainKeys = []string{"private_key", "privateKey", "key", "private_key_pem", "plain_private_key"}

func (s *Store) applyCertificatePlatformSecret(item *model.PlatformItem, creating bool) error {
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	privateKey := firstMetadataString(item.Metadata, certificatePrivateKeyPlainKeys...)
	for _, key := range certificatePrivateKeyPlainKeys {
		delete(item.Metadata, key)
	}
	if privateKey == "" {
		if creating {
			delete(item.Metadata, "certificate_private_key_encrypted")
			delete(item.Metadata, "private_key_set")
			delete(item.Metadata, "private_key_updated_at")
		}
		return nil
	}
	if len(privateKey) > 256*1024 {
		return errors.New("certificate private key is too large")
	}
	encrypted, err := s.cipher.EncryptString(privateKey)
	if err != nil {
		return err
	}
	item.Metadata["certificate_private_key_encrypted"] = encrypted
	item.Metadata["has_private_key"] = true
	item.Metadata["private_key_set"] = true
	item.Metadata["private_key_updated_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	return nil
}

var databaseAssetDSNPlainKeys = []string{"dsn", "connection_string", "connectionString", "database_url", "databaseUrl", "url"}

func (s *Store) applyDatabaseAssetPlatformSecret(item *model.PlatformItem, creating bool) error {
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	dsn := firstMetadataString(item.Metadata, databaseAssetDSNPlainKeys...)
	for _, key := range databaseAssetDSNPlainKeys {
		delete(item.Metadata, key)
	}
	if dsn == "" {
		if creating {
			delete(item.Metadata, "database_dsn_encrypted")
			delete(item.Metadata, "database_dsn_set")
			delete(item.Metadata, "database_dsn_updated_at")
		}
		return nil
	}
	if len(dsn) > 128*1024 {
		return errors.New("database dsn is too large")
	}
	encrypted, err := s.cipher.EncryptString(dsn)
	if err != nil {
		return err
	}
	item.Metadata["database_dsn_encrypted"] = encrypted
	item.Metadata["database_dsn_set"] = true
	item.Metadata["database_dsn_updated_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	return nil
}

func (s *Store) applySystemSettingPlatformSecret(req model.PlatformItemRequest, item *model.PlatformItem, creating bool) error {
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	smtpPassword := strings.TrimSpace(req.Password)
	if smtpPassword == "" {
		smtpPassword = firstMetadataString(item.Metadata, "smtp_password", "smtpPassword", "plain_smtp_password")
	}
	llmAPIKey := firstMetadataString(item.Metadata, "llm_api_key", "llmApiKey", "plain_llm_api_key")
	for _, key := range []string{
		"smtp_password",
		"smtpPassword",
		"plain_smtp_password",
		"llm_api_key",
		"llmApiKey",
		"plain_llm_api_key",
	} {
		delete(item.Metadata, key)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := s.encryptSystemSettingExternalSecrets(item.Metadata, now, creating); err != nil {
		return err
	}
	if smtpPassword == "" && llmAPIKey == "" {
		if creating {
			delete(item.Metadata, "smtp_password_encrypted")
			delete(item.Metadata, "smtp_password_set")
			delete(item.Metadata, "llm_api_key_encrypted")
			delete(item.Metadata, "llm_api_key_set")
		}
		return nil
	}
	if len(smtpPassword) > 32*1024 || len(llmAPIKey) > 32*1024 {
		return errors.New("system setting secret is too large")
	}
	if smtpPassword != "" {
		encrypted, err := s.cipher.EncryptString(smtpPassword)
		if err != nil {
			return err
		}
		item.Metadata["smtp_password_encrypted"] = encrypted
		item.Metadata["smtp_password_set"] = true
		item.Metadata["smtp_password_updated_at"] = now
	}
	if llmAPIKey != "" {
		encrypted, err := s.cipher.EncryptString(llmAPIKey)
		if err != nil {
			return err
		}
		item.Metadata["llm_api_key_encrypted"] = encrypted
		item.Metadata["llm_api_key_set"] = true
		item.Metadata["llm_api_key_updated_at"] = now
	}
	return nil
}

func (s *Store) encryptSystemSettingExternalSecrets(value any, now string, creating bool) error {
	switch typed := value.(type) {
	case map[string]any:
		for _, spec := range externalSystemSettingSecretSpecs {
			secret := firstMetadataString(typed, spec.plainKeys...)
			for _, key := range spec.plainKeys {
				delete(typed, key)
			}
			if secret != "" {
				if len(secret) > 32*1024 {
					return errors.New("system setting secret is too large")
				}
				encrypted, err := s.cipher.EncryptString(secret)
				if err != nil {
					return err
				}
				typed[spec.encryptedKey] = encrypted
				typed[spec.setKey] = true
				typed[spec.updatedAtKey] = now
			} else if creating {
				delete(typed, spec.setKey)
			}
		}
		for _, child := range typed {
			if err := s.encryptSystemSettingExternalSecrets(child, now, creating); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := s.encryptSystemSettingExternalSecrets(child, now, creating); err != nil {
				return err
			}
		}
	case []map[string]any:
		for _, child := range typed {
			if err := s.encryptSystemSettingExternalSecrets(child, now, creating); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) SystemSettingSMTPPassword(id string) (string, bool, error) {
	item, ok, err := s.GetPlatformItem("system_settings", id)
	if err != nil || !ok {
		return "", ok, err
	}
	encrypted, _ := item.Metadata["smtp_password_encrypted"].(string)
	if encrypted == "" {
		return "", true, nil
	}
	secret, err := s.cipher.DecryptString(encrypted)
	if err != nil {
		return "", true, err
	}
	return secret, true, nil
}

func (s *Store) SystemSettingLLMAPIKey(id string) (string, bool, error) {
	item, ok, err := s.GetPlatformItem("system_settings", id)
	if err != nil || !ok {
		return "", ok, err
	}
	encrypted, _ := item.Metadata["llm_api_key_encrypted"].(string)
	if encrypted == "" {
		return "", true, nil
	}
	secret, err := s.cipher.DecryptString(encrypted)
	if err != nil {
		return "", true, err
	}
	return secret, true, nil
}

func (s *Store) SystemSettingProxyPrivateKey() (string, bool, error) {
	rows, err := s.db.Query(`SELECT payload FROM platform_records WHERE collection = ?`, "system_settings")
	if err != nil {
		return "", false, fmt.Errorf("read proxy private key setting: %w", err)
	}
	defer rows.Close()

	foundProxySetting := false
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return "", false, err
		}
		var item model.PlatformItem
		if err := json.Unmarshal([]byte(payload), &item); err != nil {
			return "", false, err
		}
		if !strings.EqualFold(strings.TrimSpace(item.Type), "proxy") {
			continue
		}
		foundProxySetting = true
		encrypted, _ := item.Metadata["proxy_private_key_encrypted"].(string)
		if encrypted == "" {
			continue
		}
		secret, err := s.cipher.DecryptString(encrypted)
		if err != nil {
			return "", true, err
		}
		return secret, true, nil
	}
	if err := rows.Err(); err != nil {
		return "", false, err
	}
	return "", foundProxySetting, nil
}

func (s *Store) DecryptPlatformSecret(encrypted string) (string, error) {
	return s.cipher.DecryptString(encrypted)
}

func (s *Store) GetPlatformCredentialSecret(id string) (model.PlatformItem, CredentialSecret, bool, error) {
	item, ok, err := s.GetPlatformItem("credentials", id)
	if err != nil || !ok {
		return model.PlatformItem{}, CredentialSecret{}, ok, err
	}
	secret := CredentialSecret{}
	if encrypted, _ := item.Metadata["encrypted_password"].(string); encrypted != "" {
		secret.Password, err = s.cipher.DecryptString(encrypted)
		if err != nil {
			return model.PlatformItem{}, CredentialSecret{}, true, err
		}
	}
	if encrypted, _ := item.Metadata["encrypted_private_key"].(string); encrypted != "" {
		secret.PrivateKey, err = s.cipher.DecryptString(encrypted)
		if err != nil {
			return model.PlatformItem{}, CredentialSecret{}, true, err
		}
	}
	if encrypted, _ := item.Metadata["encrypted_passphrase"].(string); encrypted != "" {
		secret.Passphrase, err = s.cipher.DecryptString(encrypted)
		if err != nil {
			return model.PlatformItem{}, CredentialSecret{}, true, err
		}
	}
	return item, secret, true, nil
}

func (s *Store) UserMFAProfile(userID string) (MFAProfile, bool, error) {
	item, ok, err := s.GetPlatformItem("users", userID)
	if err != nil || !ok {
		return MFAProfile{}, ok, err
	}
	profile := MFAProfile{
		Enabled:       metadataBool(item.Metadata["mfa_enabled"]),
		RecoveryCount: metadataIntValue(item.Metadata["mfa_recovery_count"]),
	}
	if encrypted, _ := item.Metadata["mfa_secret_encrypted"].(string); encrypted != "" {
		profile.Secret, err = s.cipher.DecryptString(encrypted)
		if err != nil {
			return MFAProfile{}, true, err
		}
	}
	if profile.RecoveryCount == 0 {
		profile.RecoveryCount = len(metadataStringList(item.Metadata["mfa_recovery_hashes"]))
	}
	return profile, true, nil
}

func (s *Store) EnableUserMFA(userID, secret string, recoveryCodes []string) (MFAProfile, error) {
	item, ok, err := s.GetPlatformItem("users", userID)
	if err != nil {
		return MFAProfile{}, err
	}
	if !ok {
		return MFAProfile{}, os.ErrNotExist
	}
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	encrypted, err := s.cipher.EncryptString(strings.TrimSpace(secret))
	if err != nil {
		return MFAProfile{}, err
	}
	hashes := make([]string, 0, len(recoveryCodes))
	for _, code := range recoveryCodes {
		if hash := recoveryCodeHash(code); hash != "" {
			hashes = append(hashes, hash)
		}
	}
	item.Metadata["mfa_enabled"] = true
	item.Metadata["mfa_enabled_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	item.Metadata["mfa_secret_encrypted"] = encrypted
	item.Metadata["mfa_recovery_hashes"] = hashes
	item.Metadata["mfa_recovery_count"] = len(hashes)
	if _, err := s.SavePlatformItem("users", item); err != nil {
		return MFAProfile{}, err
	}
	return MFAProfile{Enabled: true, Secret: strings.TrimSpace(secret), RecoveryCount: len(hashes)}, nil
}

func (s *Store) DisableUserMFA(userID string) error {
	item, ok, err := s.GetPlatformItem("users", userID)
	if err != nil {
		return err
	}
	if !ok {
		return os.ErrNotExist
	}
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	delete(item.Metadata, "mfa_enabled")
	delete(item.Metadata, "mfa_enabled_at")
	delete(item.Metadata, "mfa_secret_encrypted")
	delete(item.Metadata, "mfa_recovery_hashes")
	delete(item.Metadata, "mfa_recovery_count")
	_, err = s.SavePlatformItem("users", item)
	return err
}

func (s *Store) ReplaceUserMFARecoveryCodes(userID string, recoveryCodes []string) (MFAProfile, error) {
	item, ok, err := s.GetPlatformItem("users", userID)
	if err != nil {
		return MFAProfile{}, err
	}
	if !ok {
		return MFAProfile{}, os.ErrNotExist
	}
	if !metadataBool(item.Metadata["mfa_enabled"]) {
		return MFAProfile{}, os.ErrInvalid
	}
	hashes := make([]string, 0, len(recoveryCodes))
	for _, code := range recoveryCodes {
		if hash := recoveryCodeHash(code); hash != "" {
			hashes = append(hashes, hash)
		}
	}
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	item.Metadata["mfa_recovery_hashes"] = hashes
	item.Metadata["mfa_recovery_count"] = len(hashes)
	if _, err := s.SavePlatformItem("users", item); err != nil {
		return MFAProfile{}, err
	}
	profile, _, err := s.UserMFAProfile(userID)
	if err != nil {
		return MFAProfile{}, err
	}
	profile.RecoveryCount = len(hashes)
	return profile, nil
}

func (s *Store) ConsumeUserMFARecoveryCode(userID, code string) (bool, error) {
	hash := recoveryCodeHash(code)
	if hash == "" {
		return false, nil
	}
	item, ok, err := s.GetPlatformItem("users", userID)
	if err != nil || !ok {
		return false, err
	}
	hashes := metadataStringList(item.Metadata["mfa_recovery_hashes"])
	next := make([]string, 0, len(hashes))
	matched := false
	for _, candidate := range hashes {
		if !matched && candidate == hash {
			matched = true
			continue
		}
		next = append(next, candidate)
	}
	if !matched {
		return false, nil
	}
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	item.Metadata["mfa_recovery_hashes"] = next
	item.Metadata["mfa_recovery_count"] = len(next)
	_, err = s.SavePlatformItem("users", item)
	return err == nil, err
}

func copyMetadataSecrets(metadata map[string]any, keys ...string) map[string]string {
	result := map[string]string{}
	for _, key := range keys {
		value, _ := metadata[key].(string)
		result[key] = value
	}
	return result
}

func copyMetadataValues(metadata map[string]any, keys ...string) map[string]any {
	result := map[string]any{}
	for _, key := range keys {
		if value, ok := metadata[key]; ok {
			result[key] = value
		}
	}
	return result
}

func restoreMetadataValues(metadata map[string]any, values map[string]string) {
	for key, value := range values {
		delete(metadata, key)
		if value != "" {
			metadata[key] = value
		}
	}
}

func restoreMetadataAnyValues(metadata map[string]any, values map[string]any) {
	for key, value := range values {
		delete(metadata, key)
		if value != nil {
			metadata[key] = value
		}
	}
}

func trimMetadataText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit]
}

func metadataStringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case bool:
		if typed {
			return "true"
		}
	case int:
		if typed != 0 {
			return fmt.Sprintf("%d", typed)
		}
	case int64:
		if typed != 0 {
			return fmt.Sprintf("%d", typed)
		}
	case float64:
		if typed != 0 {
			return fmt.Sprintf("%.0f", typed)
		}
	case []string:
		if len(typed) > 0 {
			raw, _ := json.Marshal(typed)
			return string(raw)
		}
	case []any:
		if len(typed) > 0 {
			raw, _ := json.Marshal(typed)
			return string(raw)
		}
	}
	return ""
}

func metadataBool(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		text := strings.ToLower(strings.TrimSpace(typed))
		return text == "true" || text == "1" || text == "yes" || text == "enabled"
	default:
		return false
	}
}

func metadataIntValue(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case string:
		var parsed int
		if _, err := fmt.Sscanf(strings.TrimSpace(typed), "%d", &parsed); err == nil {
			return parsed
		}
	}
	return 0
}

func metadataStringList(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string{}, typed...)
	case []any:
		out := []string{}
		for _, item := range typed {
			if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
				out = append(out, strings.TrimSpace(text))
			}
		}
		return out
	case string:
		text := strings.TrimSpace(typed)
		if text == "" {
			return nil
		}
		var decoded []string
		if strings.HasPrefix(text, "[") && json.Unmarshal([]byte(text), &decoded) == nil {
			return decoded
		}
		return strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == ';' || r == '\n' })
	default:
		return nil
	}
}

func recoveryCodeHash(code string) string {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(code), "-", ""), " ", ""))
	if normalized == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func firstMetadataString(metadata map[string]any, keys ...string) string {
	for _, key := range keys {
		value, _ := metadata[key].(string)
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func sanitizePlatformItem(item *model.PlatformItem) {
	if item.Metadata == nil {
		return
	}
	if item.Module == "database_assets" || item.Protocol == model.ProtocolDatabase {
		sanitizeDatabaseAssetMetadata(item.Metadata)
	}
	sanitizeMetadataValue(item.Metadata)
}

func sanitizeDatabaseAssetMetadata(metadata map[string]any) {
	dsnSet := firstMetadataString(metadata, "database_dsn_encrypted") != "" || metadataBool(metadata["database_dsn_set"])
	for _, key := range databaseAssetDSNPlainKeys {
		if firstMetadataString(metadata, key) != "" {
			dsnSet = true
		}
		delete(metadata, key)
	}
	delete(metadata, "database_dsn_encrypted")
	if dsnSet {
		metadata["database_dsn_set"] = true
	}
}

func stripAssetSensitiveMetadata(metadata map[string]any) {
	sanitizeMetadataValue(metadata)
}

type externalSystemSettingSecretSpec struct {
	plainKeys    []string
	encryptedKey string
	setKey       string
	updatedAtKey string
}

var externalSystemSettingSecretSpecs = []externalSystemSettingSecretSpec{
	{
		plainKeys:    []string{"client_secret", "clientSecret", "oidc_client_secret", "oidcClientSecret", "external_oidc_client_secret", "externalOidcClientSecret"},
		encryptedKey: "oidc_client_secret_encrypted",
		setKey:       "oidc_client_secret_set",
		updatedAtKey: "oidc_client_secret_updated_at",
	},
	{
		plainKeys:    []string{"bind_password", "bindPassword", "ldap_bind_password", "ldapBindPassword", "plain_ldap_bind_password"},
		encryptedKey: "ldap_bind_password_encrypted",
		setKey:       "ldap_bind_password_set",
		updatedAtKey: "ldap_bind_password_updated_at",
	},
	{
		plainKeys:    []string{"agent_secret", "agentSecret", "wecom_agent_secret", "wecomAgentSecret", "enterprise_wechat_agent_secret", "corp_secret", "corpsecret"},
		encryptedKey: "wecom_agent_secret_encrypted",
		setKey:       "wecom_agent_secret_set",
		updatedAtKey: "wecom_agent_secret_updated_at",
	},
	{
		plainKeys:    []string{"dns_api_token", "dnsApiToken", "api_token", "apiToken", "access_key_secret", "accessKeySecret", "secret_key", "secretKey"},
		encryptedKey: "dns_api_token_encrypted",
		setKey:       "dns_api_token_set",
		updatedAtKey: "dns_api_token_updated_at",
	},
	{
		plainKeys:    []string{"proxy_private_key", "proxyPrivateKey", "ssh_private_key", "sshPrivateKey", "proxy_key", "proxyKey"},
		encryptedKey: "proxy_private_key_encrypted",
		setKey:       "proxy_private_key_set",
		updatedAtKey: "proxy_private_key_updated_at",
	},
}

var sensitiveMetadataKeys = map[string]struct{}{
	"password":                                 {},
	"password_hash":                            {},
	"private_key":                              {},
	"privateKey":                               {},
	"passphrase":                               {},
	"client_secret":                            {},
	"clientSecret":                             {},
	"client_secret_hash":                       {},
	"client_secret_encrypted":                  {},
	"secret":                                   {},
	"agent_token_hash":                         {},
	"registration_token":                       {},
	"agent_token":                              {},
	"gateway_token":                            {},
	"token":                                    {},
	"encrypted_password":                       {},
	"encrypted_private_key":                    {},
	"encrypted_passphrase":                     {},
	"mfa_secret":                               {},
	"mfa_secret_encrypted":                     {},
	"mfa_recovery_hashes":                      {},
	"mfa_recovery_codes":                       {},
	"plain_password":                           {},
	"plain_private_key":                        {},
	"plain_passphrase":                         {},
	"certificate_private_key_encrypted":        {},
	"smtp_password":                            {},
	"smtpPassword":                             {},
	"plain_smtp_password":                      {},
	"smtp_password_encrypted":                  {},
	"llm_api_key":                              {},
	"llmApiKey":                                {},
	"plain_llm_api_key":                        {},
	"llm_api_key_encrypted":                    {},
	"oidc_client_secret":                       {},
	"oidcClientSecret":                         {},
	"external_oidc_client_secret":              {},
	"externalOidcClientSecret":                 {},
	"oidc_client_secret_encrypted":             {},
	"external_oidc_client_secret_encrypted":    {},
	"bind_password":                            {},
	"bindPassword":                             {},
	"bind_password_encrypted":                  {},
	"ldap_bind_password":                       {},
	"ldapBindPassword":                         {},
	"plain_ldap_bind_password":                 {},
	"ldap_bind_password_encrypted":             {},
	"agent_secret":                             {},
	"agentSecret":                              {},
	"agent_secret_encrypted":                   {},
	"wecom_agent_secret":                       {},
	"wecomAgentSecret":                         {},
	"wecom_agent_secret_encrypted":             {},
	"enterprise_wechat_agent_secret":           {},
	"enterprise_wechat_agent_secret_encrypted": {},
	"corp_secret":                              {},
	"corpsecret":                               {},
	"dns_api_token":                            {},
	"dnsApiToken":                              {},
	"dns_api_token_encrypted":                  {},
	"api_token":                                {},
	"apiToken":                                 {},
	"access_key_secret":                        {},
	"accessKeySecret":                          {},
	"secret_key":                               {},
	"secretKey":                                {},
	"mtls_client_ca":                           {},
	"client_ca":                                {},
	"proxy_private_key":                        {},
	"proxyPrivateKey":                          {},
	"ssh_private_key":                          {},
	"sshPrivateKey":                            {},
	"proxy_key":                                {},
	"proxyKey":                                 {},
	"proxy_private_key_encrypted":              {},
	"public_key_x":                             {},
	"public_key_y":                             {},
	"cose_public_key":                          {},
	"database_dsn_encrypted":                   {},
}

func sanitizeMetadataValue(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if _, sensitive := sensitiveMetadataKeys[key]; sensitive {
				delete(typed, key)
				continue
			}
			sanitizeMetadataValue(child)
		}
	case []any:
		for _, child := range typed {
			sanitizeMetadataValue(child)
		}
	case []map[string]any:
		for _, child := range typed {
			sanitizeMetadataValue(child)
		}
	}
}

func (s *Store) Bootstrap() ([]model.Server, []model.CredentialPublic, []model.ConnectionSession, []model.AuditLog) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	servers := make([]model.Server, 0, len(s.state.Servers))
	for _, item := range s.state.Servers {
		servers = append(servers, item)
	}
	sort.Slice(servers, func(i, j int) bool {
		return servers[i].CreatedAt.After(servers[j].CreatedAt)
	})
	credentials := make([]model.CredentialPublic, 0, len(s.state.Credentials))
	for _, item := range s.state.Credentials {
		credentials = append(credentials, item.Public())
	}
	sort.Slice(credentials, func(i, j int) bool {
		return credentials[i].CreatedAt.After(credentials[j].CreatedAt)
	})
	sessions := make([]model.ConnectionSession, 0, len(s.state.Sessions))
	for _, item := range s.state.Sessions {
		sessions = append(sessions, item)
	}
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].StartedAt.After(sessions[j].StartedAt)
	})
	logs := make([]model.AuditLog, len(s.state.AuditLogs))
	copy(logs, s.state.AuditLogs)
	sort.Slice(logs, func(i, j int) bool {
		return logs[i].CreatedAt.After(logs[j].CreatedAt)
	})
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
	if err := s.saveLocked(); err != nil {
		return model.Server{}, err
	}
	_, _ = s.createPlatformItem("assets", model.PlatformItem{
		ID:          server.ID,
		Name:        server.Name,
		Type:        string(server.OS),
		Status:      "active",
		Protocol:    serverProtocol(server),
		Host:        server.Host,
		Port:        serverPort(server),
		Group:       server.Group,
		Description: server.Description,
		Metadata: map[string]any{
			"source":   "server_create",
			"ssh_port": server.SSHPort,
			"rdp_port": server.RDPPort,
			"os":       server.OS,
		},
		CreatedAt: server.CreatedAt,
		UpdatedAt: server.UpdatedAt,
	})
	return server, nil
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
	if err := s.saveLocked(); err != nil {
		return model.CredentialPublic{}, err
	}
	_, _ = s.createPlatformItem("credentials", model.PlatformItem{
		ID:          credential.ID,
		Name:        credential.Name,
		Type:        string(credential.Type),
		Status:      "encrypted",
		Username:    credential.Username,
		TargetID:    credential.ServerID,
		Description: "服务端加密保存的授权凭证。",
		Metadata:    map[string]any{"domain": credential.Domain},
		CreatedAt:   credential.CreatedAt,
		UpdatedAt:   credential.UpdatedAt,
	})
	return credential.Public(), nil
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
	if err := s.saveLocked(); err != nil {
		return model.ConnectionSession{}, err
	}
	_, _ = s.createPlatformItem("online_sessions", sessionPlatformItem("online_sessions", session))
	return session, nil
}

func (s *Store) GetSession(id string) (model.ConnectionSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.state.Sessions[id]
	return session, ok
}

func (s *Store) DeleteSession(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.state.Sessions[id]; !ok {
		return os.ErrNotExist
	}
	delete(s.state.Sessions, id)
	if err := s.saveLocked(); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM platform_records WHERE id = ? AND collection IN (?, ?)`, id, "online_sessions", "offline_sessions"); err != nil {
		return fmt.Errorf("delete session platform records: %w", err)
	}
	return nil
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
	if err := s.saveLocked(); err != nil {
		return model.ConnectionSession{}, err
	}
	collection := "offline_sessions"
	if session.Status == model.SessionActive || session.Status == model.SessionPending {
		collection = "online_sessions"
	}
	_, _ = s.createPlatformItem(collection, sessionPlatformItem(collection, session))
	if collection == "offline_sessions" {
		_ = s.DeletePlatformItem("online_sessions", session.ID)
	}
	return session, nil
}

func (s *Store) CloseSession(id, reason string) (model.ConnectionSession, error) {
	now := time.Now().UTC()
	session, err := s.UpdateSession(id, func(session *model.ConnectionSession) {
		session.Status = model.SessionClosed
		session.EndedAt = &now
		if reason != "" {
			session.Error = reason
		}
	})
	if err != nil {
		return model.ConnectionSession{}, err
	}
	_, _ = s.createPlatformItem("offline_sessions", sessionPlatformItem("offline_sessions", session))
	_ = s.DeletePlatformItem("online_sessions", session.ID)
	return session, nil
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
	if err := s.saveLocked(); err != nil {
		return err
	}
	_, _ = s.createPlatformItem("operation_logs", model.PlatformItem{
		ID:          log.ID,
		Name:        log.Action,
		Type:        string(log.Protocol),
		Status:      "recorded",
		OwnerID:     log.UserID,
		TargetID:    log.TargetID,
		Description: log.Detail,
		Metadata:    map[string]any{"client_ip": log.ClientIP},
		CreatedAt:   log.CreatedAt,
		UpdatedAt:   log.CreatedAt,
	})
	return nil
}

func sessionPlatformItem(collection string, session model.ConnectionSession) model.PlatformItem {
	return model.PlatformItem{
		ID:          session.ID,
		Module:      collection,
		Name:        session.ID,
		Type:        string(session.Protocol),
		Status:      string(session.Status),
		Protocol:    session.Protocol,
		OwnerID:     session.UserID,
		TargetID:    session.ServerID,
		Description: session.Error,
		Metadata: map[string]any{
			"credential_id":         session.CredentialID,
			"client_ip":             session.ClientIP,
			"recording_path":        session.RecordingPath,
			"recording_size":        session.RecordingSize,
			"gateway_group_id":      session.GatewayGroupID,
			"gateway_id":            session.GatewayID,
			"gateway_name":          session.GatewayName,
			"gateway_collection":    session.GatewayCollection,
			"workspace_width":       session.Width,
			"workspace_height":      session.Height,
			"workspace_dpi":         session.DPI,
			"color_depth":           session.ColorDepth,
			"resize_method":         session.ResizeMethod,
			"clipboard_enabled":     optionalBoolValue(session.ClipboardEnabled),
			"file_transfer_enabled": optionalBoolValue(session.FileTransferEnabled),
			"ignore_cert":           optionalBoolValue(session.IgnoreCert),
			"read_only":             optionalBoolValue(session.ReadOnly),
			"watermark_enabled":     optionalBoolValue(session.WatermarkEnabled),
			"watermark_text":        session.WatermarkText,
			"watermark_color":       session.WatermarkColor,
			"watermark_font_size":   session.WatermarkFontSize,
			"started_at":            session.StartedAt,
			"ended_at":              session.EndedAt,
		},
		CreatedAt: session.StartedAt,
		UpdatedAt: session.LastActivityAt,
	}
}

func optionalBoolValue(value *bool) any {
	if value == nil {
		return nil
	}
	return *value
}

func (s *Store) syncCoreStateLocked() error {
	if s.db == nil {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM core_records`); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("clear core records: %w", err)
	}
	stmt, err := tx.Prepare(`INSERT INTO core_records(kind, id, payload, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("prepare core record sync: %w", err)
	}
	insert := func(kind, id string, payload any, createdAt, updatedAt time.Time) error {
		if id == "" {
			return nil
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if createdAt.IsZero() {
			createdAt = time.Now().UTC()
		}
		if updatedAt.IsZero() {
			updatedAt = createdAt
		}
		_, err = stmt.Exec(kind, id, string(raw), createdAt.Format(time.RFC3339Nano), updatedAt.Format(time.RFC3339Nano))
		return err
	}
	if s.state.Admin != nil {
		if err := insert("admin", s.state.Admin.UserID, s.state.Admin, s.state.Admin.CreatedAt, s.state.Admin.UpdatedAt); err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			return fmt.Errorf("sync admin core record: %w", err)
		}
	}
	for _, server := range s.state.Servers {
		if err := insert("servers", server.ID, server, server.CreatedAt, server.UpdatedAt); err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			return fmt.Errorf("sync server core record: %w", err)
		}
	}
	for _, credential := range s.state.Credentials {
		if err := insert("credentials", credential.ID, credential, credential.CreatedAt, credential.UpdatedAt); err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			return fmt.Errorf("sync credential core record: %w", err)
		}
	}
	for _, session := range s.state.Sessions {
		if err := insert("sessions", session.ID, session, session.StartedAt, session.LastActivityAt); err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			return fmt.Errorf("sync session core record: %w", err)
		}
	}
	for _, log := range s.state.AuditLogs {
		if err := insert("audit_logs", log.ID, log, log.CreatedAt, log.CreatedAt); err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			return fmt.Errorf("sync audit core record: %w", err)
		}
	}
	if err := stmt.Close(); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit core record sync: %w", err)
	}
	return nil
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	if err := s.syncCoreStateLocked(); err != nil {
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
	return replaceFile(tmp, s.path)
}

func replaceFile(tmp, target string) error {
	backup := target + ".bak"
	if _, err := os.Stat(target); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return os.Rename(tmp, target)
		}
		return err
	}
	_ = os.Remove(backup)
	if err := os.Rename(target, backup); err != nil {
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Rename(backup, target)
		return err
	}
	_ = os.Remove(backup)
	return nil
}

func newID(prefix string) string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
	}
	return prefix + "_" + hex.EncodeToString(buf)
}
