package app

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"openwebservermanager/internal/model"

	"github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type databaseSQLExecutionOptions struct {
	Source        string
	LogType       string
	LogName       string
	TargetID      string
	WorkOrderID   string
	Reason        string
	ExtraMetadata map[string]any
}

type sqlWorkOrderRequest struct {
	SQL          string `json:"sql"`
	Reason       string `json:"reason"`
	MFACode      string `json:"mfa_code"`
	RecoveryCode string `json:"recovery_code"`
}

type databaseAssetConnection struct {
	Driver   string
	DSN      string
	Name     string
	Username string
}

type databaseAssetSecret struct {
	Username string
	Password string
}

func (s *Server) handleDatabaseAssetQuery(w http.ResponseWriter, r *http.Request, asset model.PlatformItem, userID string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req sqlExecuteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !s.requireAccessMFA(w, r, accessMFAInput{MFACode: req.MFACode, RecoveryCode: req.RecoveryCode}) {
		return
	}
	sqlText := strings.TrimSpace(req.SQL)
	if sqlText == "" {
		writeError(w, http.StatusBadRequest, "sql is required")
		return
	}
	logItem, statusCode, err := s.executeDatabaseAssetSQL(r, asset, userID, sqlText, databaseSQLExecutionOptions{
		Source:  "access_portal",
		LogType: "database_access",
	})
	if err != nil {
		writeError(w, statusCode, err.Error())
		return
	}
	_ = s.audit(r, "access.database.query", asset.ID, model.ProtocolDatabase, logItem.Description)
	writeJSON(w, statusCode, logItem)
}

func (s *Server) handleDatabaseWorkOrderCreate(w http.ResponseWriter, r *http.Request, asset model.PlatformItem, userID string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req sqlWorkOrderRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !s.requireAccessMFA(w, r, accessMFAInput{MFACode: req.MFACode, RecoveryCode: req.RecoveryCode}) {
		return
	}
	sqlText := strings.TrimSpace(req.SQL)
	if sqlText == "" {
		writeError(w, http.StatusBadRequest, "sql is required")
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "requested from access portal"
	}
	item, err := s.cfg.Store.CreatePlatformItem("sql_work_orders", model.PlatformItemRequest{
		Name:        fmt.Sprintf("%s SQL request", asset.Name),
		Type:        "database_access",
		Status:      "pending",
		Protocol:    model.ProtocolDatabase,
		TargetID:    asset.ID,
		OwnerID:     userID,
		Description: reason,
		Metadata: map[string]any{
			"sql":          sqlText,
			"reason":       reason,
			"asset_id":     asset.ID,
			"asset_name":   asset.Name,
			"client_ip":    s.clientIP(r),
			"source":       "access_portal",
			"requested_by": userID,
			"requested_at": time.Now().UTC(),
		},
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "sql_work_order.request", item.ID, model.ProtocolDatabase, "created sql work order")
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) executeDatabaseAssetSQL(r *http.Request, asset model.PlatformItem, userID, sqlText string, opts databaseSQLExecutionOptions) (model.PlatformItem, int, error) {
	connection, err := s.databaseAssetConnection(asset)
	if err != nil {
		return model.PlatformItem{}, http.StatusBadRequest, err
	}
	db, err := sql.Open(connection.Driver, connection.DSN)
	if err != nil {
		return model.PlatformItem{}, http.StatusInternalServerError, err
	}
	defer db.Close()

	start := time.Now()
	status := "success"
	detail := "executed"
	var rowsAffected int64
	rowLimit := 100
	if configured, ok := metadataInt(asset.Metadata["row_limit"]); ok {
		rowLimit = clampInt(configured, 1, 1000, 100)
	}
	metadata := map[string]any{
		"sql":         sqlText,
		"database":    connection.Name,
		"asset_id":    asset.ID,
		"asset_name":  asset.Name,
		"client_ip":   s.clientIP(r),
		"source":      valueOrDefault(opts.Source, "access_portal"),
		"driver":      connection.Driver,
		"db_username": connection.Username,
		"row_limit":   rowLimit,
	}
	if opts.WorkOrderID != "" {
		metadata["work_order_id"] = opts.WorkOrderID
	}
	if opts.Reason != "" {
		metadata["reason"] = opts.Reason
	}
	for key, value := range opts.ExtraMetadata {
		metadata[key] = value
	}
	if isSQLQuery(sqlText) {
		queryRows, err := db.Query(sqlText)
		if err != nil {
			status = "failed"
			detail = err.Error()
		} else {
			rows, columns, truncated, err := scanSQLRows(queryRows, rowLimit)
			if err != nil {
				status = "failed"
				detail = err.Error()
			} else {
				detail = "queried"
				rowsAffected = int64(len(rows))
				metadata["columns"] = columns
				metadata["rows"] = rows
				metadata["truncated"] = truncated
			}
		}
	} else {
		result, err := db.Exec(sqlText)
		if err != nil {
			status = "failed"
			detail = err.Error()
		} else if result != nil {
			rowsAffected, _ = result.RowsAffected()
		}
	}
	metadata["rows_affected"] = rowsAffected
	metadata["duration_ms"] = time.Since(start).Milliseconds()
	logTargetID := opts.TargetID
	if logTargetID == "" {
		logTargetID = asset.ID
	}
	logName := strings.TrimSpace(opts.LogName)
	if logName == "" {
		logName = asset.Name
	}
	logType := strings.TrimSpace(opts.LogType)
	if logType == "" {
		logType = "database_access"
	}
	logItem, logErr := s.cfg.Store.CreatePlatformItem("sql_logs", model.PlatformItemRequest{
		Name:        logName,
		Type:        logType,
		Status:      status,
		Protocol:    model.ProtocolDatabase,
		TargetID:    logTargetID,
		OwnerID:     userID,
		Description: detail,
		Metadata:    metadata,
	})
	if logErr != nil {
		return model.PlatformItem{}, http.StatusInternalServerError, logErr
	}
	if status == "failed" {
		return logItem, http.StatusBadRequest, nil
	}
	return logItem, http.StatusOK, nil
}

func (s *Server) databaseAssetConnection(asset model.PlatformItem) (databaseAssetConnection, error) {
	rawAsset := asset
	if asset.ID != "" {
		item, ok, err := s.cfg.Store.GetPlatformItem("database_assets", asset.ID)
		if err != nil {
			return databaseAssetConnection{}, err
		}
		if ok {
			rawAsset = item
		}
	}
	if err := s.decryptDatabaseAssetDSN(&rawAsset); err != nil {
		return databaseAssetConnection{}, err
	}
	secret, err := s.databaseAssetSecret(rawAsset)
	if err != nil {
		return databaseAssetConnection{}, err
	}
	driver, dsn, err := databaseAssetDriverAndDSN(s.cfg.DataDir, rawAsset, secret)
	if err != nil {
		return databaseAssetConnection{}, err
	}
	username := secret.Username
	if username == "" {
		username = rawAsset.Username
	}
	return databaseAssetConnection{
		Driver:   driver,
		DSN:      dsn,
		Name:     databaseAssetName(rawAsset, dsn),
		Username: username,
	}, nil
}

func (s *Server) decryptDatabaseAssetDSN(asset *model.PlatformItem) error {
	encrypted := firstMetadataString(asset.Metadata, "database_dsn_encrypted")
	if encrypted == "" {
		return nil
	}
	dsn, err := s.cfg.Store.DecryptPlatformSecret(encrypted)
	if err != nil {
		return err
	}
	nextMetadata := map[string]any{}
	for key, value := range asset.Metadata {
		nextMetadata[key] = value
	}
	nextMetadata["dsn"] = dsn
	asset.Metadata = nextMetadata
	return nil
}

func (s *Server) databaseAssetSecret(asset model.PlatformItem) (databaseAssetSecret, error) {
	secret := databaseAssetSecret{Username: strings.TrimSpace(asset.Username)}
	credentialID := firstMetadataString(asset.Metadata, "credential_id", "credentialId", "credential")
	if credentialID == "" {
		return secret, nil
	}
	credential, credentialSecret, ok, err := s.cfg.Store.GetPlatformCredentialSecret(credentialID)
	if err != nil {
		return databaseAssetSecret{}, err
	}
	if !ok {
		return databaseAssetSecret{}, fmt.Errorf("database credential %s not found", credentialID)
	}
	if !platformCredentialEnabled(credential) {
		return databaseAssetSecret{}, fmt.Errorf("database credential %s is disabled", credentialID)
	}
	if !databaseCredentialCompatible(credential) {
		return databaseAssetSecret{}, fmt.Errorf("database credential %s is not compatible with database assets", credentialID)
	}
	if credential.Username != "" {
		secret.Username = credential.Username
	}
	secret.Password = credentialSecret.Password
	return secret, nil
}

func databaseCredentialCompatible(credential model.PlatformItem) bool {
	switch strings.ToLower(strings.TrimSpace(credential.Type)) {
	case string(model.CredentialDatabase), "database":
		return true
	default:
		return false
	}
}

func databaseAssetDriverAndDSN(dataDir string, asset model.PlatformItem, secret databaseAssetSecret) (string, string, error) {
	driver := strings.ToLower(strings.TrimSpace(asset.Type))
	if value, ok := asset.Metadata["driver"].(string); ok && strings.TrimSpace(value) != "" {
		driver = strings.ToLower(strings.TrimSpace(value))
	}
	if driver == "" || driver == "database" {
		driver = "sqlite"
	}
	switch driver {
	case "sqlite", "sqlite3":
		dsn, err := databaseAssetSQLitePath(dataDir, asset)
		return "sqlite", dsn, err
	case "mysql", "mariadb":
		dsn, err := databaseAssetMySQLDSN(asset, secret)
		return "mysql", dsn, err
	case "postgres", "postgresql", "pgx":
		dsn, err := databaseAssetPostgresDSN(asset, secret)
		return "pgx", dsn, err
	default:
		return "", "", fmt.Errorf("unsupported database driver: %s", driver)
	}
}

func databaseAssetSQLitePath(dataDir string, asset model.PlatformItem) (string, error) {
	raw := firstMetadataString(asset.Metadata, "sqlite_path", "dsn", "database", "path")
	if raw == "" {
		raw = strings.TrimSpace(asset.Host)
	}
	if raw == "" {
		raw = asset.ID + ".db"
	}
	if strings.HasPrefix(strings.ToLower(raw), "file:") {
		raw = strings.TrimPrefix(raw, "file:")
	}
	if strings.Contains(raw, "://") {
		return "", errors.New("sqlite database path must be a local relative path")
	}
	clean := filepath.Clean(filepath.FromSlash(raw))
	if clean == "." || clean == string(filepath.Separator) {
		clean = asset.ID + ".db"
	}
	if filepath.IsAbs(clean) {
		return "", errors.New("sqlite database path must be relative to data/database-assets")
	}
	root := filepath.Join(dataDir, "database-assets")
	target := filepath.Join(root, clean)
	if err := ensureChildPath(root, target); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o770); err != nil {
		return "", err
	}
	return target, nil
}

func databaseAssetMySQLDSN(asset model.PlatformItem, secret databaseAssetSecret) (string, error) {
	if dsn := firstMetadataString(asset.Metadata, "dsn", "connection_string", "connectionString", "url"); dsn != "" {
		return dsn, nil
	}
	host, port, err := databaseAssetHostPort(asset, 3306)
	if err != nil {
		return "", err
	}
	database := firstMetadataString(asset.Metadata, "database", "db_name", "dbName", "dbname", "schema")
	username := valueOrDefault(secret.Username, asset.Username)
	cfg := mysql.NewConfig()
	cfg.User = username
	cfg.Passwd = secret.Password
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(host, strconv.Itoa(port))
	cfg.DBName = database
	cfg.ParseTime = true
	cfg.Params = map[string]string{"charset": valueOrDefault(firstMetadataString(asset.Metadata, "charset"), "utf8mb4")}
	if timeout := firstMetadataString(asset.Metadata, "timeout", "connect_timeout"); timeout != "" {
		cfg.Params["timeout"] = timeout
	}
	return cfg.FormatDSN(), nil
}

func databaseAssetPostgresDSN(asset model.PlatformItem, secret databaseAssetSecret) (string, error) {
	if dsn := firstMetadataString(asset.Metadata, "dsn", "connection_string", "connectionString", "url"); dsn != "" {
		return dsn, nil
	}
	host, port, err := databaseAssetHostPort(asset, 5432)
	if err != nil {
		return "", err
	}
	database := firstMetadataString(asset.Metadata, "database", "db_name", "dbName", "dbname")
	if database == "" {
		database = "postgres"
	}
	username := valueOrDefault(secret.Username, asset.Username)
	endpoint := url.URL{
		Scheme: "postgres",
		Host:   net.JoinHostPort(host, strconv.Itoa(port)),
		Path:   "/" + database,
	}
	if username != "" {
		if secret.Password != "" {
			endpoint.User = url.UserPassword(username, secret.Password)
		} else {
			endpoint.User = url.User(username)
		}
	}
	query := endpoint.Query()
	query.Set("sslmode", valueOrDefault(firstMetadataString(asset.Metadata, "sslmode", "ssl_mode"), "disable"))
	if appName := firstMetadataString(asset.Metadata, "application_name", "applicationName"); appName != "" {
		query.Set("application_name", appName)
	}
	endpoint.RawQuery = query.Encode()
	return endpoint.String(), nil
}

func databaseAssetHostPort(asset model.PlatformItem, defaultPort int) (string, int, error) {
	host := firstMetadataString(asset.Metadata, "host", "hostname", "address")
	if host == "" {
		host = strings.TrimSpace(asset.Host)
	}
	port := asset.Port
	if configured, ok := metadataInt(asset.Metadata["port"]); ok {
		port = configured
	}
	if host == "" {
		return "", 0, errors.New("database host is required")
	}
	if port == 0 {
		if parsedHost, parsedPort, ok := splitHostPortLoose(host); ok {
			host = parsedHost
			port = parsedPort
		}
	}
	if port == 0 {
		port = defaultPort
	}
	return host, port, nil
}

func splitHostPortLoose(value string) (string, int, bool) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		if strings.Count(value, ":") != 1 {
			return "", 0, false
		}
		parts := strings.SplitN(value, ":", 2)
		host, portText = parts[0], parts[1]
	}
	port, err := strconv.Atoi(portText)
	if err != nil || strings.TrimSpace(host) == "" {
		return "", 0, false
	}
	return strings.Trim(host, "[]"), port, true
}

func databaseAssetName(asset model.PlatformItem, dsn string) string {
	if value := firstMetadataString(asset.Metadata, "database", "name"); value != "" {
		return value
	}
	if asset.Host != "" {
		return asset.Host
	}
	if asset.Name != "" {
		return asset.Name
	}
	if parsed, err := url.Parse(dsn); err == nil && parsed.Host != "" {
		if path := strings.Trim(strings.TrimSpace(parsed.Path), "/"); path != "" {
			return path
		}
		return parsed.Host
	}
	return filepath.Base(dsn)
}

func firstMetadataString(metadata map[string]any, keys ...string) string {
	for _, key := range keys {
		values := metadataStrings(metadata[key])
		if len(values) == 0 {
			continue
		}
		value := strings.TrimSpace(values[0])
		if value != "" {
			return value
		}
	}
	return ""
}

func metadataInt(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case float64:
		return int(typed), true
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		return parsed, err == nil
	default:
		return 0, false
	}
}

func valueOrDefault(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
