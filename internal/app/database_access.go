package app

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"openwebservermanager/internal/model"
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
	SQL    string `json:"sql"`
	Reason string `json:"reason"`
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
	driver, dsn, err := databaseAssetDriverAndDSN(s.cfg.DataDir, asset)
	if err != nil {
		return model.PlatformItem{}, http.StatusBadRequest, err
	}
	db, err := sql.Open(driver, dsn)
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
		"database":    databaseAssetName(asset, dsn),
		"asset_id":    asset.ID,
		"asset_name":  asset.Name,
		"client_ip":   s.clientIP(r),
		"source":      valueOrDefault(opts.Source, "access_portal"),
		"driver":      driver,
		"db_username": asset.Username,
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

func databaseAssetDriverAndDSN(dataDir string, asset model.PlatformItem) (string, string, error) {
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
	default:
		return "", "", errors.New("only sqlite database assets are supported in this build")
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

func databaseAssetName(asset model.PlatformItem, dsn string) string {
	if value := firstMetadataString(asset.Metadata, "database", "name"); value != "" {
		return value
	}
	if asset.Host != "" {
		return asset.Host
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
