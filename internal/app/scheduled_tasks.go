package app

import (
	"archive/zip"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"openwebservermanager/internal/model"
)

func (s *Server) runScheduledTask(_ *http.Request, task model.PlatformItem) (string, map[string]any, error) {
	switch normalizeScheduledTaskType(task.Type) {
	case "backup":
		metadata, err := s.createBackupSnapshot()
		return "backup completed", metadata, err
	case "log-cleanup":
		metadata, err := s.cleanupHistoryLogs(task)
		return "log cleanup completed", metadata, err
	case "asset-status":
		metadata, err := s.checkAssetStatuses(task)
		return "asset status check completed", metadata, err
	case "certificate-renewal":
		metadata, err := s.renewDueSelfSignedCertificates(task)
		return "certificate renewal completed", metadata, err
	default:
		return "task type recorded", map[string]any{"supported": false, "message": "task type has no runner yet"}, nil
	}
}

func normalizeScheduledTaskType(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "_", "-")
	return value
}

func (s *Server) createBackupSnapshot() (map[string]any, error) {
	backupDir := filepath.Join(s.cfg.DataDir, "backups")
	if err := os.MkdirAll(backupDir, 0o770); err != nil {
		return nil, err
	}
	name := "backup-" + time.Now().UTC().Format("20060102-150405-000000000") + ".zip"
	target := filepath.Join(backupDir, name)
	output, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o660)
	if err != nil {
		return nil, err
	}
	archive := zip.NewWriter(output)
	files := []string{}
	storePath := s.cfg.Store.Path()
	if err := addBackupFile(archive, storePath, filepath.Base(storePath)); err == nil {
		files = append(files, filepath.Base(storePath))
	} else if !errors.Is(err, os.ErrNotExist) {
		_ = archive.Close()
		_ = output.Close()
		return nil, err
	}
	dbPath := strings.TrimSuffix(storePath, filepath.Ext(storePath)) + ".db"
	if err := addBackupFile(archive, dbPath, filepath.Base(dbPath)); err == nil {
		files = append(files, filepath.Base(dbPath))
	} else if !errors.Is(err, os.ErrNotExist) {
		_ = archive.Close()
		_ = output.Close()
		return nil, err
	}
	manifest := map[string]any{"created_at": time.Now().UTC(), "files": files}
	manifestWriter, err := archive.Create("manifest.json")
	if err != nil {
		_ = archive.Close()
		_ = output.Close()
		return nil, err
	}
	_ = json.NewEncoder(manifestWriter).Encode(manifest)
	if err := archive.Close(); err != nil {
		_ = output.Close()
		return nil, err
	}
	if err := output.Close(); err != nil {
		return nil, err
	}
	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"backup_path": filepath.ToSlash(target),
		"backup_size": info.Size(),
		"files":       files,
	}, nil
}

func addBackupFile(archive *zip.Writer, source, name string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	writer, err := archive.Create(name)
	if err != nil {
		return err
	}
	_, err = io.Copy(writer, input)
	return err
}

func (s *Server) cleanupHistoryLogs(task model.PlatformItem) (map[string]any, error) {
	settings := s.retentionSettings()
	collections := []string{"login_logs", "operation_logs", "file_logs", "access_logs", "sql_logs", "exec_command_logs", "offline_sessions"}
	deletedByCollection := map[string]int{}
	totalDeleted := 0
	now := time.Now().UTC()
	for _, collection := range collections {
		days := retentionDaysForCollection(collection, task.Metadata, settings, 90)
		cutoff := now.AddDate(0, 0, -days)
		items, err := s.cfg.Store.ListPlatformItems(collection)
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			if item.CreatedAt.IsZero() || item.CreatedAt.After(cutoff) {
				continue
			}
			if err := s.cfg.Store.DeletePlatformItem(collection, item.ID); err != nil {
				return nil, err
			}
			deletedByCollection[collection]++
			totalDeleted++
		}
	}
	return map[string]any{
		"deleted_count": totalDeleted,
		"deleted":       deletedByCollection,
	}, nil
}

func (s *Server) retentionSettings() map[string]any {
	items, err := s.cfg.Store.ListPlatformItems("system_settings")
	if err != nil {
		return nil
	}
	for _, item := range items {
		if strings.EqualFold(item.Type, "retention") {
			return item.Metadata
		}
	}
	return nil
}

func retentionDaysForCollection(collection string, taskMetadata, settings map[string]any, fallback int) int {
	keys := []string{collection + "_days", strings.TrimSuffix(collection, "_logs") + "_days", "retention_days", "days"}
	for _, key := range keys {
		if value, ok := metadataInt(taskMetadata[key]); ok {
			return maxInt(value, 0)
		}
	}
	for _, key := range keys {
		if value, ok := metadataInt(settings[key]); ok {
			return maxInt(value, 0)
		}
	}
	return fallback
}

func (s *Server) checkAssetStatuses(task model.PlatformItem) (map[string]any, error) {
	timeout := time.Duration(clampInt(metadataIntDefault(task.Metadata["timeout_ms"], 2000), 100, 30000, 2000)) * time.Millisecond
	collections := []string{"assets", "web_assets", "database_assets"}
	checked := 0
	active := 0
	offline := 0
	skipped := 0
	results := []map[string]any{}
	now := time.Now().UTC()
	for _, collection := range collections {
		items, err := s.cfg.Store.ListPlatformItems(collection)
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			if strings.EqualFold(strings.TrimSpace(item.Status), "disabled") {
				skipped++
				continue
			}
			checked++
			started := time.Now()
			status, detail := s.checkAssetReachability(collection, item, timeout)
			latency := time.Since(started).Milliseconds()
			if status == "active" {
				active++
			} else {
				offline++
			}
			nextMetadata := map[string]any{}
			for key, value := range item.Metadata {
				nextMetadata[key] = value
			}
			nextMetadata["last_check_at"] = now
			nextMetadata["last_check_status"] = status
			nextMetadata["last_check_detail"] = detail
			nextMetadata["last_check_latency_ms"] = latency
			_, err := s.cfg.Store.UpdatePlatformItem(collection, item.ID, model.PlatformItemRequest{
				Status:   status,
				Metadata: nextMetadata,
			})
			if err != nil {
				return nil, err
			}
			results = append(results, map[string]any{
				"id":         item.ID,
				"name":       item.Name,
				"collection": collection,
				"status":     status,
				"detail":     detail,
				"latency_ms": latency,
			})
		}
	}
	return map[string]any{
		"checked": checked,
		"active":  active,
		"offline": offline,
		"skipped": skipped,
		"results": results,
	}, nil
}

func (s *Server) checkAssetReachability(collection string, item model.PlatformItem, timeout time.Duration) (string, string) {
	switch collection {
	case "web_assets":
		target, err := webAssetTargetURL(item)
		if err != nil {
			return "offline", err.Error()
		}
		client := http.Client{Timeout: timeout}
		req, err := http.NewRequest(http.MethodHead, target.String(), nil)
		if err != nil {
			return "offline", err.Error()
		}
		resp, err := client.Do(req)
		if err != nil {
			return "offline", err.Error()
		}
		defer resp.Body.Close()
		if resp.StatusCode >= http.StatusInternalServerError {
			return "offline", resp.Status
		}
		return "active", resp.Status
	case "database_assets":
		connection, err := s.databaseAssetConnection(item)
		if err != nil {
			return "offline", err.Error()
		}
		db, err := sql.Open(connection.Driver, connection.DSN)
		if err != nil {
			return "offline", err.Error()
		}
		defer db.Close()
		if err := db.Ping(); err != nil {
			return "offline", err.Error()
		}
		return "active", connection.Driver
	default:
		host := strings.TrimSpace(item.Host)
		if host == "" {
			return "offline", "host is empty"
		}
		port := item.Port
		if port == 0 {
			port = defaultProtocolPort(item.Protocol)
		}
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), timeout)
		if err != nil {
			return "offline", err.Error()
		}
		_ = conn.Close()
		return "active", fmt.Sprintf("%s:%d reachable", host, port)
	}
}

func defaultProtocolPort(protocol model.Protocol) int {
	switch protocol {
	case model.ProtocolRDP:
		return 3389
	case model.ProtocolVNC:
		return 5900
	default:
		return 22
	}
}

func (s *Server) renewDueSelfSignedCertificates(task model.PlatformItem) (map[string]any, error) {
	items, err := s.cfg.Store.ListPlatformItems("certificates")
	if err != nil {
		return nil, err
	}
	renewBeforeDays := metadataIntDefault(task.Metadata["renew_before_days"], metadataIntDefault(task.Metadata["renewal_days"], 30))
	validityDays := metadataIntDefault(task.Metadata["validity_days"], 365)
	threshold := time.Now().UTC().Add(time.Duration(maxInt(renewBeforeDays, 0)) * 24 * time.Hour)
	renewed := 0
	skipped := 0
	results := []map[string]any{}
	for _, item := range items {
		if !strings.EqualFold(item.Type, "self-signed") {
			skipped++
			continue
		}
		expiresAt, ok := metadataTime(item.Metadata["expires_at"])
		if ok && expiresAt.After(threshold) {
			skipped++
			continue
		}
		domain := firstMetadataString(item.Metadata, "domain", "common_name")
		if domain == "" {
			domain = item.Name
		}
		if strings.TrimSpace(domain) == "" {
			skipped++
			continue
		}
		certPEM, keyPEM, err := makeSelfSignedCertificate(certificateRequest{
			Domain: domain,
			DNS:    metadataStrings(item.Metadata["dns"]),
			IP:     metadataStrings(item.Metadata["ip"]),
			Days:   validityDays,
		})
		if err != nil {
			return nil, err
		}
		nextMetadata := map[string]any{}
		for key, value := range item.Metadata {
			nextMetadata[key] = value
		}
		nextExpiresAt := time.Now().UTC().Add(time.Duration(clampInt(validityDays, 1, 3650, 365)) * 24 * time.Hour)
		nextMetadata["domain"] = domain
		nextMetadata["certificate"] = string(certPEM)
		nextMetadata["private_key"] = string(keyPEM)
		nextMetadata["previous_expires_at"] = expiresAt
		nextMetadata["expires_at"] = nextExpiresAt
		nextMetadata["renewed_at"] = time.Now().UTC()
		_, err = s.cfg.Store.UpdatePlatformItem("certificates", item.ID, model.PlatformItemRequest{
			Status:   "issued",
			Metadata: nextMetadata,
		})
		if err != nil {
			return nil, err
		}
		renewed++
		results = append(results, map[string]any{"id": item.ID, "name": item.Name, "domain": domain, "expires_at": nextExpiresAt})
	}
	return map[string]any{
		"renewed_count": renewed,
		"skipped_count": skipped,
		"results":       results,
	}, nil
}

func metadataIntDefault(value any, fallback int) int {
	if parsed, ok := metadataInt(value); ok {
		return parsed
	}
	return fallback
}

func maxInt(value, minimum int) int {
	if value < minimum {
		return minimum
	}
	return value
}
