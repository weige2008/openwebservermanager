package app

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"openwebservermanager/internal/model"
)

const maxBackupUploadBytes = 512 << 20

var errBackupSpecialFile = errors.New("backup path is not a regular file")

type backupInfo struct {
	Name     string         `json:"name"`
	Size     int64          `json:"size"`
	Modified time.Time      `json:"modified_at"`
	Manifest map[string]any `json:"manifest,omitempty"`
	Files    []string       `json:"files,omitempty"`
}

type backupRetentionResult struct {
	RetentionDays int      `json:"retention_days"`
	Deleted       []string `json:"deleted,omitempty"`
	DeletedCount  int      `json:"deleted_count"`
}

type restoreArchive struct {
	LegacyRaw []byte
	SQLiteDB  string
	Manifest  map[string]any
	Files     []string
}

func (s *Server) handleBackups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.listBackups()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		metadata, err := s.createBackupSnapshot()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		backupPath, _ := metadata["backup_path"].(string)
		if err := s.createOperationLog(r, model.PlatformItemRequest{
			Name:        "backup.create",
			Type:        "backup",
			Status:      "success",
			OwnerID:     s.currentUserID(r),
			Description: "created backup snapshot",
			Metadata:    map[string]any{"client_ip": s.clientIP(r), "backup": filepath.Base(backupPath), "backup_path": backupPath},
		}); err != nil {
			if backupPath != "" {
				_ = os.Remove(filepath.FromSlash(backupPath))
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.audit(r, "backup.create", "backups", "", "created backup snapshot")
		writeJSON(w, http.StatusCreated, metadata)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleBackupDownload(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	path, err := s.backupFilePath(name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	info, err := backupRegularFileInfo(path)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "backup not found")
		return
	} else if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.createOperationLog(r, model.PlatformItemRequest{
		Name:        "backup.download",
		Type:        "backup",
		Status:      "success",
		OwnerID:     s.currentUserID(r),
		Description: "downloaded backup archive",
		Metadata:    map[string]any{"backup": name, "size": info.Size(), "client_ip": s.clientIP(r)},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "backup.download", name, "", "downloaded backup")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(path)+"\"")
	http.ServeFile(w, r, path)
}

func (s *Server) handleBackupDelete(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	path, err := s.backupFilePath(name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	info, err := backupRegularFileInfo(path)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "backup not found")
		return
	} else if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.createOperationLog(r, model.PlatformItemRequest{
		Name:        "backup.delete",
		Type:        "backup",
		Status:      "success",
		OwnerID:     s.currentUserID(r),
		Description: "deleted backup archive",
		Metadata:    map[string]any{"backup": name, "size": info.Size(), "client_ip": s.clientIP(r)},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := os.Remove(path); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "backup.delete", name, "", "deleted backup")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": name})
}

func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBackupUploadBytes)
	if err := r.ParseMultipartForm(maxBackupUploadBytes); err != nil {
		s.writeBackupRestoreFailure(w, r, http.StatusBadRequest, "invalid backup upload: "+err.Error(), nil)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		s.writeBackupRestoreFailure(w, r, http.StatusBadRequest, "backup file is required", nil)
		return
	}
	defer file.Close()
	if header.Size <= 0 {
		s.writeBackupRestoreFailure(w, r, http.StatusBadRequest, "backup file is empty", backupRestoreUploadMetadata(header.Filename, header.Size, 0))
		return
	}
	tempDir, err := os.MkdirTemp(s.cfg.DataDir, "restore-*")
	if err != nil {
		s.writeBackupRestoreFailure(w, r, http.StatusInternalServerError, err.Error(), backupRestoreUploadMetadata(header.Filename, header.Size, 0))
		return
	}
	defer os.RemoveAll(tempDir)
	uploadPath := filepath.Join(tempDir, "upload.zip")
	output, err := os.OpenFile(uploadPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		s.writeBackupRestoreFailure(w, r, http.StatusInternalServerError, err.Error(), backupRestoreUploadMetadata(header.Filename, header.Size, 0))
		return
	}
	written, copyErr := io.Copy(output, file)
	closeErr := output.Close()
	if copyErr != nil {
		s.writeBackupRestoreFailure(w, r, http.StatusBadRequest, "write backup upload: "+copyErr.Error(), backupRestoreUploadMetadata(header.Filename, header.Size, written))
		return
	}
	if closeErr != nil {
		s.writeBackupRestoreFailure(w, r, http.StatusInternalServerError, closeErr.Error(), backupRestoreUploadMetadata(header.Filename, header.Size, written))
		return
	}
	if written <= 0 || written > maxBackupUploadBytes {
		s.writeBackupRestoreFailure(w, r, http.StatusBadRequest, "backup upload size is invalid", backupRestoreUploadMetadata(header.Filename, header.Size, written))
		return
	}
	archive, err := readRestoreArchive(uploadPath, tempDir)
	if err != nil {
		s.writeBackupRestoreFailure(w, r, http.StatusBadRequest, err.Error(), backupRestoreUploadMetadata(header.Filename, header.Size, written))
		return
	}
	if isTruthy(r.URL.Query().Get("dry_run")) || isTruthy(r.FormValue("dry_run")) {
		if err := s.createOperationLog(r, model.PlatformItemRequest{
			Name:        "backup.restore.validate",
			Type:        "backup",
			Status:      "success",
			OwnerID:     s.currentUserID(r),
			Description: "validated backup archive",
			Metadata: map[string]any{
				"client_ip":         s.clientIP(r),
				"uploaded_filename": backupRestoreUploadName(header.Filename),
				"uploaded_size":     written,
				"manifest":          archive.Manifest,
				"files":             archive.Files,
			},
		}); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"valid": true, "manifest": archive.Manifest, "files": archive.Files, "size": written})
		return
	}
	preRestore, err := s.createBackupSnapshot()
	if err != nil {
		s.writeBackupRestoreFailure(w, r, http.StatusInternalServerError, "pre-restore backup failed: "+err.Error(), backupRestoreUploadMetadata(header.Filename, header.Size, written))
		return
	}
	summary, err := s.cfg.Store.RestoreSnapshot(archive.LegacyRaw, archive.SQLiteDB)
	if err != nil {
		metadata := backupRestoreUploadMetadata(header.Filename, header.Size, written)
		metadata["pre_restore_backup"] = preRestore
		s.writeBackupRestoreFailure(w, r, http.StatusBadRequest, err.Error(), metadata)
		return
	}
	if err := s.createOperationLog(r, model.PlatformItemRequest{
		Name:        "backup.restore",
		Type:        "backup",
		Status:      "success",
		OwnerID:     s.currentUserID(r),
		Description: "restored backup archive",
		Metadata: map[string]any{
			"client_ip":          s.clientIP(r),
			"uploaded_filename":  backupRestoreUploadName(header.Filename),
			"uploaded_size":      written,
			"manifest":           archive.Manifest,
			"files":              archive.Files,
			"pre_restore_backup": preRestore,
			"summary":            summary,
		},
	}); err != nil {
		if rollbackErr := s.restoreBackupSnapshot(preRestore); rollbackErr != nil {
			s.auth.clearSessions()
			writeError(w, http.StatusInternalServerError, err.Error()+"; restore rollback failed: "+rollbackErr.Error())
			return
		}
		_ = s.audit(r, "operation.log.persist_failed", "backups", "", "backup restore rolled back after operation log failure: "+err.Error())
		s.auth.clearSessions()
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auth.clearSessions()
	writeJSON(w, http.StatusOK, map[string]any{
		"restored":           true,
		"summary":            summary,
		"manifest":           archive.Manifest,
		"files":              archive.Files,
		"pre_restore_backup": preRestore,
		"login_required":     true,
	})
}

func (s *Server) writeBackupRestoreFailure(w http.ResponseWriter, r *http.Request, status int, detail string, metadata map[string]any) {
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["client_ip"] = s.clientIP(r)
	metadata["http_status"] = status
	metadata["error"] = detail
	if err := s.createOperationLog(r, model.PlatformItemRequest{
		Name:        "backup.restore.failed",
		Type:        "backup",
		Status:      "failed",
		OwnerID:     s.currentUserID(r),
		Description: detail,
		Metadata:    metadata,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeError(w, status, detail)
}

func backupRestoreUploadMetadata(filename string, headerSize, written int64) map[string]any {
	return map[string]any{
		"uploaded_filename": backupRestoreUploadName(filename),
		"header_size":       headerSize,
		"uploaded_size":     written,
	}
}

func backupRestoreUploadName(filename string) string {
	return safeUploadedFilename(filename)
}

func (s *Server) restoreBackupSnapshot(metadata map[string]any) error {
	backupPath, _ := metadata["backup_path"].(string)
	backupPath = strings.TrimSpace(backupPath)
	if backupPath == "" {
		return errors.New("pre-restore backup path is missing")
	}
	backupPath = filepath.FromSlash(backupPath)
	if _, err := backupRegularFileInfo(backupPath); err != nil {
		return err
	}
	tempDir, err := os.MkdirTemp(s.cfg.DataDir, "restore-rollback-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)
	archive, err := readRestoreArchive(backupPath, tempDir)
	if err != nil {
		return err
	}
	_, err = s.cfg.Store.RestoreSnapshot(archive.LegacyRaw, archive.SQLiteDB)
	return err
}

func safeUploadedFilename(filename string) string {
	filename = strings.TrimSpace(strings.ReplaceAll(filename, "\\", "/"))
	if filename == "" {
		return ""
	}
	return filepath.Base(filename)
}

func (s *Server) listBackups() ([]backupInfo, error) {
	dir := filepath.Join(s.cfg.DataDir, "backups")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return []backupInfo{}, nil
	}
	if err != nil {
		return nil, err
	}
	items := []backupInfo{}
	for _, entry := range entries {
		if !strings.HasSuffix(strings.ToLower(entry.Name()), ".zip") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		info, err := backupRegularFileInfo(path)
		if err != nil {
			continue
		}
		item := backupInfo{Name: entry.Name(), Size: info.Size(), Modified: info.ModTime().UTC()}
		manifest, files := backupManifest(path)
		item.Manifest = manifest
		item.Files = files
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Modified.After(items[j].Modified)
	})
	return items, nil
}

func (s *Server) backupFilePath(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, `/\`) || !strings.HasSuffix(strings.ToLower(name), ".zip") {
		return "", errors.New("backup name is invalid")
	}
	path := filepath.Join(s.cfg.DataDir, "backups", name)
	if err := ensureChildPath(filepath.Join(s.cfg.DataDir, "backups"), path); err != nil {
		return "", err
	}
	return path, nil
}

func backupRegularFileInfo(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, err
	}
	if info.IsDir() || !info.Mode().IsRegular() {
		return nil, errBackupSpecialFile
	}
	return info, nil
}

func (s *Server) cleanupExpiredBackups(now time.Time) (backupRetentionResult, error) {
	days := s.backupRetentionDays()
	result := backupRetentionResult{RetentionDays: days}
	if days <= 0 {
		return result, nil
	}
	dir := filepath.Join(s.cfg.DataDir, "backups")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	cutoff := now.AddDate(0, 0, -days)
	for _, entry := range entries {
		if !strings.HasSuffix(strings.ToLower(entry.Name()), ".zip") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		info, err := backupRegularFileInfo(path)
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		if err := ensureChildPath(dir, path); err != nil {
			return result, err
		}
		if err := os.Remove(path); err != nil {
			return result, err
		}
		result.Deleted = append(result.Deleted, entry.Name())
		result.DeletedCount++
	}
	return result, nil
}

func (s *Server) backupRetentionDays() int {
	items, err := s.cfg.Store.ListPlatformItems("scheduled_tasks")
	if err == nil {
		for _, item := range items {
			if !scheduledTaskEnabled(item) {
				continue
			}
			if !strings.EqualFold(normalizeScheduledTaskType(item.Type), "backup") {
				continue
			}
			for _, key := range []string{"backup_retention_days", "retention_days", "keep_days", "days"} {
				if value, ok := metadataInt(item.Metadata[key]); ok {
					return maxInt(value, 0)
				}
			}
		}
	}
	settings := s.retentionSettings()
	for _, key := range []string{"backup_retention_days", "backups_days", "backup_days", "retention_days", "days"} {
		if value, ok := metadataInt(settings[key]); ok {
			return maxInt(value, 0)
		}
	}
	return 0
}

func backupManifest(path string) (map[string]any, []string) {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return nil, nil
	}
	defer reader.Close()
	files := []string{}
	manifest := map[string]any{}
	for _, file := range reader.File {
		files = append(files, file.Name)
		if file.Name != "manifest.json" {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			continue
		}
		_ = json.NewDecoder(rc).Decode(&manifest)
		_ = rc.Close()
	}
	return manifest, files
}

func readRestoreArchive(path, tempDir string) (restoreArchive, error) {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return restoreArchive{}, fmt.Errorf("open backup archive: %w", err)
	}
	defer reader.Close()
	result := restoreArchive{Manifest: map[string]any{}, Files: []string{}}
	totalUncompressed := uint64(0)
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		if file.Name == "" || filepath.Base(file.Name) != file.Name || strings.ContainsAny(file.Name, `/\`) {
			return restoreArchive{}, errors.New("backup archive contains unsafe file paths")
		}
		totalUncompressed += file.UncompressedSize64
		if totalUncompressed > maxBackupUploadBytes {
			return restoreArchive{}, errors.New("backup archive is too large after decompression")
		}
		result.Files = append(result.Files, file.Name)
		switch {
		case file.Name == "manifest.json":
			raw, err := readZipFile(file, 1<<20)
			if err != nil {
				return restoreArchive{}, err
			}
			if err := json.Unmarshal(raw, &result.Manifest); err != nil {
				return restoreArchive{}, fmt.Errorf("decode backup manifest: %w", err)
			}
		case strings.HasSuffix(strings.ToLower(file.Name), ".json"):
			if result.LegacyRaw != nil {
				return restoreArchive{}, errors.New("backup archive contains multiple legacy json stores")
			}
			raw, err := readZipFile(file, 64<<20)
			if err != nil {
				return restoreArchive{}, err
			}
			result.LegacyRaw = raw
		case strings.HasSuffix(strings.ToLower(file.Name), ".db"):
			if result.SQLiteDB != "" {
				return restoreArchive{}, errors.New("backup archive contains multiple sqlite stores")
			}
			target := filepath.Join(tempDir, "restore.db")
			if err := extractZipFile(file, target, maxBackupUploadBytes); err != nil {
				return restoreArchive{}, err
			}
			result.SQLiteDB = target
		}
	}
	if result.LegacyRaw == nil && result.SQLiteDB == "" {
		return restoreArchive{}, errors.New("backup archive does not contain store json or sqlite database")
	}
	return result, nil
}

func readZipFile(file *zip.File, limit int64) ([]byte, error) {
	if file.UncompressedSize64 > uint64(limit) {
		return nil, fmt.Errorf("backup file %s is too large", file.Name)
	}
	rc, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	raw, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("backup file %s exceeds restore limit", file.Name)
	}
	return raw, nil
}

func extractZipFile(file *zip.File, target string, limit int64) error {
	if file.UncompressedSize64 > uint64(limit) {
		return fmt.Errorf("backup file %s is too large", file.Name)
	}
	rc, err := file.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(output, io.LimitReader(rc, limit+1))
	closeErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written > limit {
		return fmt.Errorf("backup file %s exceeds restore limit", file.Name)
	}
	return nil
}

func isTruthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}
