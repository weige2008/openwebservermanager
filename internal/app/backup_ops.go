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

type backupInfo struct {
	Name     string         `json:"name"`
	Size     int64          `json:"size"`
	Modified time.Time      `json:"modified_at"`
	Manifest map[string]any `json:"manifest,omitempty"`
	Files    []string       `json:"files,omitempty"`
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
	if _, err := os.Stat(path); err != nil {
		writeError(w, http.StatusNotFound, "backup not found")
		return
	}
	_ = s.audit(r, "backup.download", name, "", "downloaded backup")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(path)+"\"")
	http.ServeFile(w, r, path)
}

func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBackupUploadBytes)
	if err := r.ParseMultipartForm(maxBackupUploadBytes); err != nil {
		writeError(w, http.StatusBadRequest, "invalid backup upload: "+err.Error())
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "backup file is required")
		return
	}
	defer file.Close()
	if header.Size <= 0 {
		writeError(w, http.StatusBadRequest, "backup file is empty")
		return
	}
	tempDir, err := os.MkdirTemp(s.cfg.DataDir, "restore-*")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer os.RemoveAll(tempDir)
	uploadPath := filepath.Join(tempDir, "upload.zip")
	output, err := os.OpenFile(uploadPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	written, copyErr := io.Copy(output, file)
	closeErr := output.Close()
	if copyErr != nil {
		writeError(w, http.StatusBadRequest, "write backup upload: "+copyErr.Error())
		return
	}
	if closeErr != nil {
		writeError(w, http.StatusInternalServerError, closeErr.Error())
		return
	}
	if written <= 0 || written > maxBackupUploadBytes {
		writeError(w, http.StatusBadRequest, "backup upload size is invalid")
		return
	}
	archive, err := readRestoreArchive(uploadPath, tempDir)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if isTruthy(r.URL.Query().Get("dry_run")) || isTruthy(r.FormValue("dry_run")) {
		writeJSON(w, http.StatusOK, map[string]any{"valid": true, "manifest": archive.Manifest, "files": archive.Files, "size": written})
		return
	}
	preRestore, err := s.createBackupSnapshot()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "pre-restore backup failed: "+err.Error())
		return
	}
	summary, err := s.cfg.Store.RestoreSnapshot(archive.LegacyRaw, archive.SQLiteDB)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_, _ = s.cfg.Store.CreatePlatformItem("operation_logs", model.PlatformItemRequest{
		Name:        "backup.restore",
		Type:        "backup",
		Status:      "success",
		OwnerID:     s.currentUserID(r),
		Description: "restored backup archive",
		Metadata: map[string]any{
			"client_ip":          s.clientIP(r),
			"uploaded_filename":  header.Filename,
			"uploaded_size":      written,
			"manifest":           archive.Manifest,
			"files":              archive.Files,
			"pre_restore_backup": preRestore,
			"summary":            summary,
		},
	})
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
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".zip") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		info, err := entry.Info()
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
