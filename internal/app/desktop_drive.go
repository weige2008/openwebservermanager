package app

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"openwebservermanager/internal/model"
)

type desktopDriveEntry struct {
	Name     string    `json:"name"`
	Path     string    `json:"path"`
	IsDir    bool      `json:"is_dir"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
}

func (s *Server) handleDesktopDrive(w http.ResponseWriter, r *http.Request) {
	parts := splitPath(strings.TrimPrefix(strings.Trim(r.URL.Path, "/"), "api/connections/"))
	if len(parts) < 2 || parts[1] != "drive" {
		writeError(w, http.StatusNotFound, "drive endpoint not found")
		return
	}
	action := ""
	if len(parts) > 2 {
		action = parts[2]
	}
	operation := desktopDriveOperation(action, r.Method)
	session, root, ok := s.desktopDriveTarget(w, r, parts[0], operation)
	if !ok {
		return
	}
	switch {
	case action == "" && r.Method == http.MethodGet:
		s.handleDesktopDriveList(w, r, session, root)
	case action == "" && r.Method == http.MethodDelete:
		s.handleDesktopDriveDelete(w, r, session, root)
	case action == "download" && r.Method == http.MethodGet:
		s.handleDesktopDriveDownload(w, r, session, root)
	case action == "upload" && r.Method == http.MethodPost:
		s.handleDesktopDriveUpload(w, r, session, root)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func desktopDriveOperation(action, method string) string {
	switch {
	case action == "" && method == http.MethodGet:
		return "list"
	case action == "" && method == http.MethodDelete:
		return "delete"
	case action == "download":
		return "download"
	case action == "upload":
		return "upload"
	default:
		return "access"
	}
}

func (s *Server) desktopDriveTarget(w http.ResponseWriter, r *http.Request, sessionID, operation string) (model.ConnectionSession, string, bool) {
	session, ok := s.cfg.Store.GetSession(sessionID)
	if !ok {
		writeError(w, http.StatusNotFound, "session not found")
		return model.ConnectionSession{}, "", false
	}
	if session.Protocol != model.ProtocolRDP && session.Protocol != model.ProtocolVNC {
		writeError(w, http.StatusBadRequest, "session drive is only available for desktop sessions")
		return model.ConnectionSession{}, "", false
	}
	if !s.canAccessSession(r, session) {
		s.recordDesktopDriveDenied(r, session, operation, "session_access", r.URL.Query().Get("path"))
		writeError(w, http.StatusForbidden, "session access denied")
		return model.ConnectionSession{}, "", false
	}
	policy := s.desktopAccessPolicy(session.Protocol)
	if !boolPtrValue(session.FileTransferEnabled, policy.FileTransferEnabled) {
		s.recordDesktopDriveDenied(r, session, operation, "file_transfer_disabled", r.URL.Query().Get("path"))
		writeError(w, http.StatusForbidden, "desktop file transfer is disabled")
		return model.ConnectionSession{}, "", false
	}
	root := filepath.Join(s.cfg.DataDir, "drives", session.ID)
	if err := ensureChildPath(filepath.Join(s.cfg.DataDir, "drives"), root); err != nil {
		writeError(w, http.StatusForbidden, "drive path escapes data directory")
		return model.ConnectionSession{}, "", false
	}
	if err := os.MkdirAll(root, 0o770); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return model.ConnectionSession{}, "", false
	}
	return session, root, true
}

func (s *Server) handleDesktopDriveList(w http.ResponseWriter, r *http.Request, session model.ConnectionSession, root string) {
	dirPath, rel, ok := s.storagePath(w, r, root, r.URL.Query().Get("path"))
	if !ok {
		return
	}
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		writeError(w, http.StatusNotFound, "path not found")
		return
	}
	result := []desktopDriveEntry{}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		result = append(result, desktopDriveEntry{
			Name:     entry.Name(),
			Path:     filepath.ToSlash(filepath.Join(rel, entry.Name())),
			IsDir:    entry.IsDir(),
			Size:     info.Size(),
			Modified: info.ModTime().UTC(),
		})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].IsDir != result[j].IsDir {
			return result[i].IsDir
		}
		return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
	})
	_ = s.audit(r, "connection.drive.list", session.ID, session.Protocol, "listed session drive")
	writeJSON(w, http.StatusOK, map[string]any{"path": filepath.ToSlash(rel), "entries": result})
}

func (s *Server) handleDesktopDriveDownload(w http.ResponseWriter, r *http.Request, session model.ConnectionSession, root string) {
	target, rel, ok := s.storagePath(w, r, root, r.URL.Query().Get("path"))
	if !ok {
		return
	}
	info, err := os.Stat(target)
	if err != nil || info.IsDir() {
		writeError(w, http.StatusNotFound, "file not found")
		return
	}
	s.recordDesktopDriveFileLog(r, session, "download", "success", rel, map[string]any{
		"path": filepath.ToSlash(rel),
		"size": info.Size(),
	})
	_ = s.audit(r, "connection.drive.download", session.ID, session.Protocol, "downloaded session drive file")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeAttachmentName(filepath.Base(rel))+`"`)
	http.ServeFile(w, r, target)
}

func (s *Server) handleDesktopDriveUpload(w http.ResponseWriter, r *http.Request, session model.ConnectionSession, root string) {
	r.Body = http.MaxBytesReader(w, r.Body, 512<<20)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid multipart upload: "+err.Error())
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "file is required")
		return
	}
	defer file.Close()

	fileName := strings.TrimSpace(r.FormValue("filename"))
	if fileName == "" && header != nil {
		fileName = header.Filename
	}
	fileName = safeUploadedFilename(fileName)
	if fileName == "." || fileName == ".." || fileName == string(filepath.Separator) || fileName == "" {
		writeError(w, http.StatusBadRequest, "filename is required")
		return
	}

	targetPath := filepath.ToSlash(filepath.Join(r.FormValue("path"), fileName))
	target, rel, ok := s.storagePath(w, r, root, targetPath)
	if !ok {
		return
	}
	if info, err := os.Stat(target); err == nil && info.IsDir() {
		writeError(w, http.StatusBadRequest, "target is a directory")
		return
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o770); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	output, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o660)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	written, copyErr := io.Copy(output, file)
	closeErr := output.Close()
	if copyErr != nil {
		_ = os.Remove(target)
		writeError(w, http.StatusInternalServerError, copyErr.Error())
		return
	}
	if closeErr != nil {
		_ = os.Remove(target)
		writeError(w, http.StatusInternalServerError, closeErr.Error())
		return
	}
	s.recordDesktopDriveFileLog(r, session, "upload", "success", rel, map[string]any{
		"path":     filepath.ToSlash(rel),
		"filename": fileName,
		"size":     written,
	})
	_ = s.audit(r, "connection.drive.upload", session.ID, session.Protocol, "uploaded session drive file")
	writeJSON(w, http.StatusCreated, map[string]any{"path": filepath.ToSlash(rel), "size": written, "name": fileName})
}

func (s *Server) handleDesktopDriveDelete(w http.ResponseWriter, r *http.Request, session model.ConnectionSession, root string) {
	target, rel, ok := s.storagePath(w, r, root, r.URL.Query().Get("path"))
	if !ok {
		return
	}
	if rel == "." || strings.TrimSpace(rel) == "" {
		writeError(w, http.StatusBadRequest, "cannot delete session drive root")
		return
	}
	if _, err := os.Stat(target); err != nil {
		writeError(w, http.StatusNotFound, "file not found")
		return
	}
	if err := os.RemoveAll(target); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.recordDesktopDriveFileLog(r, session, "delete", "success", rel, map[string]any{
		"path": filepath.ToSlash(rel),
	})
	_ = s.audit(r, "connection.drive.delete", session.ID, session.Protocol, "deleted session drive file")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) recordDesktopDriveFileLog(r *http.Request, session model.ConnectionSession, action, status, path string, metadata map[string]any) {
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["session_id"] = session.ID
	metadata["asset_id"] = session.ServerID
	metadata["protocol"] = session.Protocol
	metadata["client_ip"] = s.clientIP(r)
	_, _ = s.cfg.Store.CreatePlatformItem("file_logs", model.PlatformItemRequest{
		Name:        filepath.ToSlash(path),
		Type:        action,
		Status:      status,
		Protocol:    session.Protocol,
		TargetID:    session.ID,
		OwnerID:     s.currentUserID(r),
		Description: "desktop session drive file " + action,
		Metadata:    metadata,
	})
}

func (s *Server) recordDesktopDriveDenied(r *http.Request, session model.ConnectionSession, action, reason, path string) {
	action = strings.TrimSpace(action)
	if action == "" {
		action = "access"
	}
	metadata := map[string]any{
		"path":   filepath.ToSlash(strings.TrimSpace(path)),
		"reason": reason,
	}
	s.recordDesktopDriveFileLog(r, session, action, "denied", path, metadata)
	_ = s.audit(r, "connection.drive."+action+".denied", session.ID, session.Protocol, "denied session drive "+action+": "+reason)
}

func sanitizeAttachmentName(value string) string {
	value = strings.TrimSpace(strings.Map(func(r rune) rune {
		switch r {
		case '"', '\r', '\n', '\t':
			return -1
		default:
			return r
		}
	}, value))
	if value == "" || value == "." || value == string(filepath.Separator) {
		return "download.bin"
	}
	return value
}
