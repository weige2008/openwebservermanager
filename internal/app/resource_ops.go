package app

import (
	"archive/zip"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"openwebservermanager/internal/model"

	_ "modernc.org/sqlite"
)

type importRequest struct {
	Items []model.PlatformItemRequest `json:"items"`
}

type fileWriteRequest struct {
	Path     string `json:"path"`
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

type filePathRequest struct {
	Path string `json:"path"`
}

type fileMoveRequest struct {
	Path        string `json:"path"`
	Destination string `json:"destination"`
	Overwrite   bool   `json:"overwrite"`
}

type certificateRequest struct {
	Name   string   `json:"name"`
	Domain string   `json:"domain"`
	DNS    []string `json:"dns"`
	IP     []string `json:"ip"`
	Days   int      `json:"days"`
}

type sqlExecuteRequest struct {
	SQL string `json:"sql"`
}

type workOrderDecisionRequest struct {
	Note string `json:"note"`
}

func (s *Server) handleResourceOperation(w http.ResponseWriter, r *http.Request, path string) bool {
	switch {
	case path == "admin/assets/export":
		s.handleAssetExport(w, r)
		return true
	case path == "admin/assets/import":
		s.handleAssetImport(w, r)
		return true
	case path == "admin/certificates/self-signed":
		s.handleCertificateSelfSigned(w, r)
		return true
	case path == "admin/certificates/upload":
		s.handleCertificateUpload(w, r)
		return true
	case path == "admin/system-settings/smtp/test":
		s.handleSMTPTest(w, r)
		return true
	case path == "admin/audit/access-stats":
		s.handleAccessStats(w, r)
		return true
	case path == "admin/backups":
		s.handleBackups(w, r)
		return true
	case path == "admin/backups/restore":
		s.handleBackupRestore(w, r)
		return true
	case strings.HasPrefix(path, "admin/backups/") && strings.HasSuffix(path, "/download"):
		id := pathSegmentFromTrimmed(path, 2)
		s.handleBackupDownload(w, r, id)
		return true
	case strings.HasPrefix(path, "admin/certificates/") && strings.HasSuffix(path, "/download"):
		id := pathSegmentFromTrimmed(path, 2)
		s.handleCertificateDownload(w, r, id)
		return true
	case strings.HasPrefix(path, "admin/storages/") && strings.Contains(path, "/files"):
		parts := splitPath(strings.TrimPrefix(path, "admin/storages/"))
		if len(parts) < 2 {
			return false
		}
		s.handleStorageFiles(w, r, parts[0], parts[1])
		return true
	case strings.HasPrefix(path, "admin/scheduled-tasks/") && strings.HasSuffix(path, "/run"):
		id := pathSegmentFromTrimmed(path, 2)
		s.handleScheduledTaskRun(w, r, id)
		return true
	case strings.HasPrefix(path, "admin/scheduled-tasks/") && strings.HasSuffix(path, "/logs"):
		id := pathSegmentFromTrimmed(path, 2)
		s.handleScheduledTaskLogs(w, r, id)
		return true
	case path == "admin/agent-gateways/status":
		s.handleAgentGatewayStatus(w, r)
		return true
	case strings.HasPrefix(path, "admin/agent-gateways/") && strings.HasSuffix(path, "/token"):
		id := pathSegmentFromTrimmed(path, 2)
		s.handleAgentGatewayToken(w, r, id)
		return true
	case strings.HasPrefix(path, "admin/sql-work-orders/") && strings.HasSuffix(path, "/execute"):
		id := pathSegmentFromTrimmed(path, 2)
		s.handleSQLWorkOrderExecute(w, r, id)
		return true
	case strings.HasPrefix(path, "admin/sql-work-orders/") && strings.HasSuffix(path, "/approve"):
		id := pathSegmentFromTrimmed(path, 2)
		s.handleSQLWorkOrderDecision(w, r, id, "approved")
		return true
	case strings.HasPrefix(path, "admin/sql-work-orders/") && strings.HasSuffix(path, "/reject"):
		id := pathSegmentFromTrimmed(path, 2)
		s.handleSQLWorkOrderDecision(w, r, id, "rejected")
		return true
	case strings.HasPrefix(path, "admin/audit/online-sessions/") && strings.HasSuffix(path, "/disconnect"):
		id := pathSegmentFromTrimmed(path, 3)
		s.handleAuditSessionDisconnect(w, r, id)
		return true
	case strings.HasPrefix(path, "admin/audit/offline-sessions/") && strings.HasSuffix(path, "/recording"):
		id := pathSegmentFromTrimmed(path, 3)
		s.handleAuditRecording(w, r, id)
		return true
	default:
		return false
	}
}

func (s *Server) handleAssetExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	items, err := s.cfg.Store.ListPlatformItems("assets")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "assets.export", "assets", "", "exported assets")
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "exported_at": time.Now().UTC()})
}

func (s *Server) handleAssetImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req importRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.Items) == 0 {
		writeError(w, http.StatusBadRequest, "items are required")
		return
	}
	if len(req.Items) > 500 {
		writeError(w, http.StatusBadRequest, "too many items")
		return
	}
	created := make([]model.PlatformItem, 0, len(req.Items))
	for _, itemReq := range req.Items {
		item, err := s.cfg.Store.CreatePlatformItem("assets", itemReq)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		created = append(created, item)
	}
	_ = s.audit(r, "assets.import", "assets", "", "imported assets")
	writeJSON(w, http.StatusCreated, map[string]any{"items": created})
}

func (s *Server) handleStorageFiles(w http.ResponseWriter, r *http.Request, storageID, action string) {
	if _, ok, err := s.cfg.Store.GetPlatformItem("storages", storageID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if !ok {
		writeError(w, http.StatusNotFound, "storage not found")
		return
	}
	root := filepath.Join(s.cfg.DataDir, "drives", storageID)
	if err := os.MkdirAll(root, 0o770); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	switch action {
	case "files":
		switch r.Method {
		case http.MethodGet:
			s.handleStorageList(w, r, root, storageID)
		case http.MethodDelete:
			s.handleStorageDelete(w, r, root, storageID)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	case "files-write":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleStorageWrite(w, r, root, storageID)
	case "files-mkdir":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleStorageMkdir(w, r, root, storageID)
	case "files-download":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleStorageDownload(w, r, root, storageID)
	case "files-upload":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleStorageUpload(w, r, root, storageID)
	case "files-rename":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleStorageRename(w, r, root, storageID)
	case "files-copy":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleStorageCopy(w, r, root, storageID)
	default:
		writeError(w, http.StatusNotFound, "file operation not found")
	}
}

func (s *Server) handleStorageList(w http.ResponseWriter, r *http.Request, root, storageID string) {
	dirPath, rel, ok := s.storagePath(w, r, root, r.URL.Query().Get("path"))
	if !ok {
		return
	}
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		writeError(w, http.StatusNotFound, "path not found")
		return
	}
	result := []map[string]any{}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		result = append(result, map[string]any{
			"name":     entry.Name(),
			"path":     filepath.ToSlash(filepath.Join(rel, entry.Name())),
			"is_dir":   entry.IsDir(),
			"size":     info.Size(),
			"modified": info.ModTime().UTC(),
		})
	}
	_ = s.audit(r, "storage.files.list", storageID, "", "listed files")
	writeJSON(w, http.StatusOK, map[string]any{"path": filepath.ToSlash(rel), "entries": result})
}

func (s *Server) handleStorageWrite(w http.ResponseWriter, r *http.Request, root, storageID string) {
	var req fileWriteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	target, rel, ok := s.storagePath(w, r, root, req.Path)
	if !ok {
		return
	}
	permission := "upload"
	if _, err := os.Stat(target); err == nil {
		permission = "edit"
	}
	if !s.requireStoragePermission(w, r, storageID, permission, rel) {
		return
	}
	content := []byte(req.Content)
	if strings.EqualFold(req.Encoding, "base64") {
		decoded, err := base64.StdEncoding.DecodeString(req.Content)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid base64 content")
			return
		}
		content = decoded
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o770); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := os.WriteFile(target, content, 0o660); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _ = s.cfg.Store.CreatePlatformItem("file_logs", model.PlatformItemRequest{Name: rel, Type: "write", Status: "success", TargetID: storageID, OwnerID: s.currentUserID(r), Description: "wrote file"})
	_ = s.audit(r, "storage.files.write", storageID, "", "wrote "+rel)
	writeJSON(w, http.StatusCreated, map[string]any{"path": filepath.ToSlash(rel), "size": len(content)})
}

func (s *Server) handleStorageUpload(w http.ResponseWriter, r *http.Request, root, storageID string) {
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
	fileName = filepath.Base(filepath.Clean(filepath.FromSlash(fileName)))
	if fileName == "." || fileName == ".." || fileName == string(filepath.Separator) || fileName == "" {
		writeError(w, http.StatusBadRequest, "filename is required")
		return
	}
	targetPath := filepath.ToSlash(filepath.Join(r.FormValue("path"), fileName))
	target, rel, ok := s.storagePath(w, r, root, targetPath)
	if !ok {
		return
	}
	permission := "upload"
	if _, err := os.Stat(target); err == nil {
		permission = "edit"
	}
	if !s.requireStoragePermission(w, r, storageID, permission, rel) {
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
	_, _ = s.cfg.Store.CreatePlatformItem("file_logs", model.PlatformItemRequest{
		Name:        rel,
		Type:        "upload",
		Status:      "success",
		TargetID:    storageID,
		OwnerID:     s.currentUserID(r),
		Description: "uploaded file",
		Metadata:    map[string]any{"size": written, "permission": permission},
	})
	_ = s.audit(r, "storage.files.upload", storageID, "", "uploaded "+rel)
	writeJSON(w, http.StatusCreated, map[string]any{"path": filepath.ToSlash(rel), "size": written, "name": fileName})
}

func (s *Server) handleStorageMkdir(w http.ResponseWriter, r *http.Request, root, storageID string) {
	var req filePathRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	target, rel, ok := s.storagePath(w, r, root, req.Path)
	if !ok {
		return
	}
	if !s.requireStoragePermission(w, r, storageID, "upload", rel) {
		return
	}
	if err := os.MkdirAll(target, 0o770); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _ = s.cfg.Store.CreatePlatformItem("file_logs", model.PlatformItemRequest{Name: rel, Type: "mkdir", Status: "success", TargetID: storageID, OwnerID: s.currentUserID(r), Description: "created directory"})
	_ = s.audit(r, "storage.files.mkdir", storageID, "", "created "+rel)
	writeJSON(w, http.StatusCreated, map[string]any{"path": filepath.ToSlash(rel)})
}

func (s *Server) handleStorageDelete(w http.ResponseWriter, r *http.Request, root, storageID string) {
	target, rel, ok := s.storagePath(w, r, root, r.URL.Query().Get("path"))
	if !ok {
		return
	}
	if rel == "." || rel == "" {
		writeError(w, http.StatusBadRequest, "cannot delete storage root")
		return
	}
	if !s.requireStoragePermission(w, r, storageID, "delete", rel) {
		return
	}
	if err := os.RemoveAll(target); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _ = s.cfg.Store.CreatePlatformItem("file_logs", model.PlatformItemRequest{Name: rel, Type: "delete", Status: "success", TargetID: storageID, OwnerID: s.currentUserID(r), Description: "deleted file"})
	_ = s.audit(r, "storage.files.delete", storageID, "", "deleted "+rel)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleStorageDownload(w http.ResponseWriter, r *http.Request, root, storageID string) {
	target, rel, ok := s.storagePath(w, r, root, r.URL.Query().Get("path"))
	if !ok {
		return
	}
	info, err := os.Stat(target)
	if err != nil || info.IsDir() {
		writeError(w, http.StatusNotFound, "file not found")
		return
	}
	if !s.requireStoragePermission(w, r, storageID, "download", rel) {
		return
	}
	_, _ = s.cfg.Store.CreatePlatformItem("file_logs", model.PlatformItemRequest{Name: rel, Type: "download", Status: "success", TargetID: storageID, OwnerID: s.currentUserID(r), Description: "downloaded file"})
	_ = s.audit(r, "storage.files.download", storageID, "", "downloaded "+rel)
	http.ServeFile(w, r, target)
}

func (s *Server) handleStorageRename(w http.ResponseWriter, r *http.Request, root, storageID string) {
	var req fileMoveRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	source, sourceRel, ok := s.storagePath(w, r, root, req.Path)
	if !ok {
		return
	}
	destination, destinationRel, ok := s.storagePath(w, r, root, req.Destination)
	if !ok {
		return
	}
	if sourceRel == "." || destinationRel == "." || strings.TrimSpace(req.Destination) == "" {
		writeError(w, http.StatusBadRequest, "source and destination are required")
		return
	}
	if !s.requireStoragePermission(w, r, storageID, "rename", sourceRel) {
		return
	}
	if _, err := os.Stat(source); err != nil {
		writeError(w, http.StatusNotFound, "source not found")
		return
	}
	if _, err := os.Stat(destination); err == nil && !req.Overwrite {
		writeError(w, http.StatusConflict, "destination exists")
		return
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o770); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if req.Overwrite {
		_ = os.RemoveAll(destination)
	}
	if err := os.Rename(source, destination); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _ = s.cfg.Store.CreatePlatformItem("file_logs", model.PlatformItemRequest{Name: sourceRel + " -> " + destinationRel, Type: "rename", Status: "success", TargetID: storageID, OwnerID: s.currentUserID(r), Description: "renamed file"})
	_ = s.audit(r, "storage.files.rename", storageID, "", "renamed "+sourceRel+" to "+destinationRel)
	writeJSON(w, http.StatusOK, map[string]any{"path": filepath.ToSlash(destinationRel)})
}

func (s *Server) handleStorageCopy(w http.ResponseWriter, r *http.Request, root, storageID string) {
	var req fileMoveRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	source, sourceRel, ok := s.storagePath(w, r, root, req.Path)
	if !ok {
		return
	}
	destination, destinationRel, ok := s.storagePath(w, r, root, req.Destination)
	if !ok {
		return
	}
	if sourceRel == "." || destinationRel == "." || strings.TrimSpace(req.Destination) == "" {
		writeError(w, http.StatusBadRequest, "source and destination are required")
		return
	}
	if !s.requireStoragePermission(w, r, storageID, "copy", sourceRel) || !s.requireStoragePermission(w, r, storageID, "paste", destinationRel) {
		return
	}
	info, err := os.Stat(source)
	if err != nil {
		writeError(w, http.StatusNotFound, "source not found")
		return
	}
	if _, err := os.Stat(destination); err == nil && !req.Overwrite {
		writeError(w, http.StatusConflict, "destination exists")
		return
	}
	if info.IsDir() && sameOrChildPath(source, destination) {
		writeError(w, http.StatusBadRequest, "cannot copy a directory into itself")
		return
	}
	if req.Overwrite {
		_ = os.RemoveAll(destination)
	}
	if info.IsDir() {
		if err := copyDirectory(source, destination); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	} else if err := copyFile(source, destination); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _ = s.cfg.Store.CreatePlatformItem("file_logs", model.PlatformItemRequest{Name: sourceRel + " -> " + destinationRel, Type: "copy", Status: "success", TargetID: storageID, OwnerID: s.currentUserID(r), Description: "copied file"})
	_ = s.audit(r, "storage.files.copy", storageID, "", "copied "+sourceRel+" to "+destinationRel)
	writeJSON(w, http.StatusCreated, map[string]any{"path": filepath.ToSlash(destinationRel)})
}

func (s *Server) storagePath(w http.ResponseWriter, _ *http.Request, root, value string) (string, string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || value == "/" {
		value = "."
	}
	clean := filepath.Clean(filepath.FromSlash(value))
	if filepath.IsAbs(clean) {
		clean = strings.TrimPrefix(clean, string(filepath.Separator))
	}
	target := filepath.Join(root, clean)
	if clean == "." {
		return root, ".", true
	}
	if err := ensureChildPath(root, target); err != nil {
		writeError(w, http.StatusForbidden, "path escapes storage root")
		return "", "", false
	}
	rel, err := filepath.Rel(root, target)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return "", "", false
	}
	return target, rel, true
}

func (s *Server) requireStoragePermission(w http.ResponseWriter, r *http.Request, storageID, action, path string) bool {
	if s.isAdminRequest(r) {
		return true
	}
	allowed, matched := s.storagePermissionAllowed(storageID, action, path, s.currentUserID(r))
	if !matched {
		return true
	}
	if allowed {
		return true
	}
	_, _ = s.cfg.Store.CreatePlatformItem("file_logs", model.PlatformItemRequest{
		Name:        path,
		Type:        action,
		Status:      "denied",
		TargetID:    storageID,
		OwnerID:     s.currentUserID(r),
		Description: "blocked by authorization strategy",
	})
	_ = s.audit(r, "storage.files."+action+".denied", storageID, "", "blocked "+action+" on "+path)
	writeError(w, http.StatusForbidden, "file permission denied: "+action)
	return false
}

func (s *Server) storagePermissionAllowed(storageID, action, path, userID string) (bool, bool) {
	platform, err := s.cfg.Store.PlatformBootstrap()
	if err != nil {
		return true, false
	}
	ctx := accessAuthorizationContextFor(platform, userID)
	for _, strategy := range platform["authorization_strategies"] {
		if !platformItemEnabled(strategy) || !fileStrategyMatches(strategy, storageID, path, ctx) {
			continue
		}
		if allowed, ok := strategy.Permissions[action]; ok {
			return allowed, true
		}
	}
	return true, false
}

func fileStrategyMatches(strategy model.PlatformItem, storageID, path string, ctx accessAuthorizationContext) bool {
	if strategy.Type != "" && !strings.EqualFold(strategy.Type, "file") {
		return false
	}
	if !fileStrategyStorageMatches(strategy, storageID) {
		return false
	}
	if fileStrategyHasSubjectScope(strategy) && !fileStrategySubjectMatches(strategy, ctx) {
		return false
	}
	if !fileStrategyPathMatches(strategy, path) {
		return false
	}
	return true
}

func fileStrategyStorageMatches(strategy model.PlatformItem, storageID string) bool {
	values := []string{strategy.TargetID}
	for _, key := range []string{"target_id", "target_ids", "targetId", "storage_id", "storage_ids", "storageId"} {
		values = append(values, metadataStrings(strategy.Metadata[key])...)
	}
	return strategyScopeMatches(values, storageID)
}

func fileStrategyHasSubjectScope(strategy model.PlatformItem) bool {
	if strings.TrimSpace(strategy.OwnerID) != "" || strings.TrimSpace(strategy.Username) != "" || strings.TrimSpace(strategy.ParentID) != "" || strings.TrimSpace(strategy.Group) != "" {
		return true
	}
	for _, key := range []string{
		"subject_id", "subject_ids", "subjectId",
		"user_id", "user_ids", "userId", "username", "usernames", "account", "accounts",
		"owner_id", "owner_ids", "ownerId",
		"department_id", "department_ids", "departmentId", "dept_id", "dept_ids", "department", "departments", "dept", "depts",
	} {
		if len(metadataStrings(strategy.Metadata[key])) > 0 {
			return true
		}
	}
	return false
}

func fileStrategySubjectMatches(strategy model.PlatformItem, ctx accessAuthorizationContext) bool {
	subjectKeys := map[string]bool{}
	addAuthKeys(subjectKeys, strategy.OwnerID, strategy.Username, strategy.ParentID, strategy.Group)
	addMetadataAuthKeys(subjectKeys, strategy.Metadata,
		"subject_id", "subject_ids", "subjectId",
		"user_id", "user_ids", "userId", "username", "usernames", "account", "accounts",
		"owner_id", "owner_ids", "ownerId",
		"department_id", "department_ids", "departmentId", "dept_id", "dept_ids", "department", "departments", "dept", "depts",
	)
	return authKeysOverlap(ctx.SubjectKeys, subjectKeys)
}

func fileStrategyPathMatches(strategy model.PlatformItem, path string) bool {
	values := []string{}
	for _, key := range []string{"path", "paths", "path_prefix", "path_prefixes", "pathPrefix", "pathPrefixes", "prefix", "prefixes"} {
		values = append(values, metadataStrings(strategy.Metadata[key])...)
	}
	rel := normalizeStoragePolicyPath(path)
	scoped := false
	for _, value := range values {
		for _, part := range splitCriteria(value) {
			scoped = true
			prefix := normalizeStoragePolicyPath(part)
			if prefix == "*" || prefix == "." || prefix == "" {
				return true
			}
			if rel == prefix || strings.HasPrefix(rel, strings.TrimSuffix(prefix, "/")+"/") {
				return true
			}
		}
	}
	return !scoped
}

func strategyScopeMatches(values []string, target string) bool {
	scoped := false
	for _, value := range values {
		for _, part := range splitCriteria(value) {
			scoped = true
			if part == "*" || strings.EqualFold(strings.TrimSpace(part), strings.TrimSpace(target)) {
				return true
			}
		}
	}
	return !scoped
}

func normalizeStoragePolicyPath(value string) string {
	value = strings.TrimSpace(filepath.ToSlash(value))
	if value == "" || value == "/" {
		return "."
	}
	value = filepath.ToSlash(filepath.Clean(filepath.FromSlash(value)))
	value = strings.TrimPrefix(value, "/")
	if value == "" {
		return "."
	}
	return value
}

func copyFile(source, destination string) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o770); err != nil {
		return err
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o660)
	if err != nil {
		return err
	}
	defer output.Close()
	_, err = io.Copy(output, input)
	return err
}

func copyDirectory(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o770)
		}
		return copyFile(path, target)
	})
}

func sameOrChildPath(parent, child string) bool {
	parentAbs, err := filepath.Abs(parent)
	if err != nil {
		return false
	}
	childAbs, err := filepath.Abs(child)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(parentAbs, childAbs)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".." && !filepath.IsAbs(rel))
}

func (s *Server) handleCertificateSelfSigned(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req certificateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Domain) == "" {
		writeError(w, http.StatusBadRequest, "domain is required")
		return
	}
	certPEM, keyPEM, err := makeSelfSignedCertificate(req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = req.Domain
	}
	item, err := s.cfg.Store.CreatePlatformItem("certificates", model.PlatformItemRequest{
		Name:        name,
		Type:        "self-signed",
		Status:      "issued",
		Description: "self-signed certificate for " + req.Domain,
		Metadata: map[string]any{
			"domain":      req.Domain,
			"certificate": string(certPEM),
			"private_key": string(keyPEM),
			"expires_at":  time.Now().UTC().Add(time.Duration(clampInt(req.Days, 1, 3650, 365)) * 24 * time.Hour),
		},
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "certificate.self_signed", item.ID, "", "issued self-signed certificate")
	writeJSON(w, http.StatusCreated, item)
}

func makeSelfSignedCertificate(req certificateRequest) ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	days := clampInt(req.Days, 1, 3650, 365)
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: req.Domain, Organization: []string{"openwebservermanager"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     append([]string{req.Domain}, req.DNS...),
	}
	for _, rawIP := range req.IP {
		if ip := net.ParseIP(rawIP); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM, nil
}

func (s *Server) handleCertificateUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<20)
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid certificate upload: "+err.Error())
		return
	}
	certPEM, certName, err := readMultipartTextFile(r, "certificate", 8<<20)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	keyPEM, keyName, err := readOptionalMultipartTextFile(r, "private_key", 8<<20)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	chainPEM, chainName, err := readOptionalMultipartTextFile(r, "chain", 8<<20)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	cert, err := parseFirstCertificatePEM([]byte(certPEM))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(keyPEM) != "" {
		key, err := parsePrivateKeyPEM([]byte(keyPEM))
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !certificateMatchesPrivateKey(cert, key) {
			writeError(w, http.StatusBadRequest, "private key does not match certificate")
			return
		}
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = cert.Subject.CommonName
	}
	if name == "" {
		name = strings.TrimSpace(certName)
	}
	if name == "" {
		name = "uploaded certificate"
	}
	metadata := certificateMetadata(cert)
	metadata["certificate"] = certPEM
	metadata["certificate_filename"] = certName
	if keyPEM != "" {
		metadata["private_key"] = keyPEM
		metadata["private_key_filename"] = keyName
		metadata["has_private_key"] = true
	}
	if chainPEM != "" {
		metadata["chain"] = chainPEM
		metadata["chain_filename"] = chainName
	}
	item, err := s.cfg.Store.CreatePlatformItem("certificates", model.PlatformItemRequest{
		Name:        name,
		Type:        "uploaded",
		Status:      "issued",
		Description: "uploaded certificate for " + certificateDisplayName(cert),
		Metadata:    metadata,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "certificate.upload", item.ID, "", "uploaded certificate")
	writeJSON(w, http.StatusCreated, item)
}

func readMultipartTextFile(r *http.Request, field string, limit int64) (string, string, error) {
	file, header, err := r.FormFile(field)
	if err != nil {
		return "", "", fmt.Errorf("%s file is required", field)
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return "", "", fmt.Errorf("read %s file: %w", field, err)
	}
	if int64(len(content)) > limit {
		return "", "", fmt.Errorf("%s file is too large", field)
	}
	if strings.TrimSpace(string(content)) == "" {
		return "", "", fmt.Errorf("%s file is empty", field)
	}
	name := ""
	if header != nil {
		name = header.Filename
	}
	return string(content), name, nil
}

func readOptionalMultipartTextFile(r *http.Request, field string, limit int64) (string, string, error) {
	file, header, err := r.FormFile(field)
	if err != nil {
		return "", "", nil
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return "", "", fmt.Errorf("read %s file: %w", field, err)
	}
	if int64(len(content)) > limit {
		return "", "", fmt.Errorf("%s file is too large", field)
	}
	name := ""
	if header != nil {
		name = header.Filename
	}
	return string(content), name, nil
}

func parseFirstCertificatePEM(raw []byte) (*x509.Certificate, error) {
	rest := raw
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			return nil, errors.New("certificate PEM block is required")
		}
		rest = next
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		return cert, nil
	}
}

func parsePrivateKeyPEM(raw []byte) (any, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("private key PEM block is required")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}
}

func certificateMatchesPrivateKey(cert *x509.Certificate, key any) bool {
	switch publicKey := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		privateKey, ok := key.(*rsa.PrivateKey)
		return ok && publicKey.N.Cmp(privateKey.N) == 0 && publicKey.E == privateKey.E
	case *ecdsa.PublicKey:
		privateKey, ok := key.(*ecdsa.PrivateKey)
		return ok && publicKey.X.Cmp(privateKey.X) == 0 && publicKey.Y.Cmp(privateKey.Y) == 0
	case ed25519.PublicKey:
		privateKey, ok := key.(ed25519.PrivateKey)
		return ok && publicKey.Equal(privateKey.Public())
	default:
		return false
	}
}

func certificateMetadata(cert *x509.Certificate) map[string]any {
	ips := []string{}
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}
	return map[string]any{
		"domain":        certificateDisplayName(cert),
		"common_name":   cert.Subject.CommonName,
		"dns_names":     cert.DNSNames,
		"ip_addresses":  ips,
		"issuer":        cert.Issuer.String(),
		"serial_number": cert.SerialNumber.String(),
		"not_before":    cert.NotBefore.UTC(),
		"expires_at":    cert.NotAfter.UTC(),
	}
}

func certificateDisplayName(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	if len(cert.IPAddresses) > 0 {
		return cert.IPAddresses[0].String()
	}
	return cert.SerialNumber.String()
}

func (s *Server) handleCertificateDownload(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	item, ok, err := s.cfg.Store.GetPlatformItem("certificates", id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "certificate not found")
		return
	}
	cert, _ := item.Metadata["certificate"].(string)
	if cert == "" {
		writeError(w, http.StatusNotFound, "certificate payload not found")
		return
	}
	_ = s.audit(r, "certificate.download", id, "", "downloaded certificate")
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+id+".crt\"")
	_, _ = io.WriteString(w, cert)
}

func (s *Server) handleScheduledTaskRun(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	task, ok, err := s.cfg.Store.GetPlatformItem("scheduled_tasks", id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "task not found")
		return
	}
	result, metadata, err := s.runScheduledTask(r, task)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	metadata["task_type"] = task.Type
	metadata["ran_at"] = time.Now().UTC()
	logItem, err := s.cfg.Store.CreatePlatformItem("operation_logs", model.PlatformItemRequest{
		Name:        task.Name,
		Type:        "scheduled_task",
		Status:      "success",
		TargetID:    id,
		OwnerID:     s.currentUserID(r),
		Description: result,
		Metadata:    metadata,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "scheduled_task.run", id, "", "ran scheduled task "+task.Name)
	writeJSON(w, http.StatusAccepted, logItem)
}

func (s *Server) handleScheduledTaskLogs(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	items, err := s.cfg.Store.ListPlatformItems("operation_logs")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	result := []model.PlatformItem{}
	for _, item := range items {
		if item.TargetID == id && item.Type == "scheduled_task" {
			result = append(result, item)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": result})
}

func (s *Server) handleSQLWorkOrderExecute(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	order, ok, err := s.cfg.Store.GetPlatformItem("sql_work_orders", id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "sql work order not found")
		return
	}
	if !strings.EqualFold(order.Status, "approved") {
		writeError(w, http.StatusConflict, "sql work order must be approved before execution")
		return
	}
	var req sqlExecuteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	approvedSQL := strings.TrimSpace(firstMetadataString(order.Metadata, "sql"))
	sqlText := strings.TrimSpace(req.SQL)
	if sqlText == "" {
		sqlText = approvedSQL
	}
	if approvedSQL == "" {
		writeError(w, http.StatusBadRequest, "sql is required")
		return
	}
	if sqlText != approvedSQL {
		writeError(w, http.StatusBadRequest, "sql does not match approved work order")
		return
	}

	asset, userID, ok := s.sqlWorkOrderDatabaseAsset(w, r, order)
	if !ok {
		return
	}
	logItem, statusCode, err := s.executeDatabaseAssetSQL(r, asset, userID, sqlText, databaseSQLExecutionOptions{
		Source:      "sql_work_order",
		LogType:     "work_order",
		LogName:     order.Name,
		TargetID:    asset.ID,
		WorkOrderID: id,
		Reason:      firstMetadataString(order.Metadata, "reason", "description"),
		ExtraMetadata: map[string]any{
			"requested_by": firstMetadataString(order.Metadata, "requested_by", "requester", "requester_id"),
			"approved_by":  firstMetadataString(order.Metadata, "approved_by"),
		},
	})
	if err != nil {
		writeError(w, statusCode, err.Error())
		return
	}
	if statusCode != http.StatusOK {
		writeJSON(w, statusCode, logItem)
		return
	}
	nextMetadata := map[string]any{}
	for key, value := range order.Metadata {
		nextMetadata[key] = value
	}
	nextMetadata["asset_id"] = asset.ID
	nextMetadata["asset_name"] = asset.Name
	nextMetadata["sql"] = approvedSQL
	nextMetadata["sql_log_id"] = logItem.ID
	nextMetadata["rows_affected"] = logItem.Metadata["rows_affected"]
	nextMetadata["executed_at"] = time.Now().UTC()
	nextMetadata["executed_by"] = userID
	_, _ = s.cfg.Store.UpdatePlatformItem("sql_work_orders", id, model.PlatformItemRequest{Status: "executed", Protocol: model.ProtocolDatabase, Metadata: nextMetadata})
	_ = s.audit(r, "sql_work_order.execute", id, model.ProtocolDatabase, "executed sql work order")
	writeJSON(w, http.StatusOK, logItem)
}

func (s *Server) handleSQLWorkOrderDecision(w http.ResponseWriter, r *http.Request, id, nextStatus string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	order, ok, err := s.cfg.Store.GetPlatformItem("sql_work_orders", id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "sql work order not found")
		return
	}
	if strings.EqualFold(order.Status, "executed") {
		writeError(w, http.StatusConflict, "executed sql work orders cannot be changed")
		return
	}
	var req workOrderDecisionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	asset, userID, ok := s.sqlWorkOrderDatabaseAsset(w, r, order)
	if !ok {
		return
	}
	nextMetadata := map[string]any{}
	for key, value := range order.Metadata {
		nextMetadata[key] = value
	}
	now := time.Now().UTC()
	if nextStatus == "approved" {
		nextMetadata["approved_by"] = userID
		nextMetadata["approved_at"] = now
		nextMetadata["approval_note"] = strings.TrimSpace(req.Note)
	} else {
		nextMetadata["rejected_by"] = userID
		nextMetadata["rejected_at"] = now
		nextMetadata["rejection_note"] = strings.TrimSpace(req.Note)
	}
	nextMetadata["asset_id"] = asset.ID
	nextMetadata["asset_name"] = asset.Name
	item, err := s.cfg.Store.UpdatePlatformItem("sql_work_orders", id, model.PlatformItemRequest{
		Status:   nextStatus,
		Protocol: model.ProtocolDatabase,
		Metadata: nextMetadata,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "sql_work_order."+nextStatus, id, model.ProtocolDatabase, "set sql work order "+nextStatus)
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) sqlWorkOrderDatabaseAsset(w http.ResponseWriter, r *http.Request, order model.PlatformItem) (model.PlatformItem, string, bool) {
	assetID := strings.TrimSpace(order.TargetID)
	if assetID == "" {
		assetID = firstMetadataString(order.Metadata, "asset_id", "database_asset_id", "target_id")
	}
	if assetID == "" {
		writeError(w, http.StatusBadRequest, "sql work order must target a database asset")
		return model.PlatformItem{}, "", false
	}
	platform, err := s.cfg.Store.PlatformBootstrap()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return model.PlatformItem{}, "", false
	}
	asset, ok := findAccessAsset(platform, model.ProtocolDatabase, assetID)
	if !ok {
		writeError(w, http.StatusNotFound, "database asset not found")
		return model.PlatformItem{}, "", false
	}
	userID, isAdmin := s.accessUser(r)
	if !isAccessAuthorized(platform, model.ProtocolDatabase, asset.ID, userID, isAdmin) {
		writeError(w, http.StatusForbidden, "database asset access denied")
		return model.PlatformItem{}, "", false
	}
	return asset, userID, true
}

func (s *Server) handleAuditSessionDisconnect(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if session, ok := s.cfg.Store.GetSession(id); ok {
		if !s.canAccessSession(r, session) {
			writeError(w, http.StatusForbidden, "session access denied")
			return
		}
		closed, err := s.cfg.Store.CloseSession(id, "closed by auditor")
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.audit(r, "audit.session.disconnect", id, closed.Protocol, "disconnected online session")
		writeJSON(w, http.StatusOK, closed)
		return
	}
	item, ok, err := s.cfg.Store.GetPlatformItem("online_sessions", id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	now := time.Now().UTC()
	item.Status = string(model.SessionClosed)
	item.Description = "closed by auditor"
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	item.Metadata["ended_at"] = now
	item.Metadata["close_reason"] = "closed by auditor"
	_ = s.cfg.Store.DeletePlatformItem("online_sessions", id)
	offline, err := s.cfg.Store.SavePlatformItem("offline_sessions", item)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "audit.session.disconnect", id, item.Protocol, "disconnected platform online session")
	writeJSON(w, http.StatusOK, offline)
}

func (s *Server) handleAuditRecording(w http.ResponseWriter, r *http.Request, id string) {
	switch r.Method {
	case http.MethodGet:
		s.downloadAuditRecording(w, r, id)
	case http.MethodDelete:
		s.deleteAuditRecording(w, r, id)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) downloadAuditRecording(w http.ResponseWriter, r *http.Request, id string) {
	recording, ok := s.auditRecordingTarget(w, r, id)
	if !ok {
		return
	}
	_ = s.audit(r, "audit.recording.download", id, recording.protocol, "downloaded offline session recording")
	s.serveRecordingZip(w, r, id, recording.path)
}

func (s *Server) deleteAuditRecording(w http.ResponseWriter, r *http.Request, id string) {
	recording, ok := s.auditRecordingTarget(w, r, id)
	if !ok {
		return
	}
	if err := os.RemoveAll(recording.path); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if session, exists := s.cfg.Store.GetSession(id); exists {
		_, _ = s.cfg.Store.UpdateSession(id, func(item *model.ConnectionSession) {
			item.RecordingPath = ""
			item.RecordingSize = 0
			item.Error = "recording deleted"
		})
		if offline, ok, err := s.cfg.Store.GetPlatformItem("offline_sessions", id); err == nil && ok {
			clearRecordingMetadata(&offline)
			_, _ = s.cfg.Store.SavePlatformItem("offline_sessions", offline)
		}
		_ = s.audit(r, "audit.recording.delete", id, session.Protocol, "deleted offline session recording")
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	item, ok, err := s.cfg.Store.GetPlatformItem("offline_sessions", id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ok {
		clearRecordingMetadata(&item)
		if _, err := s.cfg.Store.SavePlatformItem("offline_sessions", item); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	_ = s.audit(r, "audit.recording.delete", id, recording.protocol, "deleted platform offline session recording")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type auditRecording struct {
	path     string
	protocol model.Protocol
}

func (s *Server) auditRecordingTarget(w http.ResponseWriter, r *http.Request, id string) (auditRecording, bool) {
	if session, ok := s.cfg.Store.GetSession(id); ok {
		if !s.canAccessSession(r, session) {
			writeError(w, http.StatusForbidden, "session access denied")
			return auditRecording{}, false
		}
		return s.validateRecordingPath(w, session.RecordingPath, session.Protocol)
	}
	item, ok, err := s.cfg.Store.GetPlatformItem("offline_sessions", id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return auditRecording{}, false
	}
	if !ok {
		writeError(w, http.StatusNotFound, "session not found")
		return auditRecording{}, false
	}
	if !s.canAccessPlatformSession(r, item) {
		writeError(w, http.StatusForbidden, "session access denied")
		return auditRecording{}, false
	}
	path, _ := item.Metadata["recording_path"].(string)
	return s.validateRecordingPath(w, path, item.Protocol)
}

func (s *Server) canAccessPlatformSession(r *http.Request, item model.PlatformItem) bool {
	_, authSession, ok := s.auth.session(r)
	if !ok {
		return false
	}
	kind := s.roleDecision(authSession.Role).Kind
	return kind == roleSuperAdmin || kind == roleAdmin || kind == roleAuditor || item.OwnerID == authSession.UserID || item.Username == authSession.UserID
}

func (s *Server) validateRecordingPath(w http.ResponseWriter, recordingPath string, protocol model.Protocol) (auditRecording, bool) {
	if recordingPath == "" {
		writeError(w, http.StatusNotFound, "recording not found")
		return auditRecording{}, false
	}
	if err := ensureChildPath(filepath.Join(s.cfg.DataDir, "recordings"), recordingPath); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return auditRecording{}, false
	}
	if info, err := os.Stat(recordingPath); err != nil || !info.IsDir() {
		writeError(w, http.StatusNotFound, "recording not found")
		return auditRecording{}, false
	}
	return auditRecording{path: recordingPath, protocol: protocol}, true
}

func (s *Server) serveRecordingZip(w http.ResponseWriter, _ *http.Request, id, recordingPath string) {
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+id+".zip\"")
	archive := zip.NewWriter(w)
	defer archive.Close()
	_ = filepath.WalkDir(recordingPath, func(filePath string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(recordingPath, filePath)
		if err != nil {
			return nil
		}
		writer, err := archive.Create(filepath.ToSlash(rel))
		if err != nil {
			return nil
		}
		file, err := os.Open(filePath)
		if err != nil {
			return nil
		}
		defer file.Close()
		_, _ = io.Copy(writer, file)
		return nil
	})
}

func clearRecordingMetadata(item *model.PlatformItem) {
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	item.Metadata["recording_path"] = ""
	item.Metadata["recording_size"] = 0
	item.Metadata["recording_deleted"] = true
	item.Metadata["recording_deleted_at"] = time.Now().UTC()
	item.Description = strings.TrimSpace(item.Description + " recording deleted")
}

func isSQLQuery(sqlText string) bool {
	sqlText = strings.TrimSpace(strings.TrimLeft(sqlText, ";\ufeff"))
	fields := strings.Fields(sqlText)
	if len(fields) == 0 {
		return false
	}
	first := strings.ToLower(fields[0])
	switch first {
	case "select", "with", "pragma", "explain":
		return true
	default:
		return false
	}
}

func scanSQLRows(rows *sql.Rows, limit int) ([]map[string]any, []string, bool, error) {
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, nil, false, err
	}
	result := []map[string]any{}
	truncated := false
	for rows.Next() {
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for index := range values {
			pointers[index] = &values[index]
		}
		if err := rows.Scan(pointers...); err != nil {
			return nil, nil, false, err
		}
		if len(result) >= limit {
			truncated = true
			continue
		}
		row := map[string]any{}
		for index, column := range columns {
			value := values[index]
			if raw, ok := value.([]byte); ok {
				value = string(raw)
			}
			row[column] = value
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, false, err
	}
	return result, columns, truncated, nil
}

func pathSegmentFromTrimmed(path string, index int) string {
	parts := splitPath(path)
	if index < 0 || index >= len(parts) {
		return ""
	}
	return parts[index]
}
