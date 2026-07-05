package app

import (
	"archive/zip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
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
	case strings.HasPrefix(path, "admin/sql-work-orders/") && strings.HasSuffix(path, "/execute"):
		id := pathSegmentFromTrimmed(path, 2)
		s.handleSQLWorkOrderExecute(w, r, id)
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

func (s *Server) handleStorageMkdir(w http.ResponseWriter, r *http.Request, root, storageID string) {
	var req filePathRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	target, rel, ok := s.storagePath(w, r, root, req.Path)
	if !ok {
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
	_, _ = s.cfg.Store.CreatePlatformItem("file_logs", model.PlatformItemRequest{Name: rel, Type: "download", Status: "success", TargetID: storageID, OwnerID: s.currentUserID(r), Description: "downloaded file"})
	_ = s.audit(r, "storage.files.download", storageID, "", "downloaded "+rel)
	http.ServeFile(w, r, target)
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
	result := "completed"
	if task.Type == "backup" {
		if _, err := s.createBackupSnapshot(); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	logItem, err := s.cfg.Store.CreatePlatformItem("operation_logs", model.PlatformItemRequest{
		Name:        task.Name,
		Type:        "scheduled_task",
		Status:      "success",
		TargetID:    id,
		OwnerID:     s.currentUserID(r),
		Description: result,
		Metadata:    map[string]any{"task_type": task.Type, "ran_at": time.Now().UTC()},
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "scheduled_task.run", id, "", "ran scheduled task "+task.Name)
	writeJSON(w, http.StatusAccepted, logItem)
}

func (s *Server) createBackupSnapshot() (string, error) {
	backupDir := filepath.Join(s.cfg.DataDir, "backups")
	if err := os.MkdirAll(backupDir, 0o770); err != nil {
		return "", err
	}
	name := "backup-" + time.Now().UTC().Format("20060102-150405") + ".json"
	target := filepath.Join(backupDir, name)
	source := filepath.Join(s.cfg.DataDir, "openwebservermanager.json")
	input, err := os.Open(source)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return target, os.WriteFile(target, []byte("{}"), 0o660)
		}
		return "", err
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o660)
	if err != nil {
		return "", err
	}
	defer output.Close()
	_, err = io.Copy(output, input)
	return target, err
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
	var req sqlExecuteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	sqlText := strings.TrimSpace(req.SQL)
	if sqlText == "" {
		if value, _ := order.Metadata["sql"].(string); value != "" {
			sqlText = value
		}
	}
	if sqlText == "" {
		writeError(w, http.StatusBadRequest, "sql is required")
		return
	}
	dbPath := filepath.Join(s.cfg.DataDir, "database-proxy", "work-orders.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o770); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer db.Close()
	start := time.Now()
	status := "success"
	detail := "executed"
	var rowsAffected int64
	metadata := map[string]any{
		"sql": sqlText,
	}
	if isSQLQuery(sqlText) {
		queryRows, err := db.Query(sqlText)
		if err != nil {
			status = "failed"
			detail = err.Error()
		} else {
			rows, columns, truncated, err := scanSQLRows(queryRows, 100)
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
	logItem, logErr := s.cfg.Store.CreatePlatformItem("sql_logs", model.PlatformItemRequest{
		Name:        order.Name,
		Type:        "work_order",
		Status:      status,
		TargetID:    id,
		OwnerID:     s.currentUserID(r),
		Description: detail,
		Metadata:    metadata,
	})
	if logErr != nil {
		writeError(w, http.StatusInternalServerError, logErr.Error())
		return
	}
	if status == "failed" {
		writeJSON(w, http.StatusBadRequest, logItem)
		return
	}
	nextMetadata := map[string]any{}
	for key, value := range order.Metadata {
		nextMetadata[key] = value
	}
	nextMetadata["sql"] = sqlText
	nextMetadata["rows_affected"] = rowsAffected
	nextMetadata["executed_at"] = time.Now().UTC()
	_, _ = s.cfg.Store.UpdatePlatformItem("sql_work_orders", id, model.PlatformItemRequest{Status: "executed", Metadata: nextMetadata})
	_ = s.audit(r, "sql_work_order.execute", id, "", "executed sql work order")
	writeJSON(w, http.StatusOK, logItem)
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
