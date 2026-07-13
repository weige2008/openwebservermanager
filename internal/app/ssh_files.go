package app

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"openwebservermanager/internal/model"
	sshrunner "openwebservermanager/internal/ssh"
	"openwebservermanager/internal/store"
)

type sshFileEntry struct {
	Name     string    `json:"name"`
	Path     string    `json:"path"`
	IsDir    bool      `json:"is_dir"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
}

func (s *Server) handleSSHFiles(w http.ResponseWriter, r *http.Request) {
	parts := splitPath(strings.TrimPrefix(strings.Trim(r.URL.Path, "/"), "api/connections/"))
	if len(parts) < 2 || parts[1] != "sftp" {
		writeError(w, http.StatusNotFound, "sftp endpoint not found")
		return
	}
	action := ""
	if len(parts) > 2 {
		action = parts[2]
	}
	operation := sshFileOperation(action, r.Method)
	session, server, credential, secret, ok := s.sshFileTarget(w, r, parts[0], operation)
	if !ok {
		return
	}
	switch {
	case action == "" && r.Method == http.MethodGet:
		s.handleSSHFileList(w, r, session, server, credential, secret)
	case action == "" && r.Method == http.MethodDelete:
		s.handleSSHFileDelete(w, r, session, server, credential, secret)
	case action == "download" && r.Method == http.MethodGet:
		s.handleSSHFileDownload(w, r, session, server, credential, secret)
	case action == "upload" && r.Method == http.MethodPost:
		s.handleSSHFileUpload(w, r, session, server, credential, secret)
	case action == "write" && r.Method == http.MethodPost:
		s.handleSSHFileWrite(w, r, session, server, credential, secret)
	case action == "mkdir" && r.Method == http.MethodPost:
		s.handleSSHFileMkdir(w, r, session, server, credential, secret)
	case action == "copy" && r.Method == http.MethodPost:
		s.handleSSHFileCopy(w, r, session, server, credential, secret)
	case action == "rename" && r.Method == http.MethodPost:
		s.handleSSHFileRename(w, r, session, server, credential, secret)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func sshFileOperation(action, method string) string {
	switch {
	case action == "" && method == http.MethodGet:
		return "list"
	case action == "" && method == http.MethodDelete:
		return "delete"
	case action == "download":
		return "download"
	case action == "upload":
		return "upload"
	case action == "write":
		return "write"
	case action == "mkdir":
		return "upload"
	case action == "copy":
		return "copy"
	case action == "rename":
		return "rename"
	default:
		return "access"
	}
}

func (s *Server) sshFileTarget(w http.ResponseWriter, r *http.Request, sessionID, operation string) (model.ConnectionSession, model.Server, model.Credential, store.CredentialSecret, bool) {
	existing, exists := s.cfg.Store.GetSession(sessionID)
	if exists && existing.Protocol == model.ProtocolSSH && !s.canControlSession(r, existing) {
		if err := s.recordSSHFileDenied(r, existing, operation, "session_access", r.URL.Query().Get("path")); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return model.ConnectionSession{}, model.Server{}, model.Credential{}, store.CredentialSecret{}, false
		}
		writeError(w, http.StatusForbidden, "session access denied")
		return model.ConnectionSession{}, model.Server{}, model.Credential{}, store.CredentialSecret{}, false
	}
	session, server, credential, secret, ok := s.connectionParts(w, r, sessionID, model.ProtocolSSH)
	if !ok {
		return model.ConnectionSession{}, model.Server{}, model.Credential{}, store.CredentialSecret{}, false
	}
	platform, err := s.cfg.Store.PlatformBootstrap()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return model.ConnectionSession{}, model.Server{}, model.Credential{}, store.CredentialSecret{}, false
	}
	userID, isAdmin := s.accessUser(r)
	if !isAccessAuthorized(platform, model.ProtocolSSH, session.ServerID, userID, isAdmin) {
		if err := s.recordSSHFileDenied(r, session, operation, "asset_authorization", r.URL.Query().Get("path")); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return model.ConnectionSession{}, model.Server{}, model.Credential{}, store.CredentialSecret{}, false
		}
		writeError(w, http.StatusForbidden, "asset access denied")
		return model.ConnectionSession{}, model.Server{}, model.Credential{}, store.CredentialSecret{}, false
	}
	policy := s.sshAccessPolicy()
	if !boolPtrValue(session.FileTransferEnabled, policy.FileTransferEnabled) {
		if err := s.recordSSHFileDenied(r, session, operation, "file_transfer_disabled", r.URL.Query().Get("path")); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return model.ConnectionSession{}, model.Server{}, model.Credential{}, store.CredentialSecret{}, false
		}
		writeError(w, http.StatusForbidden, "ssh file transfer is disabled")
		return model.ConnectionSession{}, model.Server{}, model.Credential{}, store.CredentialSecret{}, false
	}
	return session, server, credential, secret, true
}

func (s *Server) openSSHFileClient(session model.ConnectionSession, server model.Server, credential model.Credential, secret store.CredentialSecret) (*sshrunner.FileClient, error) {
	return sshrunner.OpenFileClient(server, credential, secret, filepath.Join(s.cfg.DataDir, "known_hosts"), s.sshSessionDialContext(session))
}

func (s *Server) handleSSHFileList(w http.ResponseWriter, r *http.Request, session model.ConnectionSession, server model.Server, credential model.Credential, secret store.CredentialSecret) {
	remotePath, err := cleanRemotePath(r.URL.Query().Get("path"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.requireSSHFilePermission(w, r, session, "list", remotePath) {
		return
	}
	client, err := s.openSSHFileClient(session, server, credential, secret)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	defer client.Close()
	if remotePath == "." {
		if cwd, cwdErr := client.Getwd(); cwdErr == nil && strings.TrimSpace(cwd) != "" {
			remotePath = path.Clean(cwd)
		}
	}
	entries, err := client.ReadDir(remotePath)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	result := []sshFileEntry{}
	for _, entry := range entries {
		entryPath := path.Join(remotePath, entry.Name())
		if !s.sshFileListEntryVisible(session, entryPath, s.currentUserID(r), s.isAdminRequest(r)) {
			continue
		}
		result = append(result, sshFileEntry{
			Name:     entry.Name(),
			Path:     entryPath,
			IsDir:    entry.IsDir(),
			Size:     entry.Size(),
			Modified: entry.ModTime().UTC(),
		})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].IsDir != result[j].IsDir {
			return result[i].IsDir
		}
		return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
	})
	if err := s.recordSSHFileLog(r, session, "list", "success", remotePath, map[string]any{"entry_count": len(result)}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "connection.sftp.list", session.ID, model.ProtocolSSH, "listed ssh files")
	writeJSON(w, http.StatusOK, map[string]any{"path": remotePath, "entries": result})
}

func (s *Server) handleSSHFileDownload(w http.ResponseWriter, r *http.Request, session model.ConnectionSession, server model.Server, credential model.Credential, secret store.CredentialSecret) {
	remotePath, err := cleanRemotePath(r.URL.Query().Get("path"))
	if err != nil || remotePath == "." || remotePath == "/" {
		writeError(w, http.StatusBadRequest, "file path is required")
		return
	}
	if !s.requireSSHFilePermission(w, r, session, "download", remotePath) {
		return
	}
	client, err := s.openSSHFileClient(session, server, credential, secret)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	defer client.Close()
	info, err := client.Stat(remotePath)
	if err != nil {
		writeError(w, http.StatusNotFound, "file not found")
		return
	}
	if !info.Mode().IsRegular() {
		writeError(w, http.StatusBadRequest, "path is not a regular file")
		return
	}
	file, err := client.Open(remotePath)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	defer file.Close()
	if err := s.recordSSHFileLog(r, session, "download", "success", remotePath, map[string]any{"size": info.Size()}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "connection.sftp.download", session.ID, model.ProtocolSSH, "downloaded ssh file")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeAttachmentName(path.Base(remotePath))+`"`)
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	_, _ = io.Copy(w, file)
}

func (s *Server) handleSSHFileUpload(w http.ResponseWriter, r *http.Request, session model.ConnectionSession, server model.Server, credential model.Credential, secret store.CredentialSecret) {
	r.Body = http.MaxBytesReader(w, r.Body, 512<<20)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid multipart upload: "+err.Error())
		return
	}
	input, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "file is required")
		return
	}
	defer input.Close()
	fileName := strings.TrimSpace(r.FormValue("filename"))
	if fileName == "" && header != nil {
		fileName = header.Filename
	}
	fileName = safeUploadedFilename(fileName)
	if fileName == "" || fileName == "." || fileName == ".." || strings.Contains(fileName, "/") {
		writeError(w, http.StatusBadRequest, "filename is required")
		return
	}
	directory, err := cleanRemotePath(r.FormValue("path"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	target := path.Join(directory, fileName)
	client, err := s.openSSHFileClient(session, server, credential, secret)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	defer client.Close()
	if directory == "." {
		if cwd, cwdErr := client.Getwd(); cwdErr == nil && strings.TrimSpace(cwd) != "" {
			directory = path.Clean(cwd)
			target = path.Join(directory, fileName)
		}
	}
	if info, statErr := client.Stat(directory); statErr != nil || !info.IsDir() {
		writeError(w, http.StatusBadRequest, "upload directory not found")
		return
	}
	info, statErr := client.Stat(target)
	exists := statErr == nil
	if statErr != nil && !os.IsNotExist(statErr) {
		writeError(w, http.StatusBadGateway, statErr.Error())
		return
	}
	if exists && !info.Mode().IsRegular() {
		writeError(w, http.StatusBadRequest, "target is not a regular file")
		return
	}
	permission := "upload"
	if exists {
		permission = "edit"
	}
	if !s.requireSSHFilePermission(w, r, session, permission, target) {
		return
	}
	logItem, err := s.beginSSHFileLog(r, session, permission, target)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	temporary := remoteTemporaryPath(target, session.ID, "upload")
	backup := remoteTemporaryPath(target, session.ID, "backup")
	output, err := client.Create(temporary)
	if err != nil {
		_ = s.finishSSHFileLog(r, logItem, "failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	written, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if copyErr != nil || closeErr != nil {
		_ = client.Remove(temporary)
		err = errors.Join(copyErr, closeErr)
		_ = s.finishSSHFileLog(r, logItem, "failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	_ = client.Chmod(temporary, 0o660)
	if exists {
		if err := client.Rename(target, backup); err != nil {
			_ = client.Remove(temporary)
			_ = s.finishSSHFileLog(r, logItem, "failed", map[string]any{"error": err.Error()})
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
	}
	if err := client.Rename(temporary, target); err != nil {
		if exists {
			_ = client.Rename(backup, target)
		}
		_ = client.Remove(temporary)
		_ = s.finishSSHFileLog(r, logItem, "failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := s.finishSSHFileLog(r, logItem, "success", map[string]any{"size": written, "filename": fileName}); err != nil {
		_ = client.Remove(target)
		if exists {
			_ = client.Rename(backup, target)
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if exists {
		if err := client.Remove(backup); err != nil {
			_ = client.Remove(target)
			_ = client.Rename(backup, target)
			_ = s.finishSSHFileLog(r, logItem, "failed", map[string]any{"error": "remove upload backup: " + err.Error()})
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
	}
	_ = s.audit(r, "connection.sftp."+permission, session.ID, model.ProtocolSSH, "uploaded ssh file")
	writeJSON(w, http.StatusCreated, map[string]any{"path": target, "name": fileName, "size": written})
}

func (s *Server) handleSSHFileDelete(w http.ResponseWriter, r *http.Request, session model.ConnectionSession, server model.Server, credential model.Credential, secret store.CredentialSecret) {
	remotePath, err := cleanRemotePath(r.URL.Query().Get("path"))
	if err != nil || remotePath == "." || remotePath == "/" {
		writeError(w, http.StatusBadRequest, "file path is required")
		return
	}
	if !s.requireSSHFilePermission(w, r, session, "delete", remotePath) {
		return
	}
	client, err := s.openSSHFileClient(session, server, credential, secret)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	defer client.Close()
	info, err := client.Lstat(remotePath)
	if err != nil {
		writeError(w, http.StatusNotFound, "file not found")
		return
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		writeError(w, http.StatusBadRequest, "path is not a regular file or directory")
		return
	}
	logItem, err := s.beginSSHFileLog(r, session, "delete", remotePath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	backup := remoteTemporaryPath(remotePath, session.ID, "delete")
	if err := client.Rename(remotePath, backup); err != nil {
		_ = s.finishSSHFileLog(r, logItem, "failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := s.finishSSHFileLog(r, logItem, "success", map[string]any{"size": info.Size()}); err != nil {
		_ = client.Rename(backup, remotePath)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := removeSSHRemotePath(client, backup, info); err != nil {
		_ = client.Rename(backup, remotePath)
		_ = s.finishSSHFileLog(r, logItem, "failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	_ = s.audit(r, "connection.sftp.delete", session.ID, model.ProtocolSSH, "deleted ssh file or directory")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleSSHFileWrite(w http.ResponseWriter, r *http.Request, session model.ConnectionSession, server model.Server, credential model.Credential, secret store.CredentialSecret) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<20)
	var req fileWriteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	remotePath, err := cleanRemotePath(req.Path)
	if err != nil || remotePath == "." || remotePath == "/" {
		writeError(w, http.StatusBadRequest, "file path is required")
		return
	}
	content := []byte(req.Content)
	if strings.EqualFold(strings.TrimSpace(req.Encoding), "base64") {
		decoded, decodeErr := base64.StdEncoding.DecodeString(req.Content)
		if decodeErr != nil {
			writeError(w, http.StatusBadRequest, "invalid base64 content")
			return
		}
		content = decoded
	}
	client, err := s.openSSHFileClient(session, server, credential, secret)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	defer client.Close()
	info, exists, err := sshRemotePathInfo(client, remotePath)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if exists && !info.Mode().IsRegular() {
		writeError(w, http.StatusBadRequest, "target is not a regular file")
		return
	}
	permission := "upload"
	if exists {
		permission = "edit"
	}
	if !s.requireSSHFilePermission(w, r, session, permission, remotePath) {
		return
	}
	if err := requireSSHRemoteParent(client, remotePath); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	logItem, err := s.beginSSHFileLog(r, session, "write", remotePath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	temporary := remoteTemporaryPath(remotePath, session.ID, "write")
	backup := remoteTemporaryPath(remotePath, session.ID, "backup")
	output, err := client.Create(temporary)
	if err != nil {
		_ = s.finishSSHFileLog(r, logItem, "failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	written, copyErr := io.Copy(output, bytes.NewReader(content))
	closeErr := output.Close()
	if copyErr != nil || closeErr != nil {
		_ = client.Remove(temporary)
		err = errors.Join(copyErr, closeErr)
		_ = s.finishSSHFileLog(r, logItem, "failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	_ = client.Chmod(temporary, 0o660)
	if exists {
		if err := client.Rename(remotePath, backup); err != nil {
			_ = client.Remove(temporary)
			_ = s.finishSSHFileLog(r, logItem, "failed", map[string]any{"error": err.Error()})
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
	}
	if err := client.Rename(temporary, remotePath); err != nil {
		if exists {
			_ = client.Rename(backup, remotePath)
		}
		_ = client.Remove(temporary)
		_ = s.finishSSHFileLog(r, logItem, "failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := s.finishSSHFileLog(r, logItem, "success", map[string]any{"size": written, "permission": permission}); err != nil {
		_ = client.Remove(remotePath)
		if exists {
			_ = client.Rename(backup, remotePath)
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if exists {
		if err := client.Remove(backup); err != nil {
			_ = client.Remove(remotePath)
			_ = client.Rename(backup, remotePath)
			_ = s.finishSSHFileLog(r, logItem, "failed", map[string]any{"error": "remove write backup: " + err.Error()})
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
	}
	_ = s.audit(r, "connection.sftp.write", session.ID, model.ProtocolSSH, "wrote ssh file")
	writeJSON(w, http.StatusCreated, map[string]any{"path": remotePath, "size": written})
}

func (s *Server) handleSSHFileMkdir(w http.ResponseWriter, r *http.Request, session model.ConnectionSession, server model.Server, credential model.Credential, secret store.CredentialSecret) {
	var req filePathRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	remotePath, err := cleanRemotePath(req.Path)
	if err != nil || remotePath == "." || remotePath == "/" {
		writeError(w, http.StatusBadRequest, "directory path is required")
		return
	}
	if !s.requireSSHFilePermission(w, r, session, "upload", remotePath) {
		return
	}
	client, err := s.openSSHFileClient(session, server, credential, secret)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	defer client.Close()
	if _, exists, statErr := sshRemotePathInfo(client, remotePath); statErr != nil {
		writeError(w, http.StatusBadGateway, statErr.Error())
		return
	} else if exists {
		writeError(w, http.StatusConflict, "destination exists")
		return
	}
	if err := requireSSHRemoteParent(client, remotePath); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	logItem, err := s.beginSSHFileLog(r, session, "mkdir", remotePath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := client.Mkdir(remotePath); err != nil {
		_ = s.finishSSHFileLog(r, logItem, "failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := s.finishSSHFileLog(r, logItem, "success", nil); err != nil {
		_ = client.RemoveDirectory(remotePath)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "connection.sftp.mkdir", session.ID, model.ProtocolSSH, "created ssh directory")
	writeJSON(w, http.StatusCreated, map[string]any{"path": remotePath})
}

func (s *Server) handleSSHFileRename(w http.ResponseWriter, r *http.Request, session model.ConnectionSession, server model.Server, credential model.Credential, secret store.CredentialSecret) {
	var req fileMoveRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	source, destination, ok := cleanSSHMovePaths(w, req)
	if !ok {
		return
	}
	if !s.requireSSHFilePermission(w, r, session, "rename", source) || !s.requireSSHFilePermission(w, r, session, "paste", destination) {
		return
	}
	client, err := s.openSSHFileClient(session, server, credential, secret)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	defer client.Close()
	sourceInfo, sourceExists, err := sshRemotePathInfo(client, source)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if !sourceExists {
		writeError(w, http.StatusNotFound, "source not found")
		return
	}
	if !sourceInfo.IsDir() && !sourceInfo.Mode().IsRegular() {
		writeError(w, http.StatusBadRequest, "source is not a regular file or directory")
		return
	}
	if sourceInfo.IsDir() && sshPathSameOrChild(source, destination) {
		writeError(w, http.StatusBadRequest, "cannot move a directory into itself")
		return
	}
	destinationInfo, destinationExists, err := sshRemotePathInfo(client, destination)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if destinationExists {
		if !req.Overwrite {
			writeError(w, http.StatusConflict, "destination exists")
			return
		}
		if !destinationInfo.IsDir() && !destinationInfo.Mode().IsRegular() {
			writeError(w, http.StatusBadRequest, "destination is not a regular file or directory")
			return
		}
		if !s.requireSSHFilePermission(w, r, session, "edit", destination) {
			return
		}
	}
	if err := requireSSHRemoteParent(client, destination); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	logItem, err := s.beginSSHFileLog(r, session, "rename", source)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	backup := remoteTemporaryPath(destination, session.ID, "rename-backup")
	if destinationExists {
		if err := client.Rename(destination, backup); err != nil {
			_ = s.finishSSHFileLog(r, logItem, "failed", map[string]any{"error": err.Error()})
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
	}
	rollback := func() {
		_ = client.Rename(destination, source)
		if destinationExists {
			_ = client.Rename(backup, destination)
		}
	}
	if err := client.Rename(source, destination); err != nil {
		if destinationExists {
			_ = client.Rename(backup, destination)
		}
		_ = s.finishSSHFileLog(r, logItem, "failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	metadata := map[string]any{"source_path": source, "destination_path": destination, "overwrite": req.Overwrite}
	if err := s.finishSSHFileLog(r, logItem, "success", metadata); err != nil {
		rollback()
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if destinationExists {
		if err := removeSSHRemotePath(client, backup, destinationInfo); err != nil {
			rollback()
			_ = s.finishSSHFileLog(r, logItem, "failed", map[string]any{"error": "remove rename backup: " + err.Error()})
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
	}
	_ = s.audit(r, "connection.sftp.rename", session.ID, model.ProtocolSSH, "renamed ssh file or directory")
	writeJSON(w, http.StatusOK, map[string]any{"path": destination})
}

func (s *Server) handleSSHFileCopy(w http.ResponseWriter, r *http.Request, session model.ConnectionSession, server model.Server, credential model.Credential, secret store.CredentialSecret) {
	var req fileMoveRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	source, destination, ok := cleanSSHMovePaths(w, req)
	if !ok {
		return
	}
	if !s.requireSSHFilePermission(w, r, session, "copy", source) || !s.requireSSHFilePermission(w, r, session, "paste", destination) {
		return
	}
	client, err := s.openSSHFileClient(session, server, credential, secret)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	defer client.Close()
	sourceInfo, sourceExists, err := sshRemotePathInfo(client, source)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if !sourceExists {
		writeError(w, http.StatusNotFound, "source not found")
		return
	}
	if !sourceInfo.IsDir() && !sourceInfo.Mode().IsRegular() {
		writeError(w, http.StatusBadRequest, "source is not a regular file or directory")
		return
	}
	if sourceInfo.IsDir() && sshPathSameOrChild(source, destination) {
		writeError(w, http.StatusBadRequest, "cannot copy a directory into itself")
		return
	}
	destinationInfo, destinationExists, err := sshRemotePathInfo(client, destination)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if destinationExists {
		if !req.Overwrite {
			writeError(w, http.StatusConflict, "destination exists")
			return
		}
		if !destinationInfo.IsDir() && !destinationInfo.Mode().IsRegular() {
			writeError(w, http.StatusBadRequest, "destination is not a regular file or directory")
			return
		}
		if !s.requireSSHFilePermission(w, r, session, "edit", destination) {
			return
		}
	}
	if err := requireSSHRemoteParent(client, destination); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	logItem, err := s.beginSSHFileLog(r, session, "copy", source)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	backup := remoteTemporaryPath(destination, session.ID, "copy-backup")
	if destinationExists {
		if err := client.Rename(destination, backup); err != nil {
			_ = s.finishSSHFileLog(r, logItem, "failed", map[string]any{"error": err.Error()})
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
	}
	rollback := func() {
		_ = removeSSHRemotePath(client, destination, sourceInfo)
		if destinationExists {
			_ = client.Rename(backup, destination)
		}
	}
	written, err := copySSHRemotePath(client, source, destination, sourceInfo)
	if err != nil {
		rollback()
		_ = s.finishSSHFileLog(r, logItem, "failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	metadata := map[string]any{"source_path": source, "destination_path": destination, "overwrite": req.Overwrite, "size": written}
	if err := s.finishSSHFileLog(r, logItem, "success", metadata); err != nil {
		rollback()
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if destinationExists {
		if err := removeSSHRemotePath(client, backup, destinationInfo); err != nil {
			rollback()
			_ = s.finishSSHFileLog(r, logItem, "failed", map[string]any{"error": "remove copy backup: " + err.Error()})
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
	}
	_ = s.audit(r, "connection.sftp.copy", session.ID, model.ProtocolSSH, "copied ssh file or directory")
	writeJSON(w, http.StatusCreated, map[string]any{"path": destination, "size": written})
}

func cleanSSHMovePaths(w http.ResponseWriter, req fileMoveRequest) (string, string, bool) {
	source, sourceErr := cleanRemotePath(req.Path)
	destination, destinationErr := cleanRemotePath(req.Destination)
	if sourceErr != nil || destinationErr != nil || source == "." || source == "/" || destination == "." || destination == "/" || strings.TrimSpace(req.Destination) == "" {
		writeError(w, http.StatusBadRequest, "source and destination are required")
		return "", "", false
	}
	if source == destination {
		writeError(w, http.StatusBadRequest, "source and destination are the same")
		return "", "", false
	}
	return source, destination, true
}

func sshRemotePathInfo(client *sshrunner.FileClient, remotePath string) (os.FileInfo, bool, error) {
	info, err := client.Lstat(remotePath)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return info, true, nil
}

func requireSSHRemoteParent(client *sshrunner.FileClient, remotePath string) error {
	parent := path.Dir(remotePath)
	info, exists, err := sshRemotePathInfo(client, parent)
	if err != nil {
		return err
	}
	if !exists || !info.IsDir() {
		return errors.New("parent directory not found")
	}
	return nil
}

func removeSSHRemotePath(client *sshrunner.FileClient, remotePath string, info os.FileInfo) error {
	if info != nil && info.IsDir() {
		return client.RemoveAll(remotePath)
	}
	return client.Remove(remotePath)
}

func copySSHRemotePath(client *sshrunner.FileClient, source, destination string, info os.FileInfo) (int64, error) {
	if info.IsDir() {
		if err := client.Mkdir(destination); err != nil {
			return 0, err
		}
		_ = client.Chmod(destination, info.Mode().Perm())
		entries, err := client.ReadDir(source)
		if err != nil {
			return 0, err
		}
		var written int64
		for _, entry := range entries {
			if !entry.IsDir() && !entry.Mode().IsRegular() {
				return written, errors.New("source contains a non-regular file")
			}
			childWritten, err := copySSHRemotePath(client, path.Join(source, entry.Name()), path.Join(destination, entry.Name()), entry)
			written += childWritten
			if err != nil {
				return written, err
			}
		}
		return written, nil
	}
	if !info.Mode().IsRegular() {
		return 0, errors.New("source is not a regular file")
	}
	input, err := client.Open(source)
	if err != nil {
		return 0, err
	}
	defer input.Close()
	output, err := client.Create(destination)
	if err != nil {
		return 0, err
	}
	written, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if copyErr != nil || closeErr != nil {
		return written, errors.Join(copyErr, closeErr)
	}
	_ = client.Chmod(destination, info.Mode().Perm())
	return written, nil
}

func sshPathSameOrChild(parent, candidate string) bool {
	parent = path.Clean(parent)
	candidate = path.Clean(candidate)
	return candidate == parent || strings.HasPrefix(candidate, strings.TrimSuffix(parent, "/")+"/")
}

func cleanRemotePath(value string) (string, error) {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if strings.ContainsRune(value, '\x00') || strings.ContainsAny(value, "\r\n") || len(value) > 4096 {
		return "", errors.New("remote path is invalid")
	}
	if value == "" {
		return ".", nil
	}
	return path.Clean(value), nil
}

func remoteTemporaryPath(target, sessionID, operation string) string {
	name := fmt.Sprintf(".%s.owsm-%s-%s-%d", path.Base(target), operation, sessionID, time.Now().UTC().UnixNano())
	return path.Join(path.Dir(target), name)
}

func (s *Server) requireSSHFilePermission(w http.ResponseWriter, r *http.Request, session model.ConnectionSession, action, remotePath string) bool {
	if s.isAdminRequest(r) {
		return true
	}
	allowed, matched := s.filePermissionAllowed("asset", session.ServerID, action, remotePath, s.currentUserID(r))
	if action == "list" {
		allowed, matched = s.fileListPermissionAllowed("asset", session.ServerID, remotePath, s.currentUserID(r))
	}
	if !matched || allowed {
		return true
	}
	if err := s.recordSSHFileDenied(r, session, action, "authorization_strategy", remotePath); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return false
	}
	writeError(w, http.StatusForbidden, "file permission denied: "+action)
	return false
}

func (s *Server) sshFileListEntryVisible(session model.ConnectionSession, remotePath, userID string, isAdmin bool) bool {
	if isAdmin {
		return true
	}
	allowed, matched := s.fileListPermissionAllowed("asset", session.ServerID, remotePath, userID)
	return !matched || allowed
}

func (s *Server) sshFileLogRequest(r *http.Request, session model.ConnectionSession, action, status, remotePath string, metadata map[string]any) model.PlatformItemRequest {
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["session_id"] = session.ID
	metadata["asset_id"] = session.ServerID
	metadata["protocol"] = session.Protocol
	metadata["path"] = remotePath
	metadata["client_ip"] = s.clientIP(r)
	return model.PlatformItemRequest{
		Name:        remotePath,
		Type:        action,
		Status:      status,
		Protocol:    model.ProtocolSSH,
		TargetID:    session.ID,
		OwnerID:     s.currentUserID(r),
		Description: "ssh file " + action + " " + status,
		Metadata:    metadata,
	}
}

func (s *Server) recordSSHFileLog(r *http.Request, session model.ConnectionSession, action, status, remotePath string, metadata map[string]any) error {
	return s.createFileLog(r, s.sshFileLogRequest(r, session, action, status, remotePath, metadata))
}

func (s *Server) recordSSHFileDenied(r *http.Request, session model.ConnectionSession, action, reason, remotePath string) error {
	if err := s.recordSSHFileLog(r, session, action, "denied", remotePath, map[string]any{"reason": reason}); err != nil {
		return err
	}
	_ = s.audit(r, "connection.sftp."+action+".denied", session.ID, model.ProtocolSSH, "denied ssh file "+action+": "+reason)
	return nil
}

func (s *Server) beginSSHFileLog(r *http.Request, session model.ConnectionSession, action, remotePath string) (model.PlatformItem, error) {
	request := s.sshFileLogRequest(r, session, action, "requested", remotePath, nil)
	item, err := s.cfg.Store.CreatePlatformItem("file_logs", request)
	if err != nil {
		detail := "persist file log failed: " + err.Error()
		_ = s.audit(r, "file.log.persist_failed", session.ID, model.ProtocolSSH, detail)
		return model.PlatformItem{}, errors.New(detail)
	}
	return item, nil
}

func (s *Server) finishSSHFileLog(r *http.Request, item model.PlatformItem, status string, metadata map[string]any) error {
	item.Status = status
	item.Description = "ssh file " + item.Type + " " + status
	item.Metadata = cloneMetadata(item.Metadata)
	for key, value := range metadata {
		item.Metadata[key] = value
	}
	if _, err := s.cfg.Store.SavePlatformItem("file_logs", item); err != nil {
		detail := "persist file log failed: " + err.Error()
		_ = s.audit(r, "file.log.persist_failed", item.TargetID, model.ProtocolSSH, detail)
		return errors.New(detail)
	}
	return nil
}
