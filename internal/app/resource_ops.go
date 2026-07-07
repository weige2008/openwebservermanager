package app

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"openwebservermanager/internal/model"

	_ "modernc.org/sqlite"
)

type importRequest struct {
	Items          []model.PlatformItemRequest `json:"items"`
	UpdateExisting bool                        `json:"update_existing"`
	Format         string                      `json:"format"`
	Content        string                      `json:"content"`
}

type authorizationBulkRequest struct {
	NamePrefix       string         `json:"name_prefix"`
	Type             string         `json:"type"`
	Status           string         `json:"status"`
	SubjectIDs       []string       `json:"subject_ids"`
	OwnerIDs         []string       `json:"owner_ids"`
	UserIDs          []string       `json:"user_ids"`
	DepartmentIDs    []string       `json:"department_ids"`
	TargetIDs        []string       `json:"target_ids"`
	AssetIDs         []string       `json:"asset_ids"`
	AssetGroupIDs    []string       `json:"asset_group_ids"`
	WebAssetIDs      []string       `json:"web_asset_ids"`
	WebGroupIDs      []string       `json:"web_group_ids"`
	DatabaseIDs      []string       `json:"database_ids"`
	DatabaseGroupIDs []string       `json:"database_group_ids"`
	ExpiresAt        string         `json:"expires_at"`
	Metadata         map[string]any `json:"metadata"`
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

type storageUsageInfo struct {
	Bytes          int64  `json:"bytes"`
	Files          int    `json:"files"`
	Dirs           int    `json:"dirs"`
	LimitBytes     int64  `json:"limit_bytes,omitempty"`
	AvailableBytes int64  `json:"available_bytes,omitempty"`
	Used           string `json:"used"`
	Limit          string `json:"limit,omitempty"`
	CheckedAt      string `json:"checked_at"`
}

var (
	errStoragePermissionDenied = errors.New("storage permission denied")
	errStorageSpecialFile      = errors.New("storage path is not a regular file")
	errCertificateNotUsable    = errors.New("certificate is not usable")
)

type certificateRequest struct {
	Name   string   `json:"name"`
	Domain string   `json:"domain"`
	DNS    []string `json:"dns"`
	IP     []string `json:"ip"`
	Days   int      `json:"days"`
}

type certificateACMERequest struct {
	Name          string         `json:"name"`
	Domain        string         `json:"domain"`
	DNS           []string       `json:"dns"`
	IP            []string       `json:"ip"`
	Email         string         `json:"email"`
	DirectoryURL  string         `json:"directory_url"`
	ChallengeType string         `json:"challenge_type"`
	DNSProviderID string         `json:"dns_provider_id"`
	Days          int            `json:"days"`
	Default       bool           `json:"default"`
	MTLSEnabled   bool           `json:"mtls_enabled"`
	Metadata      map[string]any `json:"metadata"`
}

type dnsProviderRequest struct {
	Name     string         `json:"name"`
	Provider string         `json:"provider"`
	Zone     string         `json:"zone"`
	Token    string         `json:"token"`
	Metadata map[string]any `json:"metadata"`
}

type certificateMTLSRequest struct {
	Enabled  bool   `json:"enabled"`
	ClientCA string `json:"client_ca"`
}

type sqlExecuteRequest struct {
	SQL          string `json:"sql"`
	MFACode      string `json:"mfa_code"`
	RecoveryCode string `json:"recovery_code"`
}

type workOrderDecisionRequest struct {
	Note string `json:"note"`
}

func (s *Server) handleResourceOperation(w http.ResponseWriter, r *http.Request, path string) bool {
	switch {
	case path == "admin/assets/export":
		s.handleAssetExport(w, r)
		return true
	case path == "admin/users/export":
		s.handleUserExport(w, r)
		return true
	case path == "admin/assets/import":
		s.handleAssetImport(w, r)
		return true
	case path == "admin/users/import":
		s.handleUserImport(w, r)
		return true
	case strings.HasPrefix(path, "admin/authorizations/") && strings.HasSuffix(path, "/bulk"):
		parts := splitPath(strings.TrimPrefix(path, "admin/authorizations/"))
		if len(parts) == 2 && parts[1] == "bulk" {
			s.handleAuthorizationBulk(w, r, parts[0])
			return true
		}
		return false
	case strings.HasPrefix(path, "admin/authorizations/") && strings.HasSuffix(path, "/export"):
		route := strings.TrimSuffix(strings.TrimPrefix(path, "admin/authorizations/"), "/export")
		collection, ok := authorizationCollectionRoutes[route]
		if !ok {
			return false
		}
		s.handlePlatformCollectionExport(w, r, route, collection)
		return true
	case path == "admin/certificates/self-signed":
		s.handleCertificateSelfSigned(w, r)
		return true
	case path == "admin/certificates/upload":
		s.handleCertificateUpload(w, r)
		return true
	case path == "admin/certificates/acme":
		s.handleCertificateACME(w, r)
		return true
	case path == "admin/certificates/dns-providers":
		s.handleCertificateDNSProviders(w, r)
		return true
	case path == "admin/proxy-services":
		s.handleProxyServices(w, r)
		return true
	case path == "admin/system-settings/smtp/test":
		s.handleSMTPTest(w, r)
		return true
	case path == "admin/system-settings/llm/test":
		s.handleLLMTest(w, r)
		return true
	case path == "admin/system-settings/oidc/test":
		s.handleOIDCTest(w, r)
		return true
	case path == "admin/system-settings/ldap/test":
		s.handleLDAPTest(w, r)
		return true
	case path == "admin/system-settings/wecom/test":
		s.handleWeComTest(w, r)
		return true
	case path == "admin/audit/access-stats":
		s.handleAccessStats(w, r)
		return true
	case strings.HasPrefix(path, "admin/audit/") && strings.HasSuffix(path, "/export"):
		parts := splitPath(strings.TrimPrefix(path, "admin/audit/"))
		if len(parts) == 2 && parts[1] == "export" {
			s.handleAuditExport(w, r, parts[0])
			return true
		}
		return false
	case strings.HasPrefix(path, "admin/") && strings.HasSuffix(path, "/export"):
		route := strings.TrimSuffix(strings.TrimPrefix(path, "admin/"), "/export")
		if strings.Contains(route, "/") {
			return false
		}
		collection, ok := adminCollectionRoutes[route]
		if !ok {
			return false
		}
		s.handlePlatformCollectionExport(w, r, route, collection)
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
	case strings.HasPrefix(path, "admin/backups/"):
		id := pathSegmentFromTrimmed(path, 2)
		s.handleBackupDelete(w, r, id)
		return true
	case strings.HasPrefix(path, "admin/certificates/") && strings.HasSuffix(path, "/download"):
		id := pathSegmentFromTrimmed(path, 2)
		s.handleCertificateDownload(w, r, id)
		return true
	case strings.HasPrefix(path, "admin/certificates/") && strings.HasSuffix(path, "/bundle"):
		id := pathSegmentFromTrimmed(path, 2)
		s.handleCertificateBundleDownload(w, r, id)
		return true
	case strings.HasPrefix(path, "admin/certificates/") && strings.HasSuffix(path, "/default"):
		id := pathSegmentFromTrimmed(path, 2)
		s.handleCertificateDefault(w, r, id)
		return true
	case strings.HasPrefix(path, "admin/certificates/") && strings.HasSuffix(path, "/mtls"):
		id := pathSegmentFromTrimmed(path, 2)
		s.handleCertificateMTLS(w, r, id)
		return true
	case strings.HasPrefix(path, "admin/certificates/") && strings.HasSuffix(path, "/logs"):
		id := pathSegmentFromTrimmed(path, 2)
		s.handleCertificateLogs(w, r, id)
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
	case path == "admin/gateway-groups/status":
		s.handleGatewayGroupStatus(w, r)
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
	case strings.HasPrefix(path, "admin/command-approvals/") && strings.HasSuffix(path, "/execute"):
		id := pathSegmentFromTrimmed(path, 2)
		s.handleCommandApprovalExecute(w, r, id)
		return true
	case strings.HasPrefix(path, "admin/command-approvals/") && strings.HasSuffix(path, "/approve"):
		id := pathSegmentFromTrimmed(path, 2)
		s.handleCommandApprovalDecision(w, r, id, "approved")
		return true
	case strings.HasPrefix(path, "admin/command-approvals/") && strings.HasSuffix(path, "/reject"):
		id := pathSegmentFromTrimmed(path, 2)
		s.handleCommandApprovalDecision(w, r, id, "rejected")
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
	exportedAt := time.Now().UTC()
	_ = s.audit(r, "assets.export", "assets", "", "exported assets")
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "json"
	}
	switch format {
	case "json":
		w.Header().Set("Content-Disposition", `attachment; filename="`+auditExportFilename("assets", exportedAt, "json")+`"`)
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "exported_at": exportedAt})
	case "csv":
		w.Header().Set("Content-Disposition", `attachment; filename="`+auditExportFilename("assets", exportedAt, "csv")+`"`)
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		writeAssetExportCSV(w, items)
	default:
		writeError(w, http.StatusBadRequest, "unsupported export format")
	}
}

func writeAssetExportCSV(w io.Writer, items []model.PlatformItem) {
	writer := csv.NewWriter(w)
	_ = writer.Write([]string{"name", "type", "status", "protocol", "host", "port", "username", "group", "owner_id", "parent_id", "target_id", "tags", "description", "metadata_json"})
	for _, item := range items {
		metadata, _ := json.Marshal(item.Metadata)
		_ = writer.Write([]string{
			item.Name,
			item.Type,
			item.Status,
			string(item.Protocol),
			item.Host,
			strconv.Itoa(item.Port),
			item.Username,
			item.Group,
			item.OwnerID,
			item.ParentID,
			item.TargetID,
			strings.Join(item.Tags, ","),
			item.Description,
			string(metadata),
		})
	}
	writer.Flush()
}

func (s *Server) handleUserExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	items, err := s.cfg.Store.ListPlatformItems("users")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	exportedAt := time.Now().UTC()
	_ = s.audit(r, "users.export", "users", "", "exported users")
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "json"
	}
	switch format {
	case "json":
		w.Header().Set("Content-Disposition", `attachment; filename="`+auditExportFilename("users", exportedAt, "json")+`"`)
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "exported_at": exportedAt})
	case "csv":
		w.Header().Set("Content-Disposition", `attachment; filename="`+auditExportFilename("users", exportedAt, "csv")+`"`)
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		writeUserExportCSV(w, items)
	default:
		writeError(w, http.StatusBadRequest, "unsupported export format")
	}
}

func writeUserExportCSV(w io.Writer, items []model.PlatformItem) {
	writer := csv.NewWriter(w)
	_ = writer.Write([]string{"name", "type", "status", "role", "group", "owner_id", "department_id", "tags", "online", "last_login_at", "last_login_ip", "description", "metadata_json"})
	for _, item := range items {
		metadata, _ := json.Marshal(item.Metadata)
		online, _ := metadataBoolValue(item.Metadata["online"])
		_ = writer.Write([]string{
			item.Name,
			item.Type,
			item.Status,
			firstMetadataString(item.Metadata, "role"),
			item.Group,
			item.OwnerID,
			firstMetadataString(item.Metadata, "department_id", "departmentId", "department"),
			strings.Join(item.Tags, ","),
			strconv.FormatBool(online),
			firstMetadataString(item.Metadata, "last_login_at"),
			firstMetadataString(item.Metadata, "last_login_ip"),
			item.Description,
			string(metadata),
		})
	}
	writer.Flush()
}

func (s *Server) handlePlatformCollectionExport(w http.ResponseWriter, r *http.Request, route, collection string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	items, err := s.cfg.Store.ListPlatformItems(collection)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	exportedAt := time.Now().UTC()
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "json"
	}
	_ = s.audit(r, collection+".export", collection, "", "exported "+collection)
	switch format {
	case "json":
		w.Header().Set("Content-Disposition", `attachment; filename="`+auditExportFilename(route, exportedAt, "json")+`"`)
		writeJSON(w, http.StatusOK, map[string]any{
			"collection":  collection,
			"items":       items,
			"exported_at": exportedAt,
		})
	case "csv":
		w.Header().Set("Content-Disposition", `attachment; filename="`+auditExportFilename(route, exportedAt, "csv")+`"`)
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		writePlatformCollectionExportCSV(w, items)
	default:
		writeError(w, http.StatusBadRequest, "unsupported export format")
	}
}

func writePlatformCollectionExportCSV(w io.Writer, items []model.PlatformItem) {
	writer := csv.NewWriter(w)
	_ = writer.Write([]string{"id", "module", "name", "type", "status", "protocol", "host", "port", "username", "group", "owner_id", "parent_id", "target_id", "tags", "permissions_json", "description", "created_at", "updated_at", "metadata_json"})
	for _, item := range items {
		permissions, _ := json.Marshal(item.Permissions)
		metadata, _ := json.Marshal(item.Metadata)
		_ = writer.Write([]string{
			item.ID,
			item.Module,
			item.Name,
			item.Type,
			item.Status,
			string(item.Protocol),
			item.Host,
			strconv.Itoa(item.Port),
			item.Username,
			item.Group,
			item.OwnerID,
			item.ParentID,
			item.TargetID,
			strings.Join(item.Tags, ","),
			string(permissions),
			item.Description,
			item.CreatedAt.Format(time.RFC3339Nano),
			item.UpdatedAt.Format(time.RFC3339Nano),
			string(metadata),
		})
	}
	writer.Flush()
}

func (s *Server) handleAuditExport(w http.ResponseWriter, r *http.Request, route string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	collection, ok := auditCollectionRoutes[route]
	if !ok {
		writeError(w, http.StatusNotFound, "audit collection not found")
		return
	}
	items, err := s.cfg.Store.ListPlatformItems(collection)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	exportedAt := time.Now().UTC()
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "json"
	}
	_ = s.audit(r, "audit."+collection+".export", collection, "", "exported audit logs")
	switch format {
	case "json":
		filename := auditExportFilename(route, exportedAt, "json")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		writeJSON(w, http.StatusOK, map[string]any{
			"collection":  collection,
			"items":       items,
			"exported_at": exportedAt,
		})
	case "csv":
		filename := auditExportFilename(route, exportedAt, "csv")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		writer := csv.NewWriter(w)
		_ = writer.Write([]string{"id", "module", "name", "type", "status", "protocol", "owner_id", "target_id", "host", "port", "username", "group", "description", "created_at", "updated_at", "metadata_json"})
		for _, item := range items {
			metadata, _ := json.Marshal(item.Metadata)
			_ = writer.Write([]string{
				item.ID,
				item.Module,
				item.Name,
				item.Type,
				item.Status,
				string(item.Protocol),
				item.OwnerID,
				item.TargetID,
				item.Host,
				strconv.Itoa(item.Port),
				item.Username,
				item.Group,
				item.Description,
				item.CreatedAt.Format(time.RFC3339Nano),
				item.UpdatedAt.Format(time.RFC3339Nano),
				string(metadata),
			})
		}
		writer.Flush()
	default:
		writeError(w, http.StatusBadRequest, "unsupported export format")
	}
}

func auditExportFilename(route string, exportedAt time.Time, ext string) string {
	safeRoute := strings.NewReplacer("/", "-", "\\", "-", `"`, "", "'", "").Replace(route)
	if safeRoute == "" {
		safeRoute = "audit"
	}
	return "openwebservermanager-" + safeRoute + "-" + exportedAt.Format("20060102-150405") + "." + ext
}

func decodeImportRequest(w http.ResponseWriter, r *http.Request, collection string) (importRequest, bool) {
	var req importRequest
	if requestWantsCSVImport(r) {
		defer r.Body.Close()
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		content, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return req, false
		}
		req.Format = "csv"
		req.Content = string(content)
		req.UpdateExisting = queryBool(r.URL.Query().Get("update_existing"))
	} else if !decodeJSON(w, r, &req) {
		return req, false
	}
	if len(req.Items) == 0 && (strings.EqualFold(strings.TrimSpace(req.Format), "csv") || strings.TrimSpace(req.Content) != "") {
		items, err := parsePlatformImportCSV(req.Content, collection)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return req, false
		}
		req.Items = items
	}
	return req, true
}

func requestWantsCSVImport(r *http.Request) bool {
	if strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("format")), "csv") {
		return true
	}
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	return contentType == "text/csv" || contentType == "application/csv"
}

func parsePlatformImportCSV(content, collection string) ([]model.PlatformItemRequest, error) {
	content = strings.TrimPrefix(content, "\ufeff")
	if strings.TrimSpace(content) == "" {
		return nil, errors.New("csv content is required")
	}
	reader := csv.NewReader(strings.NewReader(content))
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse csv: %w", err)
	}
	if len(records) == 0 {
		return nil, errors.New("csv header is required")
	}
	headers := make([]string, len(records[0]))
	for index, header := range records[0] {
		headers[index] = normalizeImportHeader(header)
	}
	items := []model.PlatformItemRequest{}
	for rowIndex, record := range records[1:] {
		if csvRecordBlank(record) {
			continue
		}
		item := model.PlatformItemRequest{Metadata: map[string]any{}}
		for columnIndex, value := range record {
			if columnIndex >= len(headers) {
				continue
			}
			if err := applyImportCSVValue(&item, collection, headers[columnIndex], strings.TrimSpace(value)); err != nil {
				return nil, fmt.Errorf("csv row %d: %w", rowIndex+2, err)
			}
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		return nil, errors.New("csv items are required")
	}
	return items, nil
}

func applyImportCSVValue(item *model.PlatformItemRequest, collection, header, value string) error {
	if header == "" || value == "" {
		return nil
	}
	switch header {
	case "name":
		item.Name = value
	case "type":
		item.Type = value
	case "status":
		item.Status = value
	case "protocol":
		item.Protocol = model.Protocol(strings.ToLower(value))
	case "host", "address":
		item.Host = value
	case "port":
		port, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid port %q", value)
		}
		item.Port = port
	case "username", "user":
		item.Username = value
	case "password":
		item.Password = value
	case "private_key", "privatekey":
		item.PrivateKey = value
	case "passphrase":
		item.Passphrase = value
	case "group":
		item.Group = value
	case "owner_id", "owner":
		item.OwnerID = value
	case "parent_id", "parent":
		item.ParentID = value
	case "target_id", "target":
		item.TargetID = value
	case "tags", "tag":
		item.Tags = splitImportList(value)
	case "description", "details", "remark", "remarks":
		item.Description = value
	case "metadata", "metadata_json":
		metadata := map[string]any{}
		if err := json.Unmarshal([]byte(value), &metadata); err != nil {
			return fmt.Errorf("invalid metadata_json: %w", err)
		}
		mergeImportMetadata(item.Metadata, metadata)
	case "permissions", "permissions_json":
		permissions := map[string]bool{}
		if err := json.Unmarshal([]byte(value), &permissions); err != nil {
			return fmt.Errorf("invalid permissions_json: %w", err)
		}
		item.Permissions = permissions
	case "role":
		if collection == "users" {
			item.Metadata["role"] = value
		} else {
			item.Metadata[header] = value
		}
	default:
		if key, ok := importMetadataKey(header); ok {
			item.Metadata[key] = importMetadataScalar(value)
		}
	}
	return nil
}

func importMetadataKey(header string) (string, bool) {
	for _, prefix := range []string{"metadata_", "metadata.", "meta_", "meta."} {
		if strings.HasPrefix(header, prefix) {
			key := strings.TrimPrefix(header, prefix)
			return key, key != ""
		}
	}
	switch header {
	case "asset_group_id", "asset_group_ids", "credential_id", "database", "gateway_group_id", "gateway_id", "group_id", "group_ids", "icon", "row_limit", "sort", "sqlite_path", "target_url":
		return header, true
	default:
		return "", false
	}
}

func mergeImportMetadata(target, source map[string]any) {
	for key, value := range source {
		target[key] = value
	}
}

func splitImportList(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r'
	})
	result := []string{}
	for _, field := range fields {
		if trimmed := strings.TrimSpace(field); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func importMetadataScalar(value string) any {
	if parsed, err := strconv.ParseBool(value); err == nil {
		return parsed
	}
	if parsed, err := strconv.Atoi(value); err == nil {
		return parsed
	}
	return value
}

func normalizeImportHeader(value string) string {
	value = strings.TrimPrefix(strings.TrimSpace(value), "\ufeff")
	value = strings.ToLower(value)
	replacer := strings.NewReplacer(" ", "_", "-", "_", "/", "_")
	return replacer.Replace(value)
}

func csvRecordBlank(record []string) bool {
	for _, value := range record {
		if strings.TrimSpace(value) != "" {
			return false
		}
	}
	return true
}

func queryBool(value string) bool {
	parsed, err := strconv.ParseBool(strings.TrimSpace(value))
	return err == nil && parsed
}

func (s *Server) handleAssetImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	req, ok := decodeImportRequest(w, r, "assets")
	if !ok {
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
	existingAssets, err := s.cfg.Store.ListPlatformItems("assets")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	existingByName := map[string]model.PlatformItem{}
	for _, item := range existingAssets {
		existingByName[strings.ToLower(strings.TrimSpace(item.Name))] = item
	}
	seen := map[string]bool{}
	created := []model.PlatformItem{}
	updated := []model.PlatformItem{}
	skipped := []map[string]string{}
	for index, itemReq := range req.Items {
		itemReq.Name = strings.TrimSpace(itemReq.Name)
		if itemReq.Name == "" {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("items[%d].name is required", index))
			return
		}
		key := strings.ToLower(itemReq.Name)
		if seen[key] {
			writeError(w, http.StatusBadRequest, "duplicate asset name in import: "+itemReq.Name)
			return
		}
		seen[key] = true
		if existing, ok := existingByName[key]; ok {
			if !req.UpdateExisting {
				skipped = append(skipped, map[string]string{"name": itemReq.Name, "reason": "asset already exists"})
				continue
			}
			item, err := s.cfg.Store.UpdatePlatformItem("assets", existing.ID, itemReq)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			updated = append(updated, item)
			continue
		}
		item, err := s.cfg.Store.CreatePlatformItem("assets", itemReq)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		created = append(created, item)
	}
	_ = s.audit(r, "assets.import", "assets", "", "imported assets")
	items := append([]model.PlatformItem{}, created...)
	items = append(items, updated...)
	writeJSON(w, http.StatusCreated, map[string]any{
		"items":   items,
		"created": created,
		"updated": updated,
		"skipped": skipped,
		"summary": map[string]int{
			"created": len(created),
			"updated": len(updated),
			"skipped": len(skipped),
			"total":   len(req.Items),
		},
	})
}

func (s *Server) handleUserImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	req, ok := decodeImportRequest(w, r, "users")
	if !ok {
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
	existingUsers, err := s.cfg.Store.ListPlatformItems("users")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	existingByName := map[string]model.PlatformItem{}
	for _, user := range existingUsers {
		existingByName[strings.ToLower(strings.TrimSpace(user.Name))] = user
	}
	seen := map[string]bool{}
	created := []model.PlatformItem{}
	updated := []model.PlatformItem{}
	skipped := []map[string]string{}
	for index, itemReq := range req.Items {
		itemReq.Name = strings.TrimSpace(itemReq.Name)
		if itemReq.Name == "" {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("items[%d].name is required", index))
			return
		}
		key := strings.ToLower(itemReq.Name)
		if seen[key] {
			writeError(w, http.StatusBadRequest, "duplicate username in import: "+itemReq.Name)
			return
		}
		seen[key] = true
		if itemReq.Type == "" {
			itemReq.Type = "local"
		}
		if itemReq.Status == "" {
			itemReq.Status = "enabled"
		}
		if itemReq.Metadata == nil {
			itemReq.Metadata = map[string]any{}
		}
		if _, ok := itemReq.Metadata["role"]; !ok {
			itemReq.Metadata["role"] = "user"
		}
		if existing, ok := existingByName[key]; ok {
			if !req.UpdateExisting {
				skipped = append(skipped, map[string]string{"name": itemReq.Name, "reason": "user already exists"})
				continue
			}
			item, err := s.cfg.Store.UpdatePlatformItem("users", existing.ID, itemReq)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			updated = append(updated, item)
			continue
		}
		item, err := s.cfg.Store.CreatePlatformItem("users", itemReq)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("import user %q: %v", itemReq.Name, err))
			return
		}
		created = append(created, item)
	}
	_ = s.audit(r, "users.import", "users", "", "imported users")
	writeJSON(w, http.StatusCreated, map[string]any{
		"created": created,
		"updated": updated,
		"skipped": skipped,
		"summary": map[string]int{
			"created": len(created),
			"updated": len(updated),
			"skipped": len(skipped),
			"total":   len(req.Items),
		},
	})
}

func (s *Server) handleAuthorizationBulk(w http.ResponseWriter, r *http.Request, route string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	collection, protocol, ok := authorizationBulkCollection(route)
	if !ok {
		writeError(w, http.StatusNotFound, "authorization target not found")
		return
	}
	var req authorizationBulkRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.ExpiresAt) != "" {
		if err := validateAuthorizationExpiryMetadata(map[string]any{"expires_at": req.ExpiresAt}); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	subjects := uniqueNonEmptyStrings(req.SubjectIDs, req.OwnerIDs, req.UserIDs, req.DepartmentIDs)
	targets := uniqueNonEmptyStrings(req.TargetIDs, req.AssetIDs, req.AssetGroupIDs, req.WebAssetIDs, req.WebGroupIDs, req.DatabaseIDs, req.DatabaseGroupIDs)
	if len(subjects) == 0 {
		writeError(w, http.StatusBadRequest, "subject_ids are required")
		return
	}
	if len(targets) == 0 {
		writeError(w, http.StatusBadRequest, "target_ids are required")
		return
	}
	if len(subjects)*len(targets) > 2000 {
		writeError(w, http.StatusBadRequest, "too many authorization pairs")
		return
	}
	existing, err := s.cfg.Store.ListPlatformItems(collection)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	existingPairs := map[string][]model.PlatformItem{}
	for _, item := range existing {
		pairKey := authorizationBulkPairKey(item.OwnerID, item.TargetID)
		existingPairs[pairKey] = append(existingPairs[pairKey], item)
	}
	status := strings.TrimSpace(req.Status)
	if status == "" {
		status = "enabled"
	}
	authType := strings.TrimSpace(req.Type)
	if authType == "" {
		authType = "bulk"
	}
	namePrefix := strings.TrimSpace(req.NamePrefix)
	if namePrefix == "" {
		namePrefix = "Bulk authorization"
	}
	created := []model.PlatformItem{}
	updated := []model.PlatformItem{}
	skipped := []map[string]string{}
	for _, subjectID := range subjects {
		for _, targetID := range targets {
			pairKey := authorizationBulkPairKey(subjectID, targetID)
			existingForPair := existingPairs[pairKey]
			if activeAuthorizationExists(existingForPair) {
				skipped = append(skipped, map[string]string{"subject_id": subjectID, "target_id": targetID, "reason": "authorization already exists"})
				continue
			}
			metadata := cloneMetadata(req.Metadata)
			metadata["source"] = "bulk_authorization"
			metadata["subject_id"] = subjectID
			metadata["target_id"] = targetID
			currentUserID := s.currentUserID(r)
			metadata["created_by"] = currentUserID
			if strings.TrimSpace(req.ExpiresAt) != "" {
				metadata["expires_at"] = strings.TrimSpace(req.ExpiresAt)
			}
			itemReq := model.PlatformItemRequest{
				Name:     namePrefix + " " + subjectID + " -> " + targetID,
				Type:     authType,
				Status:   status,
				Protocol: protocol,
				OwnerID:  subjectID,
				TargetID: targetID,
				Metadata: metadata,
			}
			if len(existingForPair) > 0 {
				metadata["updated_by"] = currentUserID
				item, err := s.cfg.Store.UpdatePlatformItem(collection, existingForPair[0].ID, itemReq)
				if err != nil {
					writeError(w, http.StatusInternalServerError, err.Error())
					return
				}
				existingPairs[pairKey] = append(existingPairs[pairKey], item)
				updated = append(updated, item)
				continue
			}
			item, err := s.cfg.Store.CreatePlatformItem(collection, itemReq)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			existingPairs[pairKey] = append(existingPairs[pairKey], item)
			created = append(created, item)
		}
	}
	_ = s.audit(r, collection+".bulk_create", collection, protocol, "bulk created authorizations")
	writeJSON(w, http.StatusCreated, map[string]any{
		"created": created,
		"updated": updated,
		"skipped": skipped,
		"summary": map[string]int{
			"created": len(created),
			"updated": len(updated),
			"skipped": len(skipped),
			"total":   len(subjects) * len(targets),
		},
	})
}

func activeAuthorizationExists(items []model.PlatformItem) bool {
	for _, item := range items {
		if authorizationRecordActive(item) {
			return true
		}
	}
	return false
}

func authorizationBulkCollection(route string) (string, model.Protocol, bool) {
	switch route {
	case "assets":
		return "authorized_assets", "", true
	case "websites":
		return "authorized_web_assets", model.ProtocolHTTP, true
	case "databases":
		return "authorized_database_assets", model.ProtocolDatabase, true
	default:
		return "", "", false
	}
}

func authorizationBulkPairKey(subjectID, targetID string) string {
	return normalizeAuthKey(subjectID) + "\x00" + normalizeAuthKey(targetID)
}

func uniqueNonEmptyStrings(groups ...[]string) []string {
	result := []string{}
	seen := map[string]bool{}
	for _, group := range groups {
		for _, value := range group {
			for _, part := range splitCriteria(value) {
				trimmed := strings.TrimSpace(part)
				if trimmed == "" {
					continue
				}
				key := normalizeAuthKey(trimmed)
				if seen[key] {
					continue
				}
				seen[key] = true
				result = append(result, trimmed)
			}
		}
	}
	return result
}

func cloneMetadata(source map[string]any) map[string]any {
	next := map[string]any{}
	for key, value := range source {
		next[key] = value
	}
	return next
}

func (s *Server) handleStorageFiles(w http.ResponseWriter, r *http.Request, storageID, action string) {
	storage, ok, err := s.cfg.Store.GetPlatformItem("storages", storageID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if !ok {
		writeError(w, http.StatusNotFound, "storage not found")
		return
	}
	if !platformItemEnabled(storage) {
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
			s.handleStorageList(w, r, root, storage)
		case http.MethodDelete:
			s.handleStorageDelete(w, r, root, storage)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	case "files-write":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleStorageWrite(w, r, root, storage)
	case "files-mkdir":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleStorageMkdir(w, r, root, storage)
	case "files-download":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleStorageDownload(w, r, root, storage.ID)
	case "files-upload":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleStorageUpload(w, r, root, storage)
	case "files-rename":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleStorageRename(w, r, root, storage)
	case "files-copy":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleStorageCopy(w, r, root, storage)
	default:
		writeError(w, http.StatusNotFound, "file operation not found")
	}
}

func (s *Server) handleStorageList(w http.ResponseWriter, r *http.Request, root string, storage model.PlatformItem) {
	dirPath, rel, ok := s.storagePath(w, r, root, r.URL.Query().Get("path"))
	if !ok {
		return
	}
	if !s.requireStorageListPermission(w, r, storage.ID, rel) {
		return
	}
	if !s.requireExistingStorageDirectory(w, root, dirPath) {
		return
	}
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		writeError(w, http.StatusNotFound, "path not found")
		return
	}
	result := []map[string]any{}
	userID := s.currentUserID(r)
	isAdmin := s.isAdminRequest(r)
	for _, entry := range entries {
		entryRel := filepath.ToSlash(filepath.Join(rel, entry.Name()))
		if !s.storageListEntryVisible(storage.ID, entryRel, userID, isAdmin) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		result = append(result, map[string]any{
			"name":     entry.Name(),
			"path":     entryRel,
			"is_dir":   entry.IsDir(),
			"size":     info.Size(),
			"modified": info.ModTime().UTC(),
		})
	}
	usage, err := s.updateStorageUsage(storage.ID, root)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "storage.files.list", storage.ID, "", "listed files")
	writeJSON(w, http.StatusOK, map[string]any{"path": filepath.ToSlash(rel), "entries": result, "usage": usage})
}

func (s *Server) handleStorageWrite(w http.ResponseWriter, r *http.Request, root string, storage model.PlatformItem) {
	var req fileWriteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	target, rel, ok := s.storagePath(w, r, root, req.Path)
	if !ok {
		return
	}
	info, exists, err := storagePathInfo(target)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	permission := "upload"
	if exists {
		permission = "edit"
	}
	if !s.requireStoragePermission(w, r, storage.ID, permission, rel) {
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
	if exists && info.IsDir() {
		writeError(w, http.StatusBadRequest, "target is a directory")
		return
	}
	if exists && !info.Mode().IsRegular() {
		writeError(w, http.StatusBadRequest, "target is not a regular file")
		return
	}
	existingBytes := int64(0)
	if exists {
		existingBytes = info.Size()
	}
	if !s.requireStorageQuota(w, r, storage, root, "write", rel, int64(len(content))-existingBytes) {
		return
	}
	if !s.ensureStorageParentDirectory(w, root, target) {
		return
	}
	if err := os.WriteFile(target, content, 0o660); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	usage, err := s.updateStorageUsage(storage.ID, root)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.recordStorageFileLog(r, storage.ID, "write", "success", rel, "wrote file", map[string]any{
		"path":       filepath.ToSlash(rel),
		"size":       len(content),
		"permission": permission,
	})
	_ = s.audit(r, "storage.files.write", storage.ID, "", "wrote "+rel)
	writeJSON(w, http.StatusCreated, map[string]any{"path": filepath.ToSlash(rel), "size": len(content), "usage": usage})
}

func (s *Server) handleStorageUpload(w http.ResponseWriter, r *http.Request, root string, storage model.PlatformItem) {
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
	info, exists, err := storagePathInfo(target)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	permission := "upload"
	if exists {
		permission = "edit"
	}
	if !s.requireStoragePermission(w, r, storage.ID, permission, rel) {
		return
	}
	if exists && info.IsDir() {
		writeError(w, http.StatusBadRequest, "target is a directory")
		return
	}
	if exists && !info.Mode().IsRegular() {
		writeError(w, http.StatusBadRequest, "target is not a regular file")
		return
	}
	existingBytes := int64(0)
	if exists {
		existingBytes = info.Size()
	}
	incomingBytes := int64(0)
	if header != nil {
		incomingBytes = header.Size
	}
	if !s.requireStorageQuota(w, r, storage, root, "upload", rel, incomingBytes-existingBytes) {
		return
	}
	if !s.ensureStorageParentDirectory(w, root, target) {
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
	usage, err := s.updateStorageUsage(storage.ID, root)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.recordStorageFileLog(r, storage.ID, "upload", "success", rel, "uploaded file", map[string]any{
		"path":       filepath.ToSlash(rel),
		"filename":   fileName,
		"size":       written,
		"permission": permission,
	})
	_ = s.audit(r, "storage.files.upload", storage.ID, "", "uploaded "+rel)
	writeJSON(w, http.StatusCreated, map[string]any{"path": filepath.ToSlash(rel), "size": written, "name": fileName, "usage": usage})
}

func (s *Server) handleStorageMkdir(w http.ResponseWriter, r *http.Request, root string, storage model.PlatformItem) {
	var req filePathRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	target, rel, ok := s.storagePath(w, r, root, req.Path)
	if !ok {
		return
	}
	if !s.requireStoragePermission(w, r, storage.ID, "upload", rel) {
		return
	}
	if !s.ensureStorageDirectory(w, root, target) {
		return
	}
	usage, err := s.updateStorageUsage(storage.ID, root)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.recordStorageFileLog(r, storage.ID, "mkdir", "success", rel, "created directory", map[string]any{
		"path": filepath.ToSlash(rel),
	})
	_ = s.audit(r, "storage.files.mkdir", storage.ID, "", "created "+rel)
	writeJSON(w, http.StatusCreated, map[string]any{"path": filepath.ToSlash(rel), "usage": usage})
}

func (s *Server) handleStorageDelete(w http.ResponseWriter, r *http.Request, root string, storage model.PlatformItem) {
	target, rel, ok := s.storagePath(w, r, root, r.URL.Query().Get("path"))
	if !ok {
		return
	}
	if rel == "." || rel == "" {
		writeError(w, http.StatusBadRequest, "cannot delete storage root")
		return
	}
	if !s.requireExistingStorageParentDirectory(w, root, target) {
		return
	}
	if !s.requireStorageTreePermission(w, r, storage.ID, "delete", target, rel) {
		return
	}
	if err := os.RemoveAll(target); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	usage, err := s.updateStorageUsage(storage.ID, root)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.recordStorageFileLog(r, storage.ID, "delete", "success", rel, "deleted file", map[string]any{
		"path": filepath.ToSlash(rel),
	})
	_ = s.audit(r, "storage.files.delete", storage.ID, "", "deleted "+rel)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "usage": usage})
}

func (s *Server) handleStorageDownload(w http.ResponseWriter, r *http.Request, root, storageID string) {
	target, rel, ok := s.storagePath(w, r, root, r.URL.Query().Get("path"))
	if !ok {
		return
	}
	if !s.requireExistingStorageParentDirectory(w, root, target) {
		return
	}
	info, err := regularStorageFileInfo(target)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "file not found")
		return
	}
	if errors.Is(err, errStorageSpecialFile) {
		writeError(w, http.StatusBadRequest, "file is not a regular file")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !s.requireStoragePermission(w, r, storageID, "download", rel) {
		return
	}
	s.recordStorageFileLog(r, storageID, "download", "success", rel, "downloaded file", map[string]any{
		"path": filepath.ToSlash(rel),
		"size": info.Size(),
	})
	_ = s.audit(r, "storage.files.download", storageID, "", "downloaded "+rel)
	w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeAttachmentName(filepath.Base(rel))+`"`)
	http.ServeFile(w, r, target)
}

func (s *Server) handleStorageRename(w http.ResponseWriter, r *http.Request, root string, storage model.PlatformItem) {
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
	if !s.requireExistingStorageParentDirectory(w, root, source) {
		return
	}
	sourceInfo, err := os.Lstat(source)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "source not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !sourceInfo.IsDir() && !sourceInfo.Mode().IsRegular() {
		writeError(w, http.StatusBadRequest, "source is not a regular file")
		return
	}
	if !s.requireStorageTreePermission(w, r, storage.ID, "rename", source, sourceRel) {
		return
	}
	if !s.requireMappedStorageTreePermission(w, r, storage.ID, "paste", source, destinationRel) {
		return
	}
	destinationInfo, destinationExists, err := storagePathInfo(destination)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if destinationExists {
		if !req.Overwrite {
			writeError(w, http.StatusConflict, "destination exists")
			return
		}
		if !destinationInfo.IsDir() && !destinationInfo.Mode().IsRegular() {
			writeError(w, http.StatusBadRequest, "destination is not a regular file")
			return
		}
		if !s.requireStorageTreePermission(w, r, storage.ID, "edit", destination, destinationRel) {
			return
		}
	}
	if sameOrChildPath(source, destination) && sameOrChildPath(destination, source) {
		writeError(w, http.StatusBadRequest, "source and destination are the same")
		return
	}
	if !s.ensureStorageParentDirectory(w, root, destination) {
		return
	}
	if req.Overwrite {
		_ = os.RemoveAll(destination)
	}
	if err := os.Rename(source, destination); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	usage, err := s.updateStorageUsage(storage.ID, root)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.recordStorageFileLog(r, storage.ID, "rename", "success", sourceRel+" -> "+destinationRel, "renamed file", map[string]any{
		"path":             filepath.ToSlash(destinationRel),
		"source_path":      filepath.ToSlash(sourceRel),
		"destination_path": filepath.ToSlash(destinationRel),
		"overwrite":        req.Overwrite,
	})
	_ = s.audit(r, "storage.files.rename", storage.ID, "", "renamed "+sourceRel+" to "+destinationRel)
	writeJSON(w, http.StatusOK, map[string]any{"path": filepath.ToSlash(destinationRel), "usage": usage})
}

func (s *Server) handleStorageCopy(w http.ResponseWriter, r *http.Request, root string, storage model.PlatformItem) {
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
	if !s.requireExistingStorageParentDirectory(w, root, source) {
		return
	}
	info, err := os.Lstat(source)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "source not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		writeError(w, http.StatusBadRequest, "source is not a regular file")
		return
	}
	if !s.requireStorageTreePermission(w, r, storage.ID, "copy", source, sourceRel) {
		return
	}
	if !s.requireMappedStorageTreePermission(w, r, storage.ID, "paste", source, destinationRel) {
		return
	}
	destinationInfo, destinationExists, err := storagePathInfo(destination)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if destinationExists {
		if !req.Overwrite {
			writeError(w, http.StatusConflict, "destination exists")
			return
		}
		if !destinationInfo.IsDir() && !destinationInfo.Mode().IsRegular() {
			writeError(w, http.StatusBadRequest, "destination is not a regular file")
			return
		}
		if !s.requireStorageTreePermission(w, r, storage.ID, "edit", destination, destinationRel) {
			return
		}
	}
	if sameOrChildPath(source, destination) && sameOrChildPath(destination, source) {
		writeError(w, http.StatusBadRequest, "source and destination are the same")
		return
	}
	if info.IsDir() && sameOrChildPath(source, destination) {
		writeError(w, http.StatusBadRequest, "cannot copy a directory into itself")
		return
	}
	sourceBytes, _, _, err := storageNodeBytes(source)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	destinationBytes, _, _, err := storageNodeBytes(destination)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !s.requireStorageQuota(w, r, storage, root, "copy", destinationRel, sourceBytes-destinationBytes) {
		return
	}
	if !s.ensureStorageParentDirectory(w, root, destination) {
		return
	}
	if req.Overwrite {
		_ = os.RemoveAll(destination)
	}
	if info.IsDir() {
		if err := copyDirectory(source, destination); err != nil {
			if errors.Is(err, errStorageSpecialFile) {
				writeError(w, http.StatusBadRequest, "source contains a non-regular file")
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	} else if err := copyFile(source, destination); err != nil {
		if errors.Is(err, errStorageSpecialFile) {
			writeError(w, http.StatusBadRequest, "source is not a regular file")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	usage, err := s.updateStorageUsage(storage.ID, root)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.recordStorageFileLog(r, storage.ID, "copy", "success", sourceRel+" -> "+destinationRel, "copied file", map[string]any{
		"path":             filepath.ToSlash(destinationRel),
		"source_path":      filepath.ToSlash(sourceRel),
		"destination_path": filepath.ToSlash(destinationRel),
		"size":             sourceBytes,
		"overwrite":        req.Overwrite,
	})
	_ = s.audit(r, "storage.files.copy", storage.ID, "", "copied "+sourceRel+" to "+destinationRel)
	writeJSON(w, http.StatusCreated, map[string]any{"path": filepath.ToSlash(destinationRel), "usage": usage})
}

func (s *Server) recordStorageFileLog(r *http.Request, storageID, action, status, name, description string, metadata map[string]any) {
	if metadata == nil {
		metadata = map[string]any{}
	}
	if _, ok := metadata["path"]; !ok && strings.TrimSpace(name) != "" {
		metadata["path"] = filepath.ToSlash(name)
	}
	metadata["storage_id"] = storageID
	metadata["client_ip"] = s.clientIP(r)
	_, _ = s.cfg.Store.CreatePlatformItem("file_logs", model.PlatformItemRequest{
		Name:        filepath.ToSlash(name),
		Type:        action,
		Status:      status,
		TargetID:    storageID,
		OwnerID:     s.currentUserID(r),
		Description: description,
		Metadata:    metadata,
	})
}

func (s *Server) storagePath(w http.ResponseWriter, _ *http.Request, root, value string) (string, string, bool) {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
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

func (s *Server) requireStorageQuota(w http.ResponseWriter, r *http.Request, storage model.PlatformItem, root, action, path string, deltaBytes int64) bool {
	if deltaBytes <= 0 {
		return true
	}
	limitBytes := storageLimitBytes(storage)
	if limitBytes <= 0 {
		return true
	}
	usage, err := collectStorageUsage(root)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return false
	}
	if usage.Bytes+deltaBytes <= limitBytes {
		return true
	}
	s.recordStorageFileLog(r, storage.ID, action, "denied", path, "storage quota exceeded", map[string]any{
		"path":           filepath.ToSlash(path),
		"reason":         "quota",
		"used_bytes":     usage.Bytes,
		"incoming_bytes": deltaBytes,
		"limit_bytes":    limitBytes,
	})
	_ = s.audit(r, "storage.files."+action+".quota.denied", storage.ID, "", "quota denied "+path)
	writeError(w, http.StatusRequestEntityTooLarge, "storage quota exceeded")
	return false
}

func (s *Server) updateStorageUsage(storageID, root string) (storageUsageInfo, error) {
	item, ok, err := s.cfg.Store.GetPlatformItem("storages", storageID)
	if err != nil {
		return storageUsageInfo{}, err
	}
	if !ok {
		return storageUsageInfo{}, os.ErrNotExist
	}
	usage, err := collectStorageUsage(root)
	if err != nil {
		return storageUsageInfo{}, err
	}
	limitBytes := storageLimitBytes(item)
	checkedAt := time.Now().UTC().Format(time.RFC3339)
	response := usage.withLimit(limitBytes, checkedAt)
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	item.Metadata["used_bytes"] = usage.Bytes
	item.Metadata["used"] = formatStorageBytes(usage.Bytes)
	item.Metadata["files"] = usage.Files
	item.Metadata["dirs"] = usage.Dirs
	item.Metadata["quota_checked_at"] = checkedAt
	if limitBytes > 0 {
		item.Metadata["available_bytes"] = maxInt64(limitBytes-usage.Bytes, 0)
	} else {
		delete(item.Metadata, "available_bytes")
	}
	if _, err := s.cfg.Store.SavePlatformItem("storages", item); err != nil {
		return storageUsageInfo{}, err
	}
	return response, nil
}

func collectStorageUsage(root string) (storageUsageInfo, error) {
	usage := storageUsageInfo{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			usage.Dirs++
			return nil
		}
		usage.Files++
		usage.Bytes += info.Size()
		return nil
	})
	if err != nil {
		return storageUsageInfo{}, err
	}
	usage.Used = formatStorageBytes(usage.Bytes)
	return usage, nil
}

func (usage storageUsageInfo) withLimit(limitBytes int64, checkedAt string) storageUsageInfo {
	usage.Used = formatStorageBytes(usage.Bytes)
	usage.CheckedAt = checkedAt
	if limitBytes > 0 {
		usage.LimitBytes = limitBytes
		usage.AvailableBytes = maxInt64(limitBytes-usage.Bytes, 0)
		usage.Limit = formatStorageBytes(limitBytes)
	}
	return usage
}

func storageLimitBytes(item model.PlatformItem) int64 {
	for _, key := range []string{"limit_bytes", "quota_bytes", "capacity_bytes", "limit", "quota", "capacity"} {
		if bytes, ok := parseStorageByteSize(item.Metadata[key]); ok {
			return bytes
		}
	}
	return 0
}

func parseStorageByteSize(value any) (int64, bool) {
	switch typed := value.(type) {
	case nil:
		return 0, false
	case int:
		return int64(typed), typed > 0
	case int64:
		return typed, typed > 0
	case int32:
		return int64(typed), typed > 0
	case float64:
		return int64(typed), typed > 0
	case float32:
		return int64(typed), typed > 0
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return 0, false
		}
		return parsed, parsed > 0
	case string:
		return parseStorageByteString(typed)
	default:
		return 0, false
	}
}

func parseStorageByteString(value string) (int64, bool) {
	normalized := strings.TrimSpace(strings.ReplaceAll(value, ",", ""))
	if normalized == "" {
		return 0, false
	}
	index := 0
	for index < len(normalized) {
		ch := normalized[index]
		if (ch >= '0' && ch <= '9') || ch == '.' {
			index++
			continue
		}
		break
	}
	if index == 0 {
		return 0, false
	}
	number, err := strconv.ParseFloat(strings.TrimSpace(normalized[:index]), 64)
	if err != nil || number <= 0 {
		return 0, false
	}
	unit := strings.ToLower(strings.TrimSpace(normalized[index:]))
	unit = strings.TrimSuffix(unit, "s")
	multiplier := float64(1)
	switch unit {
	case "", "b", "byte":
	case "k", "kb", "kib":
		multiplier = 1024
	case "m", "mb", "mib":
		multiplier = 1024 * 1024
	case "g", "gb", "gib":
		multiplier = 1024 * 1024 * 1024
	case "t", "tb", "tib":
		multiplier = 1024 * 1024 * 1024 * 1024
	default:
		return 0, false
	}
	return int64(number * multiplier), true
}

func storageNodeBytes(path string) (int64, bool, bool, error) {
	info, exists, err := storagePathInfo(path)
	if err != nil {
		return 0, false, false, err
	}
	if !exists {
		return 0, false, false, nil
	}
	if !info.IsDir() {
		if !info.Mode().IsRegular() {
			return 0, true, false, errStorageSpecialFile
		}
		return info.Size(), true, false, nil
	}
	usage, err := collectStorageUsage(path)
	if err != nil {
		return 0, true, true, err
	}
	return usage.Bytes, true, true, nil
}

func storagePathInfo(path string) (os.FileInfo, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return info, true, nil
}

func regularStorageFileInfo(path string) (os.FileInfo, error) {
	info, exists, err := storagePathInfo(path)
	if err != nil {
		return nil, err
	}
	if !exists || info.IsDir() {
		return nil, os.ErrNotExist
	}
	if !info.Mode().IsRegular() {
		return nil, errStorageSpecialFile
	}
	return info, nil
}

func (s *Server) ensureStorageParentDirectory(w http.ResponseWriter, root, target string) bool {
	return s.ensureStorageDirectory(w, root, filepath.Dir(target))
}

func (s *Server) ensureStorageDirectory(w http.ResponseWriter, root, dir string) bool {
	if err := ensureRealStorageDirectory(root, dir); err != nil {
		if errors.Is(err, errStorageSpecialFile) {
			writeError(w, http.StatusBadRequest, "storage path contains a non-directory entry")
			return false
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return false
	}
	return true
}

func (s *Server) requireExistingStorageParentDirectory(w http.ResponseWriter, root, target string) bool {
	return s.requireExistingStorageDirectory(w, root, filepath.Dir(target))
}

func (s *Server) requireExistingStorageDirectory(w http.ResponseWriter, root, dir string) bool {
	if err := ensureExistingRealStorageDirectory(root, dir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, "path not found")
			return false
		}
		if errors.Is(err, errStorageSpecialFile) {
			writeError(w, http.StatusBadRequest, "storage path contains a non-directory entry")
			return false
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return false
	}
	return true
}

func ensureExistingRealStorageDirectory(root, dir string) error {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	dirAbs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	relToRoot, err := filepath.Rel(rootAbs, dirAbs)
	if err != nil {
		return err
	}
	if relToRoot != "." {
		if err := ensureChildPath(rootAbs, dirAbs); err != nil {
			return err
		}
	}
	rootInfo, exists, err := storagePathInfo(rootAbs)
	if err != nil {
		return err
	}
	if !exists {
		return os.ErrNotExist
	}
	if !rootInfo.IsDir() {
		return errStorageSpecialFile
	}
	if relToRoot == "." {
		return nil
	}
	rel := filepath.Clean(relToRoot)
	if rel == "." {
		return nil
	}
	current := rootAbs
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, exists, err := storagePathInfo(current)
		if err != nil {
			return err
		}
		if !exists {
			return os.ErrNotExist
		}
		if !info.IsDir() {
			return errStorageSpecialFile
		}
	}
	return nil
}

func ensureRealStorageDirectory(root, dir string) error {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	dirAbs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	relToRoot, err := filepath.Rel(rootAbs, dirAbs)
	if err != nil {
		return err
	}
	if relToRoot != "." {
		if err := ensureChildPath(rootAbs, dirAbs); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(root, 0o770); err != nil {
		return err
	}
	rootInfo, exists, err := storagePathInfo(root)
	if err != nil {
		return err
	}
	if !exists || !rootInfo.IsDir() {
		return errStorageSpecialFile
	}
	if relToRoot == "." {
		return nil
	}
	rel := filepath.Clean(relToRoot)
	if rel == "." {
		return nil
	}
	current := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, exists, err := storagePathInfo(current)
		if err != nil {
			return err
		}
		if !exists {
			if err := os.Mkdir(current, 0o770); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			continue
		}
		if !info.IsDir() {
			return errStorageSpecialFile
		}
	}
	return nil
}

func formatStorageBytes(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	units := []string{"KB", "MB", "GB", "TB"}
	current := float64(bytes) / 1024
	unitIndex := 0
	for current >= 1024 && unitIndex < len(units)-1 {
		current /= 1024
		unitIndex++
	}
	precision := 2
	if current >= 10 {
		precision = 1
	}
	return fmt.Sprintf("%.*f %s", precision, current, units[unitIndex])
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
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
	s.recordStorageFileLog(r, storageID, action, "denied", path, "blocked by authorization strategy", map[string]any{
		"path":   filepath.ToSlash(path),
		"reason": "authorization_strategy",
	})
	_ = s.audit(r, "storage.files."+action+".denied", storageID, "", "blocked "+action+" on "+path)
	writeError(w, http.StatusForbidden, "file permission denied: "+action)
	return false
}

func (s *Server) requireStorageListPermission(w http.ResponseWriter, r *http.Request, storageID, path string) bool {
	if s.isAdminRequest(r) {
		return true
	}
	allowed, matched := s.storageListPermissionAllowed(storageID, path, s.currentUserID(r))
	if !matched || allowed {
		return true
	}
	s.recordStorageFileLog(r, storageID, "list", "denied", path, "blocked by authorization strategy", map[string]any{
		"path":   filepath.ToSlash(path),
		"reason": "authorization_strategy",
	})
	_ = s.audit(r, "storage.files.list.denied", storageID, "", "blocked list on "+path)
	writeError(w, http.StatusForbidden, "file permission denied: list")
	return false
}

func (s *Server) storageListEntryVisible(storageID, path, userID string, isAdmin bool) bool {
	if isAdmin {
		return true
	}
	allowed, matched := s.storageListPermissionAllowed(storageID, path, userID)
	return !matched || allowed
}

func (s *Server) storageListPermissionAllowed(storageID, path, userID string) (bool, bool) {
	if allowed, matched := s.storagePermissionAllowed(storageID, "list", path, userID); matched {
		return allowed, true
	}
	if allowed, matched := s.storagePermissionAllowed(storageID, "download", path, userID); matched && !allowed {
		return false, true
	}
	return true, false
}

func (s *Server) requireStorageTreePermission(w http.ResponseWriter, r *http.Request, storageID, action, rootPath, rootRel string) bool {
	if !s.requireStoragePermission(w, r, storageID, action, rootRel) {
		return false
	}
	info, err := os.Lstat(rootPath)
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return false
	}
	if !info.IsDir() {
		return true
	}
	return s.requireStorageDescendantPermissions(w, r, storageID, action, rootPath, rootRel, rootPath)
}

func (s *Server) requireMappedStorageTreePermission(w http.ResponseWriter, r *http.Request, storageID, action, sourcePath, destinationRel string) bool {
	if !s.requireStoragePermission(w, r, storageID, action, destinationRel) {
		return false
	}
	info, err := os.Lstat(sourcePath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return false
	}
	if !info.IsDir() {
		return true
	}
	return s.requireStorageDescendantPermissions(w, r, storageID, action, sourcePath, destinationRel, sourcePath)
}

func (s *Server) requireStorageDescendantPermissions(w http.ResponseWriter, r *http.Request, storageID, action, walkRoot, mappedRootRel, skipPath string) bool {
	err := filepath.WalkDir(walkRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == skipPath {
			return nil
		}
		rel, err := filepath.Rel(walkRoot, path)
		if err != nil {
			return err
		}
		mappedRel := joinStoragePolicyPath(mappedRootRel, rel)
		if !s.requireStoragePermission(w, r, storageID, action, mappedRel) {
			return errStoragePermissionDenied
		}
		return nil
	})
	if errors.Is(err, errStoragePermissionDenied) {
		return false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return false
	}
	return true
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

func joinStoragePolicyPath(base, child string) string {
	base = normalizeStoragePolicyPath(base)
	child = normalizeStoragePolicyPath(child)
	if child == "." {
		return base
	}
	if base == "." {
		return child
	}
	return filepath.ToSlash(filepath.Join(filepath.FromSlash(base), filepath.FromSlash(child)))
}

func copyFile(source, destination string) error {
	if _, err := regularStorageFileInfo(source); err != nil {
		return err
	}
	if info, exists, err := storagePathInfo(destination); err != nil {
		return err
	} else if exists && (info.IsDir() || !info.Mode().IsRegular()) {
		return errStorageSpecialFile
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
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errStorageSpecialFile
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
			"domain":          req.Domain,
			"certificate":     string(certPEM),
			"private_key":     string(keyPEM),
			"has_private_key": true,
			"expires_at":      time.Now().UTC().Add(time.Duration(clampInt(req.Days, 1, 3650, 365)) * 24 * time.Hour),
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

func (s *Server) handleCertificateACME(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req certificateACMERequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Domain = strings.TrimSpace(req.Domain)
	if req.Domain == "" {
		writeError(w, http.StatusBadRequest, "domain is required")
		return
	}
	if len(req.DNS) == 0 {
		req.DNS = []string{req.Domain}
	}
	domains := uniqueNonEmptyStrings(append([]string{req.Domain}, req.DNS...))
	token, keyAuthorization, err := makeACMEHTTPChallenge()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	certPEM, keyPEM, err := makeSelfSignedCertificate(certificateRequest{
		Domain: req.Domain,
		DNS:    domains,
		IP:     req.IP,
		Days:   clampInt(req.Days, 1, 3650, 90),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = req.Domain
	}
	challengeType := strings.ToLower(strings.TrimSpace(req.ChallengeType))
	if challengeType == "" {
		challengeType = "http-01"
	}
	directoryURL := strings.TrimSpace(req.DirectoryURL)
	if directoryURL == "" {
		directoryURL = "local-ca"
	}
	metadata := cloneMetadata(req.Metadata)
	metadata["domain"] = req.Domain
	metadata["dns_names"] = domains
	metadata["ip_addresses"] = metadataStrings(req.IP)
	metadata["certificate"] = string(certPEM)
	metadata["private_key"] = string(keyPEM)
	metadata["has_private_key"] = true
	metadata["expires_at"] = time.Now().UTC().Add(time.Duration(clampInt(req.Days, 1, 3650, 90)) * 24 * time.Hour)
	metadata["acme_directory_url"] = directoryURL
	metadata["acme_mode"] = "local-ca"
	metadata["acme_order_status"] = "valid"
	metadata["acme_challenge_type"] = challengeType
	metadata["acme_http_token"] = token
	metadata["acme_http_key_authorization"] = keyAuthorization
	metadata["acme_http_url"] = "/.well-known/acme-challenge/" + token
	metadata["issued_at"] = time.Now().UTC()
	if strings.TrimSpace(req.Email) != "" {
		metadata["account_email"] = strings.TrimSpace(req.Email)
	}
	if dnsProviderID := strings.TrimSpace(req.DNSProviderID); dnsProviderID != "" {
		provider, ok, err := s.certificateDNSProviderByID(dnsProviderID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, "dns provider not found")
			return
		}
		metadata["dns_provider_id"] = provider.ID
		metadata["dns_provider_name"] = provider.Name
		if zone := firstMetadataString(provider.Metadata, "zone"); zone != "" {
			metadata["dns_provider_zone"] = zone
		}
	}
	if req.MTLSEnabled {
		metadata["mtls_enabled"] = true
	}
	item, err := s.cfg.Store.CreatePlatformItem("certificates", model.PlatformItemRequest{
		Name:        name,
		Type:        "acme",
		Status:      "issued",
		Description: "ACME/local-ca certificate for " + req.Domain,
		Metadata:    metadata,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "certificate.acme.request", item.ID, "", "requested ACME certificate for "+req.Domain)
	_ = s.audit(r, "certificate.acme.issue", item.ID, "", "issued local ACME certificate for "+req.Domain)
	if req.Default {
		if _, err := s.setDefaultCertificate(item.ID); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		item, _, _ = s.cfg.Store.GetPlatformItem("certificates", item.ID)
		sanitizeCertificateItem(&item)
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) certificateDNSProviderByID(id string) (model.PlatformItem, bool, error) {
	item, ok, err := s.cfg.Store.GetPlatformItem("system_settings", id)
	if err != nil || !ok {
		return model.PlatformItem{}, false, err
	}
	if !strings.EqualFold(item.Type, "dns-provider") || !platformItemEnabled(item) {
		return model.PlatformItem{}, false, nil
	}
	return item, true, nil
}

func makeACMEHTTPChallenge() (string, string, error) {
	tokenBytes := make([]byte, 24)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", "", err
	}
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", "", err
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	keyAuthorization := token + "." + base64.RawURLEncoding.EncodeToString(keyBytes)
	return token, keyAuthorization, nil
}

func (s *Server) handleCertificateDNSProviders(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.cfg.Store.ListPlatformItems("system_settings")
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		result := []model.PlatformItem{}
		for _, item := range items {
			if strings.EqualFold(item.Type, "dns-provider") {
				result = append(result, item)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": result})
	case http.MethodPost:
		var req dnsProviderRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		name := strings.TrimSpace(req.Name)
		if name == "" {
			name = strings.TrimSpace(req.Provider)
		}
		if name == "" {
			writeError(w, http.StatusBadRequest, "provider name is required")
			return
		}
		metadata := cloneMetadata(req.Metadata)
		metadata["provider"] = strings.TrimSpace(req.Provider)
		metadata["zone"] = strings.TrimSpace(req.Zone)
		if strings.TrimSpace(req.Token) != "" {
			metadata["dns_api_token"] = strings.TrimSpace(req.Token)
		}
		item, err := s.cfg.Store.CreatePlatformItem("system_settings", model.PlatformItemRequest{
			Name:        name,
			Type:        "dns-provider",
			Status:      "enabled",
			Description: "DNS provider used by ACME DNS-01 challenges",
			Metadata:    metadata,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.audit(r, "certificate.dns_provider.create", item.ID, "", "created DNS provider "+name)
		writeJSON(w, http.StatusCreated, item)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
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

func (s *Server) handleCertificateBundleDownload(w http.ResponseWriter, r *http.Request, id string) {
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
	if err := s.decryptCertificatePrivateKey(&item); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	bundle, err := certificateBundleZip(item)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	_ = s.audit(r, "certificate.bundle_download", id, "", "downloaded certificate deployment bundle")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+id+".zip\"")
	_, _ = w.Write(bundle)
}

func (s *Server) decryptCertificatePrivateKey(item *model.PlatformItem) error {
	if item.Metadata == nil || firstMetadataString(item.Metadata, "private_key", "privateKey", "key", "private_key_pem") != "" {
		return nil
	}
	encrypted := firstMetadataString(item.Metadata, "certificate_private_key_encrypted")
	if encrypted == "" {
		return nil
	}
	privateKey, err := s.cfg.Store.DecryptPlatformSecret(encrypted)
	if err != nil {
		return fmt.Errorf("decrypt certificate private key: %w", err)
	}
	metadata := cloneMetadata(item.Metadata)
	metadata["private_key"] = privateKey
	item.Metadata = metadata
	return nil
}

func certificateBundleZip(item model.PlatformItem) ([]byte, error) {
	certPEM, _ := item.Metadata["certificate"].(string)
	if strings.TrimSpace(certPEM) == "" {
		return nil, errors.New("certificate payload not found")
	}
	privateKeyPEM, _ := item.Metadata["private_key"].(string)
	chainPEM, _ := item.Metadata["chain"].(string)
	buffer := &bytes.Buffer{}
	archive := zip.NewWriter(buffer)
	if err := writeZipText(archive, "certificate.pem", certPEM); err != nil {
		return nil, err
	}
	if strings.TrimSpace(privateKeyPEM) != "" {
		if err := writeZipText(archive, "private.key", privateKeyPEM); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(chainPEM) != "" {
		if err := writeZipText(archive, "chain.pem", chainPEM); err != nil {
			return nil, err
		}
		fullchain := strings.TrimRight(certPEM, "\r\n") + "\n" + strings.TrimLeft(chainPEM, "\r\n")
		if err := writeZipText(archive, "fullchain.pem", fullchain); err != nil {
			return nil, err
		}
	}
	readme := certificateBundleReadme(item, strings.TrimSpace(privateKeyPEM) != "", strings.TrimSpace(chainPEM) != "")
	if err := writeZipText(archive, "README.txt", readme); err != nil {
		return nil, err
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func writeZipText(archive *zip.Writer, name, content string) error {
	entry, err := archive.Create(name)
	if err != nil {
		return err
	}
	_, err = io.WriteString(entry, content)
	return err
}

func certificateBundleReadme(item model.PlatformItem, hasPrivateKey, hasChain bool) string {
	lines := []string{
		"openwebservermanager certificate bundle",
		"",
		"Certificate ID: " + item.ID,
		"Certificate name: " + item.Name,
		"Domain: " + firstMetadataString(item.Metadata, "domain", "common_name"),
		"Includes private key: " + strconv.FormatBool(hasPrivateKey),
		"Includes chain: " + strconv.FormatBool(hasChain),
		"",
		"Files:",
		"- certificate.pem: leaf certificate",
	}
	if hasPrivateKey {
		lines = append(lines, "- private.key: private key for the certificate")
	}
	if hasChain {
		lines = append(lines, "- chain.pem: uploaded certificate chain", "- fullchain.pem: certificate plus chain")
	}
	return strings.Join(lines, "\n") + "\n"
}

func (s *Server) handleACMEHTTPChallenge(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
	token = strings.TrimSpace(strings.Trim(token, "/"))
	if token == "" || strings.ContainsAny(token, "/\\\x00\r\n\t") {
		writeError(w, http.StatusBadRequest, "invalid challenge token")
		return
	}
	items, err := s.cfg.Store.ListPlatformItems("certificates")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, item := range items {
		if err := certificateRuntimeUsable(item); err != nil {
			continue
		}
		if metadataText := firstMetadataString(item.Metadata, "acme_http_token"); metadataText != token {
			continue
		}
		keyAuthorization := firstMetadataString(item.Metadata, "acme_http_key_authorization")
		if keyAuthorization == "" {
			break
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, keyAuthorization)
		return
	}
	writeError(w, http.StatusNotFound, "challenge token not found")
}

func (s *Server) handleCertificateDefault(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	item, err := s.setDefaultCertificate(id)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, "certificate not found")
			return
		}
		if errors.Is(err, errCertificateNotUsable) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "certificate.default", id, "", "set default certificate "+item.Name)
	sanitizeCertificateItem(&item)
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) setDefaultCertificate(id string) (model.PlatformItem, error) {
	items, err := s.cfg.Store.ListPlatformItems("certificates")
	if err != nil {
		return model.PlatformItem{}, err
	}
	selectedItem, ok, err := s.cfg.Store.GetPlatformItem("certificates", id)
	if err != nil || !ok {
		if err != nil {
			return model.PlatformItem{}, err
		}
		return model.PlatformItem{}, os.ErrNotExist
	}
	if err := certificateRuntimeUsable(selectedItem); err != nil {
		return model.PlatformItem{}, err
	}
	var selected model.PlatformItem
	for _, item := range items {
		raw, ok, err := s.cfg.Store.GetPlatformItem("certificates", item.ID)
		if err != nil {
			return model.PlatformItem{}, err
		}
		if !ok {
			continue
		}
		if raw.Metadata == nil {
			raw.Metadata = map[string]any{}
		}
		if raw.ID == id {
			raw.Metadata["default"] = true
			raw.Metadata["default_at"] = time.Now().UTC().Format(time.RFC3339Nano)
			selected = raw
		} else {
			delete(raw.Metadata, "default")
			delete(raw.Metadata, "default_at")
		}
		if _, err := s.cfg.Store.SavePlatformItem("certificates", raw); err != nil {
			return model.PlatformItem{}, err
		}
	}
	if selected.ID == "" {
		return model.PlatformItem{}, os.ErrNotExist
	}
	return selected, nil
}

func certificateRuntimeUsable(item model.PlatformItem) error {
	status := strings.ToLower(strings.TrimSpace(item.Status))
	switch status {
	case "", "enabled", "active", "issued", "valid", "locked":
	default:
		return fmt.Errorf("%w: certificate status is %s", errCertificateNotUsable, valueOrDefault(status, "disabled"))
	}
	if expiresAt, ok := metadataTime(item.Metadata["expires_at"]); ok && !expiresAt.IsZero() && !time.Now().UTC().Before(expiresAt) {
		return fmt.Errorf("%w: certificate is expired", errCertificateNotUsable)
	}
	return nil
}

func (s *Server) handleCertificateMTLS(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
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
	var req certificateMTLSRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	item.Metadata["mtls_enabled"] = req.Enabled
	if !req.Enabled {
		clearCertificateMTLSCA(item.Metadata)
	} else if strings.TrimSpace(req.ClientCA) != "" {
		if _, err := parseFirstCertificatePEM([]byte(req.ClientCA)); err != nil {
			writeError(w, http.StatusBadRequest, "client_ca is invalid: "+err.Error())
			return
		}
		item.Metadata["mtls_client_ca"] = req.ClientCA
		item.Metadata["mtls_client_ca_set"] = true
	} else if firstMetadataString(item.Metadata, "mtls_client_ca", "client_ca", "mtls_ca", "tls_ca", "ca_certificate", "root_ca") != "" {
		item.Metadata["mtls_client_ca_set"] = true
	}
	item.Metadata["mtls_updated_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	saved, err := s.cfg.Store.SavePlatformItem("certificates", item)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "certificate.mtls.update", id, "", "updated mTLS settings for "+item.Name)
	writeJSON(w, http.StatusOK, saved)
}

func clearCertificateMTLSCA(metadata map[string]any) {
	for _, key := range []string{"mtls_client_ca", "client_ca", "mtls_ca", "tls_ca", "ca_certificate", "root_ca", "mtls_client_ca_set"} {
		delete(metadata, key)
	}
	metadata["mtls_client_ca_set"] = false
}

func (s *Server) handleCertificateLogs(w http.ResponseWriter, r *http.Request, id string) {
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
		if item.TargetID == id && strings.HasPrefix(item.Name, "certificate.") {
			result = append(result, item)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": result})
}

func sanitizeCertificateItem(item *model.PlatformItem) {
	if item.Metadata == nil {
		return
	}
	if _, ok := item.Metadata["mtls_client_ca_set"]; !ok {
		if _, hasCA := item.Metadata["mtls_client_ca"]; hasCA {
			item.Metadata["mtls_client_ca_set"] = true
		}
	}
	if _, ok := item.Metadata["private_key_set"]; !ok {
		if firstMetadataString(item.Metadata, "private_key", "privateKey", "key", "private_key_pem", "certificate_private_key_encrypted") != "" {
			item.Metadata["private_key_set"] = true
		}
	}
	for _, key := range []string{
		"private_key",
		"privateKey",
		"certificate_private_key_encrypted",
		"mtls_client_ca",
		"client_ca",
		"dns_api_token",
		"dns_api_token_encrypted",
		"api_token",
		"secret_key",
	} {
		delete(item.Metadata, key)
	}
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
	if !scheduledTaskEnabled(task) {
		writeError(w, http.StatusConflict, "scheduled task is disabled")
		return
	}
	logItem, err := s.executeScheduledTask(r, task, "manual")
	if err != nil {
		_ = s.audit(r, "scheduled_task.run.failed", id, "", "failed scheduled task "+task.Name+": "+err.Error())
		status := http.StatusInternalServerError
		if errors.Is(err, errUnsupportedScheduledTaskType) {
			status = http.StatusUnprocessableEntity
		}
		writeJSON(w, status, map[string]any{"error": err.Error(), "log": logItem})
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
			"requested_by": sqlWorkOrderRequesterID(order),
			"approved_by":  firstMetadataString(order.Metadata, "approved_by"),
		},
	})
	if err != nil {
		writeError(w, statusCode, err.Error())
		return
	}
	if statusCode != http.StatusOK {
		nextMetadata := sqlWorkOrderExecutionMetadata(order, asset, logItem, approvedSQL, userID)
		nextMetadata["execution_error"] = logItem.Description
		_, _ = s.cfg.Store.UpdatePlatformItem("sql_work_orders", id, model.PlatformItemRequest{Status: "failed", Protocol: model.ProtocolDatabase, Metadata: nextMetadata})
		_ = s.audit(r, "sql_work_order.execute.failed", id, model.ProtocolDatabase, logItem.Description)
		writeJSON(w, statusCode, logItem)
		return
	}
	nextMetadata := sqlWorkOrderExecutionMetadata(order, asset, logItem, approvedSQL, userID)
	_, _ = s.cfg.Store.UpdatePlatformItem("sql_work_orders", id, model.PlatformItemRequest{Status: "executed", Protocol: model.ProtocolDatabase, Metadata: nextMetadata})
	_ = s.audit(r, "sql_work_order.execute", id, model.ProtocolDatabase, "executed sql work order")
	writeJSON(w, http.StatusOK, logItem)
}

func sqlWorkOrderExecutionMetadata(order, asset, logItem model.PlatformItem, approvedSQL, userID string) map[string]any {
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
	nextMetadata["duration_ms"] = logItem.Metadata["duration_ms"]
	return nextMetadata
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
	status := strings.ToLower(strings.TrimSpace(order.Status))
	if status == "" {
		status = "pending"
	}
	if status != "pending" {
		writeError(w, http.StatusConflict, "sql work order decisions can only be made while pending")
		return
	}
	var req workOrderDecisionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	userID, isAdmin := s.accessUser(r)
	if nextStatus == "approved" && !isAdmin && userID != "" && sqlWorkOrderRequesterMatches(order, userID) {
		_ = s.audit(r, "sql_work_order.approve.denied", id, model.ProtocolDatabase, "sql work order cannot be self-approved")
		writeError(w, http.StatusForbidden, "sql work order cannot be self-approved")
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

func sqlWorkOrderRequesterID(order model.PlatformItem) string {
	return firstNonEmpty(
		firstMetadataString(order.Metadata, "requested_by", "requester", "requester_id", "applicant_id", "applicant"),
		order.OwnerID,
		order.Username,
	)
}

func sqlWorkOrderRequesterMatches(order model.PlatformItem, userID string) bool {
	requester := sqlWorkOrderRequesterID(order)
	return requester != "" && strings.EqualFold(strings.TrimSpace(requester), strings.TrimSpace(userID))
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
		_ = s.audit(r, "sql_work_order.database_access.denied", order.ID, model.ProtocolDatabase, "database asset access denied: "+asset.ID)
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
		if err := s.refreshSessionRecordingSize(id); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
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
	if size, ok := s.recordingSizeFromMetadata(item.Metadata); ok {
		item.Metadata["recording_size"] = size
	}
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
			_ = s.audit(r, "audit.recording.access.denied", id, session.Protocol, "recording access denied")
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
		_ = s.audit(r, "audit.recording.access.denied", id, item.Protocol, "recording access denied")
		writeError(w, http.StatusForbidden, "session access denied")
		return auditRecording{}, false
	}
	path, _ := item.Metadata["recording_path"].(string)
	return s.validateRecordingPath(w, path, item.Protocol)
}

func (s *Server) canAccessPlatformSession(r *http.Request, item model.PlatformItem) bool {
	_, authSession, ok := s.authSession(r)
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

func (s *Server) recordingSizeFromMetadata(metadata map[string]any) (int64, bool) {
	recordingPath := firstMetadataString(metadata, "recording_path")
	if recordingPath == "" {
		return 0, false
	}
	if err := ensureChildPath(filepath.Join(s.cfg.DataDir, "recordings"), recordingPath); err != nil {
		return 0, false
	}
	usage := directoryUsage(recordingPath)
	size, ok := usage["bytes"].(int64)
	return size, ok
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
		if entry.Type()&os.ModeType != 0 {
			return nil
		}
		if err := ensureChildPath(recordingPath, filePath); err != nil {
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
