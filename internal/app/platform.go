package app

import (
	"errors"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"openwebservermanager/internal/model"
)

var adminCollectionRoutes = map[string]string{
	"users":             "users",
	"roles":             "roles",
	"departments":       "departments",
	"login-policies":    "login_policies",
	"login-locked":      "login_locks",
	"oidc-clients":      "oidc_clients",
	"assets":            "assets",
	"asset-groups":      "asset_groups",
	"credentials":       "credentials",
	"command-snippets":  "command_snippets",
	"storages":          "storages",
	"websites":          "web_assets",
	"certificates":      "certificates",
	"database-assets":   "database_assets",
	"sql-work-orders":   "sql_work_orders",
	"ssh-gateways":      "ssh_gateways",
	"agent-gateways":    "agent_gateways",
	"gateway-groups":    "gateway_groups",
	"scheduled-tasks":   "scheduled_tasks",
	"command-filters":   "command_filters",
	"strategies":        "authorization_strategies",
	"system-settings":   "system_settings",
}

var authorizationCollectionRoutes = map[string]string{
	"assets":    "authorized_assets",
	"websites":  "authorized_web_assets",
	"databases": "authorized_database_assets",
}

var auditCollectionRoutes = map[string]string{
	"online-sessions":   "online_sessions",
	"offline-sessions":  "offline_sessions",
	"exec-command-logs": "exec_command_logs",
	"file-logs":         "file_logs",
	"access-logs":       "access_logs",
	"access-stats":      "access_stats",
	"login-logs":        "login_logs",
	"operation-logs":    "operation_logs",
	"sql-logs":          "sql_logs",
}

func (s *Server) handlePlatformAPI(w http.ResponseWriter, r *http.Request) bool {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/"), "/")
	switch {
	case path == "access/assets":
		s.handleAccessAssets(w, r)
		return true
	case strings.HasPrefix(path, "access/"):
		s.handleAccessAction(w, r)
		return true
	case path == "system/monitoring":
		s.handleSystemMonitoring(w, r)
		return true
	case path == "tools/ping":
		s.handlePingTool(w, r)
		return true
	case strings.HasPrefix(path, "settings/"):
		key := strings.TrimPrefix(path, "settings/")
		s.handleCollection(w, r, "system_settings", key)
		return true
	case strings.HasPrefix(path, "admin/audit/"):
		rest := strings.TrimPrefix(path, "admin/audit/")
		parts := splitPath(rest)
		collection, ok := auditCollectionRoutes[firstPart(parts)]
		if !ok {
			return false
		}
		s.handleCollection(w, r, collection, tailID(parts))
		return true
	case strings.HasPrefix(path, "admin/authorizations/"):
		rest := strings.TrimPrefix(path, "admin/authorizations/")
		parts := splitPath(rest)
		collection, ok := authorizationCollectionRoutes[firstPart(parts)]
		if !ok {
			return false
		}
		s.handleCollection(w, r, collection, tailID(parts))
		return true
	case strings.HasPrefix(path, "admin/"):
		rest := strings.TrimPrefix(path, "admin/")
		parts := splitPath(rest)
		collection, ok := adminCollectionRoutes[firstPart(parts)]
		if !ok {
			return false
		}
		s.handleCollection(w, r, collection, tailID(parts))
		return true
	default:
		return false
	}
}

func (s *Server) handleCollection(w http.ResponseWriter, r *http.Request, collection, id string) {
	switch {
	case id == "" && r.Method == http.MethodGet:
		items, err := s.cfg.Store.ListPlatformItems(collection)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	case id == "" && r.Method == http.MethodPost:
		var req model.PlatformItemRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		item, err := s.cfg.Store.CreatePlatformItem(collection, req)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.audit(r, collection+".create", item.ID, item.Protocol, "created "+item.Name)
		writeJSON(w, http.StatusCreated, item)
	case id != "" && r.Method == http.MethodPatch:
		var req model.PlatformItemRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		item, err := s.cfg.Store.UpdatePlatformItem(collection, id, req)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				writeError(w, http.StatusNotFound, "record not found")
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.audit(r, collection+".update", item.ID, item.Protocol, "updated "+item.Name)
		writeJSON(w, http.StatusOK, item)
	case id != "" && r.Method == http.MethodDelete:
		if err := s.cfg.Store.DeletePlatformItem(collection, id); err != nil {
			writeError(w, http.StatusNotFound, "record not found")
			return
		}
		_ = s.audit(r, collection+".delete", id, "", "deleted record")
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleAccessAssets(w http.ResponseWriter, r *http.Request) {
	platform, err := s.cfg.Store.PlatformBootstrap()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	userID, isAdmin := s.accessUser(r)
	assets := filterAuthorizedItems(platform["assets"], platform["authorized_assets"], userID, isAdmin)
	webAssets := filterAuthorizedItems(platform["web_assets"], platform["authorized_web_assets"], userID, isAdmin)
	databaseAssets := filterAuthorizedItems(platform["database_assets"], platform["authorized_database_assets"], userID, isAdmin)
	writeJSON(w, http.StatusOK, map[string]any{
		"text":      filterPlatformByProtocol(assets, model.ProtocolSSH),
		"desktop":   filterDesktopAssets(assets),
		"web":       webAssets,
		"database":  databaseAssets,
		"authorized": platform["authorized_assets"],
	})
}

func (s *Server) handleAccessAction(w http.ResponseWriter, r *http.Request) {
	parts := splitPath(strings.TrimPrefix(strings.Trim(r.URL.Path, "/"), "api/access/"))
	if len(parts) < 2 {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}
	protocol := model.Protocol(parts[0])
	assetID := parts[1]
	platform, err := s.cfg.Store.PlatformBootstrap()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	userID, isAdmin := s.accessUser(r)
	asset, ok := findAccessAsset(platform, protocol, assetID)
	if !ok {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}
	if !isAccessAuthorized(platform, protocol, assetID, userID, isAdmin) {
		writeError(w, http.StatusForbidden, "asset access denied")
		return
	}
	item, err := s.cfg.Store.CreatePlatformItem("online_sessions", model.PlatformItemRequest{
		Name:        protocolSessionName(protocol, asset.Name),
		Type:        string(protocol),
		Status:      "pending",
		Protocol:    protocol,
		TargetID:    assetID,
		OwnerID:     userID,
		Description: "接入门户创建的授权会话。",
		Metadata: map[string]any{
			"client_ip": s.clientIP(r),
			"source":    "access_portal",
			"asset_name": asset.Name,
		},
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "access."+string(protocol)+".create", item.ID, protocol, "created access portal session")
	writeJSON(w, http.StatusAccepted, item)
}

func (s *Server) handleSystemMonitoring(w http.ResponseWriter, _ *http.Request) {
	servers, credentials, sessions, auditLogs := s.cfg.Store.Bootstrap()
	platform, err := s.cfg.Store.PlatformBootstrap()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	active := 0
	recordings := 0
	for _, session := range sessions {
		if session.Status == model.SessionActive || session.Status == model.SessionPending {
			active++
		}
		if session.RecordingPath != "" {
			recordings++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":          "normal",
		"goroutines":      runtime.NumGoroutine(),
		"cpu":             runtime.NumCPU(),
		"memory_alloc":    mem.Alloc,
		"servers":         len(servers),
		"credentials":     len(credentials),
		"sessions":        len(sessions),
		"active_sessions": active,
		"recordings":      recordings,
		"audit_logs":      len(auditLogs),
		"users":           len(platform["users"]),
		"assets":          len(platform["assets"]),
		"web_assets":      len(platform["web_assets"]),
		"database_assets": len(platform["database_assets"]),
		"gateways":        len(platform["agent_gateways"]) + len(platform["ssh_gateways"]),
		"checked_at":      time.Now().UTC(),
	})
}

type pingRequest struct {
	Target string `json:"target"`
	Count  int    `json:"count"`
	Mode   string `json:"mode"`
}

func (s *Server) handlePingTool(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req pingRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	target := strings.TrimSpace(req.Target)
	if target == "" {
		writeError(w, http.StatusBadRequest, "target is required")
		return
	}
	count := clampInt(req.Count, 1, 10, 4)
	results := make([]map[string]any, 0, count)
	for i := 0; i < count; i++ {
		start := time.Now()
		status := "ok"
		detail := ""
		if strings.Contains(target, ":") || strings.EqualFold(req.Mode, "tcp") {
			conn, err := net.DialTimeout("tcp", target, 2*time.Second)
			if err != nil {
				status = "failed"
				detail = err.Error()
			} else {
				_ = conn.Close()
			}
		} else {
			addrs, err := net.LookupHost(target)
			if err != nil {
				status = "failed"
				detail = err.Error()
			} else {
				detail = strings.Join(addrs, ", ")
			}
		}
		results = append(results, map[string]any{
			"seq":     i + 1,
			"status":  status,
			"latency": time.Since(start).Milliseconds(),
			"detail":  detail,
		})
	}
	_ = s.audit(r, "tool.ping", target, "", "ran "+strconv.Itoa(count)+" checks")
	writeJSON(w, http.StatusOK, map[string]any{"target": target, "results": results})
}

func splitPath(value string) []string {
	value = strings.Trim(value, "/")
	if value == "" {
		return nil
	}
	return strings.Split(value, "/")
}

func firstPart(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func tailID(parts []string) string {
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

func filterPlatformByProtocol(items []model.PlatformItem, protocol model.Protocol) []model.PlatformItem {
	result := []model.PlatformItem{}
	for _, item := range items {
		if item.Protocol == protocol {
			result = append(result, item)
		}
	}
	return result
}

func filterDesktopAssets(items []model.PlatformItem) []model.PlatformItem {
	result := []model.PlatformItem{}
	for _, item := range items {
		if item.Protocol == model.ProtocolRDP || item.Protocol == model.ProtocolVNC {
			result = append(result, item)
		}
	}
	return result
}

func (s *Server) accessUser(r *http.Request) (string, bool) {
	_, session, ok := s.auth.session(r)
	if !ok {
		return "", false
	}
	return session.UserID, session.Role == "admin" || session.Role == "super_admin"
}

func filterAuthorizedItems(items, authorizations []model.PlatformItem, userID string, isAdmin bool) []model.PlatformItem {
	if isAdmin {
		return items
	}
	allowed := map[string]bool{}
	for _, authorization := range authorizations {
		if authorization.OwnerID == userID || authorization.Username == userID {
			allowed[authorization.TargetID] = true
		}
	}
	result := []model.PlatformItem{}
	for _, item := range items {
		if allowed[item.ID] {
			result = append(result, item)
		}
	}
	return result
}

func findAccessAsset(platform map[string][]model.PlatformItem, protocol model.Protocol, assetID string) (model.PlatformItem, bool) {
	collection := "assets"
	switch protocol {
	case model.ProtocolHTTP:
		collection = "web_assets"
	case model.ProtocolDatabase:
		collection = "database_assets"
	}
	for _, item := range platform[collection] {
		if item.ID != assetID {
			continue
		}
		if collection == "assets" && item.Protocol != protocol {
			return model.PlatformItem{}, false
		}
		return item, true
	}
	return model.PlatformItem{}, false
}

func isAccessAuthorized(platform map[string][]model.PlatformItem, protocol model.Protocol, assetID, userID string, isAdmin bool) bool {
	if isAdmin {
		return true
	}
	if userID == "" {
		return false
	}
	collection := "authorized_assets"
	switch protocol {
	case model.ProtocolHTTP:
		collection = "authorized_web_assets"
	case model.ProtocolDatabase:
		collection = "authorized_database_assets"
	}
	for _, item := range platform[collection] {
		if item.TargetID == assetID && (item.OwnerID == userID || item.Username == userID) {
			return true
		}
	}
	return false
}

func protocolSessionName(protocol model.Protocol, assetID string) string {
	if protocol == "" {
		protocol = "access"
	}
	return strings.ToUpper(string(protocol)) + " " + assetID
}
