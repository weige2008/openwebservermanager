package app

import (
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"openwebservermanager/internal/model"
)

var adminCollectionRoutes = map[string]string{
	"users":            "users",
	"roles":            "roles",
	"departments":      "departments",
	"login-policies":   "login_policies",
	"login-locked":     "login_locks",
	"oidc-clients":     "oidc_clients",
	"assets":           "assets",
	"asset-groups":     "asset_groups",
	"credentials":      "credentials",
	"command-snippets": "command_snippets",
	"storages":         "storages",
	"websites":         "web_assets",
	"certificates":     "certificates",
	"database-assets":  "database_assets",
	"sql-work-orders":  "sql_work_orders",
	"ssh-gateways":     "ssh_gateways",
	"agent-gateways":   "agent_gateways",
	"gateway-groups":   "gateway_groups",
	"scheduled-tasks":  "scheduled_tasks",
	"command-filters":  "command_filters",
	"strategies":       "authorization_strategies",
	"system-settings":  "system_settings",
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
	case s.handleResourceOperation(w, r, path):
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
		if collection == "agent_gateways" {
			s.refreshAgentGatewayStatuses()
		}
		items, err := s.cfg.Store.ListPlatformItems(collection)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if collection == "departments" {
			platform, err := s.cfg.Store.PlatformBootstrap()
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			items = departmentTreeItems(platform)
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
	assets := filterAuthorizedItems(platform, platform["assets"], platform["authorized_assets"], userID, isAdmin)
	webAssets := filterAuthorizedItems(platform, platform["web_assets"], platform["authorized_web_assets"], userID, isAdmin)
	databaseAssets := filterAuthorizedItems(platform, platform["database_assets"], platform["authorized_database_assets"], userID, isAdmin)
	authorizations := platform["authorized_assets"]
	if !isAdmin {
		authorizations = filterAuthorizationsForUser(platform, authorizations, userID)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"text":       filterPlatformByProtocol(assets, model.ProtocolSSH),
		"desktop":    filterDesktopAssets(assets),
		"web":        webAssets,
		"database":   databaseAssets,
		"authorized": authorizations,
	})
}

func (s *Server) handleAccessAction(w http.ResponseWriter, r *http.Request) {
	parts := splitPath(strings.TrimPrefix(strings.Trim(r.URL.Path, "/"), "api/access/"))
	if len(parts) < 2 {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}
	protocol := model.Protocol(parts[0])
	if strings.EqualFold(parts[0], "web") {
		protocol = model.ProtocolHTTP
	}
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
	if len(parts) >= 3 && parts[2] == "proxy" {
		if protocol != model.ProtocolHTTP {
			writeError(w, http.StatusBadRequest, "proxy access is only supported for web assets")
			return
		}
		s.handleWebAssetProxy(w, r, asset, userID, strings.Join(parts[3:], "/"))
		return
	}
	if len(parts) >= 3 && (parts[2] == "query" || parts[2] == "execute") {
		if protocol != model.ProtocolDatabase {
			writeError(w, http.StatusBadRequest, "query access is only supported for database assets")
			return
		}
		s.handleDatabaseAssetQuery(w, r, asset, userID)
		return
	}
	if len(parts) >= 3 && parts[2] == "work-orders" {
		if protocol != model.ProtocolDatabase {
			writeError(w, http.StatusBadRequest, "sql work orders are only supported for database assets")
			return
		}
		s.handleDatabaseWorkOrderCreate(w, r, asset, userID)
		return
	}
	if protocol == model.ProtocolRDP || protocol == model.ProtocolVNC {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		req, ok := decodeOptionalDesktopCreateRequest(w, r)
		if !ok {
			return
		}
		req.AssetID = assetID
		s.createPlatformDesktopSession(w, r, protocol, req, http.StatusAccepted)
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
			"client_ip":  s.clientIP(r),
			"source":     "access_portal",
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

func (s *Server) handleWebAssetProxy(w http.ResponseWriter, r *http.Request, asset model.PlatformItem, userID, proxyPath string) {
	started := time.Now()
	target, err := webAssetTargetURL(asset)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	targetQuery := target.RawQuery
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, proxyErr error) {
		writeError(rw, http.StatusBadGateway, proxyErr.Error())
	}
	proxy.Director = func(req *http.Request) {
		requestQuery := req.URL.RawQuery
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host
		req.URL.Path = joinProxyPath(target.Path, proxyPath)
		req.URL.RawPath = ""
		switch {
		case targetQuery == "":
			req.URL.RawQuery = requestQuery
		case req.URL.RawQuery == "":
			req.URL.RawQuery = targetQuery
		default:
			req.URL.RawQuery = targetQuery + "&" + requestQuery
		}
		req.Header.Set("X-OpenWebServerManager-User", userID)
		req.Header.Set("X-OpenWebServerManager-Asset", asset.ID)
	}
	recorder := &statusCaptureWriter{ResponseWriter: w, status: http.StatusOK}
	proxy.ServeHTTP(recorder, r)
	duration := time.Since(started)
	_, _ = s.cfg.Store.CreatePlatformItem("access_logs", model.PlatformItemRequest{
		Name:        r.Method + " " + r.URL.RequestURI(),
		Type:        r.Method,
		Status:      strconv.Itoa(recorder.status),
		Protocol:    model.ProtocolHTTP,
		OwnerID:     userID,
		TargetID:    asset.ID,
		Description: "proxied web asset request",
		Metadata: map[string]any{
			"asset_name":    asset.Name,
			"client_ip":     s.clientIP(r),
			"method":        r.Method,
			"uri":           r.URL.RequestURI(),
			"status_code":   recorder.status,
			"response_size": recorder.bytes,
			"duration_ms":   duration.Milliseconds(),
			"user_agent":    r.UserAgent(),
			"referer":       r.Referer(),
			"upstream":      target.String(),
		},
	})
	_ = s.audit(r, "access.web.proxy", asset.ID, model.ProtocolHTTP, "proxied web asset request")
}

type statusCaptureWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusCaptureWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusCaptureWriter) Write(payload []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(payload)
	w.bytes += int64(n)
	return n, err
}

func webAssetTargetURL(asset model.PlatformItem) (*url.URL, error) {
	raw := ""
	for _, key := range []string{"target_url", "upstream", "url", "target", "address"} {
		values := metadataStrings(asset.Metadata[key])
		if len(values) > 0 && strings.TrimSpace(values[0]) != "" {
			raw = strings.TrimSpace(values[0])
			break
		}
	}
	if raw == "" {
		raw = strings.TrimSpace(asset.Host)
	}
	if raw == "" {
		return nil, errors.New("web asset upstream is required")
	}
	if !strings.Contains(raw, "://") {
		scheme := "http"
		if strings.EqualFold(asset.Type, "https") || asset.Port == 443 {
			scheme = "https"
		}
		if asset.Port > 0 && !strings.Contains(raw, ":") {
			raw = net.JoinHostPort(raw, strconv.Itoa(asset.Port))
		}
		raw = scheme + "://" + raw
	}
	target, err := url.Parse(raw)
	if err != nil || target.Host == "" {
		return nil, errors.New("web asset upstream is invalid")
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, errors.New("web asset upstream must use http or https")
	}
	return target, nil
}

func joinProxyPath(basePath, proxyPath string) string {
	basePath = strings.TrimRight(basePath, "/")
	proxyPath = strings.TrimLeft(proxyPath, "/")
	if proxyPath == "" {
		if basePath == "" {
			return "/"
		}
		return basePath
	}
	if basePath == "" {
		return "/" + proxyPath
	}
	return basePath + "/" + proxyPath
}

func (s *Server) handleSystemMonitoring(w http.ResponseWriter, _ *http.Request) {
	s.refreshAgentGatewayStatuses()
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
	onlineAgentGateways := 0
	offlineAgentGateways := 0
	for _, session := range sessions {
		if session.Status == model.SessionActive || session.Status == model.SessionPending {
			active++
		}
		if session.RecordingPath != "" {
			recordings++
		}
	}
	for _, gateway := range platform["agent_gateways"] {
		if strings.EqualFold(gateway.Status, "online") {
			onlineAgentGateways++
		} else {
			offlineAgentGateways++
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
		"agent_gateways": map[string]any{
			"total":   len(platform["agent_gateways"]),
			"online":  onlineAgentGateways,
			"offline": offlineAgentGateways,
		},
		"checked_at": time.Now().UTC(),
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

func departmentTreeItems(platform map[string][]model.PlatformItem) []model.PlatformItem {
	departments := platform["departments"]
	if len(departments) == 0 {
		return []model.PlatformItem{}
	}
	byID := map[string]model.PlatformItem{}
	children := map[string][]model.PlatformItem{}
	for _, department := range departments {
		if department.Metadata == nil {
			department.Metadata = map[string]any{}
		}
		byID[department.ID] = department
		parentID := strings.TrimSpace(department.ParentID)
		if parentID != "" {
			if _, ok := byID[parentID]; !ok {
				for _, candidate := range departments {
					if strings.EqualFold(candidate.Name, parentID) {
						parentID = candidate.ID
						break
					}
				}
			}
		}
		children[parentID] = append(children[parentID], department)
	}
	for parentID := range children {
		sort.SliceStable(children[parentID], func(i, j int) bool {
			left := departmentSortValue(children[parentID][i])
			right := departmentSortValue(children[parentID][j])
			if left != right {
				return left < right
			}
			return strings.ToLower(children[parentID][i].Name) < strings.ToLower(children[parentID][j].Name)
		})
	}

	memberCounts := departmentMemberCounts(platform["users"], departments)
	totalCounts := map[string]int{}
	var countTotal func(string, map[string]bool) int
	countTotal = func(departmentID string, seen map[string]bool) int {
		if seen[departmentID] {
			return memberCounts[departmentID]
		}
		seen[departmentID] = true
		total := memberCounts[departmentID]
		for _, child := range children[departmentID] {
			total += countTotal(child.ID, seen)
		}
		totalCounts[departmentID] = total
		return total
	}
	for _, department := range departments {
		countTotal(department.ID, map[string]bool{})
	}

	result := []model.PlatformItem{}
	visited := map[string]bool{}
	var walk func(string, int, []string)
	walk = func(parentID string, level int, path []string) {
		for _, department := range children[parentID] {
			if visited[department.ID] {
				continue
			}
			visited[department.ID] = true
			if department.Metadata == nil {
				department.Metadata = map[string]any{}
			}
			department.Metadata["level"] = level
			department.Metadata["path"] = strings.Join(append(path, department.Name), " / ")
			department.Metadata["sort"] = departmentSortValue(department)
			department.Metadata["member_count"] = memberCounts[department.ID]
			department.Metadata["total_member_count"] = totalCounts[department.ID]
			department.Metadata["direct_child_count"] = len(children[department.ID])
			result = append(result, department)
			walk(department.ID, level+1, append(path, department.Name))
		}
	}
	walk("", 0, nil)
	for _, department := range departments {
		if visited[department.ID] {
			continue
		}
		walk(department.ParentID, 0, nil)
		if visited[department.ID] {
			continue
		}
		if department.Metadata == nil {
			department.Metadata = map[string]any{}
		}
		department.Metadata["level"] = 0
		department.Metadata["path"] = department.Name
		department.Metadata["sort"] = departmentSortValue(department)
		department.Metadata["member_count"] = memberCounts[department.ID]
		department.Metadata["total_member_count"] = totalCounts[department.ID]
		department.Metadata["direct_child_count"] = len(children[department.ID])
		result = append(result, department)
		visited[department.ID] = true
	}
	return result
}

func departmentSortValue(item model.PlatformItem) int {
	for _, key := range []string{"sort", "order", "priority", "weight"} {
		if value, ok := metadataInt(item.Metadata[key]); ok {
			return value
		}
	}
	if item.Port != 0 {
		return item.Port
	}
	return 0
}

func departmentMemberCounts(users, departments []model.PlatformItem) map[string]int {
	keysByDepartment := map[string]map[string]bool{}
	for _, department := range departments {
		keys := map[string]bool{}
		addAuthKeys(keys, department.ID, department.Name)
		addMetadataAuthKeys(keys, department.Metadata, "department_id", "department_ids", "departmentId", "dept_id", "dept_ids", "department", "departments", "dept", "depts")
		keysByDepartment[department.ID] = keys
	}
	counts := map[string]int{}
	for _, user := range users {
		userKeys := map[string]bool{}
		addAuthKeys(userKeys, user.ParentID, user.Group)
		addMetadataAuthKeys(userKeys, user.Metadata, "department_id", "department_ids", "departmentId", "dept_id", "dept_ids", "department", "departments", "dept", "depts")
		if len(userKeys) == 0 {
			continue
		}
		for departmentID, departmentKeys := range keysByDepartment {
			if authKeysOverlap(userKeys, departmentKeys) {
				counts[departmentID]++
			}
		}
	}
	return counts
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
	kind := s.roleDecision(session.Role).Kind
	return session.UserID, kind == roleSuperAdmin || kind == roleAdmin
}

type accessAuthorizationContext struct {
	SubjectKeys map[string]bool
}

func filterAuthorizedItems(platform map[string][]model.PlatformItem, items, authorizations []model.PlatformItem, userID string, isAdmin bool) []model.PlatformItem {
	if isAdmin {
		return items
	}
	ctx := accessAuthorizationContextFor(platform, userID)
	result := []model.PlatformItem{}
	for _, item := range items {
		if itemAuthorizedByAny(platform, authorizations, item, ctx) {
			result = append(result, item)
		}
	}
	return result
}

func itemAuthorizedByAny(platform map[string][]model.PlatformItem, authorizations []model.PlatformItem, asset model.PlatformItem, ctx accessAuthorizationContext) bool {
	for _, authorization := range authorizations {
		if authorizationAppliesToAsset(platform, authorization, asset, ctx) {
			return true
		}
	}
	return false
}

func authorizationAppliesToAsset(platform map[string][]model.PlatformItem, authorization, asset model.PlatformItem, ctx accessAuthorizationContext) bool {
	return authorizationRecordActive(authorization) &&
		authorizationSubjectMatches(ctx, authorization) &&
		authorizationTargetMatches(platform, authorization, asset)
}

func accessAuthorizationContextFor(platform map[string][]model.PlatformItem, userID string) accessAuthorizationContext {
	ctx := accessAuthorizationContext{SubjectKeys: map[string]bool{}}
	addAuthKeys(ctx.SubjectKeys, userID)
	for _, user := range platform["users"] {
		if !authKeyMatches(ctx.SubjectKeys, user.ID) {
			continue
		}
		addAuthKeys(ctx.SubjectKeys, user.ID, user.Name, user.Username, user.OwnerID)
		addAuthKeys(ctx.SubjectKeys, user.ParentID, user.Group)
		addMetadataAuthKeys(ctx.SubjectKeys, user.Metadata,
			"department_id", "department_ids", "departmentId", "dept_id", "dept_ids", "department", "departments", "dept", "depts",
			"group_id", "group_ids", "groupId",
		)
		expandRelatedItemKeys(platform["departments"], ctx.SubjectKeys)
		return ctx
	}
	return ctx
}

func authorizationSubjectMatches(ctx accessAuthorizationContext, authorization model.PlatformItem) bool {
	subjectKeys := map[string]bool{}
	addAuthKeys(subjectKeys, authorization.OwnerID, authorization.Username, authorization.ParentID, authorization.Group)
	addMetadataAuthKeys(subjectKeys, authorization.Metadata,
		"subject_id", "subject_ids", "subjectId",
		"user_id", "user_ids", "userId", "username", "usernames", "account", "accounts",
		"owner_id", "owner_ids", "ownerId",
		"department_id", "department_ids", "departmentId", "dept_id", "dept_ids", "department", "departments", "dept", "depts",
	)
	return authKeysOverlap(ctx.SubjectKeys, subjectKeys)
}

func authorizationTargetMatches(platform map[string][]model.PlatformItem, authorization, asset model.PlatformItem) bool {
	targetKeys := map[string]bool{}
	addAuthKeys(targetKeys, authorization.TargetID, authorization.ParentID, authorization.Group)
	addMetadataAuthKeys(targetKeys, authorization.Metadata,
		"target_id", "target_ids", "targetId",
		"asset_id", "asset_ids", "assetId", "resource_id", "resource_ids",
		"asset_group_id", "asset_group_ids", "assetGroupId",
		"target_group_id", "target_group_ids", "targetGroupId",
		"group_id", "group_ids", "groupId", "group", "groups",
	)
	if targetKeys["*"] {
		return true
	}
	if len(targetKeys) == 0 {
		return false
	}
	assetKeys := assetAuthorizationKeys(platform, asset)
	return authKeysOverlap(assetKeys, targetKeys)
}

func assetAuthorizationKeys(platform map[string][]model.PlatformItem, asset model.PlatformItem) map[string]bool {
	keys := map[string]bool{}
	addAuthKeys(keys, asset.ID, asset.Name, asset.TargetID, asset.ParentID, asset.Group)
	addMetadataAuthKeys(keys, asset.Metadata,
		"asset_id", "asset_ids", "assetId",
		"group_id", "group_ids", "groupId",
		"asset_group_id", "asset_group_ids", "assetGroupId",
		"parent_id", "parent_ids", "parentId",
	)
	expandRelatedItemKeys(platform["asset_groups"], keys)
	return keys
}

func authorizationRecordActive(authorization model.PlatformItem) bool {
	if !platformItemEnabled(authorization) {
		return false
	}
	for _, key := range []string{"expires_at", "expire_at", "expiresAt", "expired_at", "valid_until", "not_after"} {
		expiresAt, ok := metadataTime(authorization.Metadata[key])
		if ok && !expiresAt.IsZero() && !time.Now().UTC().Before(expiresAt) {
			return false
		}
	}
	return true
}

func expandRelatedItemKeys(items []model.PlatformItem, keys map[string]bool) {
	for {
		changed := false
		for _, item := range items {
			if !authKeyMatches(keys, item.ID) && !authKeyMatches(keys, item.Name) {
				continue
			}
			changed = addAuthKeys(keys, item.ID, item.Name, item.ParentID, item.Group) || changed
			changed = addMetadataAuthKeys(keys, item.Metadata, "parent_id", "parent_ids", "parentId", "group_id", "group_ids", "groupId") || changed
		}
		if !changed {
			return
		}
	}
}

func addMetadataAuthKeys(keys map[string]bool, metadata map[string]any, names ...string) bool {
	changed := false
	for _, name := range names {
		for _, value := range metadataStrings(metadata[name]) {
			changed = addAuthKeys(keys, value) || changed
		}
	}
	return changed
}

func addAuthKeys(keys map[string]bool, values ...string) bool {
	changed := false
	for _, value := range values {
		for _, part := range splitCriteria(value) {
			key := normalizeAuthKey(part)
			if key == "" || keys[key] {
				continue
			}
			keys[key] = true
			changed = true
		}
	}
	return changed
}

func authKeysOverlap(left, right map[string]bool) bool {
	if left["*"] || right["*"] {
		return true
	}
	for key := range right {
		if left[key] {
			return true
		}
	}
	return false
}

func authKeyMatches(keys map[string]bool, value string) bool {
	for _, part := range splitCriteria(value) {
		if keys[normalizeAuthKey(part)] {
			return true
		}
	}
	return false
}

func normalizeAuthKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func accessBootstrapPlatform(platform map[string][]model.PlatformItem, userID string) map[string][]model.PlatformItem {
	result := emptyPlatformBootstrap()
	result["assets"] = filterAuthorizedItems(platform, platform["assets"], platform["authorized_assets"], userID, false)
	result["web_assets"] = filterAuthorizedItems(platform, platform["web_assets"], platform["authorized_web_assets"], userID, false)
	result["database_assets"] = filterAuthorizedItems(platform, platform["database_assets"], platform["authorized_database_assets"], userID, false)
	result["asset_groups"] = platform["asset_groups"]
	result["command_snippets"] = filterCommandSnippetsForUser(platform["command_snippets"], userID, false)
	result["authorized_assets"] = filterAuthorizationsForUser(platform, platform["authorized_assets"], userID)
	result["authorized_web_assets"] = filterAuthorizationsForUser(platform, platform["authorized_web_assets"], userID)
	result["authorized_database_assets"] = filterAuthorizationsForUser(platform, platform["authorized_database_assets"], userID)
	result["online_sessions"] = filterItemsByOwner(platform["online_sessions"], userID)
	result["offline_sessions"] = filterItemsByOwner(platform["offline_sessions"], userID)
	return result
}

func auditBootstrapPlatform(platform map[string][]model.PlatformItem) map[string][]model.PlatformItem {
	result := emptyPlatformBootstrap()
	for _, collection := range auditCollectionRoutes {
		result[collection] = platform[collection]
	}
	result["online_sessions"] = platform["online_sessions"]
	result["offline_sessions"] = platform["offline_sessions"]
	return result
}

func emptyPlatformBootstrap() map[string][]model.PlatformItem {
	return map[string][]model.PlatformItem{
		"users":                      {},
		"roles":                      {},
		"departments":                {},
		"login_policies":             {},
		"login_locks":                {},
		"oidc_clients":               {},
		"assets":                     {},
		"asset_groups":               {},
		"credentials":                {},
		"command_snippets":           {},
		"storages":                   {},
		"web_assets":                 {},
		"certificates":               {},
		"database_assets":            {},
		"sql_work_orders":            {},
		"ssh_gateways":               {},
		"agent_gateways":             {},
		"gateway_groups":             {},
		"online_sessions":            {},
		"offline_sessions":           {},
		"exec_command_logs":          {},
		"file_logs":                  {},
		"access_logs":                {},
		"access_stats":               {},
		"login_logs":                 {},
		"operation_logs":             {},
		"sql_logs":                   {},
		"scheduled_tasks":            {},
		"command_filters":            {},
		"authorization_strategies":   {},
		"authorized_assets":          {},
		"authorized_web_assets":      {},
		"authorized_database_assets": {},
		"system_settings":            {},
	}
}

func filterAuthorizationsForUser(platform map[string][]model.PlatformItem, authorizations []model.PlatformItem, userID string) []model.PlatformItem {
	ctx := accessAuthorizationContextFor(platform, userID)
	result := []model.PlatformItem{}
	for _, authorization := range authorizations {
		if authorizationRecordActive(authorization) && authorizationSubjectMatches(ctx, authorization) {
			result = append(result, authorization)
		}
	}
	return result
}

func filterItemsByOwner(items []model.PlatformItem, userID string) []model.PlatformItem {
	result := []model.PlatformItem{}
	for _, item := range items {
		if item.OwnerID == userID || item.Username == userID {
			result = append(result, item)
		}
	}
	return result
}

func filterCommandSnippetsForUser(items []model.PlatformItem, userID string, isAdmin bool) []model.PlatformItem {
	result := []model.PlatformItem{}
	for _, item := range items {
		if !platformItemEnabled(item) {
			continue
		}
		if isAdmin || commandSnippetPublic(item) || item.OwnerID == userID || item.Username == userID {
			result = append(result, item)
		}
	}
	return result
}

func commandSnippetPublic(item model.PlatformItem) bool {
	if strings.EqualFold(strings.TrimSpace(item.Type), "public") {
		return true
	}
	if item.Permissions["public"] {
		return true
	}
	switch value := item.Metadata["public"].(type) {
	case bool:
		return value
	case string:
		return strings.EqualFold(strings.TrimSpace(value), "true") || strings.EqualFold(strings.TrimSpace(value), "yes")
	default:
		return false
	}
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
	asset, ok := findAccessAsset(platform, protocol, assetID)
	if !ok {
		return false
	}
	ctx := accessAuthorizationContextFor(platform, userID)
	collection := "authorized_assets"
	switch protocol {
	case model.ProtocolHTTP:
		collection = "authorized_web_assets"
	case model.ProtocolDatabase:
		collection = "authorized_database_assets"
	}
	for _, item := range platform[collection] {
		if authorizationAppliesToAsset(platform, item, asset, ctx) {
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
