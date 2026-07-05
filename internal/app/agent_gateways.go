package app

import (
	"net/http"
	"strings"
	"time"

	"openwebservermanager/internal/model"

	"golang.org/x/crypto/bcrypt"
)

const defaultAgentHeartbeatTimeout = 120 * time.Second

type agentGatewayAuthRequest struct {
	GatewayID         string `json:"gateway_id"`
	Token             string `json:"token"`
	RegistrationToken string `json:"registration_token"`
}

type agentGatewayRegisterRequest struct {
	agentGatewayAuthRequest
	Name          string   `json:"name"`
	Hostname      string   `json:"hostname"`
	Version       string   `json:"version"`
	OS            string   `json:"os"`
	Arch          string   `json:"arch"`
	PublicAddress string   `json:"public_address"`
	ListenAddress string   `json:"listen_address"`
	IPAddresses   []string `json:"ip_addresses"`
	Labels        []string `json:"labels"`
	Capabilities  []string `json:"capabilities"`
}

type agentGatewayHeartbeatRequest struct {
	agentGatewayAuthRequest
	Hostname         string         `json:"hostname"`
	Version          string         `json:"version"`
	LatencyMS        int            `json:"latency_ms"`
	CPUPercent       float64        `json:"cpu_percent"`
	MemoryUsedBytes  int64          `json:"memory_used_bytes"`
	MemoryTotalBytes int64          `json:"memory_total_bytes"`
	DiskUsedBytes    int64          `json:"disk_used_bytes"`
	DiskTotalBytes   int64          `json:"disk_total_bytes"`
	NetworkRxBytes   int64          `json:"network_rx_bytes"`
	NetworkTxBytes   int64          `json:"network_tx_bytes"`
	ActiveSessions   int            `json:"active_sessions"`
	Metrics          map[string]any `json:"metrics"`
}

func (s *Server) handleAgentAPI(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && (r.URL.Path == "/api/agent/gateways/register" || r.URL.Path == "/api/agent/register"):
		s.handleAgentGatewayRegister(w, r)
	case r.Method == http.MethodPost && (r.URL.Path == "/api/agent/gateways/heartbeat" || r.URL.Path == "/api/agent/heartbeat"):
		s.handleAgentGatewayHeartbeat(w, r)
	default:
		writeError(w, http.StatusNotFound, "agent endpoint not found")
	}
}

func (s *Server) handleAgentGatewayToken(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	item, ok, err := s.cfg.Store.GetPlatformItem("agent_gateways", id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "agent gateway not found")
		return
	}
	secret, err := randomToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if item.Type == "" {
		item.Type = "agent"
	}
	if item.Status == "" || strings.EqualFold(item.Status, "enabled") {
		item.Status = "offline"
	}
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	now := time.Now().UTC()
	item.Metadata["agent_token_hash"] = string(hash)
	item.Metadata["token_issued_at"] = now.Format(time.RFC3339Nano)
	item.Metadata["token_issued_by"] = s.currentUserID(r)
	item.Metadata["token_generation"] = metadataIntDefault(item.Metadata["token_generation"], 0) + 1
	item.Metadata["heartbeat_timeout_seconds"] = agentHeartbeatTimeout(item).Seconds()
	saved, err := s.cfg.Store.SavePlatformItem("agent_gateways", item)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "agent_gateway.token", item.ID, "", "issued agent gateway registration token")
	writeJSON(w, http.StatusOK, map[string]any{
		"gateway":            saved,
		"gateway_id":         item.ID,
		"token":              secret,
		"registration_token": item.ID + "." + secret,
		"expires_at":         nil,
	})
}

func (s *Server) handleAgentGatewayRegister(w http.ResponseWriter, r *http.Request) {
	var req agentGatewayRegisterRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, ok := s.agentGatewayFromAuth(w, r, req.agentGatewayAuthRequest)
	if !ok {
		return
	}
	now := time.Now().UTC()
	if req.Name != "" {
		item.Name = strings.TrimSpace(req.Name)
	}
	if item.Name == "" {
		item.Name = valueOrDefault(req.Hostname, "Agent Gateway")
	}
	if item.Type == "" {
		item.Type = "agent"
	}
	item.Status = "online"
	if item.Host == "" {
		item.Host = firstNonEmpty(req.PublicAddress, req.ListenAddress, req.Hostname, s.clientIP(r))
	}
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	applyAgentIdentityMetadata(item.Metadata, req.Hostname, req.Version, req.OS, req.Arch)
	if req.PublicAddress != "" {
		item.Metadata["public_address"] = strings.TrimSpace(req.PublicAddress)
	}
	if req.ListenAddress != "" {
		item.Metadata["listen_address"] = strings.TrimSpace(req.ListenAddress)
	}
	if len(req.IPAddresses) > 0 {
		item.Metadata["ip_addresses"] = req.IPAddresses
	}
	if len(req.Labels) > 0 {
		item.Tags = req.Labels
		item.Metadata["labels"] = req.Labels
	}
	if len(req.Capabilities) > 0 {
		item.Metadata["capabilities"] = req.Capabilities
	}
	item.Metadata["registered_at"] = now.Format(time.RFC3339Nano)
	item.Metadata["last_heartbeat_at"] = now.Format(time.RFC3339Nano)
	item.Metadata["last_client_ip"] = s.clientIP(r)
	item.Metadata["heartbeat_count"] = metadataIntDefault(item.Metadata["heartbeat_count"], 0) + 1
	item.Metadata["offline_reason"] = ""
	saved, err := s.cfg.Store.SavePlatformItem("agent_gateways", item)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _ = s.cfg.Store.CreatePlatformItem("operation_logs", model.PlatformItemRequest{
		Name:        "agent.gateway.register",
		Type:        "agent",
		Status:      "success",
		TargetID:    saved.ID,
		Description: "agent gateway registered",
		Metadata:    map[string]any{"client_ip": s.clientIP(r), "gateway_id": saved.ID, "hostname": req.Hostname, "version": req.Version},
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"gateway":                    saved,
		"heartbeat_interval_seconds": 30,
		"server_time":                now,
	})
}

func (s *Server) handleAgentGatewayHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req agentGatewayHeartbeatRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, ok := s.agentGatewayFromAuth(w, r, req.agentGatewayAuthRequest)
	if !ok {
		return
	}
	now := time.Now().UTC()
	item.Status = "online"
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	applyAgentIdentityMetadata(item.Metadata, req.Hostname, req.Version, "", "")
	item.Metadata["last_heartbeat_at"] = now.Format(time.RFC3339Nano)
	item.Metadata["last_client_ip"] = s.clientIP(r)
	item.Metadata["heartbeat_count"] = metadataIntDefault(item.Metadata["heartbeat_count"], 0) + 1
	item.Metadata["latency_ms"] = clampInt(req.LatencyMS, 0, 300000, 0)
	item.Metadata["cpu_percent"] = clampFloat(req.CPUPercent, 0, 100)
	item.Metadata["memory_used_bytes"] = nonNegativeInt64(req.MemoryUsedBytes)
	item.Metadata["memory_total_bytes"] = nonNegativeInt64(req.MemoryTotalBytes)
	item.Metadata["memory_percent"] = percentOf(req.MemoryUsedBytes, req.MemoryTotalBytes)
	item.Metadata["disk_used_bytes"] = nonNegativeInt64(req.DiskUsedBytes)
	item.Metadata["disk_total_bytes"] = nonNegativeInt64(req.DiskTotalBytes)
	item.Metadata["disk_percent"] = percentOf(req.DiskUsedBytes, req.DiskTotalBytes)
	item.Metadata["network_rx_bytes"] = nonNegativeInt64(req.NetworkRxBytes)
	item.Metadata["network_tx_bytes"] = nonNegativeInt64(req.NetworkTxBytes)
	item.Metadata["active_sessions"] = clampInt(req.ActiveSessions, 0, 1000000, 0)
	item.Metadata["offline_reason"] = ""
	if len(req.Metrics) > 0 {
		item.Metadata["metrics"] = req.Metrics
	}
	saved, err := s.cfg.Store.SavePlatformItem("agent_gateways", item)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"gateway":                    saved,
		"heartbeat_interval_seconds": 30,
		"server_time":                now,
	})
}

func (s *Server) handleAgentGatewayStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	s.refreshAgentGatewayStatuses()
	items, err := s.cfg.Store.ListPlatformItems("agent_gateways")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	online := 0
	offline := 0
	for _, item := range items {
		if strings.EqualFold(item.Status, "online") {
			online++
		} else {
			offline++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "online": online, "offline": offline, "checked_at": time.Now().UTC()})
}

func (s *Server) agentGatewayFromAuth(w http.ResponseWriter, r *http.Request, auth agentGatewayAuthRequest) (model.PlatformItem, bool) {
	gatewayID, token := normalizeAgentGatewayAuth(r, auth)
	if gatewayID == "" || token == "" {
		writeError(w, http.StatusUnauthorized, "gateway_id and token are required")
		return model.PlatformItem{}, false
	}
	item, ok, err := s.cfg.Store.GetPlatformItem("agent_gateways", gatewayID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return model.PlatformItem{}, false
	}
	if !ok {
		writeError(w, http.StatusUnauthorized, "agent gateway token is invalid")
		return model.PlatformItem{}, false
	}
	if strings.EqualFold(item.Status, "disabled") {
		writeError(w, http.StatusForbidden, "agent gateway is disabled")
		return model.PlatformItem{}, false
	}
	hash, _ := item.Metadata["agent_token_hash"].(string)
	if hash == "" || bcrypt.CompareHashAndPassword([]byte(hash), []byte(token)) != nil {
		writeError(w, http.StatusUnauthorized, "agent gateway token is invalid")
		return model.PlatformItem{}, false
	}
	return item, true
}

func normalizeAgentGatewayAuth(r *http.Request, auth agentGatewayAuthRequest) (string, string) {
	gatewayID := strings.TrimSpace(auth.GatewayID)
	token := strings.TrimSpace(firstNonEmpty(auth.RegistrationToken, auth.Token))
	if bearer := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")); token == "" && bearer != "" {
		token = bearer
	}
	if headerID := strings.TrimSpace(r.Header.Get("X-Gateway-ID")); gatewayID == "" && headerID != "" {
		gatewayID = headerID
	}
	if strings.Contains(token, ".") {
		parts := strings.SplitN(token, ".", 2)
		if gatewayID == "" {
			gatewayID = strings.TrimSpace(parts[0])
		}
		token = strings.TrimSpace(parts[1])
	}
	return gatewayID, token
}

func (s *Server) refreshAgentGatewayStatuses() {
	items, err := s.cfg.Store.ListPlatformItems("agent_gateways")
	if err != nil {
		return
	}
	now := time.Now().UTC()
	for _, item := range items {
		if !strings.EqualFold(item.Status, "online") {
			continue
		}
		raw, ok, err := s.cfg.Store.GetPlatformItem("agent_gateways", item.ID)
		if err != nil || !ok {
			continue
		}
		last, ok := metadataTime(raw.Metadata["last_heartbeat_at"])
		if !ok || last.IsZero() || now.Sub(last) <= agentHeartbeatTimeout(raw) {
			continue
		}
		if raw.Metadata == nil {
			raw.Metadata = map[string]any{}
		}
		raw.Status = "offline"
		raw.Metadata["last_offline_at"] = now.Format(time.RFC3339Nano)
		raw.Metadata["offline_reason"] = "heartbeat timeout"
		_, _ = s.cfg.Store.SavePlatformItem("agent_gateways", raw)
	}
}

func agentHeartbeatTimeout(item model.PlatformItem) time.Duration {
	seconds := metadataIntDefault(item.Metadata["heartbeat_timeout_seconds"], int(defaultAgentHeartbeatTimeout.Seconds()))
	seconds = clampInt(seconds, 30, 3600, int(defaultAgentHeartbeatTimeout.Seconds()))
	return time.Duration(seconds) * time.Second
}

func applyAgentIdentityMetadata(metadata map[string]any, hostname, version, osName, arch string) {
	if hostname != "" {
		metadata["hostname"] = strings.TrimSpace(hostname)
	}
	if version != "" {
		metadata["version"] = strings.TrimSpace(version)
	}
	if osName != "" {
		metadata["os"] = strings.TrimSpace(osName)
	}
	if arch != "" {
		metadata["arch"] = strings.TrimSpace(arch)
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func clampFloat(value, min, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func nonNegativeInt64(value int64) int64 {
	if value < 0 {
		return 0
	}
	return value
}

func percentOf(used, total int64) float64 {
	if used <= 0 || total <= 0 {
		return 0
	}
	return clampFloat((float64(used)/float64(total))*100, 0, 100)
}
