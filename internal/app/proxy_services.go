package app

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"openwebservermanager/internal/model"
)

type proxyServicesRequest struct {
	SSHEnabled               bool           `json:"ssh_enabled"`
	SSHListenAddress         string         `json:"ssh_listen_address"`
	SSHDisablePasswordAuth   bool           `json:"ssh_disable_password_auth"`
	SSHForwardAllowlist      []string       `json:"ssh_forward_allowlist"`
	SSHPrivateKey            string         `json:"ssh_private_key"`
	RDPEnabled               bool           `json:"rdp_enabled"`
	RDPListenAddress         string         `json:"rdp_listen_address"`
	DatabaseEnabled          bool           `json:"database_enabled"`
	DatabaseListenAddress    string         `json:"database_listen_address"`
	DatabaseForwardAllowlist []string       `json:"database_forward_allowlist"`
	ProxyPrivateKey          string         `json:"proxy_private_key"`
	Metadata                 map[string]any `json:"metadata"`
}

func (s *Server) handleProxyServices(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		item, err := s.proxyServiceSetting()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, s.proxyServicesResponse(item))
	case http.MethodPost:
		var req proxyServicesRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		item, err := s.saveProxyServices(req)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.audit(r, "proxy_services.update", item.ID, "", "updated proxy service settings")
		writeJSON(w, http.StatusOK, s.proxyServicesResponse(item))
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) saveProxyServices(req proxyServicesRequest) (model.PlatformItem, error) {
	metadata := cloneMetadata(req.Metadata)
	sshListen := normalizeListenAddress(req.SSHListenAddress, "0.0.0.0:2022")
	rdpListen := normalizeListenAddress(req.RDPListenAddress, "0.0.0.0:23389")
	databaseListen := normalizeListenAddress(req.DatabaseListenAddress, "127.0.0.1:23306")
	sshAllowlist := uniqueNonEmptyStrings(req.SSHForwardAllowlist)
	databaseAllowlist := uniqueNonEmptyStrings(req.DatabaseForwardAllowlist)

	metadata["ssh_gateway_enabled"] = req.SSHEnabled
	metadata["ssh_listen_address"] = sshListen
	metadata["ssh_disable_password_auth"] = req.SSHDisablePasswordAuth
	metadata["ssh_forward_allowlist"] = sshAllowlist
	metadata["rdp_proxy_enabled"] = req.RDPEnabled
	metadata["rdp_listen_address"] = rdpListen
	metadata["database_proxy_enabled"] = req.DatabaseEnabled
	metadata["database_listen_address"] = databaseListen
	metadata["database_forward_allowlist"] = databaseAllowlist
	metadata["updated_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	if secret := strings.TrimSpace(firstNonEmpty(req.ProxyPrivateKey, req.SSHPrivateKey)); secret != "" {
		metadata["proxy_private_key"] = secret
	}

	setting, err := s.upsertProxyServiceSetting(metadata)
	if err != nil {
		return model.PlatformItem{}, err
	}
	if err := s.syncSSHGatewayFromProxySetting(req.SSHEnabled, sshListen, req.SSHDisablePasswordAuth, sshAllowlist); err != nil {
		return model.PlatformItem{}, err
	}
	if err := s.reloadSSHGatewayRuntime(); err != nil {
		return model.PlatformItem{}, err
	}
	if err := s.reloadDatabaseProxyRuntime(); err != nil {
		return model.PlatformItem{}, err
	}
	return setting, nil
}

func (s *Server) upsertProxyServiceSetting(metadata map[string]any) (model.PlatformItem, error) {
	existing, ok, err := s.rawSystemSettingByType("proxy")
	if err != nil {
		return model.PlatformItem{}, err
	}
	req := model.PlatformItemRequest{
		Name:        "Proxy service settings",
		Type:        "proxy",
		Status:      "enabled",
		Description: "SSH, RDP, and database proxy listener settings.",
		Metadata:    metadata,
	}
	if ok {
		return s.cfg.Store.UpdatePlatformItem("system_settings", existing.ID, req)
	}
	return s.cfg.Store.CreatePlatformItem("system_settings", req)
}

func (s *Server) syncSSHGatewayFromProxySetting(enabled bool, listenAddress string, disablePasswordAuth bool, allowlist []string) error {
	host, port := splitListenAddress(listenAddress, "0.0.0.0", 2022)
	metadata := map[string]any{
		"source":                "proxy_services",
		"listen_address":        listenAddress,
		"disable_password_auth": disablePasswordAuth,
		"forward_allowlist":     allowlist,
		"updated_at":            time.Now().UTC().Format(time.RFC3339Nano),
	}
	req := model.PlatformItemRequest{
		Name:        "Built-in SSH gateway",
		Type:        "builtin",
		Status:      enabledStatus(enabled),
		Protocol:    model.ProtocolSSH,
		Host:        host,
		Port:        port,
		Description: "Native SSH client gateway synchronized from proxy service settings.",
		Metadata:    metadata,
	}
	existing, ok, err := s.rawSSHGatewayForProxySettings()
	if err != nil {
		return err
	}
	if ok {
		_, err = s.cfg.Store.UpdatePlatformItem("ssh_gateways", existing.ID, req)
		return err
	}
	_, err = s.cfg.Store.CreatePlatformItem("ssh_gateways", req)
	return err
}

func (s *Server) proxyServiceSetting() (model.PlatformItem, error) {
	item, ok, err := s.rawSystemSettingByType("proxy")
	if err != nil {
		return model.PlatformItem{}, err
	}
	if !ok {
		return s.cfg.Store.CreatePlatformItem("system_settings", model.PlatformItemRequest{
			Name:        "Proxy service settings",
			Type:        "proxy",
			Status:      "enabled",
			Description: "SSH, RDP, and database proxy listener settings.",
			Metadata: map[string]any{
				"ssh_gateway_enabled":        false,
				"ssh_listen_address":         "0.0.0.0:2022",
				"rdp_proxy_enabled":          false,
				"rdp_listen_address":         "0.0.0.0:23389",
				"database_proxy_enabled":     false,
				"database_listen_address":    "127.0.0.1:23306",
				"ssh_forward_allowlist":      []string{},
				"database_forward_allowlist": []string{},
			},
		})
	}
	sanitizeProxyServiceItem(&item)
	return item, nil
}

func (s *Server) proxyServicesResponse(item model.PlatformItem) map[string]any {
	sanitizeProxyServiceItem(&item)
	metadata := item.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	sshEnabled := proxyMetadataBool(metadata["ssh_gateway_enabled"])
	rdpEnabled := proxyMetadataBool(metadata["rdp_proxy_enabled"])
	databaseEnabled := proxyMetadataBool(metadata["database_proxy_enabled"])
	guacdAddress := ""
	if s.cfg.Guacd != nil {
		guacdAddress = s.cfg.Guacd.Address()
	}
	sshLiveAddress := s.sshGatewayAddress()
	sshLastError := s.sshGatewayLastError()
	databaseListen := firstMetadataString(metadata, "database_listen_address")
	databaseAllowlist := metadataStrings(metadata["database_forward_allowlist"])
	databaseLiveAddress := s.databaseProxyAddress()
	databaseTarget := firstNonEmpty(s.databaseProxyTarget(), firstString(databaseAllowlist))
	databaseLastError := s.databaseProxyLastError()
	return map[string]any{
		"settings": item,
		"status": map[string]any{
			"ssh_gateway": map[string]any{
				"enabled":        sshEnabled,
				"listen_address": firstMetadataString(metadata, "ssh_listen_address", "listen_address"),
				"live_address":   sshLiveAddress,
				"state":          proxyRuntimeState(sshEnabled, sshLiveAddress, sshLastError),
				"last_error":     sshLastError,
			},
			"rdp_proxy": map[string]any{
				"enabled":        rdpEnabled,
				"listen_address": firstMetadataString(metadata, "rdp_listen_address"),
				"guacd_address":  guacdAddress,
				"state":          rdpProxyRuntimeState(rdpEnabled, guacdAddress),
			},
			"database_proxy": map[string]any{
				"enabled":         databaseEnabled,
				"listen_address":  databaseListen,
				"live_address":    databaseLiveAddress,
				"target":          databaseTarget,
				"active":          s.databaseProxyActiveConnections(),
				"allowlist_count": len(databaseAllowlist),
				"state":           databaseProxyRuntimeState(databaseEnabled, databaseListen, databaseAllowlist, databaseLiveAddress, databaseLastError),
				"last_error":      databaseProxyRuntimeError(databaseEnabled, databaseListen, databaseAllowlist, databaseLiveAddress, databaseLastError),
			},
		},
	}
}

func (s *Server) reloadSSHGatewayRuntime() error {
	if s.cfg.SSHGateway == nil {
		return nil
	}
	return s.cfg.SSHGateway.Reload()
}

func (s *Server) reloadDatabaseProxyRuntime() error {
	if s.cfg.DatabaseProxy == nil {
		return nil
	}
	return s.cfg.DatabaseProxy.Reload()
}

func (s *Server) sshGatewayAddress() string {
	if s.cfg.SSHGateway != nil {
		return s.cfg.SSHGateway.Address()
	}
	return s.cfg.SSHGatewayAddress
}

func (s *Server) sshGatewayLastError() string {
	if s.cfg.SSHGateway != nil {
		return s.cfg.SSHGateway.LastError()
	}
	return ""
}

func (s *Server) databaseProxyAddress() string {
	if s.cfg.DatabaseProxy != nil {
		return s.cfg.DatabaseProxy.Address()
	}
	return ""
}

func (s *Server) databaseProxyTarget() string {
	if s.cfg.DatabaseProxy != nil {
		return s.cfg.DatabaseProxy.Target()
	}
	return ""
}

func (s *Server) databaseProxyLastError() string {
	if s.cfg.DatabaseProxy != nil {
		return s.cfg.DatabaseProxy.LastError()
	}
	return ""
}

func (s *Server) databaseProxyActiveConnections() int {
	if s.cfg.DatabaseProxy != nil {
		return s.cfg.DatabaseProxy.ActiveConnections()
	}
	return 0
}

func (s *Server) rawSystemSettingByType(settingType string) (model.PlatformItem, bool, error) {
	items, err := s.cfg.Store.ListPlatformItems("system_settings")
	if err != nil {
		return model.PlatformItem{}, false, err
	}
	for _, item := range items {
		if strings.EqualFold(item.Type, settingType) {
			return s.cfg.Store.GetPlatformItem("system_settings", item.ID)
		}
	}
	return model.PlatformItem{}, false, nil
}

func (s *Server) rawSSHGatewayForProxySettings() (model.PlatformItem, bool, error) {
	items, err := s.cfg.Store.ListPlatformItems("ssh_gateways")
	if err != nil {
		return model.PlatformItem{}, false, err
	}
	for _, item := range items {
		if strings.EqualFold(firstMetadataString(item.Metadata, "source"), "proxy_services") || strings.EqualFold(item.Type, "builtin") {
			return s.cfg.Store.GetPlatformItem("ssh_gateways", item.ID)
		}
	}
	return model.PlatformItem{}, false, nil
}

func sanitizeProxyServiceItem(item *model.PlatformItem) {
	if item.Metadata == nil {
		return
	}
	if _, ok := item.Metadata["proxy_private_key_set"]; !ok {
		if firstMetadataString(item.Metadata, "proxy_private_key", "ssh_private_key", "proxy_private_key_encrypted") != "" {
			item.Metadata["proxy_private_key_set"] = true
		}
	}
	for _, key := range []string{
		"proxy_private_key",
		"ssh_private_key",
		"private_key",
		"proxy_private_key_encrypted",
	} {
		delete(item.Metadata, key)
	}
}

func normalizeListenAddress(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	host, port, err := net.SplitHostPort(value)
	if err == nil && strings.TrimSpace(host) != "" && strings.TrimSpace(port) != "" {
		return net.JoinHostPort(strings.TrimSpace(host), strings.TrimSpace(port))
	}
	if err == nil && strings.TrimSpace(port) != "" {
		return net.JoinHostPort("0.0.0.0", strings.TrimSpace(port))
	}
	if strings.Count(value, ":") == 1 && !strings.HasPrefix(value, ":") {
		return value
	}
	if strings.HasPrefix(value, ":") {
		return "0.0.0.0" + value
	}
	return value
}

func splitListenAddress(value, fallbackHost string, fallbackPort int) (string, int) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		if parts := strings.Split(value, ":"); len(parts) == 2 {
			host = strings.TrimSpace(parts[0])
			portText = strings.TrimSpace(parts[1])
		}
	}
	if strings.TrimSpace(host) == "" {
		host = fallbackHost
	}
	port, err := strconv.Atoi(strings.TrimSpace(portText))
	if err != nil || port <= 0 || port > 65535 {
		port = fallbackPort
	}
	return host, port
}

func enabledStatus(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

func proxyRuntimeState(enabled bool, liveAddress, lastError string) string {
	if !enabled {
		return "disabled"
	}
	if strings.TrimSpace(lastError) != "" {
		return "error"
	}
	if strings.TrimSpace(liveAddress) != "" {
		return "running"
	}
	return "restart_required"
}

func rdpProxyRuntimeState(enabled bool, guacdAddress string) string {
	if !enabled {
		return "disabled"
	}
	if strings.TrimSpace(guacdAddress) != "" {
		return "online"
	}
	return "guacd_unavailable"
}

func databaseProxyRuntimeState(enabled bool, listenAddress string, allowlist []string, liveAddress, lastError string) string {
	if !enabled {
		return "disabled"
	}
	if err := validateDatabaseProxyConfig(listenAddress, allowlist); err != nil {
		return "invalid_config"
	}
	if strings.TrimSpace(lastError) != "" {
		return "error"
	}
	if strings.TrimSpace(liveAddress) != "" {
		return "running"
	}
	if err := probeTCPListenAddress(listenAddress); err != nil {
		return "port_unavailable"
	}
	return "ready"
}

func databaseProxyRuntimeError(enabled bool, listenAddress string, allowlist []string, liveAddress, lastError string) string {
	if !enabled {
		return ""
	}
	if err := validateDatabaseProxyConfig(listenAddress, allowlist); err != nil {
		return err.Error()
	}
	if strings.TrimSpace(lastError) != "" {
		return lastError
	}
	if strings.TrimSpace(liveAddress) != "" {
		return ""
	}
	if err := probeTCPListenAddress(listenAddress); err != nil {
		return err.Error()
	}
	return ""
}

func validateDatabaseProxyConfig(listenAddress string, allowlist []string) error {
	if err := validateListenAddress(listenAddress); err != nil {
		return err
	}
	if len(allowlist) == 0 {
		return errors.New("database proxy forward allowlist is required")
	}
	for _, entry := range allowlist {
		if err := validateHostPort(entry); err != nil {
			return fmt.Errorf("invalid database proxy allowlist entry %q: %w", entry, err)
		}
	}
	return nil
}

func validateListenAddress(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("listen address is required")
	}
	return validateHostPort(value)
}

func validateHostPort(value string) error {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil {
		if strings.Count(value, ":") != 1 || strings.HasPrefix(value, ":") {
			return errors.New("address must be host:port")
		}
		parts := strings.SplitN(value, ":", 2)
		host = parts[0]
		portText = parts[1]
	}
	if strings.TrimSpace(host) == "" {
		return errors.New("host is required")
	}
	port, err := strconv.Atoi(strings.TrimSpace(portText))
	if err != nil || port <= 0 || port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	return nil
}

func firstString(items []string) string {
	if len(items) == 0 {
		return ""
	}
	return strings.TrimSpace(items[0])
}

func probeTCPListenAddress(value string) error {
	listener, err := net.Listen("tcp", value)
	if err != nil {
		return err
	}
	return listener.Close()
}

func proxyMetadataBool(value any) bool {
	parsed, ok := metadataBoolValue(value)
	return ok && parsed
}
