package app

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"openwebservermanager/internal/model"
)

type localLicenseRequest struct {
	Licensee  string   `json:"licensee"`
	Contact   string   `json:"contact"`
	Serial    string   `json:"serial"`
	IssuedAt  string   `json:"issued_at"`
	ExpiresAt string   `json:"expires_at"`
	Notes     string   `json:"notes"`
	Features  []string `json:"features"`
}

type localLicenseInfo struct {
	Edition                 string               `json:"edition"`
	Status                  string               `json:"status"`
	Enforcement             string               `json:"enforcement"`
	Licensee                string               `json:"licensee,omitempty"`
	Contact                 string               `json:"contact,omitempty"`
	Serial                  string               `json:"serial,omitempty"`
	IssuedAt                string               `json:"issued_at,omitempty"`
	ExpiresAt               string               `json:"expires_at,omitempty"`
	Notes                   string               `json:"notes,omitempty"`
	UpdatedAt               string               `json:"updated_at,omitempty"`
	SettingID               string               `json:"setting_id,omitempty"`
	Version                 string               `json:"version"`
	Commit                  string               `json:"commit,omitempty"`
	InstallationFingerprint string               `json:"installation_fingerprint"`
	Runtime                 map[string]string    `json:"runtime"`
	Limits                  map[string]string    `json:"limits"`
	Usage                   map[string]int       `json:"usage"`
	Features                []string             `json:"features"`
	Modules                 []localLicenseModule `json:"modules"`
}

type localLicenseModule struct {
	Key     string `json:"key"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

func (s *Server) handleAdminLicense(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		info, err := s.localLicenseInfo()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, info)
	case http.MethodPut, http.MethodPatch:
		var req localLicenseRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		item, err := s.saveLocalLicense(req)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.audit(r, "license.update", item.ID, "", "updated local license information")
		info, err := s.localLicenseInfo()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, info)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) saveLocalLicense(req localLicenseRequest) (model.PlatformItem, error) {
	platform, err := s.cfg.Store.PlatformBootstrap()
	if err != nil {
		return model.PlatformItem{}, err
	}
	current, ok := findLocalLicenseSetting(platform["system_settings"])
	features := normalizeLicenseFeatures(req.Features)
	metadata := map[string]any{
		"licensee":   req.Licensee,
		"contact":    req.Contact,
		"serial":     req.Serial,
		"issued_at":  req.IssuedAt,
		"expires_at": req.ExpiresAt,
		"notes":      req.Notes,
		"features":   features,
		"updated_at": time.Now().UTC().Format(time.RFC3339),
	}
	payload := model.PlatformItemRequest{
		Name:        "Local license",
		Type:        "license",
		Status:      "enabled",
		Description: "Local license information without commercial enforcement.",
		Metadata:    metadata,
	}
	if ok {
		payload.Name = current.Name
		payload.Description = current.Description
		return s.cfg.Store.UpdatePlatformItem("system_settings", current.ID, payload)
	}
	return s.cfg.Store.CreatePlatformItem("system_settings", payload)
}

func (s *Server) localLicenseInfo() (localLicenseInfo, error) {
	platform, err := s.cfg.Store.PlatformBootstrap()
	if err != nil {
		return localLicenseInfo{}, err
	}
	setting, ok := findLocalLicenseSetting(platform["system_settings"])
	metadata := map[string]any{}
	if ok && setting.Metadata != nil {
		metadata = setting.Metadata
	}
	status := localLicenseStatus(metadataText(metadata["expires_at"]))
	features := normalizeLicenseFeatures(metadataStringList(metadata["features"]))
	modules := localLicenseModules(features)
	if len(features) == 0 {
		for _, module := range modules {
			features = append(features, module.Key)
		}
	}
	info := localLicenseInfo{
		Edition:                 "Community",
		Status:                  status,
		Enforcement:             "none",
		Licensee:                metadataText(metadata["licensee"]),
		Contact:                 metadataText(metadata["contact"]),
		Serial:                  metadataText(metadata["serial"]),
		IssuedAt:                metadataText(metadata["issued_at"]),
		ExpiresAt:               metadataText(metadata["expires_at"]),
		Notes:                   metadataText(metadata["notes"]),
		UpdatedAt:               metadataText(metadata["updated_at"]),
		Version:                 s.cfg.Public.Version,
		Commit:                  s.cfg.Public.Commit,
		InstallationFingerprint: s.localLicenseFingerprint(),
		Runtime: map[string]string{
			"os":         runtime.GOOS,
			"arch":       runtime.GOARCH,
			"go_version": runtime.Version(),
		},
		Limits: map[string]string{
			"users":    "unlimited",
			"assets":   "unlimited",
			"gateways": "unlimited",
			"sessions": "unlimited",
		},
		Usage: map[string]int{
			"users":             len(platform["users"]),
			"assets":            len(platform["assets"]),
			"web_assets":        len(platform["web_assets"]),
			"database_assets":   len(platform["database_assets"]),
			"agent_gateways":    len(platform["agent_gateways"]),
			"ssh_gateways":      len(platform["ssh_gateways"]),
			"gateway_groups":    len(platform["gateway_groups"]),
			"online_sessions":   len(platform["online_sessions"]),
			"offline_sessions":  len(platform["offline_sessions"]),
			"scheduled_tasks":   len(platform["scheduled_tasks"]),
			"system_settings":   len(platform["system_settings"]),
			"authorization_set": len(platform["authorized_assets"]) + len(platform["authorized_web_assets"]) + len(platform["authorized_database_assets"]),
		},
		Features: features,
		Modules:  modules,
	}
	if ok {
		info.SettingID = setting.ID
	}
	return info, nil
}

func findLocalLicenseSetting(items []model.PlatformItem) (model.PlatformItem, bool) {
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item.Type), "license") {
			return item, true
		}
	}
	return model.PlatformItem{}, false
}

func localLicenseStatus(expiresAt string) string {
	expiresAt = strings.TrimSpace(expiresAt)
	if expiresAt == "" || strings.EqualFold(expiresAt, "never") {
		return "active"
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		expires, err := time.Parse(layout, expiresAt)
		if err != nil {
			continue
		}
		if time.Now().UTC().After(expires) {
			return "expired"
		}
		return "active"
	}
	return "active"
}

func (s *Server) localLicenseFingerprint() string {
	hostname, _ := os.Hostname()
	seed := strings.Join([]string{
		hostname,
		s.cfg.Store.DatabasePath(),
		s.cfg.DataDir,
		runtime.GOOS,
		runtime.GOARCH,
	}, "\n")
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])[:32]
}

func normalizeLicenseFeatures(items []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, item := range items {
		value := strings.TrimSpace(item)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func metadataStringList(value any) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		result := []string{}
		for _, item := range typed {
			if text := metadataText(item); text != "" {
				result = append(result, text)
			}
		}
		return result
	case string:
		parts := strings.FieldsFunc(typed, func(r rune) bool {
			return r == ',' || r == '\n' || r == ';'
		})
		result := []string{}
		for _, item := range parts {
			if text := strings.TrimSpace(item); text != "" {
				result = append(result, text)
			}
		}
		return result
	default:
		return nil
	}
}

func metadataText(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return strings.TrimSpace(fmt.Sprint(typed))
	case bool:
		if typed {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func localLicenseModules(features []string) []localLicenseModule {
	enabled := map[string]bool{}
	for _, feature := range features {
		enabled[strings.ToLower(strings.TrimSpace(feature))] = true
	}
	modules := []localLicenseModule{
		{Key: "ssh", Name: "SSH access", Enabled: true},
		{Key: "rdp", Name: "RDP access", Enabled: true},
		{Key: "vnc", Name: "VNC access", Enabled: true},
		{Key: "web", Name: "Web asset proxy", Enabled: true},
		{Key: "database", Name: "Database access", Enabled: true},
		{Key: "audit", Name: "Audit and recording", Enabled: true},
		{Key: "gateway", Name: "Gateway services", Enabled: true},
		{Key: "identity", Name: "LDAP / OIDC / Passkey", Enabled: true},
		{Key: "backup", Name: "Backup and restore", Enabled: true},
	}
	for index, module := range modules {
		if enabled[module.Key] {
			modules[index].Enabled = true
		}
	}
	return modules
}
