package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"openwebservermanager/internal/model"
)

const (
	smtpConnectTimeout  = 10 * time.Second
	smtpSessionTimeout  = 15 * time.Second
	llmRequestTimeout   = 20 * time.Second
	maxLLMPromptBytes   = 64 << 10
	maxLLMResponseBytes = 1 << 20
	maxLLMErrorBytes    = 8 << 10
	maxLLMRedirects     = 3
)

type smtpTestRequest struct {
	SettingID string `json:"setting_id"`
	To        string `json:"to"`
	Subject   string `json:"subject"`
	Body      string `json:"body"`
}

type llmTestRequest struct {
	SettingID string `json:"setting_id"`
	Prompt    string `json:"prompt"`
}

type ldapTestRequest struct {
	SettingID  string `json:"setting_id"`
	ProviderID string `json:"provider_id"`
	Username   string `json:"username"`
	Password   string `json:"password"`
}

type weComTestRequest struct {
	SettingID  string `json:"setting_id"`
	ProviderID string `json:"provider_id"`
}

type oidcTestRequest struct {
	SettingID  string `json:"setting_id"`
	ProviderID string `json:"provider_id"`
}

type smtpDeliveryConfig struct {
	SettingID          string
	Host               string
	Port               int
	Username           string
	Password           string
	From               string
	FromAddress        string
	To                 []string
	ToAddresses        []string
	UseTLS             bool
	StartTLS           bool
	ServerName         string
	InsecureSkipVerify bool
}

type llmDeliveryConfig struct {
	SettingID string
	Provider  string
	BaseURL   string
	Model     string
	APIKey    string
}

func (s *Server) handleSMTPTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req smtpTestRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, ok, err := s.smtpIntegrationSetting(req.SettingID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "SMTP integration setting not found")
		return
	}
	password, ok, err := s.cfg.Store.SystemSettingSMTPPassword(item.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "SMTP integration setting not found")
		return
	}
	cfg, err := smtpDeliveryConfigFromSetting(item, password, req.To)
	if err != nil {
		if logErr := s.createIntegrationTestOperationLog(r, "system_settings.smtp_test.failed", "failed", item.ID, err.Error(), map[string]any{"integration": "smtp"}); logErr != nil {
			writeError(w, http.StatusInternalServerError, logErr.Error())
			return
		}
		_ = s.audit(r, "system_settings.smtp_test.failed", item.ID, "", err.Error())
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	subject := strings.TrimSpace(req.Subject)
	if subject == "" {
		subject = "Open Web Server Manager SMTP test"
	}
	body := strings.TrimSpace(req.Body)
	if body == "" {
		body = "This is a test email from Open Web Server Manager."
	}
	started := time.Now()
	if err := sendSMTPTestMail(r.Context(), cfg, subject, body); err != nil {
		errText := sanitizeSMTPTestText(cfg, err.Error())
		if logErr := s.createIntegrationTestOperationLog(r, "system_settings.smtp_test.failed", "failed", item.ID, "SMTP test failed: "+errText, map[string]any{
			"integration":     "smtp",
			"host":            cfg.Host,
			"port":            cfg.Port,
			"recipient_count": len(cfg.To),
		}); logErr != nil {
			writeError(w, http.StatusInternalServerError, logErr.Error())
			return
		}
		_ = s.audit(r, "system_settings.smtp_test.failed", item.ID, "", "SMTP test failed: "+errText)
		writeError(w, http.StatusBadGateway, "send SMTP test email: "+errText)
		return
	}
	durationMS := time.Since(started).Milliseconds()
	if logErr := s.createIntegrationTestOperationLog(r, "system_settings.smtp_test", "success", item.ID, "sent SMTP test email", map[string]any{
		"integration":     "smtp",
		"host":            cfg.Host,
		"port":            cfg.Port,
		"recipient_count": len(cfg.To),
		"duration_ms":     durationMS,
	}); logErr != nil {
		writeError(w, http.StatusInternalServerError, logErr.Error())
		return
	}
	_ = s.audit(r, "system_settings.smtp_test", item.ID, "", "sent SMTP test email")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"message":     "SMTP test email sent",
		"setting_id":  item.ID,
		"host":        cfg.Host,
		"port":        cfg.Port,
		"to":          cfg.To,
		"duration_ms": durationMS,
		"sent_at":     time.Now().UTC(),
	})
}

func (s *Server) handleLLMTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req llmTestRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, ok, err := s.smtpIntegrationSetting(req.SettingID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "LLM integration setting not found")
		return
	}
	apiKey, ok, err := s.cfg.Store.SystemSettingLLMAPIKey(item.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "LLM integration setting not found")
		return
	}
	cfg, err := llmDeliveryConfigFromSetting(item, apiKey)
	if err != nil {
		if logErr := s.createIntegrationTestOperationLog(r, "system_settings.llm_test.failed", "failed", item.ID, err.Error(), map[string]any{"integration": "llm"}); logErr != nil {
			writeError(w, http.StatusInternalServerError, logErr.Error())
			return
		}
		_ = s.audit(r, "system_settings.llm_test.failed", item.ID, "", err.Error())
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	prompt := strings.TrimSpace(req.Prompt)
	if prompt == "" {
		prompt = "Reply with the single word: ok"
	}
	if len(prompt) > maxLLMPromptBytes {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("LLM test prompt must not exceed %d bytes", maxLLMPromptBytes))
		return
	}
	started := time.Now()
	content, err := sendLLMTestPrompt(r.Context(), cfg, prompt)
	if err != nil {
		errText := sanitizeLLMTestText(cfg, err.Error())
		if logErr := s.createIntegrationTestOperationLog(r, "system_settings.llm_test.failed", "failed", item.ID, "LLM test failed: "+errText, map[string]any{
			"integration": "llm",
			"provider":    cfg.Provider,
			"model":       cfg.Model,
		}); logErr != nil {
			writeError(w, http.StatusInternalServerError, logErr.Error())
			return
		}
		_ = s.audit(r, "system_settings.llm_test.failed", item.ID, "", "LLM test failed: "+errText)
		writeError(w, http.StatusBadGateway, "send LLM test prompt: "+errText)
		return
	}
	content = sanitizeLLMTestText(cfg, content)
	durationMS := time.Since(started).Milliseconds()
	if logErr := s.createIntegrationTestOperationLog(r, "system_settings.llm_test", "success", item.ID, "sent LLM test prompt", map[string]any{
		"integration": "llm",
		"provider":    cfg.Provider,
		"model":       cfg.Model,
		"duration_ms": durationMS,
	}); logErr != nil {
		writeError(w, http.StatusInternalServerError, logErr.Error())
		return
	}
	_ = s.audit(r, "system_settings.llm_test", item.ID, "", "sent LLM test prompt")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"message":     "LLM test prompt completed",
		"setting_id":  item.ID,
		"provider":    cfg.Provider,
		"base_url":    cfg.BaseURL,
		"model":       cfg.Model,
		"response":    content,
		"duration_ms": durationMS,
		"tested_at":   time.Now().UTC(),
	})
}

func (s *Server) handleLDAPTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req ldapTestRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	username := strings.TrimSpace(req.Username)
	if username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "ldap test username and password are required")
		return
	}
	item, providers, ok, err := s.ldapTestSetting(req.SettingID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "LDAP identity setting not found")
		return
	}
	provider, ok := selectLDAPTestProvider(providers, req.ProviderID)
	if !ok {
		writeError(w, http.StatusBadRequest, "LDAP provider is not configured")
		return
	}
	started := time.Now()
	claims, authenticated, err := s.ldap.Authenticate(r.Context(), provider, username, req.Password)
	if err != nil {
		errText := sanitizeLDAPText(provider, req.Password, err.Error())
		if logErr := s.createIntegrationTestOperationLog(r, "system_settings.ldap_test.failed", "failed", item.ID, "LDAP test failed: "+errText, map[string]any{"provider_id": provider.ID}); logErr != nil {
			writeError(w, http.StatusInternalServerError, logErr.Error())
			return
		}
		_ = s.audit(r, "system_settings.ldap_test.failed", item.ID, "", "LDAP test failed: "+errText)
		writeError(w, http.StatusBadGateway, "test LDAP login: "+errText)
		return
	}
	if !authenticated {
		if logErr := s.createIntegrationTestOperationLog(r, "system_settings.ldap_test.failed", "failed", item.ID, "LDAP test credentials rejected", map[string]any{"provider_id": provider.ID}); logErr != nil {
			writeError(w, http.StatusInternalServerError, logErr.Error())
			return
		}
		_ = s.audit(r, "system_settings.ldap_test.failed", item.ID, "", "LDAP test credentials rejected")
		writeError(w, http.StatusUnauthorized, "LDAP test credentials were rejected")
		return
	}
	if logErr := s.createIntegrationTestOperationLog(r, "system_settings.ldap_test", "success", item.ID, "LDAP test login succeeded", map[string]any{"provider_id": provider.ID}); logErr != nil {
		writeError(w, http.StatusInternalServerError, logErr.Error())
		return
	}
	_ = s.audit(r, "system_settings.ldap_test", item.ID, "", "LDAP test login succeeded")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"message":      "LDAP test login succeeded",
		"setting_id":   item.ID,
		"provider_id":  provider.ID,
		"provider":     provider.Name,
		"subject":      claims.Subject,
		"dn":           claims.DN,
		"username":     claims.Username,
		"display_name": claims.DisplayName,
		"email":        claims.Email,
		"groups":       claims.Groups,
		"duration_ms":  time.Since(started).Milliseconds(),
		"tested_at":    time.Now().UTC(),
	})
}

func (s *Server) handleOIDCTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req oidcTestRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, providers, ok, err := s.oidcTestSetting(req.SettingID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "External OIDC identity setting not found")
		return
	}
	provider, ok := selectOIDCTestProvider(providers, req.ProviderID)
	if !ok {
		writeError(w, http.StatusBadRequest, "External OIDC provider is not configured")
		return
	}
	redirectURI := externalOIDCRedirectURI(r, s.cfg.TrustProxyHeaders)
	started := time.Now()
	statusCode, authorizeURL, err := testExternalOIDCAuthorizationEndpoint(provider, redirectURI)
	if err != nil {
		errText := sanitizedOIDCTestError(provider, err)
		if logErr := s.createIntegrationTestOperationLog(r, "system_settings.oidc_test.failed", "failed", item.ID, "External OIDC test failed: "+errText, map[string]any{"provider_id": provider.ID}); logErr != nil {
			writeError(w, http.StatusInternalServerError, logErr.Error())
			return
		}
		_ = s.audit(r, "system_settings.oidc_test.failed", item.ID, "", "External OIDC test failed: "+errText)
		writeError(w, http.StatusBadGateway, "test external OIDC authorization endpoint: "+errText)
		return
	}
	if logErr := s.createIntegrationTestOperationLog(r, "system_settings.oidc_test", "success", item.ID, "External OIDC authorization endpoint test succeeded", map[string]any{"provider_id": provider.ID, "status_code": statusCode}); logErr != nil {
		writeError(w, http.StatusInternalServerError, logErr.Error())
		return
	}
	_ = s.audit(r, "system_settings.oidc_test", item.ID, "", "External OIDC authorization endpoint test succeeded")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                     true,
		"message":                "External OIDC authorization endpoint test succeeded",
		"setting_id":             item.ID,
		"provider_id":            provider.ID,
		"provider":               provider.Name,
		"authorization_endpoint": provider.AuthorizationEndpoint,
		"authorize_url":          authorizeURL,
		"redirect_uri":           redirectURI,
		"client_id":              provider.ClientID,
		"scopes":                 provider.Scopes,
		"status_code":            statusCode,
		"duration_ms":            time.Since(started).Milliseconds(),
		"tested_at":              time.Now().UTC(),
	})
}

func (s *Server) handleWeComTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req weComTestRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, providers, ok, err := s.weComTestSetting(req.SettingID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Enterprise WeChat identity setting not found")
		return
	}
	provider, ok := selectWeComTestProvider(providers, req.ProviderID)
	if !ok {
		writeError(w, http.StatusBadRequest, "Enterprise WeChat provider is not configured")
		return
	}
	started := time.Now()
	expiresIn, err := testExternalWeComAccessToken(r.Context(), provider)
	if err != nil {
		errText := sanitizedWeComTestError(provider, err)
		if logErr := s.createIntegrationTestOperationLog(r, "system_settings.wecom_test.failed", "failed", item.ID, "Enterprise WeChat test failed: "+errText, map[string]any{"provider_id": provider.ID}); logErr != nil {
			writeError(w, http.StatusInternalServerError, logErr.Error())
			return
		}
		_ = s.audit(r, "system_settings.wecom_test.failed", item.ID, "", "Enterprise WeChat test failed: "+errText)
		writeError(w, http.StatusBadGateway, "test Enterprise WeChat token: "+errText)
		return
	}
	if logErr := s.createIntegrationTestOperationLog(r, "system_settings.wecom_test", "success", item.ID, "Enterprise WeChat token test succeeded", map[string]any{"provider_id": provider.ID, "expires_in_seconds": expiresIn}); logErr != nil {
		writeError(w, http.StatusInternalServerError, logErr.Error())
		return
	}
	_ = s.audit(r, "system_settings.wecom_test", item.ID, "", "Enterprise WeChat token test succeeded")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                 true,
		"message":            "Enterprise WeChat token test succeeded",
		"setting_id":         item.ID,
		"provider_id":        provider.ID,
		"provider":           provider.Name,
		"corp_id":            provider.CorpID,
		"agent_id":           provider.AgentID,
		"expires_in_seconds": expiresIn,
		"duration_ms":        time.Since(started).Milliseconds(),
		"tested_at":          time.Now().UTC(),
	})
}

func (s *Server) createIntegrationTestOperationLog(r *http.Request, name, status, settingID, description string, metadata map[string]any) error {
	if metadata == nil {
		metadata = map[string]any{}
	} else {
		metadata = cloneMetadata(metadata)
	}
	metadata["client_ip"] = s.clientIP(r)
	metadata["setting_id"] = settingID
	return s.createOperationLog(r, model.PlatformItemRequest{
		Name:        name,
		Type:        "integration_test",
		Status:      status,
		OwnerID:     s.currentUserID(r),
		TargetID:    settingID,
		Description: description,
		Metadata:    metadata,
	})
}

func (s *Server) smtpIntegrationSetting(id string) (model.PlatformItem, bool, error) {
	if strings.TrimSpace(id) != "" {
		item, ok, err := s.cfg.Store.GetPlatformItem("system_settings", strings.TrimSpace(id))
		if err != nil || !ok {
			return model.PlatformItem{}, ok, err
		}
		if !strings.EqualFold(strings.TrimSpace(item.Type), "integration") || !platformItemEnabled(item) {
			return model.PlatformItem{}, false, nil
		}
		return item, true, nil
	}
	items, err := s.cfg.Store.ListPlatformItems("system_settings")
	if err != nil {
		return model.PlatformItem{}, false, err
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item.Type), "integration") && platformItemEnabled(item) {
			return item, true, nil
		}
	}
	return model.PlatformItem{}, false, nil
}

func (s *Server) ldapTestSetting(id string) (model.PlatformItem, []externalLDAPProvider, bool, error) {
	if strings.TrimSpace(id) != "" {
		item, ok, err := s.cfg.Store.GetPlatformItem("system_settings", strings.TrimSpace(id))
		if err != nil || !ok {
			return model.PlatformItem{}, nil, ok, err
		}
		if !strings.EqualFold(strings.TrimSpace(item.Type), "identity") || !platformItemEnabled(item) {
			return model.PlatformItem{}, nil, false, nil
		}
		providers, err := s.externalLDAPProvidersFromMetadata(item.Metadata)
		if err != nil {
			return model.PlatformItem{}, nil, false, err
		}
		return item, providers, true, nil
	}
	items, err := s.cfg.Store.ListPlatformItems("system_settings")
	if err != nil {
		return model.PlatformItem{}, nil, false, err
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	for _, item := range items {
		if !strings.EqualFold(strings.TrimSpace(item.Type), "identity") || !platformItemEnabled(item) {
			continue
		}
		providers, err := s.externalLDAPProvidersFromMetadata(item.Metadata)
		if err != nil {
			return model.PlatformItem{}, nil, false, err
		}
		if len(providers) > 0 {
			return item, providers, true, nil
		}
	}
	return model.PlatformItem{}, nil, false, nil
}

func (s *Server) oidcTestSetting(id string) (model.PlatformItem, []externalOIDCProvider, bool, error) {
	if strings.TrimSpace(id) != "" {
		item, ok, err := s.cfg.Store.GetPlatformItem("system_settings", strings.TrimSpace(id))
		if err != nil || !ok {
			return model.PlatformItem{}, nil, ok, err
		}
		if !strings.EqualFold(strings.TrimSpace(item.Type), "identity") || !platformItemEnabled(item) {
			return model.PlatformItem{}, nil, false, nil
		}
		providers, err := s.externalOIDCProvidersFromMetadata(item.Metadata)
		if err != nil {
			return model.PlatformItem{}, nil, false, err
		}
		return item, providers, true, nil
	}
	items, err := s.cfg.Store.ListPlatformItems("system_settings")
	if err != nil {
		return model.PlatformItem{}, nil, false, err
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	for _, item := range items {
		if !strings.EqualFold(strings.TrimSpace(item.Type), "identity") || !platformItemEnabled(item) {
			continue
		}
		providers, err := s.externalOIDCProvidersFromMetadata(item.Metadata)
		if err != nil {
			return model.PlatformItem{}, nil, false, err
		}
		if len(providers) > 0 {
			return item, providers, true, nil
		}
	}
	return model.PlatformItem{}, nil, false, nil
}

func (s *Server) weComTestSetting(id string) (model.PlatformItem, []externalWeComProvider, bool, error) {
	if strings.TrimSpace(id) != "" {
		item, ok, err := s.cfg.Store.GetPlatformItem("system_settings", strings.TrimSpace(id))
		if err != nil || !ok {
			return model.PlatformItem{}, nil, ok, err
		}
		if !strings.EqualFold(strings.TrimSpace(item.Type), "identity") || !platformItemEnabled(item) {
			return model.PlatformItem{}, nil, false, nil
		}
		providers, err := s.externalWeComProvidersFromMetadata(item.Metadata)
		if err != nil {
			return model.PlatformItem{}, nil, false, err
		}
		return item, providers, true, nil
	}
	items, err := s.cfg.Store.ListPlatformItems("system_settings")
	if err != nil {
		return model.PlatformItem{}, nil, false, err
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	for _, item := range items {
		if !strings.EqualFold(strings.TrimSpace(item.Type), "identity") || !platformItemEnabled(item) {
			continue
		}
		providers, err := s.externalWeComProvidersFromMetadata(item.Metadata)
		if err != nil {
			return model.PlatformItem{}, nil, false, err
		}
		if len(providers) > 0 {
			return item, providers, true, nil
		}
	}
	return model.PlatformItem{}, nil, false, nil
}

func selectLDAPTestProvider(providers []externalLDAPProvider, id string) (externalLDAPProvider, bool) {
	id = strings.TrimSpace(id)
	if id == "" && len(providers) > 0 {
		return providers[0], true
	}
	for _, provider := range providers {
		if provider.ID == id {
			return provider, true
		}
	}
	return externalLDAPProvider{}, false
}

func selectOIDCTestProvider(providers []externalOIDCProvider, id string) (externalOIDCProvider, bool) {
	id = strings.TrimSpace(id)
	if id == "" && len(providers) > 0 {
		return providers[0], true
	}
	for _, provider := range providers {
		if provider.ID == id {
			return provider, true
		}
	}
	return externalOIDCProvider{}, false
}

func selectWeComTestProvider(providers []externalWeComProvider, id string) (externalWeComProvider, bool) {
	id = strings.TrimSpace(id)
	if id == "" && len(providers) > 0 {
		return providers[0], true
	}
	for _, provider := range providers {
		if provider.ID == id {
			return provider, true
		}
	}
	return externalWeComProvider{}, false
}

func testExternalOIDCAuthorizationEndpoint(provider externalOIDCProvider, redirectURI string) (int, string, error) {
	authorizeURL, err := url.Parse(provider.AuthorizationEndpoint)
	if err != nil {
		return 0, "", err
	}
	values := authorizeURL.Query()
	values.Set("response_type", "code")
	values.Set("client_id", provider.ClientID)
	values.Set("redirect_uri", redirectURI)
	values.Set("scope", strings.Join(provider.Scopes, " "))
	values.Set("state", "configuration-test")
	values.Set("nonce", "configuration-test")
	authorizeURL.RawQuery = values.Encode()
	client := http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(authorizeURL.String())
	if err != nil {
		return 0, authorizeURL.String(), err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return resp.StatusCode, authorizeURL.String(), fmt.Errorf("oidc authorization endpoint returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return resp.StatusCode, authorizeURL.String(), nil
}

func sanitizedOIDCTestError(provider externalOIDCProvider, err error) string {
	return redactSecretVariants(err.Error(), provider.ClientSecret)
}

func testExternalWeComAccessToken(parent context.Context, provider externalWeComProvider) (int, error) {
	ctx, cancel := context.WithTimeout(parent, externalWeComRequestTimeout)
	defer cancel()
	client := externalWeComHTTPClient()
	tokenURL, err := url.Parse(provider.TokenEndpoint)
	if err != nil {
		return 0, err
	}
	tokenQuery := tokenURL.Query()
	tokenQuery.Set("corpid", provider.CorpID)
	tokenQuery.Set("corpsecret", provider.AgentSecret)
	tokenURL.RawQuery = tokenQuery.Encode()
	payload, err := fetchExternalWeComJSON(ctx, client, tokenURL.String())
	if err != nil {
		return 0, err
	}
	if firstMetadataString(payload, "access_token") == "" {
		return 0, errors.New("wecom token response missing access_token")
	}
	expiresIn, _ := metadataInt(payload["expires_in"])
	return expiresIn, nil
}

func sanitizedWeComTestError(provider externalWeComProvider, err error) string {
	return redactSecretVariants(err.Error(), provider.AgentSecret)
}

func redactSecretVariants(text string, secrets ...string) string {
	for _, secret := range secrets {
		secret = strings.TrimSpace(secret)
		if secret == "" {
			continue
		}
		variants := []string{secret, url.QueryEscape(secret), url.PathEscape(secret)}
		for _, variant := range variants {
			if variant == "" {
				continue
			}
			text = strings.ReplaceAll(text, variant, "[redacted]")
		}
	}
	return text
}

func smtpDeliveryConfigFromSetting(item model.PlatformItem, password, toOverride string) (smtpDeliveryConfig, error) {
	metadata := item.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	cfg := smtpDeliveryConfig{
		SettingID:          item.ID,
		Host:               firstNonEmpty(smtpMetadataString(metadata, "smtp_host", "host"), item.Host),
		Port:               smtpFirstNonZero(smtpMetadataInt(metadata, "smtp_port", "port"), item.Port, 587),
		Username:           firstNonEmpty(smtpMetadataString(metadata, "smtp_username", "username"), item.Username),
		Password:           password,
		From:               smtpMetadataString(metadata, "smtp_from", "from", "mail_from"),
		UseTLS:             smtpMetadataBoolAny(metadata, "smtp_use_tls", "smtp_ssl", "use_tls", "ssl", "tls"),
		StartTLS:           smtpMetadataBoolAny(metadata, "smtp_start_tls", "smtp_starttls", "start_tls", "starttls"),
		ServerName:         smtpMetadataString(metadata, "smtp_server_name", "server_name"),
		InsecureSkipVerify: smtpMetadataBoolAny(metadata, "smtp_insecure_skip_verify", "insecure_skip_verify"),
	}
	if cfg.UseTLS && cfg.StartTLS {
		return smtpDeliveryConfig{}, errors.New("smtp_use_tls and smtp_start_tls cannot both be enabled")
	}
	if cfg.From == "" {
		cfg.From = cfg.Username
	}
	if cfg.Host == "" {
		return smtpDeliveryConfig{}, errors.New("smtp_host is required")
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return smtpDeliveryConfig{}, errors.New("smtp_port is invalid")
	}
	if cfg.From == "" {
		return smtpDeliveryConfig{}, errors.New("smtp_from is required")
	}
	fromHeader, fromAddress, err := parseSMTPMailbox(cfg.From)
	if err != nil {
		return smtpDeliveryConfig{}, fmt.Errorf("smtp_from is invalid: %w", err)
	}
	cfg.From = fromHeader
	cfg.FromAddress = fromAddress
	recipientValue := firstNonEmpty(strings.TrimSpace(toOverride), smtpMetadataString(metadata, "smtp_to", "to", "test_to"))
	if recipientValue == "" {
		recipientValue = cfg.From
	}
	toHeaders, toAddresses, err := parseSMTPRecipientList(recipientValue)
	if err != nil {
		return smtpDeliveryConfig{}, fmt.Errorf("smtp_to is invalid: %w", err)
	}
	if len(toAddresses) == 0 {
		return smtpDeliveryConfig{}, errors.New("smtp_to is required")
	}
	cfg.To = toHeaders
	cfg.ToAddresses = toAddresses
	if cfg.ServerName == "" {
		cfg.ServerName = cfg.Host
	}
	return cfg, nil
}

func llmDeliveryConfigFromSetting(item model.PlatformItem, apiKey string) (llmDeliveryConfig, error) {
	metadata := item.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	cfg := llmDeliveryConfig{
		SettingID: item.ID,
		Provider:  firstNonEmpty(smtpMetadataString(metadata, "llm_provider", "provider"), "openai-compatible"),
		BaseURL:   smtpMetadataString(metadata, "llm_base_url", "base_url", "api_base_url", "openai_base_url"),
		Model:     smtpMetadataString(metadata, "llm_model", "model"),
		APIKey:    apiKey,
	}
	if cfg.BaseURL == "" {
		return llmDeliveryConfig{}, errors.New("llm_base_url is required")
	}
	if cfg.Model == "" {
		return llmDeliveryConfig{}, errors.New("llm_model is required")
	}
	if len(cfg.Provider) > 128 {
		return llmDeliveryConfig{}, errors.New("llm_provider must not exceed 128 bytes")
	}
	if len(cfg.Model) > 256 {
		return llmDeliveryConfig{}, errors.New("llm_model must not exceed 256 bytes")
	}
	target, err := llmChatCompletionsURL(cfg.BaseURL)
	if err != nil {
		return llmDeliveryConfig{}, err
	}
	cfg.BaseURL = target
	return cfg, nil
}

func sendSMTPTestMail(ctx context.Context, cfg smtpDeliveryConfig, subject, body string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, smtpSessionTimeout)
	defer cancel()

	address := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	tlsConfig := &tls.Config{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}
	dialer := &net.Dialer{Timeout: smtpConnectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return smtpContextError(ctx, err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return err
		}
	}
	stopCancellationWatch := make(chan struct{})
	defer close(stopCancellationWatch)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stopCancellationWatch:
		}
	}()

	var client *smtp.Client
	if cfg.UseTLS {
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return smtpContextError(ctx, err)
		}
		conn = tlsConn
	}
	client, err = smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return smtpContextError(ctx, err)
	}
	defer client.Close()
	if err := client.Hello("openwebservermanager"); err != nil {
		return smtpContextError(ctx, err)
	}
	if cfg.StartTLS && !cfg.UseTLS {
		ok, _ := client.Extension("STARTTLS")
		if !ok {
			return errors.New("SMTP server does not advertise STARTTLS")
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return smtpContextError(ctx, err)
		}
	}
	if cfg.Username != "" && cfg.Password != "" {
		if err := client.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			return smtpContextError(ctx, err)
		}
	}
	if err := client.Mail(cfg.FromAddress); err != nil {
		return smtpContextError(ctx, err)
	}
	for _, recipient := range cfg.ToAddresses {
		if err := client.Rcpt(recipient); err != nil {
			return smtpContextError(ctx, err)
		}
	}
	writer, err := client.Data()
	if err != nil {
		return smtpContextError(ctx, err)
	}
	if _, err := io.WriteString(writer, smtpMessage(cfg.From, cfg.To, subject, body)); err != nil {
		_ = writer.Close()
		return smtpContextError(ctx, err)
	}
	if err := writer.Close(); err != nil {
		return smtpContextError(ctx, err)
	}
	return smtpContextError(ctx, client.Quit())
}

func smtpContextError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	return err
}

func sendLLMTestPrompt(ctx context.Context, cfg llmDeliveryConfig, prompt string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(prompt) > maxLLMPromptBytes {
		return "", fmt.Errorf("LLM test prompt must not exceed %d bytes", maxLLMPromptBytes)
	}
	ctx, cancel := context.WithTimeout(ctx, llmRequestTimeout)
	defer cancel()

	payload := map[string]any{
		"model": cfg.Model,
		"messages": []map[string]string{
			{"role": "system", "content": "You are a connectivity probe for Open Web Server Manager."},
			{"role": "user", "content": prompt},
		},
		"max_tokens":  24,
		"temperature": 0,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.BaseURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(cfg.APIKey) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(cfg.APIKey))
	}
	client := &http.Client{Timeout: llmRequestTimeout, CheckRedirect: llmRedirectPolicy}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	responseLimit := int64(maxLLMResponseBytes)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		responseLimit = maxLLMErrorBytes
	}
	limited, err := io.ReadAll(io.LimitReader(resp.Body, responseLimit+1))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		truncated := len(limited) > int(responseLimit)
		if truncated {
			limited = limited[:responseLimit]
		}
		detail := strings.TrimSpace(string(limited))
		if truncated {
			detail += " [truncated]"
		}
		return "", fmt.Errorf("LLM provider returned %s: %s", resp.Status, detail)
	}
	if len(limited) > int(responseLimit) {
		return "", fmt.Errorf("LLM provider response exceeds %d bytes", maxLLMResponseBytes)
	}
	var decoded struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			Text string `json:"text"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(limited, &decoded); err != nil {
		return "", fmt.Errorf("decode LLM provider response: %w", err)
	}
	for _, choice := range decoded.Choices {
		if content := strings.TrimSpace(choice.Message.Content); content != "" {
			return content, nil
		}
		if content := strings.TrimSpace(choice.Text); content != "" {
			return content, nil
		}
	}
	return "", errors.New("LLM provider response did not include a completion")
}

func llmRedirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) > maxLLMRedirects {
		return fmt.Errorf("LLM provider redirected more than %d times", maxLLMRedirects)
	}
	if len(via) == 0 {
		return nil
	}
	origin := via[0].URL
	if !strings.EqualFold(req.URL.Scheme, origin.Scheme) || !strings.EqualFold(req.URL.Host, origin.Host) {
		return errors.New("LLM provider redirect must remain on the configured origin")
	}
	return nil
}

func sanitizeLLMTestText(cfg llmDeliveryConfig, text string) string {
	secret := strings.TrimSpace(cfg.APIKey)
	if secret == "" || text == "" {
		return text
	}
	replacements := []string{
		"Bearer " + secret, "Bearer [redacted]",
		secret, "[redacted]",
		url.QueryEscape(secret), "[redacted]",
	}
	return strings.NewReplacer(replacements...).Replace(text)
}

func sanitizeSMTPTestText(cfg smtpDeliveryConfig, text string) string {
	if text == "" {
		return text
	}
	replacements := make([]string, 0, 12)
	password := strings.TrimSpace(cfg.Password)
	if password != "" {
		replacements = append(replacements,
			password, "[redacted]",
			url.QueryEscape(password), "[redacted]",
		)
	}
	username := strings.TrimSpace(cfg.Username)
	if username != "" && password != "" {
		authPayload := base64.StdEncoding.EncodeToString([]byte("\x00" + username + "\x00" + password))
		replacements = append(replacements,
			username+":"+password, username+":[redacted]",
			url.QueryEscape(username+":"+password), url.QueryEscape(username+":[redacted]"),
			authPayload, "[redacted]",
			url.QueryEscape(authPayload), "[redacted]",
		)
	}
	if len(replacements) == 0 {
		return text
	}
	return strings.NewReplacer(replacements...).Replace(text)
}

func llmChatCompletionsURL(base string) (string, error) {
	raw := strings.TrimSpace(base)
	if raw == "" {
		return "", errors.New("llm_base_url is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("llm_base_url is invalid")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("llm_base_url must use http or https")
	}
	if parsed.User != nil {
		return "", errors.New("llm_base_url must not include credentials")
	}
	if len(raw) > 4096 {
		return "", errors.New("llm_base_url must not exceed 4096 bytes")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	if parsed.Path == "" {
		parsed.Path = "/v1/chat/completions"
	} else if !strings.HasSuffix(parsed.Path, "/chat/completions") {
		parsed.Path += "/chat/completions"
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func smtpMessage(from string, to []string, subject, body string) string {
	subject = sanitizeSMTPHeader(subject)
	if !isASCII(subject) {
		subject = mime.QEncoding.Encode("utf-8", subject)
	}
	headers := []string{
		"From: " + from,
		"To: " + strings.Join(to, ", "),
		"Subject: " + subject,
		"Date: " + time.Now().UTC().Format(time.RFC1123Z),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
	}
	return strings.Join(headers, "\r\n") + "\r\n\r\n" + body + "\r\n"
}

func parseSMTPMailbox(value string) (string, string, error) {
	address, err := mail.ParseAddress(strings.TrimSpace(value))
	if err != nil {
		return "", "", err
	}
	if strings.TrimSpace(address.Address) == "" {
		return "", "", errors.New("email address is empty")
	}
	header := address.Address
	if strings.TrimSpace(address.Name) != "" {
		header = address.String()
	}
	return header, address.Address, nil
}

func parseSMTPRecipientList(value string) ([]string, []string, error) {
	normalized := strings.NewReplacer(";", ",", "\r", ",", "\n", ",").Replace(strings.TrimSpace(value))
	if normalized == "" {
		return nil, nil, nil
	}
	addresses, err := mail.ParseAddressList(normalized)
	if err != nil {
		return nil, nil, err
	}
	headers := make([]string, 0, len(addresses))
	envelopes := make([]string, 0, len(addresses))
	seen := map[string]bool{}
	for _, address := range addresses {
		envelope := strings.TrimSpace(address.Address)
		if envelope == "" || seen[strings.ToLower(envelope)] {
			continue
		}
		seen[strings.ToLower(envelope)] = true
		header := envelope
		if strings.TrimSpace(address.Name) != "" {
			header = address.String()
		}
		headers = append(headers, header)
		envelopes = append(envelopes, envelope)
	}
	return headers, envelopes, nil
}

func isASCII(value string) bool {
	for _, r := range value {
		if r > 127 {
			return false
		}
	}
	return true
}

func sanitizeSMTPHeader(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.TrimSpace(value)
}

func smtpMetadataString(metadata map[string]any, keys ...string) string {
	for _, key := range keys {
		switch value := metadata[key].(type) {
		case string:
			if strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		case fmt.Stringer:
			if strings.TrimSpace(value.String()) != "" {
				return strings.TrimSpace(value.String())
			}
		}
	}
	return ""
}

func smtpMetadataInt(metadata map[string]any, keys ...string) int {
	for _, key := range keys {
		switch value := metadata[key].(type) {
		case int:
			return value
		case int64:
			return int(value)
		case float64:
			return int(value)
		case string:
			parsed, err := strconv.Atoi(strings.TrimSpace(value))
			if err == nil {
				return parsed
			}
		}
	}
	return 0
}

func smtpMetadataBoolAny(metadata map[string]any, keys ...string) bool {
	for _, key := range keys {
		switch value := metadata[key].(type) {
		case bool:
			if value {
				return true
			}
		case int:
			if value != 0 {
				return true
			}
		case float64:
			if value != 0 {
				return true
			}
		case string:
			switch strings.ToLower(strings.TrimSpace(value)) {
			case "true", "1", "yes", "enabled", "on":
				return true
			}
		}
	}
	return false
}

func smtpFirstNonZero(values ...int) int {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}
