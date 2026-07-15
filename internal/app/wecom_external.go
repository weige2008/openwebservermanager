package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"openwebservermanager/internal/model"
	"openwebservermanager/internal/store"
)

const externalWeComStateTTL = 5 * time.Minute
const externalWeComStateCollection = "external_wecom_states"
const externalWeComRequestTimeout = 10 * time.Second

type externalWeComState struct {
	ProviderID string    `json:"provider_id"`
	Next       string    `json:"next"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type externalWeComProvider struct {
	ID                 string
	Name               string
	CorpID             string
	AgentID            string
	AgentSecret        string
	AuthorizeEndpoint  string
	TokenEndpoint      string
	UserInfoEndpoint   string
	UserDetailEndpoint string
	Scope              string
	Role               string
	AutoCreate         bool
}

type externalWeComClaims struct {
	Subject     string
	UserID      string
	OpenID      string
	Username    string
	DisplayName string
	Email       string
	Mobile      string
}

var (
	errExternalWeComUserDisabled   = errors.New("external wecom user is disabled")
	errExternalWeComUserNotAllowed = errors.New("external wecom user auto creation is disabled")
)

func (s *Server) handleExternalWeComAPI(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/auth/wecom/providers":
		s.handleExternalWeComProviders(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/auth/wecom/start":
		s.handleExternalWeComStart(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/auth/wecom/callback":
		s.handleExternalWeComCallback(w, r)
	default:
		writeError(w, http.StatusNotFound, "external wecom endpoint not found")
	}
}

func (s *Server) handleExternalWeComProviders(w http.ResponseWriter, _ *http.Request) {
	providers, err := s.externalWeComProviders()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	result := []map[string]string{}
	for _, provider := range providers {
		result = append(result, map[string]string{"id": provider.ID, "name": provider.Name})
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": result})
}

func (s *Server) handleExternalWeComStart(w http.ResponseWriter, r *http.Request) {
	provider, ok, err := s.externalWeComProviderByID(r.URL.Query().Get("provider"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "wecom provider not found")
		return
	}
	next := safeRedirectPath(r.URL.Query().Get("next"))
	state, err := s.auth.createExternalWeComState(provider.ID, next)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	authorizeURL, err := url.Parse(provider.AuthorizeEndpoint)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	values := authorizeURL.Query()
	values.Set("appid", provider.CorpID)
	values.Set("redirect_uri", externalWeComRedirectURI(r, s.cfg.TrustProxyHeaders))
	values.Set("response_type", "code")
	values.Set("scope", firstNonEmpty(provider.Scope, "snsapi_base"))
	values.Set("state", state)
	if provider.AgentID != "" {
		values.Set("agentid", provider.AgentID)
	}
	authorizeURL.RawQuery = values.Encode()
	if authorizeURL.Fragment == "" && strings.Contains(provider.AuthorizeEndpoint, "open.weixin.qq.com") {
		authorizeURL.Fragment = "wechat_redirect"
	}
	http.Redirect(w, r, authorizeURL.String(), http.StatusFound)
}

func (s *Server) handleExternalWeComCallback(w http.ResponseWriter, r *http.Request) {
	state, ok, err := s.auth.consumeExternalWeComState(r.URL.Query().Get("state"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusBadRequest, "wecom state is invalid or expired")
		return
	}
	provider, ok, err := s.externalWeComProviderByID(state.ProviderID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "wecom provider not found")
		return
	}
	if errText := strings.TrimSpace(r.URL.Query().Get("error")); errText != "" {
		err := errors.New("wecom provider returned error: " + errText)
		if logErr := s.recordExternalWeComLoginFailure(r, provider, externalWeComClaims{}, err); logErr != nil {
			writeError(w, http.StatusInternalServerError, logErr.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		err := errors.New("code is required")
		if logErr := s.recordExternalWeComLoginFailure(r, provider, externalWeComClaims{}, err); logErr != nil {
			writeError(w, http.StatusInternalServerError, logErr.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	claims, err := s.fetchExternalWeComClaims(r.Context(), provider, code)
	if err != nil {
		safeErr := sanitizedExternalProviderError(err, provider.AgentSecret)
		if logErr := s.recordExternalWeComLoginFailure(r, provider, externalWeComClaims{}, safeErr); logErr != nil {
			writeError(w, http.StatusInternalServerError, logErr.Error())
			return
		}
		writeError(w, http.StatusBadGateway, safeErr.Error())
		return
	}
	previousUser, hadPreviousUser, err := s.externalUserSnapshot("wecom", provider.ID, claims.Subject)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	user, err := s.upsertExternalWeComUser(provider, claims)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, errExternalWeComUserDisabled) || errors.Is(err, errExternalWeComUserNotAllowed) {
			status = http.StatusForbidden
		}
		if logErr := s.recordExternalWeComLoginFailure(r, provider, claims, err); logErr != nil {
			writeError(w, http.StatusInternalServerError, logErr.Error())
			return
		}
		writeError(w, status, err.Error())
		return
	}
	if err := s.createLoginLog(r, model.PlatformItemRequest{
		Name:        user.Username,
		Type:        "wecom",
		Status:      "success",
		OwnerID:     user.UserID,
		Description: "signed in with enterprise wechat",
		Metadata:    map[string]any{"client_ip": s.clientIP(r), "provider_id": provider.ID, "subject": claims.Subject},
	}); err != nil {
		err = s.restoreExternalUserAfterLoginLogFailure(r, user.UserID, previousUser, hadPreviousUser, err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	token, session, err := s.auth.create(user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.recordUserLoginState(r, token, session, s.clientIP(r)); err != nil {
		err = s.restoreExternalUserAfterLoginStateFailure(r, user.UserID, previousUser, hadPreviousUser, err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "auth.wecom.login", session.UserID, "", "signed in with enterprise wechat provider "+provider.ID)
	http.SetCookie(w, s.authCookie(r, token, int(authSessionTTL.Seconds())))
	http.Redirect(w, r, state.Next, http.StatusFound)
}

func (s *Server) recordExternalWeComLoginFailure(r *http.Request, provider externalWeComProvider, claims externalWeComClaims, err error) error {
	detail := "external wecom login failed"
	if err != nil {
		detail = err.Error()
	}
	account := firstNonEmpty(claims.Username, claims.UserID, claims.OpenID, claims.Subject)
	if logErr := s.createLoginLog(r, model.PlatformItemRequest{
		Name:        account,
		Type:        "wecom",
		Status:      "failed",
		Description: detail,
		Metadata: map[string]any{
			"client_ip":   s.clientIP(r),
			"account":     account,
			"provider_id": provider.ID,
			"subject":     claims.Subject,
		},
	}); logErr != nil {
		return logErr
	}
	_ = s.audit(r, "auth.wecom.login_failed", provider.ID, "wecom", detail)
	return nil
}

func (s *Server) fetchExternalWeComClaims(parent context.Context, provider externalWeComProvider, code string) (externalWeComClaims, error) {
	ctx, cancel := context.WithTimeout(parent, externalWeComRequestTimeout)
	defer cancel()
	client := externalWeComHTTPClient()
	tokenURL, err := url.Parse(provider.TokenEndpoint)
	if err != nil {
		return externalWeComClaims{}, err
	}
	tokenQuery := tokenURL.Query()
	tokenQuery.Set("corpid", provider.CorpID)
	tokenQuery.Set("corpsecret", provider.AgentSecret)
	tokenURL.RawQuery = tokenQuery.Encode()
	tokenPayload, err := fetchExternalWeComJSON(ctx, client, tokenURL.String())
	if err != nil {
		return externalWeComClaims{}, err
	}
	accessToken := firstMetadataString(tokenPayload, "access_token")
	if accessToken == "" {
		return externalWeComClaims{}, errors.New("wecom token response missing access_token")
	}
	userInfoURL, err := url.Parse(provider.UserInfoEndpoint)
	if err != nil {
		return externalWeComClaims{}, err
	}
	userInfoQuery := userInfoURL.Query()
	userInfoQuery.Set("access_token", accessToken)
	userInfoQuery.Set("code", code)
	userInfoURL.RawQuery = userInfoQuery.Encode()
	userInfo, err := fetchExternalWeComJSON(ctx, client, userInfoURL.String())
	if err != nil {
		if ctx.Err() != nil {
			return externalWeComClaims{}, ctx.Err()
		}
		return externalWeComClaims{}, sanitizedExternalProviderError(err, provider.AgentSecret, accessToken, code)
	}
	claims := externalWeComClaims{
		UserID: firstMetadataString(userInfo, "UserId", "userid", "user_id"),
		OpenID: firstMetadataString(userInfo, "OpenId", "openid", "open_id"),
	}
	claims.Subject = firstNonEmpty(claims.UserID, claims.OpenID)
	if claims.Subject == "" {
		return externalWeComClaims{}, errors.New("wecom userinfo response missing userid/openid")
	}
	if provider.UserDetailEndpoint != "" && claims.UserID != "" {
		userDetailURL, err := url.Parse(provider.UserDetailEndpoint)
		if err != nil {
			return externalWeComClaims{}, err
		}
		userDetailQuery := userDetailURL.Query()
		userDetailQuery.Set("access_token", accessToken)
		userDetailQuery.Set("userid", claims.UserID)
		userDetailURL.RawQuery = userDetailQuery.Encode()
		if detail, err := fetchExternalWeComJSON(ctx, client, userDetailURL.String()); err == nil {
			claims.Username = firstMetadataString(detail, "userid", "UserId", "username", "name")
			claims.DisplayName = firstMetadataString(detail, "name", "display_name", "alias")
			claims.Email = firstMetadataString(detail, "email", "biz_mail")
			claims.Mobile = firstMetadataString(detail, "mobile")
		} else if ctx.Err() != nil {
			return externalWeComClaims{}, ctx.Err()
		}
	}
	if claims.Username == "" {
		claims.Username = firstNonEmpty(claims.UserID, claims.OpenID)
	}
	if claims.DisplayName == "" {
		claims.DisplayName = claims.Username
	}
	return claims, nil
}

func fetchExternalWeComJSON(ctx context.Context, client *http.Client, endpoint string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("wecom endpoint returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	payload := map[string]any{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	if code, ok := wecomErrCode(payload); ok && code != 0 {
		return nil, fmt.Errorf("wecom endpoint returned errcode %d: %s", code, firstMetadataString(payload, "errmsg"))
	}
	return payload, nil
}

func externalWeComHTTPClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func wecomErrCode(payload map[string]any) (int, bool) {
	switch value := payload["errcode"].(type) {
	case float64:
		return int(value), true
	case int:
		return value, true
	case string:
		if strings.TrimSpace(value) == "" {
			return 0, false
		}
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		return parsed, err == nil
	default:
		return 0, false
	}
}

func (s *Server) upsertExternalWeComUser(provider externalWeComProvider, claims externalWeComClaims) (store.AdminPublic, error) {
	subject := strings.TrimSpace(claims.Subject)
	if subject == "" {
		return store.AdminPublic{}, errors.New("wecom claims missing subject")
	}
	username := strings.TrimSpace(firstNonEmpty(claims.Username, claims.DisplayName, claims.Email, subject))
	role := strings.TrimSpace(provider.Role)
	if role == "" {
		role = "user"
	}
	users, err := s.cfg.Store.ListPlatformItems("users")
	if err != nil {
		return store.AdminPublic{}, err
	}
	for _, item := range users {
		if firstMetadataString(item.Metadata, "external_provider") != "wecom" || firstMetadataString(item.Metadata, "external_provider_id") != provider.ID || firstMetadataString(item.Metadata, "external_subject") != subject {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(item.Status), "disabled") {
			return store.AdminPublic{}, errExternalWeComUserDisabled
		}
		metadata := cloneMetadata(item.Metadata)
		metadata["role"] = role
		metadata["external_provider"] = "wecom"
		metadata["external_provider_id"] = provider.ID
		metadata["external_subject"] = subject
		metadata["wecom_userid"] = claims.UserID
		metadata["wecom_openid"] = claims.OpenID
		metadata["email"] = claims.Email
		metadata["mobile"] = claims.Mobile
		metadata["display_name"] = claims.DisplayName
		metadata["external_claims_updated_at"] = time.Now().UTC().Format(time.RFC3339Nano)
		updated, err := s.cfg.Store.UpdatePlatformItem("users", item.ID, model.PlatformItemRequest{
			Name:     username,
			Type:     "wecom",
			Status:   item.Status,
			Metadata: metadata,
		})
		if err != nil {
			return store.AdminPublic{}, err
		}
		return storeAdminPublicFromPlatformItem(updated, role), nil
	}
	if !provider.AutoCreate {
		return store.AdminPublic{}, errExternalWeComUserNotAllowed
	}
	item, err := s.cfg.Store.CreatePlatformItem("users", model.PlatformItemRequest{
		Name:   username,
		Type:   "wecom",
		Status: "enabled",
		Metadata: map[string]any{
			"role":                       role,
			"external_provider":          "wecom",
			"external_provider_id":       provider.ID,
			"external_subject":           subject,
			"wecom_userid":               claims.UserID,
			"wecom_openid":               claims.OpenID,
			"email":                      claims.Email,
			"mobile":                     claims.Mobile,
			"display_name":               claims.DisplayName,
			"external_claims_created_at": time.Now().UTC().Format(time.RFC3339Nano),
		},
	})
	if err != nil {
		return store.AdminPublic{}, err
	}
	return storeAdminPublicFromPlatformItem(item, role), nil
}

func (s *Server) externalWeComProviderByID(id string) (externalWeComProvider, bool, error) {
	providers, err := s.externalWeComProviders()
	if err != nil {
		return externalWeComProvider{}, false, err
	}
	if strings.TrimSpace(id) == "" && len(providers) == 1 {
		return providers[0], true, nil
	}
	for _, provider := range providers {
		if provider.ID == id {
			return provider, true, nil
		}
	}
	return externalWeComProvider{}, false, nil
}

func (s *Server) externalWeComProviders() ([]externalWeComProvider, error) {
	items, err := s.cfg.Store.ListPlatformItems("system_settings")
	if err != nil {
		return nil, err
	}
	providers := []externalWeComProvider{}
	for _, item := range items {
		if !strings.EqualFold(strings.TrimSpace(item.Type), "identity") || !platformItemEnabled(item) {
			continue
		}
		raw, ok, err := s.cfg.Store.GetPlatformItem("system_settings", item.ID)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		next, err := s.externalWeComProvidersFromMetadata(raw.Metadata)
		if err != nil {
			return nil, err
		}
		providers = append(providers, next...)
	}
	return providers, nil
}

func (s *Server) externalWeComProvidersFromMetadata(metadata map[string]any) ([]externalWeComProvider, error) {
	result := []externalWeComProvider{}
	for _, object := range metadataObjectList(metadata["wecom_providers"]) {
		provider, ok, err := s.externalWeComProviderFromObject(object, false)
		if err != nil {
			return nil, err
		}
		if ok {
			result = append(result, provider)
		}
	}
	for _, object := range metadataObjectList(metadata["enterprise_wechat_providers"]) {
		provider, ok, err := s.externalWeComProviderFromObject(object, false)
		if err != nil {
			return nil, err
		}
		if ok {
			result = append(result, provider)
		}
	}
	provider, ok, err := s.externalWeComProviderFromObject(metadata, true)
	if err != nil {
		return nil, err
	}
	if ok {
		result = append(result, provider)
	}
	return result, nil
}

func (s *Server) externalWeComProviderFromObject(object map[string]any, requireExplicitEnable bool) (externalWeComProvider, bool, error) {
	if requireExplicitEnable {
		enabled, ok := metadataBoolValue(object["wecom_enabled"])
		if !ok {
			enabled, ok = metadataBoolValue(object["wecom_login_enabled"])
		}
		if !ok {
			enabled, ok = metadataBoolValue(object["enterprise_wechat_enabled"])
		}
		if !ok || !enabled {
			return externalWeComProvider{}, false, nil
		}
	} else if enabled, ok := metadataBoolValue(object["enabled"]); ok && !enabled {
		return externalWeComProvider{}, false, nil
	}
	provider := externalWeComProviderShapeFromObject(object)
	secret, err := s.externalWeComAgentSecret(object)
	if err != nil {
		return externalWeComProvider{}, false, err
	}
	provider.AgentSecret = secret
	if err := validateExternalWeComProviderShape(provider, true, secret != ""); err != nil {
		return externalWeComProvider{}, false, err
	}
	return provider, true, nil
}

func externalWeComProviderShapeFromObject(object map[string]any) externalWeComProvider {
	provider := externalWeComProvider{
		ID:                 firstMetadataString(object, "id", "provider_id", "wecom_provider_id", "enterprise_wechat_provider_id"),
		Name:               firstMetadataString(object, "name", "label", "provider_name", "wecom_provider_name", "enterprise_wechat_provider_name"),
		CorpID:             firstMetadataString(object, "corp_id", "corpid", "wecom_corp_id", "enterprise_wechat_corp_id"),
		AgentID:            firstMetadataString(object, "agent_id", "agentid", "wecom_agent_id", "enterprise_wechat_agent_id"),
		AuthorizeEndpoint:  firstMetadataString(object, "authorize_endpoint", "authorization_endpoint", "wecom_authorize_endpoint"),
		TokenEndpoint:      firstMetadataString(object, "token_endpoint", "wecom_token_endpoint"),
		UserInfoEndpoint:   firstMetadataString(object, "userinfo_endpoint", "user_info_endpoint", "wecom_userinfo_endpoint"),
		UserDetailEndpoint: firstMetadataString(object, "user_detail_endpoint", "user_endpoint", "wecom_user_detail_endpoint"),
		Scope:              firstMetadataString(object, "scope", "wecom_scope"),
		Role:               firstMetadataString(object, "role", "default_role", "wecom_role"),
	}
	if provider.AuthorizeEndpoint == "" {
		provider.AuthorizeEndpoint = "https://open.weixin.qq.com/connect/oauth2/authorize"
	}
	if provider.TokenEndpoint == "" {
		provider.TokenEndpoint = "https://qyapi.weixin.qq.com/cgi-bin/gettoken"
	}
	if provider.UserInfoEndpoint == "" {
		provider.UserInfoEndpoint = "https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo"
	}
	if provider.UserDetailEndpoint == "" && strings.EqualFold(provider.TokenEndpoint, "https://qyapi.weixin.qq.com/cgi-bin/gettoken") && strings.EqualFold(provider.UserInfoEndpoint, "https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo") {
		provider.UserDetailEndpoint = "https://qyapi.weixin.qq.com/cgi-bin/user/get"
	}
	if provider.ID == "" {
		provider.ID = firstNonEmpty(provider.AgentID, provider.CorpID)
	}
	if provider.Name == "" {
		provider.Name = "Enterprise WeChat"
	}
	provider.AutoCreate = true
	if autoCreate, ok := metadataBoolValue(object["auto_create"]); ok {
		provider.AutoCreate = autoCreate
	}
	if autoCreate, ok := metadataBoolValue(object["wecom_auto_create"]); ok {
		provider.AutoCreate = autoCreate
	}
	return provider
}

func validateExternalWeComProviderShape(provider externalWeComProvider, required, secretConfigured bool) error {
	for label, value := range map[string]string{
		"provider id":   provider.ID,
		"provider name": provider.Name,
		"Corp ID":       provider.CorpID,
		"Agent ID":      provider.AgentID,
		"scope":         provider.Scope,
		"default role":  provider.Role,
	} {
		if strings.ContainsAny(value, "\x00\r\n\t") {
			return fmt.Errorf("Enterprise WeChat %s must not contain control characters", label)
		}
	}
	if len(provider.ID) > 256 || len(provider.Name) > 256 {
		return errors.New("Enterprise WeChat provider id and name must not exceed 256 bytes")
	}
	if provider.ID != "" && !ldapRolePattern.MatchString(provider.ID) {
		return errors.New("Enterprise WeChat provider id is invalid")
	}
	if len(provider.CorpID) > 256 || strings.ContainsAny(provider.CorpID, " /\\@?#") {
		return errors.New("Enterprise WeChat Corp ID is invalid")
	}
	if provider.AgentID != "" {
		if len(provider.AgentID) > 32 {
			return errors.New("Enterprise WeChat Agent ID is invalid")
		}
		for _, char := range provider.AgentID {
			if char < '0' || char > '9' {
				return errors.New("Enterprise WeChat Agent ID must contain only digits")
			}
		}
	}
	if provider.Role != "" && !ldapRolePattern.MatchString(provider.Role) {
		return errors.New("Enterprise WeChat default role is invalid")
	}
	scope := firstNonEmpty(provider.Scope, "snsapi_base")
	switch scope {
	case "snsapi_base", "snsapi_userinfo", "snsapi_privateinfo":
	default:
		return fmt.Errorf("Enterprise WeChat scope %q is not supported", scope)
	}
	if scope == "snsapi_privateinfo" && provider.AgentID == "" {
		return errors.New("Enterprise WeChat Agent ID is required for snsapi_privateinfo")
	}
	if _, err := parseExternalWeComEndpoint(provider.AuthorizeEndpoint, "authorization", true); err != nil {
		return err
	}
	tokenURL, err := parseExternalWeComEndpoint(provider.TokenEndpoint, "token", false)
	if err != nil {
		return err
	}
	userInfoURL, err := parseExternalWeComEndpoint(provider.UserInfoEndpoint, "userinfo", false)
	if err != nil {
		return err
	}
	if !sameExternalWeComOrigin(tokenURL, userInfoURL) {
		return errors.New("Enterprise WeChat token and userinfo endpoints must use the same origin")
	}
	if provider.UserDetailEndpoint != "" {
		userDetailURL, err := parseExternalWeComEndpoint(provider.UserDetailEndpoint, "user detail", false)
		if err != nil {
			return err
		}
		if !sameExternalWeComOrigin(tokenURL, userDetailURL) {
			return errors.New("Enterprise WeChat token, userinfo, and user detail endpoints must use the same origin")
		}
	}
	if required && provider.CorpID == "" {
		return errors.New("Enterprise WeChat Corp ID is required when login is enabled")
	}
	if required && !secretConfigured {
		return errors.New("Enterprise WeChat Agent secret is required when login is enabled")
	}
	return nil
}

func parseExternalWeComEndpoint(raw, label string, allowWeChatFragment bool) (*url.URL, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, fmt.Errorf("Enterprise WeChat %s endpoint is required", label)
	}
	if len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n\t") {
		return nil, fmt.Errorf("Enterprise WeChat %s endpoint is invalid", label)
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Opaque != "" || parsed.Hostname() == "" {
		return nil, fmt.Errorf("Enterprise WeChat %s endpoint is invalid", label)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, fmt.Errorf("Enterprise WeChat %s endpoint must use http or https", label)
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("Enterprise WeChat %s endpoint must not contain URL credentials", label)
	}
	if parsed.Fragment != "" && (!allowWeChatFragment || parsed.Fragment != "wechat_redirect") {
		return nil, fmt.Errorf("Enterprise WeChat %s endpoint contains an invalid fragment", label)
	}
	if parsed.Scheme == "http" && !externalWeComLoopbackHost(parsed.Hostname()) {
		return nil, fmt.Errorf("Enterprise WeChat %s endpoint must use https unless it targets loopback", label)
	}
	return parsed, nil
}

func externalWeComLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "localhost" {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func sameExternalWeComOrigin(left, right *url.URL) bool {
	if left == nil || right == nil || !strings.EqualFold(left.Scheme, right.Scheme) || !strings.EqualFold(left.Hostname(), right.Hostname()) {
		return false
	}
	return externalWeComEffectivePort(left) == externalWeComEffectivePort(right)
}

func externalWeComEffectivePort(endpoint *url.URL) string {
	if port := endpoint.Port(); port != "" {
		return port
	}
	if endpoint.Scheme == "https" {
		return "443"
	}
	return "80"
}

func (s *Server) externalWeComAgentSecret(object map[string]any) (string, error) {
	if secret := firstMetadataString(object, "agent_secret", "agentSecret", "wecom_agent_secret", "enterprise_wechat_agent_secret", "corp_secret", "corpsecret"); secret != "" {
		return secret, nil
	}
	encrypted := firstMetadataString(object, "wecom_agent_secret_encrypted", "enterprise_wechat_agent_secret_encrypted", "agent_secret_encrypted")
	if encrypted == "" {
		return "", nil
	}
	return s.cfg.Store.DecryptPlatformSecret(encrypted)
}

func (m *authManager) createExternalWeComState(providerID, next string) (string, error) {
	state, err := randomToken()
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	item := externalWeComState{ProviderID: providerID, Next: next, ExpiresAt: now.Add(externalWeComStateTTL)}
	if m.store != nil {
		if err := m.pruneAuthRuntimeStates(externalWeComStateCollection); err != nil {
			return "", err
		}
		if err := m.persistAuthRuntimeState(externalWeComStateCollection, state, item, item.ExpiresAt); err != nil {
			return "", err
		}
		return state, nil
	}
	for key, item := range m.wecomStates {
		if now.After(item.ExpiresAt) {
			delete(m.wecomStates, key)
		}
	}
	m.wecomStates[state] = item
	return state, nil
}

func (m *authManager) consumeExternalWeComState(value string) (externalWeComState, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.store != nil {
		var state externalWeComState
		ok, err := m.consumeAuthRuntimeState(externalWeComStateCollection, value, &state)
		if err != nil || !ok {
			return externalWeComState{}, ok, err
		}
		if !time.Now().UTC().Before(state.ExpiresAt) {
			return externalWeComState{}, false, nil
		}
		return state, true, nil
	}
	state, ok := m.wecomStates[value]
	if !ok {
		return externalWeComState{}, false, nil
	}
	delete(m.wecomStates, value)
	if time.Now().UTC().After(state.ExpiresAt) {
		return externalWeComState{}, false, nil
	}
	return state, true, nil
}

func externalWeComRedirectURI(r *http.Request, trustProxy bool) string {
	return requestBaseURL(r, trustProxy) + "/api/auth/wecom/callback"
}
