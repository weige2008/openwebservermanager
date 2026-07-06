package app

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"openwebservermanager/internal/model"
	"openwebservermanager/internal/store"
)

const externalOIDCStateTTL = 5 * time.Minute

type externalOIDCState struct {
	ProviderID string
	Next       string
	Nonce      string
	ExpiresAt  time.Time
}

type externalOIDCProvider struct {
	ID                    string
	Name                  string
	AuthorizationEndpoint string
	TokenEndpoint         string
	UserInfoEndpoint      string
	ClientID              string
	ClientSecret          string
	Scopes                []string
	Role                  string
	AutoCreate            bool
}

func (s *Server) handleExternalOIDCAPI(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/auth/oidc/providers":
		s.handleExternalOIDCProviders(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/auth/oidc/start":
		s.handleExternalOIDCStart(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/auth/oidc/callback":
		s.handleExternalOIDCCallback(w, r)
	default:
		writeError(w, http.StatusNotFound, "external oidc endpoint not found")
	}
}

func (s *Server) handleExternalOIDCProviders(w http.ResponseWriter, _ *http.Request) {
	providers, err := s.externalOIDCProviders()
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

func (s *Server) handleExternalOIDCStart(w http.ResponseWriter, r *http.Request) {
	provider, ok, err := s.externalOIDCProviderByID(r.URL.Query().Get("provider"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "oidc provider not found")
		return
	}
	next := safeRedirectPath(r.URL.Query().Get("next"))
	state, nonce, err := s.auth.createExternalOIDCState(provider.ID, next)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	authorizeURL, err := url.Parse(provider.AuthorizationEndpoint)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	values := authorizeURL.Query()
	values.Set("response_type", "code")
	values.Set("client_id", provider.ClientID)
	values.Set("redirect_uri", externalOIDCRedirectURI(r, s.cfg.TrustProxyHeaders))
	values.Set("scope", strings.Join(provider.Scopes, " "))
	values.Set("state", state)
	values.Set("nonce", nonce)
	authorizeURL.RawQuery = values.Encode()
	http.Redirect(w, r, authorizeURL.String(), http.StatusFound)
}

func (s *Server) handleExternalOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if errText := strings.TrimSpace(r.URL.Query().Get("error")); errText != "" {
		writeError(w, http.StatusBadRequest, "oidc provider returned error: "+errText)
		return
	}
	state, ok := s.auth.consumeExternalOIDCState(r.URL.Query().Get("state"))
	if !ok {
		writeError(w, http.StatusBadRequest, "oidc state is invalid or expired")
		return
	}
	provider, ok, err := s.externalOIDCProviderByID(state.ProviderID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "oidc provider not found")
		return
	}
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		err := errors.New("code is required")
		s.recordExternalOIDCLoginFailure(r, provider, nil, err)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	claims, err := s.exchangeExternalOIDCCode(r, provider, code)
	if err != nil {
		safeErr := sanitizedExternalProviderError(err, provider.ClientSecret)
		s.recordExternalOIDCLoginFailure(r, provider, nil, safeErr)
		writeError(w, http.StatusBadGateway, safeErr.Error())
		return
	}
	if nonce := firstMetadataString(claims, "nonce"); nonce != "" && nonce != state.Nonce {
		err := errors.New("oidc nonce mismatch")
		s.recordExternalOIDCLoginFailure(r, provider, claims, err)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	user, err := s.upsertExternalOIDCUser(provider, claims)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, errExternalOIDCUserDisabled) {
			status = http.StatusForbidden
		}
		if errors.Is(err, errExternalOIDCUserNotAllowed) {
			status = http.StatusForbidden
		}
		s.recordExternalOIDCLoginFailure(r, provider, claims, err)
		writeError(w, status, err.Error())
		return
	}
	token, session, err := s.auth.create(user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	http.SetCookie(w, s.authCookie(r, token, int(authSessionTTL.Seconds())))
	_ = s.cfg.Store.RecordUserLogin(session.UserID, s.clientIP(r), r.UserAgent())
	_ = s.audit(r, "auth.oidc.login", session.UserID, "", "signed in with external oidc provider "+provider.ID)
	_, _ = s.cfg.Store.CreatePlatformItem("login_logs", model.PlatformItemRequest{
		Name:        session.Username,
		Type:        "oidc",
		Status:      "success",
		OwnerID:     session.UserID,
		Description: "signed in with external oidc",
		Metadata:    map[string]any{"client_ip": s.clientIP(r), "provider_id": provider.ID, "subject": firstMetadataString(claims, "sub")},
	})
	http.Redirect(w, r, state.Next, http.StatusFound)
}

func (s *Server) recordExternalOIDCLoginFailure(r *http.Request, provider externalOIDCProvider, claims map[string]any, err error) {
	detail := "external oidc login failed"
	if err != nil {
		detail = err.Error()
	}
	subject := firstMetadataString(claims, "sub", "id", "user_id")
	account := firstMetadataString(claims, "preferred_username", "name", "email", "login")
	if account == "" {
		account = subject
	}
	_, _ = s.cfg.Store.CreatePlatformItem("login_logs", model.PlatformItemRequest{
		Name:        account,
		Type:        "oidc",
		Status:      "failed",
		Description: detail,
		Metadata: map[string]any{
			"client_ip":   s.clientIP(r),
			"account":     account,
			"provider_id": provider.ID,
			"subject":     subject,
		},
	})
	_ = s.audit(r, "auth.oidc.login_failed", provider.ID, "oidc", detail)
}

func sanitizedExternalProviderError(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	text := err.Error()
	for _, secret := range secrets {
		secret = strings.TrimSpace(secret)
		if secret == "" {
			continue
		}
		text = strings.ReplaceAll(text, secret, "[redacted]")
	}
	return errors.New(text)
}

func (s *Server) exchangeExternalOIDCCode(r *http.Request, provider externalOIDCProvider, code string) (map[string]any, error) {
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {externalOIDCRedirectURI(r, s.cfg.TrustProxyHeaders)},
		"client_id":    {provider.ClientID},
	}
	req, err := http.NewRequest(http.MethodPost, provider.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if provider.ClientSecret != "" {
		req.SetBasicAuth(provider.ClientID, provider.ClientSecret)
	}
	client := http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("oidc token endpoint returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	tokenPayload := map[string]any{}
	if err := json.Unmarshal(body, &tokenPayload); err != nil {
		return nil, fmt.Errorf("decode oidc token response: %w", err)
	}
	accessToken := firstMetadataString(tokenPayload, "access_token")
	if accessToken == "" {
		return nil, errors.New("oidc token response missing access_token")
	}
	if provider.UserInfoEndpoint != "" {
		claims, err := fetchExternalOIDCUserInfo(client, provider.UserInfoEndpoint, accessToken)
		if err == nil {
			return claims, nil
		}
	}
	idToken := firstMetadataString(tokenPayload, "id_token")
	if idToken == "" {
		return nil, errors.New("oidc provider did not return userinfo or id_token")
	}
	return parseUnverifiedJWTClaims(idToken)
}

func fetchExternalOIDCUserInfo(client http.Client, endpoint, accessToken string) (map[string]any, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("userinfo returned %s", resp.Status)
	}
	claims := map[string]any{}
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

var (
	errExternalOIDCUserDisabled   = errors.New("external oidc user is disabled")
	errExternalOIDCUserNotAllowed = errors.New("external oidc user auto creation is disabled")
)

func (s *Server) upsertExternalOIDCUser(provider externalOIDCProvider, claims map[string]any) (store.AdminPublic, error) {
	subject := firstMetadataString(claims, "sub", "id", "user_id")
	if subject == "" {
		return store.AdminPublic{}, errors.New("oidc claims missing subject")
	}
	username := firstMetadataString(claims, "preferred_username", "name", "email", "login")
	if username == "" {
		username = subject
	}
	role := provider.Role
	if role == "" {
		role = firstMetadataString(claims, "role")
	}
	if role == "" {
		role = "user"
	}
	users, err := s.cfg.Store.ListPlatformItems("users")
	if err != nil {
		return store.AdminPublic{}, err
	}
	for _, item := range users {
		if firstMetadataString(item.Metadata, "external_provider") != "oidc" || firstMetadataString(item.Metadata, "external_provider_id") != provider.ID || firstMetadataString(item.Metadata, "external_subject") != subject {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(item.Status), "disabled") {
			return store.AdminPublic{}, errExternalOIDCUserDisabled
		}
		metadata := cloneMetadata(item.Metadata)
		metadata["role"] = role
		metadata["external_provider"] = "oidc"
		metadata["external_provider_id"] = provider.ID
		metadata["external_subject"] = subject
		metadata["external_claims_updated_at"] = time.Now().UTC().Format(time.RFC3339Nano)
		updated, err := s.cfg.Store.UpdatePlatformItem("users", item.ID, model.PlatformItemRequest{
			Name:     username,
			Type:     "oidc",
			Status:   item.Status,
			Metadata: metadata,
		})
		if err != nil {
			return store.AdminPublic{}, err
		}
		return storeAdminPublicFromPlatformItem(updated, role), nil
	}
	if !provider.AutoCreate {
		return store.AdminPublic{}, errExternalOIDCUserNotAllowed
	}
	item, err := s.cfg.Store.CreatePlatformItem("users", model.PlatformItemRequest{
		Name:   username,
		Type:   "oidc",
		Status: "enabled",
		Metadata: map[string]any{
			"role":                       role,
			"external_provider":          "oidc",
			"external_provider_id":       provider.ID,
			"external_subject":           subject,
			"external_claims_created_at": time.Now().UTC().Format(time.RFC3339Nano),
		},
	})
	if err != nil {
		return store.AdminPublic{}, err
	}
	return storeAdminPublicFromPlatformItem(item, role), nil
}

func storeAdminPublicFromPlatformItem(item model.PlatformItem, role string) store.AdminPublic {
	return store.AdminPublic{
		UserID:    item.ID,
		Username:  item.Name,
		Role:      role,
		CreatedAt: item.CreatedAt,
		UpdatedAt: item.UpdatedAt,
	}
}

func (s *Server) externalOIDCProviderByID(id string) (externalOIDCProvider, bool, error) {
	providers, err := s.externalOIDCProviders()
	if err != nil {
		return externalOIDCProvider{}, false, err
	}
	if strings.TrimSpace(id) == "" && len(providers) == 1 {
		return providers[0], true, nil
	}
	for _, provider := range providers {
		if provider.ID == id {
			return provider, true, nil
		}
	}
	return externalOIDCProvider{}, false, nil
}

func (s *Server) externalOIDCProviders() ([]externalOIDCProvider, error) {
	items, err := s.cfg.Store.ListPlatformItems("system_settings")
	if err != nil {
		return nil, err
	}
	providers := []externalOIDCProvider{}
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
		next, err := s.externalOIDCProvidersFromMetadata(raw.Metadata)
		if err != nil {
			return nil, err
		}
		providers = append(providers, next...)
	}
	return providers, nil
}

func (s *Server) externalOIDCProvidersFromMetadata(metadata map[string]any) ([]externalOIDCProvider, error) {
	result := []externalOIDCProvider{}
	for _, object := range metadataObjectList(metadata["oidc_providers"]) {
		provider, ok, err := s.externalOIDCProviderFromObject(object, false)
		if err != nil {
			return nil, err
		}
		if ok {
			result = append(result, provider)
		}
	}
	for _, object := range metadataObjectList(metadata["external_oidc_providers"]) {
		provider, ok, err := s.externalOIDCProviderFromObject(object, false)
		if err != nil {
			return nil, err
		}
		if ok {
			result = append(result, provider)
		}
	}
	provider, ok, err := s.externalOIDCProviderFromObject(metadata, true)
	if err != nil {
		return nil, err
	}
	if ok {
		result = append(result, provider)
	}
	return result, nil
}

func (s *Server) externalOIDCProviderFromObject(object map[string]any, requireExplicitEnable bool) (externalOIDCProvider, bool, error) {
	if requireExplicitEnable {
		enabled, ok := metadataBoolValue(object["oidc_login_enabled"])
		if !ok {
			enabled, ok = metadataBoolValue(object["external_oidc_enabled"])
		}
		if !ok || !enabled {
			return externalOIDCProvider{}, false, nil
		}
	} else if enabled, ok := metadataBoolValue(object["enabled"]); ok && !enabled {
		return externalOIDCProvider{}, false, nil
	}
	clientSecret, err := s.externalOIDCClientSecret(object)
	if err != nil {
		return externalOIDCProvider{}, false, err
	}
	provider := externalOIDCProvider{
		ID:                    firstMetadataString(object, "id", "provider_id", "oidc_provider_id"),
		Name:                  firstMetadataString(object, "name", "label", "provider_name", "oidc_provider_name"),
		AuthorizationEndpoint: firstMetadataString(object, "authorization_endpoint", "authorize_endpoint", "authorization_url", "oidc_authorization_endpoint"),
		TokenEndpoint:         firstMetadataString(object, "token_endpoint", "token_url", "oidc_token_endpoint"),
		UserInfoEndpoint:      firstMetadataString(object, "userinfo_endpoint", "user_info_endpoint", "userinfo_url", "oidc_userinfo_endpoint"),
		ClientID:              firstMetadataString(object, "client_id", "clientId", "oidc_client_id"),
		ClientSecret:          clientSecret,
		Role:                  firstMetadataString(object, "role", "default_role", "oidc_role"),
	}
	if provider.ID == "" {
		provider.ID = provider.ClientID
	}
	if provider.Name == "" {
		provider.Name = provider.ID
	}
	provider.Scopes = externalOIDCScopes(object)
	provider.AutoCreate = true
	if autoCreate, ok := metadataBoolValue(object["auto_create"]); ok {
		provider.AutoCreate = autoCreate
	}
	if autoCreate, ok := metadataBoolValue(object["oidc_auto_create"]); ok {
		provider.AutoCreate = autoCreate
	}
	if provider.ID == "" || provider.AuthorizationEndpoint == "" || provider.TokenEndpoint == "" || provider.ClientID == "" {
		return externalOIDCProvider{}, false, nil
	}
	return provider, true, nil
}

func (s *Server) externalOIDCClientSecret(object map[string]any) (string, error) {
	if secret := firstMetadataString(object, "client_secret", "clientSecret", "oidc_client_secret", "external_oidc_client_secret", "externalOidcClientSecret"); secret != "" {
		return secret, nil
	}
	encrypted := firstMetadataString(object, "oidc_client_secret_encrypted", "client_secret_encrypted", "external_oidc_client_secret_encrypted")
	if encrypted == "" {
		return "", nil
	}
	return s.cfg.Store.DecryptPlatformSecret(encrypted)
}

func externalOIDCScopes(metadata map[string]any) []string {
	values := []string{}
	for _, key := range []string{"scopes", "scope", "oidc_scopes"} {
		for _, value := range metadataStrings(metadata[key]) {
			values = append(values, strings.Fields(strings.ReplaceAll(value, ",", " "))...)
		}
	}
	if len(values) == 0 {
		return []string{"openid", "profile", "email"}
	}
	return uniqueNonEmptyStrings(values)
}

func metadataObjectList(value any) []map[string]any {
	switch typed := value.(type) {
	case []map[string]any:
		return typed
	case []any:
		result := []map[string]any{}
		for _, item := range typed {
			if object, ok := item.(map[string]any); ok {
				result = append(result, object)
			}
		}
		return result
	default:
		return nil
	}
}

func (m *authManager) createExternalOIDCState(providerID, next string) (string, string, error) {
	state, err := randomToken()
	if err != nil {
		return "", "", err
	}
	nonce, err := randomToken()
	if err != nil {
		return "", "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	for key, item := range m.oidcStates {
		if now.After(item.ExpiresAt) {
			delete(m.oidcStates, key)
		}
	}
	m.oidcStates[state] = externalOIDCState{ProviderID: providerID, Next: next, Nonce: nonce, ExpiresAt: now.Add(externalOIDCStateTTL)}
	return state, nonce, nil
}

func (m *authManager) consumeExternalOIDCState(value string) (externalOIDCState, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.oidcStates[value]
	if !ok {
		return externalOIDCState{}, false
	}
	delete(m.oidcStates, value)
	if time.Now().UTC().After(state.ExpiresAt) {
		return externalOIDCState{}, false
	}
	return state, true
}

func parseUnverifiedJWTClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, errors.New("invalid id_token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	claims := map[string]any{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func externalOIDCRedirectURI(r *http.Request, trustProxy bool) string {
	return requestBaseURL(r, trustProxy) + "/api/auth/oidc/callback"
}

func safeRedirectPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") {
		return "/app"
	}
	return value
}
