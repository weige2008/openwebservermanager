package app

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
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
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	UserInfoEndpoint      string
	JWKSEndpoint          string
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
	if errText := strings.TrimSpace(r.URL.Query().Get("error")); errText != "" {
		err := errors.New("oidc provider returned error: " + errText)
		if logErr := s.recordExternalOIDCLoginFailure(r, provider, nil, err); logErr != nil {
			writeError(w, http.StatusInternalServerError, logErr.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		err := errors.New("code is required")
		if logErr := s.recordExternalOIDCLoginFailure(r, provider, nil, err); logErr != nil {
			writeError(w, http.StatusInternalServerError, logErr.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	claims, err := s.exchangeExternalOIDCCode(r, provider, code, state.Nonce)
	if err != nil {
		safeErr := sanitizedExternalProviderError(err, provider.ClientSecret)
		if logErr := s.recordExternalOIDCLoginFailure(r, provider, nil, safeErr); logErr != nil {
			writeError(w, http.StatusInternalServerError, logErr.Error())
			return
		}
		writeError(w, http.StatusBadGateway, safeErr.Error())
		return
	}
	if nonce := firstMetadataString(claims, "nonce"); nonce != "" && nonce != state.Nonce {
		err := errors.New("oidc nonce mismatch")
		if logErr := s.recordExternalOIDCLoginFailure(r, provider, claims, err); logErr != nil {
			writeError(w, http.StatusInternalServerError, logErr.Error())
			return
		}
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
		if logErr := s.recordExternalOIDCLoginFailure(r, provider, claims, err); logErr != nil {
			writeError(w, http.StatusInternalServerError, logErr.Error())
			return
		}
		writeError(w, status, err.Error())
		return
	}
	token, session, err := s.auth.create(user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.cfg.Store.RecordUserLogin(session.UserID, s.clientIP(r), r.UserAgent())
	_ = s.audit(r, "auth.oidc.login", session.UserID, "", "signed in with external oidc provider "+provider.ID)
	if err := s.createLoginLog(r, model.PlatformItemRequest{
		Name:        session.Username,
		Type:        "oidc",
		Status:      "success",
		OwnerID:     session.UserID,
		Description: "signed in with external oidc",
		Metadata:    map[string]any{"client_ip": s.clientIP(r), "provider_id": provider.ID, "subject": firstMetadataString(claims, "sub")},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	http.SetCookie(w, s.authCookie(r, token, int(authSessionTTL.Seconds())))
	http.Redirect(w, r, state.Next, http.StatusFound)
}

func (s *Server) recordExternalOIDCLoginFailure(r *http.Request, provider externalOIDCProvider, claims map[string]any, err error) error {
	detail := "external oidc login failed"
	if err != nil {
		detail = err.Error()
	}
	subject := firstMetadataString(claims, "sub", "id", "user_id")
	account := firstMetadataString(claims, "preferred_username", "name", "email", "login")
	if account == "" {
		account = subject
	}
	if logErr := s.createLoginLog(r, model.PlatformItemRequest{
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
	}); logErr != nil {
		return logErr
	}
	_ = s.audit(r, "auth.oidc.login_failed", provider.ID, "oidc", detail)
	return nil
}

func sanitizedExternalProviderError(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	return errors.New(redactSecretVariants(err.Error(), secrets...))
}

func (s *Server) exchangeExternalOIDCCode(r *http.Request, provider externalOIDCProvider, code, expectedNonce string) (map[string]any, error) {
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
		return nil, fmt.Errorf("oidc userinfo failed: %w", err)
	}
	idToken := firstMetadataString(tokenPayload, "id_token")
	if idToken == "" {
		return nil, errors.New("oidc provider did not return userinfo or id_token")
	}
	return verifyExternalOIDCIDToken(client, provider, idToken, expectedNonce)
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

type externalOIDCJWKS struct {
	Keys []externalOIDCJWK `json:"keys"`
}

type externalOIDCJWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func verifyExternalOIDCIDToken(client http.Client, provider externalOIDCProvider, token, expectedNonce string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid id_token")
	}
	header := map[string]any{}
	if err := decodeJWTPart(parts[0], &header); err != nil {
		return nil, fmt.Errorf("decode id_token header: %w", err)
	}
	if alg := firstMetadataString(header, "alg"); alg != "RS256" {
		return nil, errors.New("unsupported id_token alg")
	}
	claims := map[string]any{}
	if err := decodeJWTPart(parts[1], &claims); err != nil {
		return nil, fmt.Errorf("decode id_token claims: %w", err)
	}
	jwksURI, issuer, err := externalOIDCJWKSURI(client, provider)
	if err != nil {
		return nil, err
	}
	publicKey, err := externalOIDCJWKSKey(client, jwksURI, firstMetadataString(header, "kid"))
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode id_token signature: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]
	sum := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, sum[:], signature); err != nil {
		return nil, errors.New("id_token signature is invalid")
	}
	if err := validateExternalOIDCIDTokenClaims(claims, provider.ClientID, issuer, expectedNonce, time.Now().UTC()); err != nil {
		return nil, err
	}
	return claims, nil
}

func externalOIDCJWKSURI(client http.Client, provider externalOIDCProvider) (string, string, error) {
	jwksURI := strings.TrimSpace(provider.JWKSEndpoint)
	issuer := strings.TrimRight(strings.TrimSpace(provider.Issuer), "/")
	if issuer == "" {
		return "", "", errors.New("oidc id_token verification requires issuer")
	}
	if jwksURI != "" {
		return jwksURI, issuer, nil
	}
	discoveryURL := issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequest(http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("oidc discovery returned %s", resp.Status)
	}
	discovery := map[string]any{}
	if err := json.Unmarshal(body, &discovery); err != nil {
		return "", "", fmt.Errorf("decode oidc discovery: %w", err)
	}
	if discoveredIssuer := strings.TrimRight(firstMetadataString(discovery, "issuer"), "/"); discoveredIssuer != "" && discoveredIssuer != issuer {
		return "", "", errors.New("oidc discovery issuer mismatch")
	}
	jwksURI = firstMetadataString(discovery, "jwks_uri")
	if jwksURI == "" {
		return "", "", errors.New("oidc discovery missing jwks_uri")
	}
	return jwksURI, issuer, nil
}

func externalOIDCJWKSKey(client http.Client, jwksURI, kid string) (*rsa.PublicKey, error) {
	req, err := http.NewRequest(http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("oidc jwks returned %s", resp.Status)
	}
	var jwks externalOIDCJWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("decode oidc jwks: %w", err)
	}
	keys := []*rsa.PublicKey{}
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" || (key.Use != "" && key.Use != "sig") || (key.Alg != "" && key.Alg != "RS256") {
			continue
		}
		if kid != "" && key.Kid != kid {
			continue
		}
		publicKey, err := rsaPublicKeyFromJWK(key)
		if err != nil {
			return nil, err
		}
		keys = append(keys, publicKey)
	}
	if len(keys) == 1 {
		return keys[0], nil
	}
	if len(keys) > 1 {
		return nil, errors.New("oidc jwks matched multiple signing keys")
	}
	if kid == "" {
		return nil, errors.New("oidc id_token missing kid and jwks has no single matching key")
	}
	return nil, errors.New("oidc jwks signing key not found")
}

func rsaPublicKeyFromJWK(key externalOIDCJWK) (*rsa.PublicKey, error) {
	if key.N == "" || key.E == "" {
		return nil, errors.New("oidc jwk missing rsa modulus or exponent")
	}
	nRaw, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("decode oidc jwk modulus: %w", err)
	}
	eRaw, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("decode oidc jwk exponent: %w", err)
	}
	exponent := new(big.Int).SetBytes(eRaw).Int64()
	if exponent <= 1 || exponent > int64(^uint(0)>>1) {
		return nil, errors.New("oidc jwk exponent is invalid")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nRaw), E: int(exponent)}, nil
}

func validateExternalOIDCIDTokenClaims(claims map[string]any, clientID, issuer, expectedNonce string, now time.Time) error {
	if subject := firstMetadataString(claims, "sub"); subject == "" {
		return errors.New("id_token missing subject")
	}
	if issuer != "" && firstMetadataString(claims, "iss") != issuer {
		return errors.New("id_token issuer mismatch")
	}
	if !externalOIDCAudienceContains(claims["aud"], clientID) {
		return errors.New("id_token audience mismatch")
	}
	if values := externalOIDCAudiences(claims["aud"]); len(values) > 1 && firstMetadataString(claims, "azp") != clientID {
		return errors.New("id_token authorized party mismatch")
	}
	exp, ok := metadataUnixTime(claims["exp"])
	if !ok {
		return errors.New("id_token missing expiration")
	}
	if now.After(exp.Add(time.Minute)) {
		return errors.New("id_token is expired")
	}
	if nbf, ok := metadataUnixTime(claims["nbf"]); ok && now.Add(time.Minute).Before(nbf) {
		return errors.New("id_token is not valid yet")
	}
	if iat, ok := metadataUnixTime(claims["iat"]); ok && now.Add(5*time.Minute).Before(iat) {
		return errors.New("id_token issued-at is in the future")
	}
	if expectedNonce == "" || firstMetadataString(claims, "nonce") != expectedNonce {
		return errors.New("id_token nonce mismatch")
	}
	return nil
}

func externalOIDCAudienceContains(value any, clientID string) bool {
	for _, audience := range externalOIDCAudiences(value) {
		if audience == clientID {
			return true
		}
	}
	return false
}

func externalOIDCAudiences(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{strings.TrimSpace(typed)}
	case []string:
		return uniqueNonEmptyStrings(typed)
	case []any:
		values := []string{}
		for _, item := range typed {
			if text, ok := item.(string); ok {
				values = append(values, strings.TrimSpace(text))
			}
		}
		return uniqueNonEmptyStrings(values)
	default:
		return nil
	}
}

func metadataUnixTime(value any) (time.Time, bool) {
	var seconds int64
	switch typed := value.(type) {
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return time.Time{}, false
		}
		seconds = parsed
	case float64:
		seconds = int64(typed)
	case int:
		seconds = int64(typed)
	case int64:
		seconds = typed
	default:
		return time.Time{}, false
	}
	if seconds <= 0 {
		return time.Time{}, false
	}
	return time.Unix(seconds, 0).UTC(), true
}

func decodeJWTPart(part string, out any) error {
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	return decoder.Decode(out)
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
		Issuer:                strings.TrimRight(firstMetadataString(object, "issuer", "issuer_url", "oidc_issuer", "oidc_issuer_url"), "/"),
		AuthorizationEndpoint: firstMetadataString(object, "authorization_endpoint", "authorize_endpoint", "authorization_url", "oidc_authorization_endpoint"),
		TokenEndpoint:         firstMetadataString(object, "token_endpoint", "token_url", "oidc_token_endpoint"),
		UserInfoEndpoint:      firstMetadataString(object, "userinfo_endpoint", "user_info_endpoint", "userinfo_url", "oidc_userinfo_endpoint"),
		JWKSEndpoint:          firstMetadataString(object, "jwks_uri", "jwks_endpoint", "jwks_url", "oidc_jwks_uri", "oidc_jwks_endpoint"),
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
