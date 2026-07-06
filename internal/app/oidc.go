package app

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"openwebservermanager/internal/model"

	"golang.org/x/crypto/bcrypt"
)

const (
	oidcAuthorizationCodeTTL = 5 * time.Minute
	oidcAccessTokenTTL       = time.Hour
)

type oidcManager struct {
	mu           sync.Mutex
	privateKey   *rsa.PrivateKey
	keyID        string
	codes        map[string]oidcAuthorizationCode
	accessTokens map[string]oidcAccessToken
}

type oidcAuthorizationCode struct {
	ClientID            string
	RedirectURI         string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	UserID              string
	Username            string
	Role                string
	ExpiresAt           time.Time
}

type oidcAccessToken struct {
	ClientID  string
	Scope     string
	UserID    string
	Username  string
	Role      string
	ExpiresAt time.Time
}

type oidcClientCredentials struct {
	ClientID     string
	ClientSecret string
}

func newOIDCManager() *oidcManager {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	kid, err := randomToken()
	if err != nil {
		panic(err)
	}
	return &oidcManager{
		privateKey:   key,
		keyID:        kid[:16],
		codes:        map[string]oidcAuthorizationCode{},
		accessTokens: map[string]oidcAccessToken{},
	}
}

func (s *Server) handleOIDCAPI(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/oidc/jwks":
		s.handleOIDCJWKS(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/oidc/authorize":
		s.handleOIDCAuthorize(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/oidc/token":
		s.handleOIDCToken(w, r)
	case (r.Method == http.MethodGet || r.Method == http.MethodPost) && r.URL.Path == "/api/oidc/userinfo":
		s.handleOIDCUserInfo(w, r)
	default:
		writeError(w, http.StatusNotFound, "oidc endpoint not found")
	}
}

func (s *Server) handleOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	issuer := requestBaseURL(r, s.cfg.TrustProxyHeaders)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/api/oidc/authorize",
		"token_endpoint":                        issuer + "/api/oidc/token",
		"userinfo_endpoint":                     issuer + "/api/oidc/userinfo",
		"jwks_uri":                              issuer + "/api/oidc/jwks",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "name", "preferred_username", "role"},
		"code_challenge_methods_supported":      []string{"plain", "S256"},
	})
}

func (s *Server) handleOIDCJWKS(w http.ResponseWriter, _ *http.Request) {
	publicKey := s.oidc.privateKey.Public().(*rsa.PublicKey)
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"use": "sig",
			"kid": s.oidc.keyID,
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
		}},
	})
}

func (s *Server) handleOIDCAuthorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if query.Get("response_type") != "code" {
		writeError(w, http.StatusBadRequest, "unsupported response_type")
		return
	}
	client, err := s.oidcClientByID(query.Get("client_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	redirectURI := strings.TrimSpace(query.Get("redirect_uri"))
	if !oidcRedirectAllowed(client, redirectURI) {
		writeError(w, http.StatusBadRequest, "redirect_uri is not allowed for client")
		return
	}
	scope, err := oidcValidateScope(client, query.Get("scope"))
	if err != nil {
		s.redirectOIDCError(w, r, redirectURI, "invalid_scope", err.Error())
		return
	}
	codeChallengeMethod := strings.TrimSpace(query.Get("code_challenge_method"))
	if codeChallengeMethod == "" {
		codeChallengeMethod = "plain"
	}
	if query.Get("code_challenge") != "" && codeChallengeMethod != "plain" && codeChallengeMethod != "S256" {
		s.redirectOIDCError(w, r, redirectURI, "invalid_request", "unsupported code_challenge_method")
		return
	}
	_, session, ok := s.auth.session(r)
	if !ok {
		if query.Get("prompt") == "none" {
			s.redirectOIDCError(w, r, redirectURI, "login_required", "user is not signed in")
			return
		}
		next := r.URL.RequestURI()
		http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusFound)
		return
	}
	code, err := s.oidc.createAuthorizationCode(oidcAuthorizationCode{
		ClientID:            oidcClientID(client),
		RedirectURI:         redirectURI,
		Scope:               scope,
		Nonce:               query.Get("nonce"),
		CodeChallenge:       query.Get("code_challenge"),
		CodeChallengeMethod: codeChallengeMethod,
		UserID:              session.UserID,
		Username:            session.Username,
		Role:                session.Role,
		ExpiresAt:           time.Now().UTC().Add(oidcAuthorizationCodeTTL),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	location, _ := url.Parse(redirectURI)
	values := location.Query()
	values.Set("code", code)
	if state := query.Get("state"); state != "" {
		values.Set("state", state)
	}
	location.RawQuery = values.Encode()
	_ = s.audit(r, "oidc.authorize", oidcClientID(client), "", "issued authorization code")
	http.Redirect(w, r, location.String(), http.StatusFound)
}

func (s *Server) handleOIDCToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid token request")
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		writeError(w, http.StatusBadRequest, "unsupported grant_type")
		return
	}
	credentials := oidcClientCredentialsFromRequest(r)
	client, err := s.oidcClientByID(credentials.ClientID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid client")
		return
	}
	if !oidcClientSecretValid(client, credentials.ClientSecret) {
		writeError(w, http.StatusUnauthorized, "invalid client")
		return
	}
	redirectURI := strings.TrimSpace(r.PostForm.Get("redirect_uri"))
	code, err := s.oidc.consumeAuthorizationCode(r.PostForm.Get("code"), oidcClientID(client), redirectURI, r.PostForm.Get("code_verifier"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	issuer := requestBaseURL(r, s.cfg.TrustProxyHeaders)
	accessToken, err := s.oidc.createAccessToken(oidcAccessToken{
		ClientID:  code.ClientID,
		Scope:     code.Scope,
		UserID:    code.UserID,
		Username:  code.Username,
		Role:      code.Role,
		ExpiresAt: time.Now().UTC().Add(oidcAccessTokenTTL),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	idToken, err := s.oidc.signIDToken(issuer, code)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _ = s.cfg.Store.CreatePlatformItem("operation_logs", model.PlatformItemRequest{
		Name:        "oidc.token",
		Type:        "oidc",
		Status:      "success",
		OwnerID:     code.UserID,
		TargetID:    code.ClientID,
		Description: "issued oidc tokens",
		Metadata:    map[string]any{"client_ip": s.clientIP(r), "client_id": code.ClientID, "scope": code.Scope},
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(oidcAccessTokenTTL.Seconds()),
		"scope":        code.Scope,
		"id_token":     idToken,
	})
}

func (s *Server) handleOIDCUserInfo(w http.ResponseWriter, r *http.Request) {
	token := oidcBearerTokenFromRequest(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "bearer token required")
		return
	}
	accessToken, ok := s.oidc.accessToken(token)
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid bearer token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sub":                accessToken.UserID,
		"name":               accessToken.Username,
		"preferred_username": accessToken.Username,
		"role":               accessToken.Role,
	})
}

func oidcBearerTokenFromRequest(r *http.Request) string {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader != "" {
		parts := strings.Fields(authHeader)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			return strings.TrimSpace(parts[1])
		}
	}
	if r.Method != http.MethodPost {
		return ""
	}
	if err := r.ParseForm(); err != nil {
		return ""
	}
	return strings.TrimSpace(r.PostForm.Get("access_token"))
}

func (s *Server) redirectOIDCError(w http.ResponseWriter, r *http.Request, redirectURI, code, description string) {
	location, err := url.Parse(redirectURI)
	if err != nil {
		writeError(w, http.StatusBadRequest, description)
		return
	}
	values := location.Query()
	values.Set("error", code)
	if description != "" {
		values.Set("error_description", description)
	}
	if state := r.URL.Query().Get("state"); state != "" {
		values.Set("state", state)
	}
	location.RawQuery = values.Encode()
	http.Redirect(w, r, location.String(), http.StatusFound)
}

func (s *Server) oidcClientByID(clientID string) (model.PlatformItem, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return model.PlatformItem{}, errors.New("client_id is required")
	}
	items, err := s.cfg.Store.ListPlatformItems("oidc_clients")
	if err != nil {
		return model.PlatformItem{}, err
	}
	for _, item := range items {
		if !platformItemEnabled(item) {
			continue
		}
		if oidcClientID(item) != clientID {
			continue
		}
		raw, ok, err := s.cfg.Store.GetPlatformItem("oidc_clients", item.ID)
		if err != nil {
			return model.PlatformItem{}, err
		}
		if !ok {
			return model.PlatformItem{}, errors.New("oidc client not found")
		}
		return raw, nil
	}
	return model.PlatformItem{}, errors.New("oidc client not found")
}

func oidcClientCredentialsFromRequest(r *http.Request) oidcClientCredentials {
	clientID, clientSecret, _ := r.BasicAuth()
	if clientID == "" {
		clientID = r.PostForm.Get("client_id")
	}
	if clientSecret == "" {
		clientSecret = r.PostForm.Get("client_secret")
	}
	return oidcClientCredentials{
		ClientID:     strings.TrimSpace(clientID),
		ClientSecret: clientSecret,
	}
}

func oidcClientID(item model.PlatformItem) string {
	if value := firstMetadataString(item.Metadata, "client_id", "clientId"); value != "" {
		return value
	}
	if item.Name != "" {
		return item.Name
	}
	return item.ID
}

func oidcRedirectAllowed(item model.PlatformItem, redirectURI string) bool {
	redirectURI = strings.TrimSpace(redirectURI)
	if redirectURI == "" {
		return false
	}
	for _, candidate := range oidcRedirectURIs(item) {
		if strings.TrimSpace(candidate) == redirectURI {
			return true
		}
	}
	return false
}

func oidcRedirectURIs(item model.PlatformItem) []string {
	values := []string{}
	for _, key := range []string{"redirect_uris", "redirectUris", "redirect_uri", "redirectUri", "callbacks", "callback_urls"} {
		for _, value := range metadataStrings(item.Metadata[key]) {
			values = append(values, splitCriteria(value)...)
		}
	}
	if item.Host != "" {
		values = append(values, item.Host)
	}
	return values
}

func oidcValidateScope(item model.PlatformItem, requested string) (string, error) {
	requestedScopes := strings.Fields(strings.TrimSpace(requested))
	if len(requestedScopes) == 0 {
		requestedScopes = []string{"openid"}
	}
	allowed := map[string]bool{}
	allowedScopes := metadataStrings(item.Metadata["scopes"])
	if len(allowedScopes) == 0 {
		allowedScopes = []string{"openid", "profile", "email"}
	}
	for _, value := range allowedScopes {
		for _, scope := range strings.Fields(strings.ReplaceAll(value, ",", " ")) {
			allowed[strings.TrimSpace(scope)] = true
		}
	}
	hasOpenID := false
	for _, scope := range requestedScopes {
		if scope == "openid" {
			hasOpenID = true
		}
		if !allowed[scope] {
			return "", errors.New("scope is not allowed: " + scope)
		}
	}
	if !hasOpenID {
		return "", errors.New("openid scope is required")
	}
	return strings.Join(requestedScopes, " "), nil
}

func oidcClientSecretValid(item model.PlatformItem, secret string) bool {
	hash, _ := item.Metadata["client_secret_hash"].(string)
	if hash == "" {
		method := strings.ToLower(firstMetadataString(item.Metadata, "token_endpoint_auth_method", "auth_method", "authMethod"))
		clientType := strings.ToLower(strings.TrimSpace(item.Type))
		return strings.TrimSpace(secret) == "" && (clientType == "public" || method == "none")
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret)) == nil
}

func (m *oidcManager) createAuthorizationCode(code oidcAuthorizationCode) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked()
	m.codes[token] = code
	return token, nil
}

func (m *oidcManager) consumeAuthorizationCode(codeValue, clientID, redirectURI, verifier string) (oidcAuthorizationCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked()
	code, ok := m.codes[codeValue]
	if !ok {
		return oidcAuthorizationCode{}, errors.New("authorization code is invalid or already used")
	}
	delete(m.codes, codeValue)
	if time.Now().UTC().After(code.ExpiresAt) {
		return oidcAuthorizationCode{}, errors.New("authorization code expired")
	}
	if code.ClientID != clientID || code.RedirectURI != redirectURI {
		return oidcAuthorizationCode{}, errors.New("authorization code does not match client or redirect_uri")
	}
	if !oidcPKCEValid(code, verifier) {
		return oidcAuthorizationCode{}, errors.New("code_verifier is invalid")
	}
	return code, nil
}

func (m *oidcManager) createAccessToken(token oidcAccessToken) (string, error) {
	value, err := randomToken()
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked()
	m.accessTokens[value] = token
	return value, nil
}

func (m *oidcManager) accessToken(value string) (oidcAccessToken, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked()
	token, ok := m.accessTokens[value]
	return token, ok
}

func (m *oidcManager) pruneLocked() {
	now := time.Now().UTC()
	for key, code := range m.codes {
		if now.After(code.ExpiresAt) {
			delete(m.codes, key)
		}
	}
	for key, token := range m.accessTokens {
		if now.After(token.ExpiresAt) {
			delete(m.accessTokens, key)
		}
	}
}

func oidcPKCEValid(code oidcAuthorizationCode, verifier string) bool {
	if code.CodeChallenge == "" {
		return true
	}
	if verifier == "" {
		return false
	}
	switch code.CodeChallengeMethod {
	case "S256":
		sum := sha256.Sum256([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(sum[:]) == code.CodeChallenge
	default:
		return verifier == code.CodeChallenge
	}
}

func (m *oidcManager) signIDToken(issuer string, code oidcAuthorizationCode) (string, error) {
	now := time.Now().UTC()
	claims := map[string]any{
		"iss":                issuer,
		"sub":                code.UserID,
		"aud":                code.ClientID,
		"exp":                now.Add(oidcAccessTokenTTL).Unix(),
		"iat":                now.Unix(),
		"auth_time":          now.Unix(),
		"name":               code.Username,
		"preferred_username": code.Username,
		"role":               code.Role,
	}
	if code.Nonce != "" {
		claims["nonce"] = code.Nonce
	}
	return m.signJWT(claims)
}

func (m *oidcManager) signJWT(claims map[string]any) (string, error) {
	header := map[string]any{"typ": "JWT", "alg": "RS256", "kid": m.keyID}
	headerRaw, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsRaw, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerRaw) + "." + base64.RawURLEncoding.EncodeToString(claimsRaw)
	sum := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, m.privateKey, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func requestBaseURL(r *http.Request, trustProxy bool) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if trustProxy {
		if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); forwarded == "http" || forwarded == "https" {
			scheme = forwarded
		}
	}
	return scheme + "://" + effectiveHost(r, trustProxy)
}
