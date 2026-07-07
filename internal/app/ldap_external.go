package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"openwebservermanager/internal/model"
	"openwebservermanager/internal/store"

	goldap "github.com/go-ldap/ldap/v3"
)

const externalLDAPTimeout = 10 * time.Second

type externalLDAPProvider struct {
	ID                   string
	Name                 string
	URL                  string
	BindDN               string
	BindPassword         string
	BaseDN               string
	UserFilter           string
	UserDNTemplate       string
	UsernameAttribute    string
	DisplayNameAttribute string
	EmailAttribute       string
	Role                 string
	AutoCreate           bool
	StartTLS             bool
	InsecureSkipVerify   bool
	ServerName           string
}

type externalLDAPClaims struct {
	Subject     string
	DN          string
	Username    string
	DisplayName string
	Email       string
	Groups      []string
}

type realLDAPAuthenticator struct{}

var (
	errExternalLDAPUserDisabled   = errors.New("external ldap user is disabled")
	errExternalLDAPUserNotAllowed = errors.New("external ldap user auto creation is disabled")
)

func (s *Server) ldapLoginConfigured() bool {
	providers, err := s.externalLDAPProviders()
	return err == nil && len(providers) > 0
}

func (s *Server) authenticateExternalLDAP(ctx context.Context, username, password string) (store.AdminPublic, string, bool, model.PlatformItem, bool, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return store.AdminPublic{}, "", false, model.PlatformItem{}, false, nil
	}
	providers, err := s.externalLDAPProviders()
	if err != nil {
		return store.AdminPublic{}, "", false, model.PlatformItem{}, false, err
	}
	var firstErr error
	var firstProviderID string
	for _, provider := range providers {
		claims, ok, err := s.ldap.Authenticate(ctx, provider, username, password)
		if err != nil {
			if firstErr == nil {
				firstErr = sanitizedLDAPProviderError(provider, password, err)
				firstProviderID = provider.ID
			}
			continue
		}
		if !ok {
			continue
		}
		subject := strings.TrimSpace(firstNonEmpty(claims.Subject, claims.DN, username))
		previousUser, hadPreviousUser, err := s.externalUserSnapshot("ldap", provider.ID, subject)
		if err != nil {
			return store.AdminPublic{}, provider.ID, false, model.PlatformItem{}, false, err
		}
		user, err := s.upsertExternalLDAPUser(provider, claims, username)
		return user, provider.ID, true, previousUser, hadPreviousUser, err
	}
	if firstErr != nil {
		return store.AdminPublic{}, firstProviderID, false, model.PlatformItem{}, false, firstErr
	}
	return store.AdminPublic{}, "", false, model.PlatformItem{}, false, nil
}

func sanitizedLDAPProviderError(provider externalLDAPProvider, password string, err error) error {
	if err == nil {
		return nil
	}
	return errors.New(sanitizeLDAPText(provider, password, err.Error()))
}

func sanitizeLDAPText(provider externalLDAPProvider, password, text string) string {
	if text == "" {
		return text
	}
	replacements := []string{}
	seen := map[string]bool{}
	addSecret := func(secret string) {
		secret = strings.TrimSpace(secret)
		if secret == "" || seen[secret] {
			return
		}
		seen[secret] = true
		replacements = append(replacements, secret, "[redacted]")
		escaped := url.QueryEscape(secret)
		if escaped != secret && !seen[escaped] {
			seen[escaped] = true
			replacements = append(replacements, escaped, "[redacted]")
		}
	}
	addSecret(provider.BindPassword)
	addSecret(password)
	if len(replacements) == 0 {
		return text
	}
	return strings.NewReplacer(replacements...).Replace(text)
}

func (realLDAPAuthenticator) Authenticate(ctx context.Context, provider externalLDAPProvider, username, password string) (externalLDAPClaims, bool, error) {
	if err := ctx.Err(); err != nil {
		return externalLDAPClaims{}, false, err
	}
	tlsConfig := &tls.Config{
		ServerName:         provider.ServerName,
		InsecureSkipVerify: provider.InsecureSkipVerify,
	}
	conn, err := goldap.DialURL(provider.URL, goldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return externalLDAPClaims{}, false, fmt.Errorf("connect ldap provider %s: %w", provider.ID, err)
	}
	defer conn.Close()
	conn.SetTimeout(externalLDAPTimeout)
	if provider.StartTLS {
		if err := conn.StartTLS(tlsConfig); err != nil {
			return externalLDAPClaims{}, false, fmt.Errorf("start ldap tls for %s: %w", provider.ID, err)
		}
	}
	if strings.TrimSpace(provider.UserDNTemplate) != "" {
		userDN := strings.ReplaceAll(provider.UserDNTemplate, "{username}", username)
		if err := conn.Bind(userDN, password); err != nil {
			if ldapInvalidCredentials(err) {
				return externalLDAPClaims{}, false, nil
			}
			return externalLDAPClaims{}, false, fmt.Errorf("bind ldap user for %s: %w", provider.ID, err)
		}
		return externalLDAPClaims{
			Subject:  userDN,
			DN:       userDN,
			Username: username,
		}, true, nil
	}
	if provider.BindDN != "" {
		if err := conn.Bind(provider.BindDN, provider.BindPassword); err != nil {
			return externalLDAPClaims{}, false, fmt.Errorf("bind ldap service account for %s: %w", provider.ID, err)
		}
	}
	filter := provider.UserFilter
	if filter == "" {
		filter = "(|(uid={username})(sAMAccountName={username})(userPrincipalName={username})(mail={username}))"
	}
	filter = strings.ReplaceAll(filter, "{username}", goldap.EscapeFilter(username))
	attributes := uniqueNonEmptyStrings([]string{
		provider.UsernameAttribute,
		provider.DisplayNameAttribute,
		provider.EmailAttribute,
		"uid",
		"cn",
		"displayName",
		"mail",
		"memberOf",
	})
	search := goldap.NewSearchRequest(
		provider.BaseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		2,
		int(externalLDAPTimeout.Seconds()),
		false,
		filter,
		attributes,
		nil,
	)
	result, err := conn.Search(search)
	if err != nil {
		return externalLDAPClaims{}, false, fmt.Errorf("search ldap user for %s: %w", provider.ID, err)
	}
	if len(result.Entries) != 1 {
		return externalLDAPClaims{}, false, nil
	}
	entry := result.Entries[0]
	if err := conn.Bind(entry.DN, password); err != nil {
		if ldapInvalidCredentials(err) {
			return externalLDAPClaims{}, false, nil
		}
		return externalLDAPClaims{}, false, fmt.Errorf("bind ldap user for %s: %w", provider.ID, err)
	}
	claims := externalLDAPClaims{
		Subject:     firstNonEmpty(entry.DN, entry.GetAttributeValue(provider.UsernameAttribute), username),
		DN:          entry.DN,
		Username:    firstNonEmpty(entry.GetAttributeValue(provider.UsernameAttribute), entry.GetAttributeValue("uid"), entry.GetAttributeValue("sAMAccountName"), username),
		DisplayName: firstNonEmpty(entry.GetAttributeValue(provider.DisplayNameAttribute), entry.GetAttributeValue("displayName"), entry.GetAttributeValue("cn")),
		Email:       firstNonEmpty(entry.GetAttributeValue(provider.EmailAttribute), entry.GetAttributeValue("mail")),
		Groups:      entry.GetAttributeValues("memberOf"),
	}
	return claims, true, nil
}

func ldapInvalidCredentials(err error) bool {
	var ldapErr *goldap.Error
	return errors.As(err, &ldapErr) && ldapErr.ResultCode == goldap.LDAPResultInvalidCredentials
}

func (s *Server) upsertExternalLDAPUser(provider externalLDAPProvider, claims externalLDAPClaims, fallbackUsername string) (store.AdminPublic, error) {
	subject := strings.TrimSpace(firstNonEmpty(claims.Subject, claims.DN, fallbackUsername))
	if subject == "" {
		return store.AdminPublic{}, errors.New("ldap claims missing subject")
	}
	username := strings.TrimSpace(firstNonEmpty(claims.Username, claims.DisplayName, claims.Email, fallbackUsername, subject))
	role := strings.TrimSpace(provider.Role)
	if role == "" {
		role = "user"
	}
	users, err := s.cfg.Store.ListPlatformItems("users")
	if err != nil {
		return store.AdminPublic{}, err
	}
	for _, item := range users {
		if firstMetadataString(item.Metadata, "external_provider") != "ldap" || firstMetadataString(item.Metadata, "external_provider_id") != provider.ID || firstMetadataString(item.Metadata, "external_subject") != subject {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(item.Status), "disabled") {
			return store.AdminPublic{}, errExternalLDAPUserDisabled
		}
		metadata := cloneMetadata(item.Metadata)
		metadata["role"] = role
		metadata["external_provider"] = "ldap"
		metadata["external_provider_id"] = provider.ID
		metadata["external_subject"] = subject
		metadata["external_dn"] = claims.DN
		metadata["email"] = claims.Email
		metadata["display_name"] = claims.DisplayName
		metadata["external_claims_updated_at"] = time.Now().UTC().Format(time.RFC3339Nano)
		updated, err := s.cfg.Store.UpdatePlatformItem("users", item.ID, model.PlatformItemRequest{
			Name:     username,
			Type:     "ldap",
			Status:   item.Status,
			Metadata: metadata,
		})
		if err != nil {
			return store.AdminPublic{}, err
		}
		return storeAdminPublicFromPlatformItem(updated, role), nil
	}
	if !provider.AutoCreate {
		return store.AdminPublic{}, errExternalLDAPUserNotAllowed
	}
	item, err := s.cfg.Store.CreatePlatformItem("users", model.PlatformItemRequest{
		Name:   username,
		Type:   "ldap",
		Status: "enabled",
		Metadata: map[string]any{
			"role":                       role,
			"external_provider":          "ldap",
			"external_provider_id":       provider.ID,
			"external_subject":           subject,
			"external_dn":                claims.DN,
			"email":                      claims.Email,
			"display_name":               claims.DisplayName,
			"external_claims_created_at": time.Now().UTC().Format(time.RFC3339Nano),
		},
	})
	if err != nil {
		return store.AdminPublic{}, err
	}
	return storeAdminPublicFromPlatformItem(item, role), nil
}

func (s *Server) externalLDAPProviders() ([]externalLDAPProvider, error) {
	items, err := s.cfg.Store.ListPlatformItems("system_settings")
	if err != nil {
		return nil, err
	}
	providers := []externalLDAPProvider{}
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
		next, err := s.externalLDAPProvidersFromMetadata(raw.Metadata)
		if err != nil {
			return nil, err
		}
		providers = append(providers, next...)
	}
	return providers, nil
}

func (s *Server) externalLDAPProvidersFromMetadata(metadata map[string]any) ([]externalLDAPProvider, error) {
	result := []externalLDAPProvider{}
	for _, object := range metadataObjectList(metadata["ldap_providers"]) {
		provider, ok, err := s.externalLDAPProviderFromObject(object, false)
		if err != nil {
			return nil, err
		}
		if ok {
			result = append(result, provider)
		}
	}
	for _, object := range metadataObjectList(metadata["external_ldap_providers"]) {
		provider, ok, err := s.externalLDAPProviderFromObject(object, false)
		if err != nil {
			return nil, err
		}
		if ok {
			result = append(result, provider)
		}
	}
	provider, ok, err := s.externalLDAPProviderFromObject(metadata, true)
	if err != nil {
		return nil, err
	}
	if ok {
		result = append(result, provider)
	}
	return result, nil
}

func (s *Server) externalLDAPProviderFromObject(object map[string]any, requireExplicitEnable bool) (externalLDAPProvider, bool, error) {
	if requireExplicitEnable {
		enabled, ok := metadataBoolValue(object["ldap_enabled"])
		if !ok {
			enabled, ok = metadataBoolValue(object["ldap_login_enabled"])
		}
		if !ok {
			enabled, ok = metadataBoolValue(object["external_ldap_enabled"])
		}
		if !ok || !enabled {
			return externalLDAPProvider{}, false, nil
		}
	} else if enabled, ok := metadataBoolValue(object["enabled"]); ok && !enabled {
		return externalLDAPProvider{}, false, nil
	}
	bindPassword, err := s.externalLDAPBindPassword(object)
	if err != nil {
		return externalLDAPProvider{}, false, err
	}
	provider := externalLDAPProvider{
		ID:                   firstMetadataString(object, "id", "provider_id", "ldap_provider_id"),
		Name:                 firstMetadataString(object, "name", "label", "provider_name", "ldap_provider_name"),
		URL:                  externalLDAPURL(object),
		BindDN:               firstMetadataString(object, "bind_dn", "ldap_bind_dn", "manager_dn"),
		BindPassword:         bindPassword,
		BaseDN:               firstMetadataString(object, "base_dn", "ldap_base_dn", "search_base", "user_base_dn"),
		UserFilter:           firstMetadataString(object, "user_filter", "ldap_user_filter", "filter"),
		UserDNTemplate:       firstMetadataString(object, "user_dn_template", "ldap_user_dn_template"),
		UsernameAttribute:    firstMetadataString(object, "username_attribute", "ldap_username_attribute"),
		DisplayNameAttribute: firstMetadataString(object, "display_name_attribute", "ldap_display_name_attribute"),
		EmailAttribute:       firstMetadataString(object, "email_attribute", "ldap_email_attribute"),
		Role:                 firstMetadataString(object, "role", "default_role", "ldap_role"),
		ServerName:           firstMetadataString(object, "server_name", "tls_server_name", "ldap_server_name"),
	}
	if provider.ID == "" {
		provider.ID = firstNonEmpty(provider.Name, provider.URL)
	}
	if provider.Name == "" {
		provider.Name = provider.ID
	}
	if provider.UsernameAttribute == "" {
		provider.UsernameAttribute = "uid"
	}
	if provider.DisplayNameAttribute == "" {
		provider.DisplayNameAttribute = "cn"
	}
	if provider.EmailAttribute == "" {
		provider.EmailAttribute = "mail"
	}
	provider.AutoCreate = true
	if autoCreate, ok := metadataBoolValue(object["auto_create"]); ok {
		provider.AutoCreate = autoCreate
	}
	if autoCreate, ok := metadataBoolValue(object["ldap_auto_create"]); ok {
		provider.AutoCreate = autoCreate
	}
	provider.StartTLS, _ = metadataBoolValue(object["ldap_start_tls"])
	if value, ok := metadataBoolValue(object["start_tls"]); ok {
		provider.StartTLS = value
	}
	provider.InsecureSkipVerify, _ = metadataBoolValue(object["ldap_insecure_skip_verify"])
	if value, ok := metadataBoolValue(object["insecure_skip_verify"]); ok {
		provider.InsecureSkipVerify = value
	}
	if provider.URL == "" || (provider.BaseDN == "" && provider.UserDNTemplate == "") {
		return externalLDAPProvider{}, false, nil
	}
	return provider, true, nil
}

func (s *Server) externalLDAPBindPassword(object map[string]any) (string, error) {
	if secret := firstMetadataString(object, "bind_password", "bindPassword", "ldap_bind_password", "ldapBindPassword", "plain_ldap_bind_password"); secret != "" {
		return secret, nil
	}
	encrypted := firstMetadataString(object, "ldap_bind_password_encrypted", "bind_password_encrypted")
	if encrypted == "" {
		return "", nil
	}
	return s.cfg.Store.DecryptPlatformSecret(encrypted)
}

func externalLDAPURL(metadata map[string]any) string {
	if raw := firstMetadataString(metadata, "url", "ldap_url"); raw != "" {
		return raw
	}
	host := firstMetadataString(metadata, "host", "ldap_host")
	if host == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		if useTLS, _ := metadataBoolValue(metadata["ldap_use_tls"]); useTLS {
			return "ldaps://" + host
		}
		return "ldap://" + host
	}
	useTLS, _ := metadataBoolValue(metadata["ldap_use_tls"])
	if value, ok := metadataBoolValue(metadata["use_tls"]); ok {
		useTLS = value
	}
	scheme := "ldap"
	port := 389
	if useTLS {
		scheme = "ldaps"
		port = 636
	}
	if text := firstMetadataString(metadata, "port", "ldap_port"); text != "" {
		if parsed, err := strconv.Atoi(text); err == nil && parsed > 0 {
			port = parsed
		}
	}
	return (&url.URL{Scheme: scheme, Host: net.JoinHostPort(host, strconv.Itoa(port))}).String()
}
