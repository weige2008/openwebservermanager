package app

import (
	"net"
	"strings"
	"time"

	"openwebservermanager/internal/model"
)

func (s *Server) loginPolicyAllows(username, clientIP string) (bool, string) {
	policies, err := s.cfg.Store.ListPlatformItems("login_policies")
	if err != nil {
		return true, ""
	}
	hasAllowPolicy := false
	allowMatched := false
	for _, policy := range policies {
		if !platformItemEnabled(policy) || !loginPolicyMatches(policy, username, clientIP) {
			continue
		}
		action := loginPolicyAction(policy)
		if action == "deny" || action == "reject" || action == "block" {
			return false, "blocked by login policy " + policy.Name
		}
		if action == "allow" {
			hasAllowPolicy = true
			allowMatched = true
		}
	}
	for _, policy := range policies {
		if !platformItemEnabled(policy) {
			continue
		}
		if loginPolicyAction(policy) == "allow" {
			hasAllowPolicy = true
		}
	}
	if hasAllowPolicy && !allowMatched {
		return false, "no allow login policy matched"
	}
	return true, ""
}

func (s *Server) activeLoginLock(username, clientIP string) (time.Duration, bool) {
	locks, err := s.cfg.Store.ListPlatformItems("login_locks")
	if err != nil {
		return 0, false
	}
	now := time.Now().UTC()
	for _, lock := range locks {
		if !platformItemEnabled(lock) || !loginLockMatches(lock, username, clientIP) {
			continue
		}
		until, ok := metadataTime(lock.Metadata["locked_until"])
		if !ok || now.Before(until) {
			if ok {
				return time.Until(until).Round(time.Second), true
			}
			return 5 * time.Minute, true
		}
	}
	return 0, false
}

func (s *Server) createLoginLock(username, clientIP string, failure loginFailure) {
	lockedUntil := failure.LockedUntil
	if lockedUntil.IsZero() {
		lockedUntil = time.Now().UTC().Add(5 * time.Minute)
	}
	_, _ = s.cfg.Store.CreatePlatformItem("login_locks", model.PlatformItemRequest{
		Name:        username,
		Type:        "password",
		Status:      "locked",
		Username:    username,
		Host:        clientIP,
		Description: "too many failed login attempts",
		Metadata: map[string]any{
			"account":       username,
			"client_ip":     clientIP,
			"failure_count": failure.Count,
			"locked_until":  lockedUntil.UTC(),
			"last_failure":  failure.LastFailure.UTC(),
		},
	})
}

func (s *Server) passwordLoginDisabled() bool {
	items, err := s.cfg.Store.ListPlatformItems("system_settings")
	if err != nil {
		return false
	}
	for _, item := range items {
		if !platformItemEnabled(item) {
			continue
		}
		itemType := strings.ToLower(strings.TrimSpace(item.Type))
		if itemType != "security" && itemType != "identity" && itemType != "login" && itemType != "password" {
			continue
		}
		for _, key := range []string{"disable_password_login", "password_login_disabled", "disablePasswordLogin", "passwordLoginDisabled", "no_password_login"} {
			if metadataBoolForMFA(item.Metadata[key]) {
				return true
			}
		}
		for _, key := range []string{"password_login", "enable_password_login", "password_auth", "local_password_login"} {
			if enabled, ok := metadataBoolValue(item.Metadata[key]); ok && !enabled {
				return true
			}
		}
	}
	return false
}

func platformItemEnabled(item model.PlatformItem) bool {
	status := strings.ToLower(strings.TrimSpace(item.Status))
	return status == "" || status == "enabled" || status == "active" || status == "locked"
}

func loginPolicyAction(policy model.PlatformItem) string {
	action := strings.ToLower(strings.TrimSpace(policy.Type))
	if value, ok := policy.Metadata["action"].(string); ok && strings.TrimSpace(value) != "" {
		action = strings.ToLower(strings.TrimSpace(value))
	}
	if action == "" {
		action = "allow"
	}
	return action
}

func loginPolicyMatches(policy model.PlatformItem, username, clientIP string) bool {
	if !accountMatches(policy, username) {
		return false
	}
	values := []string{policy.Host, policy.TargetID, policy.Group}
	for _, key := range []string{"ip", "cidr", "ip_range", "client_ip", "ips"} {
		values = append(values, metadataStrings(policy.Metadata[key])...)
	}
	return ipCriteriaMatches(values, clientIP)
}

func loginLockMatches(lock model.PlatformItem, username, clientIP string) bool {
	if !accountMatches(lock, username) {
		return false
	}
	values := []string{lock.Host}
	values = append(values, metadataStrings(lock.Metadata["client_ip"])...)
	return ipCriteriaMatches(values, clientIP)
}

func accountMatches(item model.PlatformItem, username string) bool {
	candidates := []string{item.Username}
	candidates = append(candidates, metadataStrings(item.Metadata["account"])...)
	candidates = append(candidates, metadataStrings(item.Metadata["username"])...)
	hasCriteria := false
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		hasCriteria = true
		if candidate == "*" || strings.EqualFold(candidate, username) {
			return true
		}
	}
	return !hasCriteria
}

func ipCriteriaMatches(values []string, clientIP string) bool {
	hasCriteria := false
	for _, value := range values {
		for _, item := range splitCriteria(value) {
			hasCriteria = true
			if item == "*" || item == "0.0.0.0/0" || ipMatches(item, clientIP) {
				return true
			}
		}
	}
	return !hasCriteria
}

func ipMatches(pattern, clientIP string) bool {
	pattern = strings.TrimSpace(pattern)
	clientIP = strings.TrimSpace(clientIP)
	if pattern == clientIP {
		return true
	}
	if _, network, err := net.ParseCIDR(pattern); err == nil {
		ip := net.ParseIP(clientIP)
		return ip != nil && network.Contains(ip)
	}
	return false
}

func metadataStrings(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []string:
		return typed
	case []any:
		result := []string{}
		for _, item := range typed {
			if text, ok := item.(string); ok {
				result = append(result, text)
			}
		}
		return result
	default:
		return nil
	}
}

func metadataBoolValue(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		text := strings.ToLower(strings.TrimSpace(typed))
		switch text {
		case "true", "1", "yes", "enabled", "required", "on":
			return true, true
		case "false", "0", "no", "disabled", "off":
			return false, true
		default:
			return false, false
		}
	case float64:
		return typed != 0, true
	case int:
		return typed != 0, true
	case int64:
		return typed != 0, true
	default:
		return false, false
	}
}

func splitCriteria(value string) []string {
	raw := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n'
	})
	result := []string{}
	for _, item := range raw {
		if strings.TrimSpace(item) != "" {
			result = append(result, strings.TrimSpace(item))
		}
	}
	return result
}

func metadataTime(value any) (time.Time, bool) {
	switch typed := value.(type) {
	case time.Time:
		return typed, true
	case string:
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
			parsed, err := time.Parse(layout, typed)
			if err == nil {
				return parsed.UTC(), true
			}
		}
	case float64:
		return time.Unix(int64(typed), 0).UTC(), true
	case int64:
		return time.Unix(typed, 0).UTC(), true
	}
	return time.Time{}, false
}
