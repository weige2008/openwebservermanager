package app

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"openwebservermanager/internal/model"

	goldap "github.com/go-ldap/ldap/v3"
)

const (
	maxCommandFilterPatterns = 128
	maxCommandFilterPattern  = 4096
	maxIntegrationSecret     = 32 << 10
)

func preparePlatformItemCreateRequest(collection string, req *model.PlatformItemRequest) error {
	switch collection {
	case "command_filters":
		if req.Protocol == "" {
			req.Protocol = model.ProtocolSSH
		}
	case "scheduled_tasks":
		if req.Metadata == nil {
			req.Metadata = map[string]any{}
		}
		normalizeScheduledTaskMutation(req)
	case "system_settings":
		switch strings.ToLower(strings.TrimSpace(req.Type)) {
		case "integration":
			if err := validateIntegrationMetadataInput(req.Metadata); err != nil {
				return err
			}
		case "identity":
			if err := validateIdentityMetadataInput(req.Metadata); err != nil {
				return err
			}
		}
	}
	return validatePlatformItemRequest(collection, *req)
}

func preparePlatformItemUpdateRequest(collection string, existing model.PlatformItem, req *model.PlatformItemRequest) error {
	if collection == "scheduled_tasks" {
		normalizeScheduledTaskMutation(req)
	}
	item := platformItemAfterUpdate(existing, *req)
	if collection == "system_settings" && req.Metadata != nil {
		switch strings.ToLower(strings.TrimSpace(item.Type)) {
		case "integration":
			if err := validateIntegrationMetadataInput(req.Metadata); err != nil {
				return err
			}
		case "identity":
			if err := validateIdentityMetadataInput(req.Metadata); err != nil {
				return err
			}
		}
	}
	switch collection {
	case "command_filters":
		return validateCommandFilterItem(item)
	case "scheduled_tasks":
		return validateScheduledTaskItem(item)
	case "system_settings":
		return validateSystemSettingItemWithExisting(item, existing.Metadata)
	default:
		return validatePlatformItemRequest(collection, *req)
	}
}

func validatePlatformItemRequest(collection string, req model.PlatformItemRequest) error {
	switch collection {
	case "storages":
		return validateStorageRequest(req)
	case "command_filters":
		return validateCommandFilterItem(model.PlatformItem{
			Name:        strings.TrimSpace(req.Name),
			Type:        strings.TrimSpace(req.Type),
			Status:      strings.TrimSpace(req.Status),
			Protocol:    req.Protocol,
			Host:        strings.TrimSpace(req.Host),
			Group:       strings.TrimSpace(req.Group),
			Description: strings.TrimSpace(req.Description),
			Metadata:    req.Metadata,
		})
	case "scheduled_tasks":
		return validateScheduledTaskItem(model.PlatformItem{
			Name:     strings.TrimSpace(req.Name),
			Type:     strings.TrimSpace(req.Type),
			Status:   strings.TrimSpace(req.Status),
			Metadata: req.Metadata,
		})
	case "system_settings":
		return validateSystemSettingItem(model.PlatformItem{
			Name:     strings.TrimSpace(req.Name),
			Type:     strings.TrimSpace(req.Type),
			Status:   strings.TrimSpace(req.Status),
			Host:     strings.TrimSpace(req.Host),
			Port:     req.Port,
			Username: strings.TrimSpace(req.Username),
			Metadata: req.Metadata,
		})
	default:
		return nil
	}
}

func validateStorageRequest(req model.PlatformItemRequest) error {
	if req.Metadata == nil {
		return nil
	}
	if value, exists := req.Metadata["limit_bytes"]; exists && !metadataValueEmpty(value) {
		if _, ok := parseStorageByteSize(value); !ok {
			return fmt.Errorf("storage quota must be a positive byte value such as 1073741824 or 10GB")
		}
	}
	return nil
}

func platformItemAfterUpdate(existing model.PlatformItem, req model.PlatformItemRequest) model.PlatformItem {
	item := existing
	if strings.TrimSpace(req.Name) != "" {
		item.Name = strings.TrimSpace(req.Name)
	}
	if req.Type != "" {
		item.Type = strings.TrimSpace(req.Type)
	}
	if req.Status != "" {
		item.Status = strings.TrimSpace(req.Status)
	}
	if req.Protocol != "" {
		item.Protocol = req.Protocol
	}
	if req.Host != "" {
		item.Host = strings.TrimSpace(req.Host)
	}
	if req.Group != "" {
		item.Group = strings.TrimSpace(req.Group)
	}
	if req.Description != "" {
		item.Description = strings.TrimSpace(req.Description)
	}
	if req.Metadata != nil {
		item.Metadata = req.Metadata
	}
	return item
}

func normalizeScheduledTaskMutation(req *model.PlatformItemRequest) {
	if req.Type != "" {
		req.Type = normalizeScheduledTaskType(req.Type)
	}
	if req.Metadata == nil {
		return
	}
	req.Metadata = cloneMetadata(req.Metadata)
	if !scheduledTaskMetadataHasSchedule(req.Metadata) {
		if _, exists := req.Metadata["manual_only"]; !exists {
			req.Metadata["manual_only"] = true
		}
	}
}

func validateScheduledTaskItem(item model.PlatformItem) error {
	if strings.TrimSpace(item.Name) == "" {
		return errors.New("scheduled task name is required")
	}
	taskType := normalizeScheduledTaskType(item.Type)
	switch taskType {
	case "backup", "log-cleanup", "asset-status", "certificate-renewal":
	default:
		return fmt.Errorf("scheduled task type must be backup, log-cleanup, asset-status, or certificate-renewal, got %q", taskType)
	}
	status := strings.ToLower(strings.TrimSpace(item.Status))
	if status != "" {
		switch status {
		case "enabled", "active", "disabled", "inactive":
		default:
			return fmt.Errorf("scheduled task status must be enabled or disabled, got %q", status)
		}
	}
	metadata := item.Metadata
	intervalKeys := scheduledTaskNonEmptyKeys(metadata,
		"interval_ms", "run_every_ms", "every_ms",
		"interval_seconds", "run_every_seconds", "every_seconds",
		"interval_minutes", "run_every_minutes", "every_minutes",
		"interval", "run_every", "every",
	)
	if len(intervalKeys) > 1 {
		return fmt.Errorf("scheduled task must use only one interval field, got %s", strings.Join(intervalKeys, ", "))
	}
	if len(intervalKeys) == 1 {
		duration, ok := scheduledTaskInterval(map[string]any{intervalKeys[0]: metadata[intervalKeys[0]]})
		if !ok {
			return fmt.Errorf("scheduled task %s must be a positive interval", intervalKeys[0])
		}
		if duration > 365*24*time.Hour {
			return errors.New("scheduled task interval must not exceed 365 days")
		}
		if number, ok := metadata[intervalKeys[0]].(float64); ok && number != math.Trunc(number) {
			return fmt.Errorf("scheduled task %s must be an integer", intervalKeys[0])
		}
	}
	cronKeys := scheduledTaskNonEmptyKeys(metadata, "cron", "cron_expression", "cronExpression")
	if len(cronKeys) > 1 {
		return fmt.Errorf("scheduled task must use only one cron field, got %s", strings.Join(cronKeys, ", "))
	}
	if len(cronKeys) == 1 {
		cron := strings.TrimSpace(firstMetadataString(metadata, cronKeys[0]))
		if _, ok := nextCronRun(cron, time.Date(2023, 12, 31, 23, 59, 58, 0, time.UTC)); !ok {
			return fmt.Errorf("scheduled task cron expression is invalid or cannot run: %q", cron)
		}
	}
	if len(intervalKeys) > 0 && len(cronKeys) > 0 {
		return errors.New("scheduled task interval and cron expression cannot be configured together")
	}
	for _, key := range []string{"next_run_at"} {
		if value, exists := metadata[key]; exists && !metadataValueEmpty(value) {
			if _, ok := metadataTime(value); !ok {
				return fmt.Errorf("scheduled task %s must be a valid RFC3339 timestamp", key)
			}
		}
	}
	runOnStart, err := scheduledTaskBooleanMetadata(metadata, "run_on_start")
	if err != nil {
		return err
	}
	manualOnly, err := scheduledTaskBooleanMetadata(metadata, "manual_only")
	if err != nil {
		return err
	}
	hasScheduledRun := len(intervalKeys) > 0 || len(cronKeys) > 0 || runOnStart || scheduledTaskMetadataTimePresent(metadata, "next_run_at")
	if manualOnly && hasScheduledRun {
		return errors.New("manual-only scheduled task cannot define interval, cron, startup, or next-run scheduling")
	}
	if !manualOnly && !hasScheduledRun {
		return errors.New("scheduled task must define a schedule or set manual_only to true")
	}
	if err := validateScheduledTaskTypeMetadata(taskType, metadata); err != nil {
		return err
	}
	return nil
}

func scheduledTaskMetadataHasSchedule(metadata map[string]any) bool {
	if len(scheduledTaskNonEmptyKeys(metadata,
		"interval_ms", "run_every_ms", "every_ms",
		"interval_seconds", "run_every_seconds", "every_seconds",
		"interval_minutes", "run_every_minutes", "every_minutes",
		"interval", "run_every", "every",
		"cron", "cron_expression", "cronExpression", "next_run_at",
	)) > 0 {
		return true
	}
	value, ok := metadataBoolValue(metadata["run_on_start"])
	return ok && value
}

func scheduledTaskNonEmptyKeys(metadata map[string]any, keys ...string) []string {
	result := []string{}
	for _, key := range keys {
		if value, exists := metadata[key]; exists && !metadataValueEmpty(value) {
			result = append(result, key)
		}
	}
	return result
}

func scheduledTaskBooleanMetadata(metadata map[string]any, key string) (bool, error) {
	value, exists := metadata[key]
	if !exists || metadataValueEmpty(value) {
		return false, nil
	}
	parsed, ok := metadataBoolValue(value)
	if !ok {
		return false, fmt.Errorf("scheduled task %s must be a boolean", key)
	}
	return parsed, nil
}

func scheduledTaskMetadataTimePresent(metadata map[string]any, key string) bool {
	value, exists := metadata[key]
	return exists && !metadataValueEmpty(value)
}

func validateScheduledTaskTypeMetadata(taskType string, metadata map[string]any) error {
	switch taskType {
	case "asset-status":
		return validateScheduledTaskInteger(metadata, "timeout_ms", 100, 30000)
	case "backup":
		return validateScheduledTaskInteger(metadata, "retention_days", 0, 36500)
	case "log-cleanup":
		return validateRetentionDaysMetadata(metadata, "scheduled task")
	case "certificate-renewal":
		if err := validateScheduledTaskInteger(metadata, "renew_before_days", 0, 3650); err != nil {
			return err
		}
		return validateScheduledTaskInteger(metadata, "validity_days", 1, 3650)
	default:
		return nil
	}
}

var retentionDayMetadataKeys = []string{
	"retention_days",
	"days",
	"connection_sessions_days",
	"connection_session_days",
	"sessions_days",
	"session_days",
	"offline_sessions_days",
	"offline_session_days",
	"recordings_days",
	"recording_days",
	"login_logs_days",
	"login_days",
	"scheduled_task_logs_days",
	"scheduled_tasks_days",
	"scheduled_task_days",
	"operation_logs_days",
	"operation_days",
	"file_logs_days",
	"file_days",
	"access_logs_days",
	"access_days",
	"sql_logs_days",
	"sql_days",
	"exec_command_logs_days",
	"exec_command_days",
}

func validateSystemSettingItem(item model.PlatformItem) error {
	return validateSystemSettingItemWithExisting(item, nil)
}

func validateSystemSettingItemWithExisting(item model.PlatformItem, existingMetadata map[string]any) error {
	settingType := strings.ToLower(strings.TrimSpace(item.Type))
	status := strings.ToLower(strings.TrimSpace(item.Status))
	if status != "" {
		switch status {
		case "enabled", "active", "disabled", "inactive":
		default:
			return fmt.Errorf("%s setting status must be enabled or disabled, got %q", firstNonEmpty(settingType, "system"), status)
		}
	}
	switch settingType {
	case "retention":
		return validateRetentionDaysMetadata(item.Metadata, "retention setting")
	case "integration":
		if err := validateSMTPIntegrationItem(item); err != nil {
			return err
		}
		return validateLLMIntegrationItem(item)
	case "identity":
		return validateIdentitySettingItem(item, existingMetadata)
	default:
		return nil
	}
}

var ldapTopLevelMetadataTypes = map[string]string{
	"ldap_enabled":                  "boolean",
	"ldap_login_enabled":            "boolean",
	"external_ldap_enabled":         "boolean",
	"ldap_provider_id":              "string",
	"ldap_provider_name":            "string",
	"ldap_url":                      "string",
	"ldap_host":                     "string",
	"ldap_port":                     "integer",
	"ldap_use_tls":                  "boolean",
	"ldap_bind_dn":                  "string",
	"ldap_bind_password":            "secret",
	"plain_ldap_bind_password":      "secret",
	"ldap_bind_password_clear":      "boolean",
	"clear_ldap_bind_password":      "boolean",
	"ldap_bind_password_encrypted":  "string",
	"ldap_bind_password_set":        "boolean",
	"ldap_bind_password_updated_at": "string",
	"ldap_base_dn":                  "string",
	"ldap_user_filter":              "string",
	"ldap_user_dn_template":         "string",
	"ldap_username_attribute":       "string",
	"ldap_display_name_attribute":   "string",
	"ldap_email_attribute":          "string",
	"ldap_role":                     "string",
	"ldap_auto_create":              "boolean",
	"ldap_start_tls":                "boolean",
	"ldap_insecure_skip_verify":     "boolean",
	"ldap_server_name":              "string",
	"ldap_providers":                "object_list",
	"external_ldap_providers":       "object_list",
}

var ldapProviderMetadataTypes = map[string]string{
	"id":                            "string",
	"provider_id":                   "string",
	"ldap_provider_id":              "string",
	"name":                          "string",
	"label":                         "string",
	"provider_name":                 "string",
	"ldap_provider_name":            "string",
	"enabled":                       "boolean",
	"url":                           "string",
	"ldap_url":                      "string",
	"host":                          "string",
	"ldap_host":                     "string",
	"port":                          "integer",
	"ldap_port":                     "integer",
	"use_tls":                       "boolean",
	"ldap_use_tls":                  "boolean",
	"bind_dn":                       "string",
	"ldap_bind_dn":                  "string",
	"manager_dn":                    "string",
	"bind_password":                 "secret",
	"ldap_bind_password":            "secret",
	"plain_ldap_bind_password":      "secret",
	"ldap_bind_password_clear":      "boolean",
	"clear_ldap_bind_password":      "boolean",
	"bind_password_clear":           "boolean",
	"clear_bind_password":           "boolean",
	"ldap_bind_password_encrypted":  "string",
	"bind_password_encrypted":       "string",
	"ldap_bind_password_set":        "boolean",
	"ldap_bind_password_updated_at": "string",
	"base_dn":                       "string",
	"ldap_base_dn":                  "string",
	"search_base":                   "string",
	"user_base_dn":                  "string",
	"user_filter":                   "string",
	"ldap_user_filter":              "string",
	"filter":                        "string",
	"user_dn_template":              "string",
	"ldap_user_dn_template":         "string",
	"username_attribute":            "string",
	"ldap_username_attribute":       "string",
	"display_name_attribute":        "string",
	"ldap_display_name_attribute":   "string",
	"email_attribute":               "string",
	"ldap_email_attribute":          "string",
	"role":                          "string",
	"default_role":                  "string",
	"ldap_role":                     "string",
	"auto_create":                   "boolean",
	"ldap_auto_create":              "boolean",
	"start_tls":                     "boolean",
	"ldap_start_tls":                "boolean",
	"insecure_skip_verify":          "boolean",
	"ldap_insecure_skip_verify":     "boolean",
	"server_name":                   "string",
	"tls_server_name":               "string",
	"ldap_server_name":              "string",
}

var weComTopLevelMetadataTypes = map[string]string{
	"wecom_enabled":                            "boolean",
	"wecom_login_enabled":                      "boolean",
	"enterprise_wechat_enabled":                "boolean",
	"wecom_provider_id":                        "string",
	"enterprise_wechat_provider_id":            "string",
	"wecom_provider_name":                      "string",
	"enterprise_wechat_provider_name":          "string",
	"wecom_corp_id":                            "string",
	"enterprise_wechat_corp_id":                "string",
	"wecom_agent_id":                           "string",
	"enterprise_wechat_agent_id":               "string",
	"wecom_agent_secret":                       "secret",
	"enterprise_wechat_agent_secret":           "secret",
	"wecom_agent_secret_clear":                 "boolean",
	"clear_wecom_agent_secret":                 "boolean",
	"wecom_agent_secret_encrypted":             "string",
	"enterprise_wechat_agent_secret_encrypted": "string",
	"wecom_agent_secret_set":                   "boolean",
	"wecom_agent_secret_updated_at":            "string",
	"wecom_authorize_endpoint":                 "string",
	"wecom_token_endpoint":                     "string",
	"wecom_userinfo_endpoint":                  "string",
	"wecom_user_detail_endpoint":               "string",
	"wecom_scope":                              "string",
	"wecom_role":                               "string",
	"wecom_auto_create":                        "boolean",
	"wecom_providers":                          "object_list",
	"enterprise_wechat_providers":              "object_list",
}

var weComProviderMetadataTypes = map[string]string{
	"id":                              "string",
	"provider_id":                     "string",
	"wecom_provider_id":               "string",
	"enterprise_wechat_provider_id":   "string",
	"name":                            "string",
	"label":                           "string",
	"provider_name":                   "string",
	"wecom_provider_name":             "string",
	"enterprise_wechat_provider_name": "string",
	"enabled":                         "boolean",
	"corp_id":                         "string",
	"corpid":                          "string",
	"wecom_corp_id":                   "string",
	"enterprise_wechat_corp_id":       "string",
	"agent_id":                        "string",
	"agentid":                         "string",
	"wecom_agent_id":                  "string",
	"enterprise_wechat_agent_id":      "string",
	"agent_secret":                    "secret",
	"wecom_agent_secret":              "secret",
	"enterprise_wechat_agent_secret":  "secret",
	"corp_secret":                     "secret",
	"corpsecret":                      "secret",
	"wecom_agent_secret_clear":        "boolean",
	"clear_wecom_agent_secret":        "boolean",
	"agent_secret_clear":              "boolean",
	"clear_agent_secret":              "boolean",
	"wecom_agent_secret_encrypted":    "string",
	"enterprise_wechat_agent_secret_encrypted": "string",
	"agent_secret_encrypted":                   "string",
	"wecom_agent_secret_set":                   "boolean",
	"wecom_agent_secret_updated_at":            "string",
	"authorize_endpoint":                       "string",
	"authorization_endpoint":                   "string",
	"wecom_authorize_endpoint":                 "string",
	"token_endpoint":                           "string",
	"wecom_token_endpoint":                     "string",
	"userinfo_endpoint":                        "string",
	"user_info_endpoint":                       "string",
	"wecom_userinfo_endpoint":                  "string",
	"user_detail_endpoint":                     "string",
	"user_endpoint":                            "string",
	"wecom_user_detail_endpoint":               "string",
	"scope":                                    "string",
	"wecom_scope":                              "string",
	"role":                                     "string",
	"default_role":                             "string",
	"wecom_role":                               "string",
	"auto_create":                              "boolean",
	"wecom_auto_create":                        "boolean",
}

var oidcTopLevelMetadataTypes = map[string]string{
	"oidc_enabled":                          "boolean",
	"oidc_login_enabled":                    "boolean",
	"external_oidc_enabled":                 "boolean",
	"oidc_provider_id":                      "string",
	"oidc_provider_name":                    "string",
	"oidc_issuer":                           "string",
	"oidc_issuer_url":                       "string",
	"oidc_authorization_endpoint":           "string",
	"oidc_token_endpoint":                   "string",
	"oidc_userinfo_endpoint":                "string",
	"oidc_jwks_uri":                         "string",
	"oidc_jwks_endpoint":                    "string",
	"oidc_client_id":                        "string",
	"oidc_client_secret":                    "secret",
	"external_oidc_client_secret":           "secret",
	"oidc_client_secret_clear":              "boolean",
	"clear_oidc_client_secret":              "boolean",
	"oidc_client_secret_encrypted":          "string",
	"external_oidc_client_secret_encrypted": "string",
	"oidc_client_secret_set":                "boolean",
	"oidc_client_secret_updated_at":         "string",
	"oidc_scopes":                           "string_list",
	"oidc_role":                             "string",
	"oidc_auto_create":                      "boolean",
	"oidc_token_endpoint_auth_method":       "string",
	"oidc_auth_method":                      "string",
	"oidc_require_id_token":                 "boolean",
	"oidc_verify_id_token":                  "boolean",
	"oidc_providers":                        "object_list",
	"external_oidc_providers":               "object_list",
}

var oidcProviderMetadataTypes = map[string]string{
	"id":                                    "string",
	"provider_id":                           "string",
	"oidc_provider_id":                      "string",
	"name":                                  "string",
	"label":                                 "string",
	"provider_name":                         "string",
	"oidc_provider_name":                    "string",
	"enabled":                               "boolean",
	"issuer":                                "string",
	"issuer_url":                            "string",
	"oidc_issuer":                           "string",
	"oidc_issuer_url":                       "string",
	"authorization_endpoint":                "string",
	"authorize_endpoint":                    "string",
	"authorization_url":                     "string",
	"oidc_authorization_endpoint":           "string",
	"token_endpoint":                        "string",
	"token_url":                             "string",
	"oidc_token_endpoint":                   "string",
	"userinfo_endpoint":                     "string",
	"user_info_endpoint":                    "string",
	"userinfo_url":                          "string",
	"oidc_userinfo_endpoint":                "string",
	"jwks_uri":                              "string",
	"jwks_endpoint":                         "string",
	"jwks_url":                              "string",
	"oidc_jwks_uri":                         "string",
	"oidc_jwks_endpoint":                    "string",
	"client_id":                             "string",
	"oidc_client_id":                        "string",
	"client_secret":                         "secret",
	"oidc_client_secret":                    "secret",
	"external_oidc_client_secret":           "secret",
	"oidc_client_secret_clear":              "boolean",
	"clear_oidc_client_secret":              "boolean",
	"client_secret_clear":                   "boolean",
	"clear_client_secret":                   "boolean",
	"oidc_client_secret_encrypted":          "string",
	"client_secret_encrypted":               "string",
	"external_oidc_client_secret_encrypted": "string",
	"oidc_client_secret_set":                "boolean",
	"oidc_client_secret_updated_at":         "string",
	"scopes":                                "string_list",
	"scope":                                 "string_list",
	"oidc_scopes":                           "string_list",
	"role":                                  "string",
	"default_role":                          "string",
	"oidc_role":                             "string",
	"auto_create":                           "boolean",
	"oidc_auto_create":                      "boolean",
	"token_endpoint_auth_method":            "string",
	"oidc_token_endpoint_auth_method":       "string",
	"client_auth_method":                    "string",
	"oidc_auth_method":                      "string",
	"require_id_token":                      "boolean",
	"oidc_require_id_token":                 "boolean",
	"verify_id_token":                       "boolean",
	"oidc_verify_id_token":                  "boolean",
}

var ldapAttributeNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._;-]{0,127}$`)
var ldapRolePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

func validateIdentityMetadataInput(metadata map[string]any) error {
	if err := validateLDAPMetadataInput(metadata); err != nil {
		return err
	}
	if err := validateOIDCMetadataInput(metadata); err != nil {
		return err
	}
	return validateWeComMetadataInput(metadata)
}

func validateLDAPMetadataInput(metadata map[string]any) error {
	for key, value := range metadata {
		normalized := strings.ToLower(strings.TrimSpace(key))
		valueType, known := ldapTopLevelMetadataTypes[normalized]
		if !known {
			if strings.HasPrefix(normalized, "ldap_") || strings.HasPrefix(normalized, "external_ldap_") || strings.HasPrefix(normalized, "plain_ldap_") {
				return fmt.Errorf("identity setting field %q is not supported", key)
			}
			continue
		}
		if key != normalized {
			return fmt.Errorf("identity setting field %q must use the canonical name %q", key, normalized)
		}
		if err := validateLDAPMetadataValue(key, value, valueType); err != nil {
			return err
		}
		if valueType != "object_list" || value == nil {
			continue
		}
		objects, _ := strictMetadataObjectList(value)
		for index, object := range objects {
			context := fmt.Sprintf("identity setting %s[%d]", key, index)
			for childKey, childValue := range object {
				normalizedChild := strings.ToLower(strings.TrimSpace(childKey))
				childType, ok := ldapProviderMetadataTypes[normalizedChild]
				if !ok {
					return fmt.Errorf("%s field %q is not supported", context, childKey)
				}
				if childKey != normalizedChild {
					return fmt.Errorf("%s field %q must use the canonical name %q", context, childKey, normalizedChild)
				}
				if err := validateLDAPMetadataValue(context+"."+childKey, childValue, childType); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateWeComMetadataInput(metadata map[string]any) error {
	for key, value := range metadata {
		normalized := strings.ToLower(strings.TrimSpace(key))
		valueType, known := weComTopLevelMetadataTypes[normalized]
		if !known {
			if strings.HasPrefix(normalized, "wecom_") || strings.HasPrefix(normalized, "enterprise_wechat_") {
				return fmt.Errorf("identity setting field %q is not supported", key)
			}
			continue
		}
		if key != normalized {
			return fmt.Errorf("identity setting field %q must use the canonical name %q", key, normalized)
		}
		if err := validateLDAPMetadataValue(key, value, valueType); err != nil {
			return err
		}
		if valueType != "object_list" || value == nil {
			continue
		}
		objects, _ := strictMetadataObjectList(value)
		for index, object := range objects {
			context := fmt.Sprintf("identity setting %s[%d]", key, index)
			for childKey, childValue := range object {
				normalizedChild := strings.ToLower(strings.TrimSpace(childKey))
				childType, ok := weComProviderMetadataTypes[normalizedChild]
				if !ok {
					return fmt.Errorf("%s field %q is not supported", context, childKey)
				}
				if childKey != normalizedChild {
					return fmt.Errorf("%s field %q must use the canonical name %q", context, childKey, normalizedChild)
				}
				if err := validateLDAPMetadataValue(context+"."+childKey, childValue, childType); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateOIDCMetadataInput(metadata map[string]any) error {
	for key, value := range metadata {
		normalized := strings.ToLower(strings.TrimSpace(key))
		valueType, known := oidcTopLevelMetadataTypes[normalized]
		if !known {
			if strings.HasPrefix(normalized, "oidc_") || strings.HasPrefix(normalized, "external_oidc_") {
				return fmt.Errorf("identity setting field %q is not supported", key)
			}
			continue
		}
		if key != normalized {
			return fmt.Errorf("identity setting field %q must use the canonical name %q", key, normalized)
		}
		if err := validateLDAPMetadataValue(key, value, valueType); err != nil {
			return err
		}
		if valueType != "object_list" || value == nil {
			continue
		}
		objects, _ := strictMetadataObjectList(value)
		for index, object := range objects {
			context := fmt.Sprintf("identity setting %s[%d]", key, index)
			for childKey, childValue := range object {
				normalizedChild := strings.ToLower(strings.TrimSpace(childKey))
				childType, ok := oidcProviderMetadataTypes[normalizedChild]
				if !ok {
					return fmt.Errorf("%s field %q is not supported", context, childKey)
				}
				if childKey != normalizedChild {
					return fmt.Errorf("%s field %q must use the canonical name %q", context, childKey, normalizedChild)
				}
				if err := validateLDAPMetadataValue(context+"."+childKey, childValue, childType); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateLDAPMetadataValue(key string, value any, valueType string) error {
	if value == nil {
		return nil
	}
	switch valueType {
	case "string", "secret":
		text, ok := value.(string)
		if !ok {
			return fmt.Errorf("%s must be a string", key)
		}
		limit := 64 << 10
		if valueType == "secret" {
			limit = maxIntegrationSecret
		}
		if len(text) > limit {
			return fmt.Errorf("%s must not exceed %d bytes", key, limit)
		}
	case "integer":
		port, ok := strictMetadataInteger(value)
		if !ok || port < 1 || port > 65535 {
			return fmt.Errorf("%s must be an integer between 1 and 65535", key)
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("%s must be a boolean", key)
		}
	case "object_list":
		if _, ok := strictMetadataObjectList(value); !ok {
			return fmt.Errorf("%s must be an array of objects", key)
		}
	case "string_list":
		if _, ok := value.(string); ok {
			return nil
		}
		if _, ok := strictMetadataStringList(value); !ok {
			return fmt.Errorf("%s must be a string or an array of strings", key)
		}
	}
	return nil
}

func strictMetadataObjectList(value any) ([]map[string]any, bool) {
	switch typed := value.(type) {
	case []map[string]any:
		return typed, true
	case []any:
		result := make([]map[string]any, 0, len(typed))
		for _, entry := range typed {
			object, ok := entry.(map[string]any)
			if !ok {
				return nil, false
			}
			result = append(result, object)
		}
		return result, true
	default:
		return nil, false
	}
}

func validateIdentitySettingItem(item model.PlatformItem, existingMetadata map[string]any) error {
	if item.Metadata == nil {
		return nil
	}
	if err := validateIdentityMetadataInput(item.Metadata); err != nil {
		return err
	}
	providerIDs := map[string]bool{}
	for _, key := range []string{"ldap_providers", "external_ldap_providers"} {
		objects, _ := strictMetadataObjectList(item.Metadata[key])
		for index, object := range objects {
			id, enabled, err := validateLDAPProviderObject(object, false, fmt.Sprintf("identity setting %s[%d]", key, index))
			if err != nil {
				return err
			}
			if enabled && id != "" {
				if providerIDs[id] {
					return fmt.Errorf("identity setting LDAP provider id %q is duplicated", id)
				}
				providerIDs[id] = true
			}
		}
	}
	if identityHasLDAPMetadata(item.Metadata) {
		id, enabled, err := validateLDAPProviderObject(item.Metadata, true, "identity setting LDAP provider")
		if err != nil {
			return err
		}
		if enabled && id != "" && providerIDs[id] {
			return fmt.Errorf("identity setting LDAP provider id %q is duplicated", id)
		}
	}
	if err := validateOIDCSettingMetadata(item.Metadata, existingMetadata); err != nil {
		return err
	}
	return validateWeComSettingMetadata(item.Metadata, existingMetadata)
}

func identityHasLDAPMetadata(metadata map[string]any) bool {
	for key := range metadata {
		normalized := strings.ToLower(strings.TrimSpace(key))
		if strings.HasPrefix(normalized, "ldap_") || strings.HasPrefix(normalized, "external_ldap_") || strings.HasPrefix(normalized, "plain_ldap_") {
			return true
		}
	}
	return false
}

func validateOIDCSettingMetadata(metadata, existingMetadata map[string]any) error {
	providerIDs := map[string]bool{}
	for _, key := range []string{"oidc_providers", "external_oidc_providers"} {
		objects, _ := strictMetadataObjectList(metadata[key])
		existingObjects, _ := strictMetadataObjectList(existingMetadata[key])
		for index, object := range objects {
			existingObject := matchingOIDCProviderObject(object, existingObjects, index)
			id, enabled, err := validateOIDCProviderObject(object, existingObject, false, fmt.Sprintf("identity setting %s[%d]", key, index))
			if err != nil {
				return err
			}
			if enabled && id != "" {
				if providerIDs[id] {
					return fmt.Errorf("identity setting OIDC provider id %q is duplicated", id)
				}
				providerIDs[id] = true
			}
		}
	}
	if !identityHasFlatOIDCMetadata(metadata) {
		return nil
	}
	existingObject := matchingFlatOIDCProviderObject(metadata, existingMetadata)
	id, enabled, err := validateOIDCProviderObject(metadata, existingObject, true, "identity setting OIDC provider")
	if err != nil {
		return err
	}
	if enabled && id != "" && providerIDs[id] {
		return fmt.Errorf("identity setting OIDC provider id %q is duplicated", id)
	}
	return nil
}

func identityHasOIDCMetadata(metadata map[string]any) bool {
	for key := range metadata {
		normalized := strings.ToLower(strings.TrimSpace(key))
		if strings.HasPrefix(normalized, "oidc_") || strings.HasPrefix(normalized, "external_oidc_") {
			return true
		}
	}
	return false
}

func identityHasFlatOIDCMetadata(metadata map[string]any) bool {
	for key := range metadata {
		normalized := strings.ToLower(strings.TrimSpace(key))
		if normalized == "oidc_providers" || normalized == "external_oidc_providers" {
			continue
		}
		if strings.HasPrefix(normalized, "oidc_") || strings.HasPrefix(normalized, "external_oidc_") {
			return true
		}
	}
	return false
}

func validateOIDCProviderObject(object, existing map[string]any, requireExplicitEnable bool, context string) (string, bool, error) {
	enabled := !requireExplicitEnable
	if requireExplicitEnable {
		enabled, _ = metadataBoolValue(object["oidc_enabled"])
		if _, exists := object["oidc_enabled"]; !exists {
			enabled, _ = metadataBoolValue(object["oidc_login_enabled"])
			if _, legacyExists := object["oidc_login_enabled"]; !legacyExists {
				enabled, _ = metadataBoolValue(object["external_oidc_enabled"])
			}
		}
	} else if value, exists := object["enabled"]; exists {
		enabled, _ = metadataBoolValue(value)
	}
	provider := externalOIDCProviderShapeFromObject(object)
	secretConfigured := oidcProviderSecretConfigured(object, existing)
	if err := validateExternalOIDCProviderShape(provider, enabled, secretConfigured); err != nil {
		return provider.ID, enabled, fmt.Errorf("%s: %w", context, err)
	}
	return provider.ID, enabled, nil
}

func matchingFlatOIDCProviderObject(incoming, existing map[string]any) map[string]any {
	if existing == nil || !identityHasOIDCMetadata(existing) {
		return nil
	}
	incomingID := externalOIDCProviderShapeFromObject(incoming).ID
	existingID := externalOIDCProviderShapeFromObject(existing).ID
	if incomingID != "" && existingID != "" && incomingID != existingID {
		return nil
	}
	return existing
}

func matchingOIDCProviderObject(incoming map[string]any, existing []map[string]any, index int) map[string]any {
	incomingID := externalOIDCProviderShapeFromObject(incoming).ID
	if incomingID != "" {
		for _, candidate := range existing {
			if externalOIDCProviderShapeFromObject(candidate).ID == incomingID {
				return candidate
			}
		}
		return nil
	}
	if index >= 0 && index < len(existing) {
		return existing[index]
	}
	return nil
}

func oidcProviderSecretConfigured(object, existing map[string]any) bool {
	if clearRequested, _ := metadataBoolByKeys(object, "oidc_client_secret_clear", "clear_oidc_client_secret", "client_secret_clear", "clear_client_secret"); clearRequested {
		return false
	}
	if firstMetadataString(object, "client_secret", "oidc_client_secret", "external_oidc_client_secret") != "" {
		return true
	}
	if existing == nil {
		return false
	}
	return firstMetadataString(existing,
		"client_secret",
		"oidc_client_secret",
		"external_oidc_client_secret",
		"oidc_client_secret_encrypted",
		"client_secret_encrypted",
		"external_oidc_client_secret_encrypted",
	) != ""
}

func validateWeComSettingMetadata(metadata, existingMetadata map[string]any) error {
	providerIDs := map[string]bool{}
	for _, key := range []string{"wecom_providers", "enterprise_wechat_providers"} {
		objects, _ := strictMetadataObjectList(metadata[key])
		existingObjects, _ := strictMetadataObjectList(existingMetadata[key])
		for index, object := range objects {
			existingObject := matchingWeComProviderObject(object, existingObjects, index)
			id, enabled, err := validateWeComProviderObject(object, existingObject, false, fmt.Sprintf("identity setting %s[%d]", key, index))
			if err != nil {
				return err
			}
			if enabled && id != "" {
				if providerIDs[id] {
					return fmt.Errorf("identity setting Enterprise WeChat provider id %q is duplicated", id)
				}
				providerIDs[id] = true
			}
		}
	}
	if !identityHasFlatWeComMetadata(metadata) {
		return nil
	}
	existingObject := matchingFlatWeComProviderObject(metadata, existingMetadata)
	id, enabled, err := validateWeComProviderObject(metadata, existingObject, true, "identity setting Enterprise WeChat provider")
	if err != nil {
		return err
	}
	if enabled && id != "" && providerIDs[id] {
		return fmt.Errorf("identity setting Enterprise WeChat provider id %q is duplicated", id)
	}
	return nil
}

func identityHasWeComMetadata(metadata map[string]any) bool {
	for key := range metadata {
		normalized := strings.ToLower(strings.TrimSpace(key))
		if strings.HasPrefix(normalized, "wecom_") || strings.HasPrefix(normalized, "enterprise_wechat_") {
			return true
		}
	}
	return false
}

func identityHasFlatWeComMetadata(metadata map[string]any) bool {
	for key := range metadata {
		normalized := strings.ToLower(strings.TrimSpace(key))
		if normalized == "wecom_providers" || normalized == "enterprise_wechat_providers" {
			continue
		}
		if strings.HasPrefix(normalized, "wecom_") || strings.HasPrefix(normalized, "enterprise_wechat_") {
			return true
		}
	}
	return false
}

func validateWeComProviderObject(object, existing map[string]any, requireExplicitEnable bool, context string) (string, bool, error) {
	enabled := !requireExplicitEnable
	if requireExplicitEnable {
		enabled, _ = metadataBoolValue(object["wecom_enabled"])
		if _, exists := object["wecom_enabled"]; !exists {
			enabled, _ = metadataBoolValue(object["wecom_login_enabled"])
			if _, legacyExists := object["wecom_login_enabled"]; !legacyExists {
				enabled, _ = metadataBoolValue(object["enterprise_wechat_enabled"])
			}
		}
	} else if value, exists := object["enabled"]; exists {
		enabled, _ = metadataBoolValue(value)
	}
	provider := externalWeComProviderShapeFromObject(object)
	secretConfigured := weComProviderSecretConfigured(object, existing)
	if err := validateExternalWeComProviderShape(provider, enabled, secretConfigured); err != nil {
		return provider.ID, enabled, fmt.Errorf("%s: %w", context, err)
	}
	return provider.ID, enabled, nil
}

func matchingFlatWeComProviderObject(incoming, existing map[string]any) map[string]any {
	if existing == nil || !identityHasWeComMetadata(existing) {
		return nil
	}
	incomingID := externalWeComProviderShapeFromObject(incoming).ID
	existingID := externalWeComProviderShapeFromObject(existing).ID
	if incomingID != "" && existingID != "" && incomingID != existingID {
		return nil
	}
	return existing
}

func matchingWeComProviderObject(incoming map[string]any, existing []map[string]any, index int) map[string]any {
	incomingID := externalWeComProviderShapeFromObject(incoming).ID
	if incomingID != "" {
		for _, candidate := range existing {
			if externalWeComProviderShapeFromObject(candidate).ID == incomingID {
				return candidate
			}
		}
		return nil
	}
	if index >= 0 && index < len(existing) {
		return existing[index]
	}
	return nil
}

func weComProviderSecretConfigured(object, existing map[string]any) bool {
	if clearRequested, _ := metadataBoolByKeys(object, "wecom_agent_secret_clear", "clear_wecom_agent_secret", "agent_secret_clear", "clear_agent_secret"); clearRequested {
		return false
	}
	if firstMetadataString(object, "agent_secret", "wecom_agent_secret", "enterprise_wechat_agent_secret", "corp_secret", "corpsecret") != "" {
		return true
	}
	if existing == nil {
		return false
	}
	return firstMetadataString(existing,
		"agent_secret",
		"wecom_agent_secret",
		"enterprise_wechat_agent_secret",
		"corp_secret",
		"corpsecret",
		"wecom_agent_secret_encrypted",
		"enterprise_wechat_agent_secret_encrypted",
		"agent_secret_encrypted",
	) != ""
}

func validateLDAPProviderObject(object map[string]any, requireExplicitEnable bool, context string) (string, bool, error) {
	enabled := !requireExplicitEnable
	if requireExplicitEnable {
		enabled, _ = metadataBoolValue(object["ldap_enabled"])
		if _, exists := object["ldap_enabled"]; !exists {
			enabled, _ = metadataBoolValue(object["ldap_login_enabled"])
			if _, legacyExists := object["ldap_login_enabled"]; !legacyExists {
				enabled, _ = metadataBoolValue(object["external_ldap_enabled"])
			}
		}
	} else if value, exists := object["enabled"]; exists {
		enabled, _ = metadataBoolValue(value)
	}
	provider := externalLDAPProvider{
		ID:                   firstMetadataString(object, "id", "provider_id", "ldap_provider_id"),
		Name:                 firstMetadataString(object, "name", "label", "provider_name", "ldap_provider_name"),
		URL:                  externalLDAPURL(object),
		BindDN:               firstMetadataString(object, "bind_dn", "ldap_bind_dn", "manager_dn"),
		BaseDN:               firstMetadataString(object, "base_dn", "ldap_base_dn", "search_base", "user_base_dn"),
		UserFilter:           firstMetadataString(object, "user_filter", "ldap_user_filter", "filter"),
		UserDNTemplate:       firstMetadataString(object, "user_dn_template", "ldap_user_dn_template"),
		UsernameAttribute:    firstMetadataString(object, "username_attribute", "ldap_username_attribute"),
		DisplayNameAttribute: firstMetadataString(object, "display_name_attribute", "ldap_display_name_attribute"),
		EmailAttribute:       firstMetadataString(object, "email_attribute", "ldap_email_attribute"),
		Role:                 firstMetadataString(object, "role", "default_role", "ldap_role"),
		ServerName:           firstMetadataString(object, "server_name", "tls_server_name", "ldap_server_name"),
	}
	provider.StartTLS, _ = metadataBoolValue(object["ldap_start_tls"])
	if value, exists := object["start_tls"]; exists {
		provider.StartTLS, _ = metadataBoolValue(value)
	}
	provider.InsecureSkipVerify, _ = metadataBoolValue(object["ldap_insecure_skip_verify"])
	if value, exists := object["insecure_skip_verify"]; exists {
		provider.InsecureSkipVerify, _ = metadataBoolValue(value)
	}
	if provider.ID == "" {
		provider.ID = firstNonEmpty(provider.Name, provider.URL)
	}
	if err := validateExternalLDAPProviderShape(provider, enabled); err != nil {
		return provider.ID, enabled, fmt.Errorf("%s: %w", context, err)
	}
	return provider.ID, enabled, nil
}

func validateExternalLDAPProvider(provider externalLDAPProvider) error {
	return validateExternalLDAPProviderShape(provider, true)
}

func validateExternalLDAPProviderShape(provider externalLDAPProvider, required bool) error {
	var parsedScheme string
	if strings.TrimSpace(provider.URL) != "" {
		parsed, err := parseLDAPURL(provider.URL)
		if err != nil {
			return err
		}
		parsedScheme = parsed.Scheme
	} else if required {
		return errors.New("ldap URL is required when LDAP login is enabled")
	}
	if provider.StartTLS && parsedScheme == "ldaps" {
		return errors.New("ldap STARTTLS cannot be enabled with an ldaps URL")
	}
	for label, value := range map[string]string{
		"provider id":      provider.ID,
		"provider name":    provider.Name,
		"bind identity":    provider.BindDN,
		"base DN":          provider.BaseDN,
		"user DN template": provider.UserDNTemplate,
		"TLS server name":  provider.ServerName,
	} {
		if strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("ldap %s must not contain control characters", label)
		}
	}
	if len(provider.ID) > 256 || len(provider.Name) > 256 {
		return errors.New("ldap provider id and name must not exceed 256 bytes")
	}
	if len(provider.BindDN) > 4096 || len(provider.BaseDN) > 4096 || len(provider.UserDNTemplate) > 4096 {
		return errors.New("ldap DN fields must not exceed 4096 bytes")
	}
	if len(provider.ServerName) > 255 || strings.ContainsAny(provider.ServerName, " /\\@\t") {
		return errors.New("ldap TLS server name is invalid")
	}
	if provider.BaseDN != "" {
		if _, err := goldap.ParseDN(provider.BaseDN); err != nil {
			return fmt.Errorf("ldap base DN is invalid: %w", err)
		}
	}
	if provider.UserDNTemplate != "" {
		if strings.Count(provider.UserDNTemplate, "{username}") != 1 {
			return errors.New("ldap user DN template must contain exactly one {username} placeholder")
		}
		probe := strings.ReplaceAll(provider.UserDNTemplate, "{username}", "ldap-template-user")
		if strings.ContainsAny(probe, ",=") {
			if _, err := goldap.ParseDN(probe); err != nil {
				return fmt.Errorf("ldap user DN template is invalid: %w", err)
			}
		}
	}
	if required && provider.BaseDN == "" && provider.UserDNTemplate == "" {
		return errors.New("ldap base DN or user DN template is required when LDAP login is enabled")
	}
	if provider.UserDNTemplate == "" {
		filter := provider.UserFilter
		if filter == "" {
			filter = "(|(uid={username})(sAMAccountName={username})(userPrincipalName={username})(mail={username}))"
		}
		if !strings.Contains(filter, "{username}") {
			return errors.New("ldap user filter must contain the {username} placeholder")
		}
		if len(filter) > 4096 {
			return errors.New("ldap user filter must not exceed 4096 bytes")
		}
		compiled := strings.ReplaceAll(filter, "{username}", goldap.EscapeFilter("ldap-filter-user"))
		if _, err := goldap.CompileFilter(compiled); err != nil {
			return fmt.Errorf("ldap user filter is invalid: %w", err)
		}
	}
	for label, attribute := range map[string]string{
		"username attribute":     provider.UsernameAttribute,
		"display name attribute": provider.DisplayNameAttribute,
		"email attribute":        provider.EmailAttribute,
	} {
		if attribute != "" && !ldapAttributeNamePattern.MatchString(attribute) {
			return fmt.Errorf("ldap %s is invalid", label)
		}
	}
	if provider.Role != "" && !ldapRolePattern.MatchString(provider.Role) {
		return errors.New("ldap default role is invalid")
	}
	return nil
}

var integrationMetadataTypes = map[string]string{
	"host":                             "string",
	"port":                             "integer",
	"username":                         "string",
	"from":                             "string",
	"mail_from":                        "string",
	"to":                               "string",
	"test_to":                          "string",
	"use_tls":                          "boolean",
	"ssl":                              "boolean",
	"tls":                              "boolean",
	"start_tls":                        "boolean",
	"starttls":                         "boolean",
	"server_name":                      "string",
	"insecure_skip_verify":             "boolean",
	"notifications_enabled":            "boolean",
	"notification_categories":          "string_list",
	"notifications_send_existing":      "boolean",
	"smtp_host":                        "string",
	"smtp_port":                        "integer",
	"smtp_username":                    "string",
	"smtp_from":                        "string",
	"smtp_to":                          "string",
	"smtp_test_to":                     "string",
	"smtp_use_tls":                     "boolean",
	"smtp_ssl":                         "boolean",
	"smtp_start_tls":                   "boolean",
	"smtp_starttls":                    "boolean",
	"smtp_server_name":                 "string",
	"smtp_insecure_skip_verify":        "boolean",
	"smtp_notifications_enabled":       "boolean",
	"smtp_notification_categories":     "string_list",
	"smtp_notifications_send_existing": "boolean",
	"smtp_password":                    "string",
	"smtp_password_clear":              "boolean",
	"smtp_password_encrypted":          "string",
	"smtp_password_set":                "boolean",
	"smtp_password_updated_at":         "string",
	"provider":                         "string",
	"base_url":                         "string",
	"api_base_url":                     "string",
	"openai_base_url":                  "string",
	"model":                            "string",
	"llm_provider":                     "string",
	"llm_base_url":                     "string",
	"llm_model":                        "string",
	"llm_api_key":                      "string",
	"plain_llm_api_key":                "string",
	"llm_api_key_clear":                "boolean",
	"llm_api_key_encrypted":            "string",
	"llm_api_key_set":                  "boolean",
	"llm_api_key_updated_at":           "string",
}

func validateIntegrationMetadataInput(metadata map[string]any) error {
	for key, value := range metadata {
		normalized := strings.ToLower(strings.TrimSpace(key))
		valueType, known := integrationMetadataTypes[normalized]
		if !known {
			if strings.HasPrefix(normalized, "smtp_") || strings.HasPrefix(normalized, "llm") {
				return fmt.Errorf("integration setting field %q is not supported", key)
			}
			continue
		}
		if key != normalized {
			return fmt.Errorf("integration setting field %q must use the canonical name %q", key, normalized)
		}
		if value == nil {
			continue
		}
		switch valueType {
		case "string":
			text, ok := value.(string)
			if !ok {
				return fmt.Errorf("integration setting %s must be a string", key)
			}
			if (normalized == "llm_api_key" || normalized == "plain_llm_api_key") && len(text) > maxIntegrationSecret {
				return fmt.Errorf("integration setting %s must not exceed %d bytes", key, maxIntegrationSecret)
			}
		case "integer":
			port, ok := strictMetadataInteger(value)
			if !ok || port < 1 || port > 65535 {
				return fmt.Errorf("integration setting %s must be an integer between 1 and 65535", key)
			}
		case "boolean":
			if _, ok := value.(bool); !ok {
				return fmt.Errorf("integration setting %s must be a boolean", key)
			}
		case "string_list":
			categories, ok := strictMetadataStringList(value)
			if !ok {
				return fmt.Errorf("integration setting %s must be an array of strings", key)
			}
			allowed := map[string]bool{"security": true, "task": true, "gateway": true, "operation": true}
			for _, category := range categories {
				if !allowed[strings.ToLower(strings.TrimSpace(category))] {
					return fmt.Errorf("integration setting %s contains unsupported category %q", key, category)
				}
			}
		}
	}
	return nil
}

func validateSMTPIntegrationItem(item model.PlatformItem) error {
	metadata := item.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	useTLS := smtpMetadataBoolAny(metadata, "smtp_use_tls", "smtp_ssl", "use_tls", "ssl", "tls")
	startTLS := smtpMetadataBoolAny(metadata, "smtp_start_tls", "smtp_starttls", "start_tls", "starttls")
	if useTLS && startTLS {
		return errors.New("integration setting smtp_use_tls and smtp_start_tls cannot both be enabled")
	}
	if item.Port < 0 || item.Port > 65535 {
		return errors.New("integration setting port must be between 1 and 65535 when set")
	}
	if value, exists := firstMetadataValue(metadata, "smtp_port"); exists && !metadataValueEmpty(value) {
		port, ok := metadataInt(value)
		if number, isFloat := value.(float64); isFloat && number != math.Trunc(number) {
			ok = false
		}
		if !ok || port < 1 || port > 65535 {
			return errors.New("integration setting smtp_port must be an integer between 1 and 65535")
		}
	}
	if from := smtpMetadataString(metadata, "smtp_from", "from", "mail_from"); from != "" {
		if _, _, err := parseSMTPMailbox(from); err != nil {
			return fmt.Errorf("integration setting smtp_from is invalid: %w", err)
		}
	}
	if recipients := smtpMetadataString(metadata, "smtp_to", "to"); recipients != "" {
		if _, _, err := parseSMTPRecipientList(recipients); err != nil {
			return fmt.Errorf("integration setting smtp_to is invalid: %w", err)
		}
	}
	if recipient := smtpMetadataString(metadata, "smtp_test_to", "test_to"); recipient != "" {
		if _, _, err := parseSMTPRecipientList(recipient); err != nil {
			return fmt.Errorf("integration setting smtp_test_to is invalid: %w", err)
		}
	}
	if !smtpMetadataBoolAny(metadata, "smtp_notifications_enabled", "notifications_enabled") {
		return nil
	}
	if firstNonEmpty(smtpMetadataString(metadata, "smtp_host", "host"), item.Host) == "" {
		return errors.New("integration setting smtp_host is required when email notifications are enabled")
	}
	if smtpMetadataString(metadata, "smtp_from", "from", "mail_from") == "" {
		return errors.New("integration setting smtp_from is required when email notifications are enabled")
	}
	if smtpMetadataString(metadata, "smtp_to", "to") == "" {
		return errors.New("integration setting smtp_to is required when email notifications are enabled")
	}
	if _, err := smtpDeliveryConfigFromSetting(item, "", ""); err != nil {
		return fmt.Errorf("integration setting SMTP notification configuration is invalid: %w", err)
	}
	return nil
}

func validateLLMIntegrationItem(item model.PlatformItem) error {
	metadata := item.Metadata
	if metadata == nil {
		return nil
	}
	provider := smtpMetadataString(metadata, "llm_provider", "provider")
	if len(provider) > 128 {
		return errors.New("integration setting llm_provider must not exceed 128 bytes")
	}
	modelName := smtpMetadataString(metadata, "llm_model", "model")
	if len(modelName) > 256 {
		return errors.New("integration setting llm_model must not exceed 256 bytes")
	}
	baseURL := smtpMetadataString(metadata, "llm_base_url", "base_url", "api_base_url", "openai_base_url")
	if baseURL == "" {
		return nil
	}
	if _, err := llmChatCompletionsURL(baseURL); err != nil {
		return fmt.Errorf("integration setting LLM configuration is invalid: %w", err)
	}
	return nil
}

func strictMetadataInteger(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int8:
		return int(typed), true
	case int16:
		return int(typed), true
	case int32:
		return int(typed), true
	case int64:
		return int(typed), true
	case uint:
		return int(typed), true
	case uint8:
		return int(typed), true
	case uint16:
		return int(typed), true
	case uint32:
		return int(typed), true
	case uint64:
		if uint64(int(typed)) != typed {
			return 0, false
		}
		return int(typed), true
	case float64:
		if typed != math.Trunc(typed) {
			return 0, false
		}
		return int(typed), true
	default:
		return 0, false
	}
}

func strictMetadataStringList(value any) ([]string, bool) {
	switch typed := value.(type) {
	case []string:
		return typed, true
	case []any:
		result := make([]string, 0, len(typed))
		for _, entry := range typed {
			text, ok := entry.(string)
			if !ok {
				return nil, false
			}
			result = append(result, text)
		}
		return result, true
	default:
		return nil, false
	}
}

func validateRetentionDaysMetadata(metadata map[string]any, context string) error {
	allowed := make(map[string]bool, len(retentionDayMetadataKeys))
	for _, key := range retentionDayMetadataKeys {
		allowed[key] = true
	}
	for key := range metadata {
		if strings.HasSuffix(strings.ToLower(strings.TrimSpace(key)), "_days") && !allowed[key] {
			return fmt.Errorf("%s field %q is not supported", context, key)
		}
	}
	for _, key := range retentionDayMetadataKeys {
		value, exists := metadata[key]
		if !exists || metadataValueEmpty(value) {
			continue
		}
		parsed, ok := metadataInt(value)
		if number, isFloat := value.(float64); isFloat && number != math.Trunc(number) {
			ok = false
		}
		if !ok || parsed < 0 || parsed > 36500 {
			return fmt.Errorf("%s %s must be an integer between 0 and 36500", context, key)
		}
	}
	return nil
}

func validateScheduledTaskInteger(metadata map[string]any, key string, minimum, maximum int) error {
	value, exists := metadata[key]
	if !exists || metadataValueEmpty(value) {
		return nil
	}
	parsed, ok := metadataInt(value)
	if number, isFloat := value.(float64); isFloat && number != math.Trunc(number) {
		ok = false
	}
	if !ok || parsed < minimum || parsed > maximum {
		return fmt.Errorf("scheduled task %s must be an integer between %d and %d", key, minimum, maximum)
	}
	return nil
}

func validateCommandFilterItem(item model.PlatformItem) error {
	if strings.TrimSpace(item.Name) == "" {
		return errors.New("command filter name is required")
	}
	if item.Protocol != "" && item.Protocol != model.ProtocolSSH {
		return errors.New("command filters only support the ssh protocol")
	}
	action := commandFilterValidationAction(item)
	switch action {
	case "allow", "deny", "approval":
	default:
		return fmt.Errorf("command filter action must be allow, deny, or approval, got %q", action)
	}
	status := strings.ToLower(strings.TrimSpace(item.Status))
	if status != "" {
		switch status {
		case "enabled", "active", "disabled", "inactive":
		default:
			return fmt.Errorf("command filter status must be enabled or disabled, got %q", status)
		}
	}
	risk := strings.ToLower(firstMetadataString(item.Metadata, "risk", "risk_level", "riskLevel", "level"))
	if risk == "" {
		risk = strings.ToLower(strings.TrimSpace(item.Group))
	}
	if risk != "" {
		switch risk {
		case "normal", "low", "medium", "high", "critical", "emergency":
		default:
			return fmt.Errorf("command filter risk must be normal, low, medium, high, critical, or emergency, got %q", risk)
		}
	}
	patterns := commandFilterValidationPatterns(item)
	if len(patterns) == 0 {
		return errors.New("command filter pattern is required")
	}
	if len(patterns) > maxCommandFilterPatterns {
		return fmt.Errorf("command filter supports at most %d patterns", maxCommandFilterPatterns)
	}
	for _, pattern := range patterns {
		if len(pattern) > maxCommandFilterPattern {
			return fmt.Errorf("command filter pattern exceeds %d bytes", maxCommandFilterPattern)
		}
		if pattern == "*" {
			continue
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("invalid command filter pattern %q: %w", pattern, err)
		}
	}
	return nil
}

func commandFilterValidationAction(item model.PlatformItem) string {
	action := strings.ToLower(strings.TrimSpace(item.Type))
	for _, key := range []string{"action", "mode", "effect"} {
		if value := strings.ToLower(firstMetadataString(item.Metadata, key)); value != "" {
			return value
		}
	}
	return action
}

func commandFilterValidationPatterns(item model.PlatformItem) []string {
	values := []string{}
	for _, key := range []string{"pattern", "patterns", "command", "commands", "match", "matches"} {
		values = append(values, metadataStrings(item.Metadata[key])...)
	}
	if strings.TrimSpace(item.Host) != "" {
		values = append(values, item.Host)
	}
	if len(values) == 0 && strings.TrimSpace(item.Description) != "" {
		values = append(values, item.Description)
	}
	patterns := []string{}
	for _, value := range values {
		for _, part := range strings.FieldsFunc(value, func(r rune) bool {
			return r == ',' || r == ';' || r == '\n'
		}) {
			if pattern := strings.TrimSpace(part); pattern != "" {
				patterns = append(patterns, pattern)
			}
		}
	}
	return patterns
}
