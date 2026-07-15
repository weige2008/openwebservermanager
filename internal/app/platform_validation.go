package app

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"openwebservermanager/internal/model"
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
		if strings.EqualFold(strings.TrimSpace(req.Type), "integration") {
			if err := validateIntegrationMetadataInput(req.Metadata); err != nil {
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
	if collection == "system_settings" && strings.EqualFold(strings.TrimSpace(item.Type), "integration") && req.Metadata != nil {
		if err := validateIntegrationMetadataInput(req.Metadata); err != nil {
			return err
		}
	}
	switch collection {
	case "command_filters":
		return validateCommandFilterItem(item)
	case "scheduled_tasks":
		return validateScheduledTaskItem(item)
	case "system_settings":
		return validateSystemSettingItem(item)
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
	default:
		return nil
	}
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
