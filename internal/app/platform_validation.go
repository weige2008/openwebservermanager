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
	}
	return validatePlatformItemRequest(collection, *req)
}

func preparePlatformItemUpdateRequest(collection string, existing model.PlatformItem, req *model.PlatformItemRequest) error {
	if collection == "scheduled_tasks" {
		normalizeScheduledTaskMutation(req)
	}
	item := platformItemAfterUpdate(existing, *req)
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
	if !strings.EqualFold(strings.TrimSpace(item.Type), "retention") {
		return nil
	}
	status := strings.ToLower(strings.TrimSpace(item.Status))
	if status != "" {
		switch status {
		case "enabled", "active", "disabled", "inactive":
		default:
			return fmt.Errorf("retention setting status must be enabled or disabled, got %q", status)
		}
	}
	return validateRetentionDaysMetadata(item.Metadata, "retention setting")
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
