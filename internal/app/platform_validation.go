package app

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"openwebservermanager/internal/model"
)

const (
	maxCommandFilterPatterns = 128
	maxCommandFilterPattern  = 4096
)

func preparePlatformItemCreateRequest(collection string, req *model.PlatformItemRequest) error {
	if collection == "command_filters" && req.Protocol == "" {
		req.Protocol = model.ProtocolSSH
	}
	return validatePlatformItemRequest(collection, *req)
}

func validatePlatformItemUpdateRequest(collection string, existing model.PlatformItem, req model.PlatformItemRequest) error {
	if collection == "command_filters" {
		return validateCommandFilterItem(commandFilterItemAfterUpdate(existing, req))
	}
	return validatePlatformItemRequest(collection, req)
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

func commandFilterItemAfterUpdate(existing model.PlatformItem, req model.PlatformItemRequest) model.PlatformItem {
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
