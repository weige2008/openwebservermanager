package sshsession

import (
	"regexp"
	"strings"
	"time"

	"openwebservermanager/internal/model"
	"openwebservermanager/internal/store"
)

const clearCurrentLine = byte(0x15)

type commandInterceptor struct {
	store   *store.Store
	session model.ConnectionSession
	buffer  []byte
}

type commandEvent struct {
	Command string
	Blocked bool
	Notice  string
}

type commandDecision struct {
	Action   string
	Risk     string
	RuleID   string
	RuleName string
	Pattern  string
	Status   string
	Blocked  bool
}

func newCommandInterceptor(st *store.Store, session model.ConnectionSession) *commandInterceptor {
	return &commandInterceptor{store: st, session: session}
}

func (i *commandInterceptor) Process(raw []byte) ([]byte, []commandEvent) {
	filtered := make([]byte, 0, len(raw))
	events := []commandEvent{}
	skipLF := false
	for _, b := range raw {
		if b == '\n' && skipLF {
			skipLF = false
			continue
		}
		skipLF = b == '\r'
		switch b {
		case '\r', '\n':
			command := strings.TrimSpace(string(i.buffer))
			i.buffer = i.buffer[:0]
			if command == "" {
				filtered = append(filtered, b)
				continue
			}
			decision := i.evaluate(command)
			i.record(command, decision)
			if decision.Blocked {
				filtered = append(filtered, clearCurrentLine)
				events = append(events, commandEvent{
					Command: command,
					Blocked: true,
					Notice:  commandBlockNotice(command, decision),
				})
				continue
			}
			filtered = append(filtered, b)
			events = append(events, commandEvent{Command: command})
		case 0x03:
			i.buffer = i.buffer[:0]
			filtered = append(filtered, b)
		case clearCurrentLine:
			i.buffer = i.buffer[:0]
			filtered = append(filtered, b)
		case 0x7f, 0x08:
			if len(i.buffer) > 0 {
				i.buffer = i.buffer[:len(i.buffer)-1]
			}
			filtered = append(filtered, b)
		default:
			if b == '\t' || b >= 0x20 {
				i.buffer = append(i.buffer, b)
			}
			filtered = append(filtered, b)
		}
	}
	return filtered, events
}

func (i *commandInterceptor) evaluate(command string) commandDecision {
	decision := commandDecision{Action: "allow", Risk: "normal", RuleName: "default", Pattern: "", Status: "submitted"}
	if i.store == nil {
		return decision
	}
	filters, err := i.store.ListPlatformItems("command_filters")
	if err != nil {
		return decision
	}
	for _, filter := range filters {
		if !commandFilterEnabled(filter) {
			continue
		}
		if !commandFilterAppliesToSession(filter, i.session) {
			continue
		}
		for _, pattern := range commandFilterPatterns(filter) {
			if !commandMatchesPattern(command, pattern) {
				continue
			}
			decision.Action = commandFilterAction(filter)
			decision.Risk = commandFilterRisk(filter)
			decision.RuleID = filter.ID
			decision.RuleName = filter.Name
			decision.Pattern = pattern
			decision.Blocked = commandActionBlocks(decision.Action)
			decision.Status = commandDecisionStatus(decision.Action, decision.Blocked)
			return decision
		}
	}
	return decision
}

func (i *commandInterceptor) record(command string, decision commandDecision) {
	if i.store == nil {
		return
	}
	_, _ = i.store.CreatePlatformItem("exec_command_logs", model.PlatformItemRequest{
		Name:        command,
		Type:        decision.Action,
		Status:      decision.Status,
		Protocol:    model.ProtocolSSH,
		OwnerID:     i.session.UserID,
		TargetID:    i.session.ServerID,
		Description: "interactive ssh command " + decision.Status,
		Metadata: map[string]any{
			"session_id":    i.session.ID,
			"server_id":     i.session.ServerID,
			"credential_id": i.session.CredentialID,
			"client_ip":     i.session.ClientIP,
			"command":       command,
			"action":        decision.Action,
			"risk":          decision.Risk,
			"rule_id":       decision.RuleID,
			"rule_name":     decision.RuleName,
			"pattern":       decision.Pattern,
			"blocked":       decision.Blocked,
			"interactive":   true,
			"recorded_at":   time.Now().UTC(),
		},
	})
}

func commandFilterEnabled(item model.PlatformItem) bool {
	status := strings.ToLower(strings.TrimSpace(item.Status))
	return status == "" || status == "enabled" || status == "active"
}

func commandFilterAppliesToSession(item model.PlatformItem, session model.ConnectionSession) bool {
	if item.Protocol != "" && item.Protocol != session.Protocol {
		return false
	}
	if !commandScopeMatches(commandFilterScopeValues(item, []string{item.TargetID}, "target_id", "target_ids", "targetId", "asset_id", "asset_ids", "assetId", "server_id", "server_ids", "serverId", "resource_id", "resource_ids", "resourceId"), session.ServerID) {
		return false
	}
	if !commandScopeMatches(commandFilterScopeValues(item, []string{item.OwnerID, item.Username}, "user_id", "user_ids", "userId", "username", "usernames", "account", "accounts", "owner_id", "owner_ids", "ownerId"), session.UserID) {
		return false
	}
	return true
}

func commandFilterScopeValues(item model.PlatformItem, direct []string, metadataKeys ...string) []string {
	values := []string{}
	values = append(values, direct...)
	for _, key := range metadataKeys {
		values = append(values, metadataStrings(item.Metadata[key])...)
	}
	result := []string{}
	for _, value := range values {
		for _, part := range splitCriteria(value) {
			if part != "" {
				result = append(result, part)
			}
		}
	}
	return result
}

func commandScopeMatches(values []string, target string) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if value == "*" {
			return true
		}
		if target != "" && strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(target)) {
			return true
		}
	}
	return false
}

func commandFilterPatterns(item model.PlatformItem) []string {
	values := []string{}
	for _, key := range []string{"pattern", "patterns", "command", "commands", "match", "matches"} {
		values = append(values, metadataStrings(item.Metadata[key])...)
	}
	if item.Host != "" {
		values = append(values, item.Host)
	}
	if item.Description != "" && len(values) == 0 {
		values = append(values, item.Description)
	}
	result := []string{}
	for _, value := range values {
		for _, part := range splitCriteria(value) {
			if part != "" {
				result = append(result, part)
			}
		}
	}
	return result
}

func commandFilterAction(item model.PlatformItem) string {
	action := strings.ToLower(strings.TrimSpace(item.Type))
	for _, key := range []string{"action", "mode", "effect"} {
		if value, ok := item.Metadata[key].(string); ok && strings.TrimSpace(value) != "" {
			action = strings.ToLower(strings.TrimSpace(value))
			break
		}
	}
	if action == "" {
		action = "deny"
	}
	return action
}

func commandFilterRisk(item model.PlatformItem) string {
	for _, key := range []string{"risk", "risk_level", "riskLevel", "level"} {
		if value, ok := item.Metadata[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.ToLower(strings.TrimSpace(value))
		}
	}
	if item.Group != "" {
		return strings.ToLower(strings.TrimSpace(item.Group))
	}
	return "normal"
}

func commandActionBlocks(action string) bool {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "deny", "reject", "block", "blocked", "approval", "approve", "review":
		return true
	default:
		return false
	}
}

func commandDecisionStatus(action string, blocked bool) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "approval", "approve", "review":
		return "approval_required"
	case "deny", "reject", "block", "blocked":
		return "denied"
	default:
		if blocked {
			return "blocked"
		}
		return "submitted"
	}
}

func commandBlockNotice(command string, decision commandDecision) string {
	switch commandDecisionStatus(decision.Action, decision.Blocked) {
	case "approval_required":
		return "\r\n[openwebservermanager] command requires approval by " + decision.RuleName + " (" + decision.Risk + "): " + command + "\r\n"
	default:
		return "\r\n[openwebservermanager] command blocked by " + decision.RuleName + " (" + decision.Risk + "): " + command + "\r\n"
	}
}

func commandMatchesPattern(command, pattern string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if pattern == "*" {
		return true
	}
	if expr, err := regexp.Compile(pattern); err == nil {
		return expr.MatchString(command)
	}
	return strings.Contains(strings.ToLower(command), strings.ToLower(pattern))
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
