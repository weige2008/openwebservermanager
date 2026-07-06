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
	Command    string
	Blocked    bool
	ApprovalID string
	Notice     string
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
			approvalID := i.record(command, decision)
			if decision.Blocked {
				filtered = append(filtered, clearCurrentLine)
				events = append(events, commandEvent{
					Command:    command,
					Blocked:    true,
					ApprovalID: approvalID,
					Notice:     commandBlockNotice(command, decision, approvalID),
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
		if !commandFilterAppliesToSession(i.store, filter, i.session) {
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

func (i *commandInterceptor) record(command string, decision commandDecision) string {
	metadata := map[string]any{}
	approvalID := ""
	if commandDecisionStatus(decision.Action, decision.Blocked) == "approval_required" {
		approval, err := i.createCommandApproval(command, decision, true, nil)
		if err == nil && approval.ID != "" {
			approvalID = approval.ID
			metadata["approval_id"] = approval.ID
			metadata["approval_status"] = approval.Status
		} else if err != nil {
			metadata["approval_error"] = err.Error()
		}
	}
	i.recordCommand(command, decision, true, "interactive ssh command "+decision.Status, metadata)
	return approvalID
}

func (i *commandInterceptor) recordExec(command string, decision commandDecision, description string, metadata map[string]any) {
	i.recordCommand(command, decision, false, description, metadata)
}

func (i *commandInterceptor) recordCommand(command string, decision commandDecision, interactive bool, description string, metadata map[string]any) {
	if i.store == nil {
		return
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["session_id"] = i.session.ID
	metadata["server_id"] = i.session.ServerID
	metadata["credential_id"] = i.session.CredentialID
	metadata["client_ip"] = i.session.ClientIP
	metadata["command"] = command
	metadata["action"] = decision.Action
	metadata["risk"] = decision.Risk
	metadata["rule_id"] = decision.RuleID
	metadata["rule_name"] = decision.RuleName
	metadata["pattern"] = decision.Pattern
	metadata["blocked"] = decision.Blocked
	metadata["interactive"] = interactive
	metadata["recorded_at"] = time.Now().UTC()
	_, _ = i.store.CreatePlatformItem("exec_command_logs", model.PlatformItemRequest{
		Name:        command,
		Type:        decision.Action,
		Status:      decision.Status,
		Protocol:    model.ProtocolSSH,
		OwnerID:     i.session.UserID,
		TargetID:    i.session.ServerID,
		Description: description,
		Metadata:    metadata,
	})
}

func (i *commandInterceptor) createCommandApproval(command string, decision commandDecision, interactive bool, metadata map[string]any) (model.PlatformItem, error) {
	if i.store == nil {
		return model.PlatformItem{}, nil
	}
	nextMetadata := map[string]any{}
	for key, value := range metadata {
		nextMetadata[key] = value
	}
	nextMetadata["session_id"] = i.session.ID
	nextMetadata["server_id"] = i.session.ServerID
	nextMetadata["credential_id"] = i.session.CredentialID
	nextMetadata["client_ip"] = i.session.ClientIP
	nextMetadata["command"] = command
	nextMetadata["action"] = decision.Action
	nextMetadata["risk"] = decision.Risk
	nextMetadata["rule_id"] = decision.RuleID
	nextMetadata["rule_name"] = decision.RuleName
	nextMetadata["pattern"] = decision.Pattern
	nextMetadata["interactive"] = interactive
	nextMetadata["requested_by"] = i.session.UserID
	nextMetadata["requested_at"] = time.Now().UTC()
	return i.store.CreatePlatformItem("command_approvals", model.PlatformItemRequest{
		Name:        commandApprovalName(command),
		Type:        "ssh_command",
		Status:      "pending",
		Protocol:    model.ProtocolSSH,
		OwnerID:     i.session.UserID,
		TargetID:    i.session.ServerID,
		Description: "approval required by " + decision.RuleName,
		Metadata:    nextMetadata,
	})
}

func commandApprovalName(command string) string {
	command = strings.TrimSpace(command)
	if command == "" {
		return "SSH command approval"
	}
	const max = 120
	if len(command) <= max {
		return command
	}
	return command[:max] + "..."
}

func commandFilterEnabled(item model.PlatformItem) bool {
	status := strings.ToLower(strings.TrimSpace(item.Status))
	return status == "" || status == "enabled" || status == "active"
}

func commandFilterAppliesToSession(st *store.Store, item model.PlatformItem, session model.ConnectionSession) bool {
	if item.Protocol != "" && item.Protocol != session.Protocol {
		return false
	}
	if !commandScopeMatches(commandFilterScopeValues(item, []string{item.TargetID}, "target_id", "target_ids", "targetId", "asset_id", "asset_ids", "assetId", "server_id", "server_ids", "serverId", "resource_id", "resource_ids", "resourceId"), session.ServerID) {
		return false
	}
	if !commandSubjectScopeMatches(st, commandFilterScopeValues(item, []string{item.OwnerID, item.Username}, "user_id", "user_ids", "userId", "username", "usernames", "account", "accounts", "owner_id", "owner_ids", "ownerId"), session) {
		return false
	}
	return true
}

func commandSubjectScopeMatches(st *store.Store, values []string, session model.ConnectionSession) bool {
	if len(values) == 0 {
		return true
	}
	subjects := commandSessionSubjectValues(st, session)
	for _, value := range values {
		if strings.TrimSpace(value) == "*" {
			return true
		}
		for _, subject := range subjects {
			if subject != "" && strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(subject)) {
				return true
			}
		}
	}
	return false
}

func commandSessionSubjectValues(st *store.Store, session model.ConnectionSession) []string {
	values := []string{session.UserID}
	if st == nil || strings.TrimSpace(session.UserID) == "" {
		return values
	}
	users, err := st.ListPlatformItems("users")
	if err != nil {
		return values
	}
	for _, user := range users {
		if !commandScopeMatches([]string{user.ID, user.Name, user.Username}, session.UserID) {
			continue
		}
		values = append(values, user.ID, user.Name, user.Username, user.OwnerID, user.ParentID, user.Group)
		values = append(values, metadataStrings(user.Metadata["department_id"])...)
		values = append(values, metadataStrings(user.Metadata["department_ids"])...)
		values = append(values, metadataStrings(user.Metadata["department"])...)
		values = append(values, metadataStrings(user.Metadata["departments"])...)
		values = append(values, metadataStrings(user.Metadata["account"])...)
		values = append(values, metadataStrings(user.Metadata["accounts"])...)
		break
	}
	return values
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

func commandBlockNotice(command string, decision commandDecision, approvalID string) string {
	switch commandDecisionStatus(decision.Action, decision.Blocked) {
	case "approval_required":
		if approvalID != "" {
			return "\r\n[openwebservermanager] command requires approval by " + decision.RuleName + " (" + decision.Risk + "), approval " + approvalID + ": " + command + "\r\n"
		}
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
