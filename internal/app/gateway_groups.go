package app

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"openwebservermanager/internal/model"
)

type gatewayGroupStatus struct {
	ID                string               `json:"id"`
	Name              string               `json:"name"`
	Type              string               `json:"type"`
	Status            string               `json:"status"`
	SelectionMode     string               `json:"selection_mode"`
	MemberIDs         []string             `json:"member_ids"`
	RequiredLabels    []string             `json:"required_labels,omitempty"`
	RequiredCaps      []string             `json:"required_capabilities,omitempty"`
	Members           []gatewayGroupMember `json:"members"`
	Online            int                  `json:"online"`
	Offline           int                  `json:"offline"`
	SelectedGatewayID string               `json:"selected_gateway_id,omitempty"`
	SelectedGateway   *gatewayGroupMember  `json:"selected_gateway,omitempty"`
	CheckedAt         time.Time            `json:"checked_at"`
}

type gatewayGroupMember struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Collection      string         `json:"collection"`
	Type            string         `json:"type,omitempty"`
	Status          string         `json:"status"`
	Online          bool           `json:"online"`
	Host            string         `json:"host,omitempty"`
	Port            int            `json:"port,omitempty"`
	Tags            []string       `json:"tags,omitempty"`
	LatencyMS       int            `json:"latency_ms,omitempty"`
	ActiveSessions  int            `json:"active_sessions,omitempty"`
	Capabilities    []string       `json:"capabilities,omitempty"`
	LastHeartbeatAt string         `json:"last_heartbeat_at,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
}

func (s *Server) handleGatewayGroupStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	s.refreshAgentGatewayStatuses()
	groups, err := s.cfg.Store.ListPlatformItems("gateway_groups")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	statuses := s.gatewayGroupStatuses(groups)
	writeJSON(w, http.StatusOK, map[string]any{"items": statuses, "checked_at": time.Now().UTC()})
}

func (s *Server) gatewayGroupsWithStatus(groups []model.PlatformItem) []model.PlatformItem {
	statuses := s.gatewayGroupStatuses(groups)
	byID := map[string]gatewayGroupStatus{}
	for _, status := range statuses {
		byID[status.ID] = status
	}
	out := make([]model.PlatformItem, 0, len(groups))
	for _, group := range groups {
		status, ok := byID[group.ID]
		if !ok {
			out = append(out, group)
			continue
		}
		item := group
		if item.Metadata == nil {
			item.Metadata = map[string]any{}
		} else {
			item.Metadata = cloneMetadata(item.Metadata)
		}
		item.Metadata["member_count"] = len(status.Members)
		item.Metadata["online_count"] = status.Online
		item.Metadata["offline_count"] = status.Offline
		item.Metadata["selected_gateway_id"] = status.SelectedGatewayID
		item.Metadata["selection_mode"] = status.SelectionMode
		item.Metadata["required_labels"] = status.RequiredLabels
		item.Metadata["required_capabilities"] = status.RequiredCaps
		out = append(out, item)
	}
	return out
}

func (s *Server) gatewayGroupStatuses(groups []model.PlatformItem) []gatewayGroupStatus {
	gateways := s.gatewayGroupGatewayCandidates()
	statuses := make([]gatewayGroupStatus, 0, len(groups))
	now := time.Now().UTC()
	for _, group := range groups {
		status := gatewayGroupStatus{
			ID:             group.ID,
			Name:           group.Name,
			Type:           group.Type,
			Status:         group.Status,
			SelectionMode:  gatewayGroupSelectionMode(group),
			MemberIDs:      gatewayGroupMemberIDs(group),
			RequiredLabels: gatewayGroupCriteria(group, "labels", "label", "required_labels", "required_label", "tags", "tag"),
			RequiredCaps:   gatewayGroupCriteria(group, "capabilities", "capability", "required_capabilities", "required_capability", "protocols", "protocol"),
			CheckedAt:      now,
		}
		for _, gateway := range gateways {
			if !gatewayGroupMatches(status, group, gateway) {
				continue
			}
			status.Members = append(status.Members, gateway)
			if gateway.Online {
				status.Online++
			} else {
				status.Offline++
			}
		}
		if status.SelectionMode == "manual" && len(status.MemberIDs) > 0 {
			sort.SliceStable(status.Members, func(i, j int) bool {
				return gatewayGroupManualOrder(status.MemberIDs, status.Members[i]) < gatewayGroupManualOrder(status.MemberIDs, status.Members[j])
			})
		} else {
			sort.SliceStable(status.Members, func(i, j int) bool {
				left := status.Members[i]
				right := status.Members[j]
				if left.Online != right.Online {
					return left.Online
				}
				if left.LatencyMS != right.LatencyMS {
					return left.LatencyMS < right.LatencyMS
				}
				if left.ActiveSessions != right.ActiveSessions {
					return left.ActiveSessions < right.ActiveSessions
				}
				return left.Name < right.Name
			})
		}
		for _, member := range status.Members {
			if !member.Online {
				continue
			}
			selected := member
			status.SelectedGatewayID = member.ID
			status.SelectedGateway = &selected
			break
		}
		statuses = append(statuses, status)
	}
	return statuses
}

func (s *Server) gatewayGroupGatewayCandidates() []gatewayGroupMember {
	result := []gatewayGroupMember{}
	if items, err := s.cfg.Store.ListPlatformItems("agent_gateways"); err == nil {
		for _, item := range items {
			result = append(result, gatewayGroupMemberFromItem("agent_gateways", item))
		}
	}
	if items, err := s.cfg.Store.ListPlatformItems("ssh_gateways"); err == nil {
		for _, item := range items {
			result = append(result, gatewayGroupMemberFromItem("ssh_gateways", item))
		}
	}
	return result
}

func gatewayGroupMemberFromItem(collection string, item model.PlatformItem) gatewayGroupMember {
	latency, _ := metadataInt(item.Metadata["latency_ms"])
	activeSessions, _ := metadataInt(item.Metadata["active_sessions"])
	return gatewayGroupMember{
		ID:              item.ID,
		Name:            item.Name,
		Collection:      collection,
		Type:            item.Type,
		Status:          item.Status,
		Online:          gatewayGroupMemberOnline(collection, item),
		Host:            item.Host,
		Port:            item.Port,
		Tags:            item.Tags,
		LatencyMS:       latency,
		ActiveSessions:  activeSessions,
		Capabilities:    compactGatewayGroupCriteria(metadataStrings(item.Metadata["capabilities"])),
		LastHeartbeatAt: firstMetadataString(item.Metadata, "last_heartbeat_at"),
		Metadata: map[string]any{
			"public_address":  firstMetadataString(item.Metadata, "public_address"),
			"listen_address":  firstMetadataString(item.Metadata, "listen_address"),
			"last_client_ip":  firstMetadataString(item.Metadata, "last_client_ip"),
			"offline_reason":  firstMetadataString(item.Metadata, "offline_reason"),
			"heartbeat_count": item.Metadata["heartbeat_count"],
		},
	}
}

func gatewayGroupMemberOnline(collection string, item model.PlatformItem) bool {
	status := strings.ToLower(strings.TrimSpace(item.Status))
	if status == "disabled" || status == "offline" || status == "failed" {
		return false
	}
	if collection == "agent_gateways" {
		return status == "online"
	}
	return status == "" || status == "enabled" || status == "active" || status == "online" || status == "running"
}

func gatewayGroupManualOrder(memberIDs []string, gateway gatewayGroupMember) int {
	for index, value := range memberIDs {
		if value == "*" || strings.EqualFold(value, gateway.ID) || strings.EqualFold(value, gateway.Name) {
			return index
		}
	}
	return len(memberIDs)
}

func gatewayGroupSelectionMode(group model.PlatformItem) string {
	mode := strings.ToLower(strings.TrimSpace(firstNonEmpty(
		firstMetadataString(group.Metadata, "selection_mode", "selection", "mode"),
		group.Type,
	)))
	switch mode {
	case "auto", "automatic", "label", "labels", "capability", "capabilities", "least-latency", "least_latency", "least-sessions", "least_sessions":
		return "auto"
	default:
		return "manual"
	}
}

func gatewayGroupMemberIDs(group model.PlatformItem) []string {
	values := []string{group.TargetID}
	values = append(values, metadataStrings(group.Metadata["gateway_id"])...)
	values = append(values, metadataStrings(group.Metadata["gateway_ids"])...)
	values = append(values, metadataStrings(group.Metadata["member_id"])...)
	values = append(values, metadataStrings(group.Metadata["member_ids"])...)
	values = append(values, metadataStrings(group.Metadata["members"])...)
	values = append(values, metadataStrings(group.Metadata["agent_gateway_ids"])...)
	values = append(values, metadataStrings(group.Metadata["ssh_gateway_ids"])...)
	return compactGatewayGroupCriteria(values)
}

func gatewayGroupCriteria(group model.PlatformItem, keys ...string) []string {
	values := []string{}
	for _, key := range keys {
		values = append(values, metadataStrings(group.Metadata[key])...)
	}
	return compactGatewayGroupCriteria(values)
}

func compactGatewayGroupCriteria(values []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, value := range values {
		for _, part := range splitCriteria(value) {
			key := strings.ToLower(strings.TrimSpace(part))
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			result = append(result, strings.TrimSpace(part))
		}
	}
	return result
}

func gatewayGroupMatches(status gatewayGroupStatus, group model.PlatformItem, gateway gatewayGroupMember) bool {
	if !platformItemEnabled(group) {
		return false
	}
	if len(status.MemberIDs) > 0 {
		return gatewayGroupIDMatches(status.MemberIDs, gateway.ID, gateway.Name)
	}
	if status.SelectionMode == "manual" {
		return false
	}
	if len(status.RequiredLabels) > 0 && !gatewayGroupLabelsMatch(status.RequiredLabels, gateway.Tags) {
		return false
	}
	if len(status.RequiredCaps) > 0 && !gatewayGroupCapabilitiesMatch(status.RequiredCaps, gateway.Capabilities) {
		return false
	}
	return len(status.RequiredLabels) > 0 || len(status.RequiredCaps) > 0
}

func gatewayGroupIDMatches(values []string, id, name string) bool {
	for _, value := range values {
		if value == "*" || strings.EqualFold(value, id) || strings.EqualFold(value, name) {
			return true
		}
	}
	return false
}

func gatewayGroupLabelsMatch(required, tags []string) bool {
	tagSet := map[string]bool{}
	for _, tag := range tags {
		tagSet[strings.ToLower(strings.TrimSpace(tag))] = true
	}
	for _, label := range required {
		if !tagSet[strings.ToLower(strings.TrimSpace(label))] {
			return false
		}
	}
	return true
}

func gatewayGroupCapabilitiesMatch(required, capabilities []string) bool {
	capSet := map[string]bool{}
	for _, capability := range capabilities {
		capSet[strings.ToLower(strings.TrimSpace(capability))] = true
	}
	for _, capability := range required {
		if !capSet[strings.ToLower(strings.TrimSpace(capability))] {
			return false
		}
	}
	return true
}
