package app

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
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

type gatewayRouteDecision struct {
	GatewayGroupID    string
	GatewayGroupName  string
	GatewayID         string
	GatewayName       string
	GatewayCollection string
	GatewayType       string
	Candidates        []gatewayRouteTarget
	AttemptTimeout    time.Duration
	FailureCooldown   time.Duration
	tracker           *gatewayRouteTracker
}

type gatewayRouteTarget struct {
	ID         string
	Name       string
	Collection string
	Type       string
}

type gatewayRouteTracker struct {
	mu     sync.RWMutex
	target gatewayRouteTarget
}

type gatewayRouteError struct {
	Status  int
	Message string
}

func (e gatewayRouteError) Error() string {
	return e.Message
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

func (s *Server) requireAssetGatewayRoute(w http.ResponseWriter, asset model.PlatformItem) (gatewayRouteDecision, bool) {
	route, required, err := s.assetGatewayRoute(asset)
	if err != nil {
		status := http.StatusServiceUnavailable
		if routeErr, ok := err.(gatewayRouteError); ok {
			status = routeErr.Status
		}
		writeError(w, status, err.Error())
		return gatewayRouteDecision{}, false
	}
	if !required {
		return gatewayRouteDecision{}, true
	}
	return route, true
}

func (s *Server) assetGatewayRoute(asset model.PlatformItem) (gatewayRouteDecision, bool, error) {
	groupRef := assetGatewayGroupRef(asset)
	if groupRef == "" {
		return gatewayRouteDecision{}, false, nil
	}
	s.refreshAgentGatewayStatuses()
	groups, err := s.cfg.Store.ListPlatformItems("gateway_groups")
	if err != nil {
		return gatewayRouteDecision{}, true, err
	}
	group, ok := findGatewayGroup(groups, groupRef)
	if !ok {
		return gatewayRouteDecision{}, true, gatewayRouteError{Status: http.StatusBadRequest, Message: "gateway group not found"}
	}
	if !platformItemEnabled(group) {
		return gatewayRouteDecision{}, true, gatewayRouteError{Status: http.StatusServiceUnavailable, Message: "gateway group is disabled"}
	}
	statuses := s.gatewayGroupStatuses([]model.PlatformItem{group})
	if len(statuses) == 0 {
		return gatewayRouteDecision{}, true, gatewayRouteError{Status: http.StatusServiceUnavailable, Message: "gateway group has no online gateway"}
	}
	if statuses[0].SelectedGateway == nil {
		return gatewayRouteDecision{}, true, gatewayRouteError{Status: http.StatusServiceUnavailable, Message: "gateway group has no online gateway"}
	}
	candidates := s.gatewayRouteCandidates(group, statuses[0], asset.Protocol, true)
	if len(candidates) == 0 {
		return gatewayRouteDecision{}, true, gatewayRouteError{Status: http.StatusServiceUnavailable, Message: "gateway group has no compatible online gateway"}
	}
	selected := candidates[0]
	return gatewayRouteDecision{
		GatewayGroupID:    group.ID,
		GatewayGroupName:  group.Name,
		GatewayID:         selected.ID,
		GatewayName:       selected.Name,
		GatewayCollection: selected.Collection,
		GatewayType:       selected.Type,
		Candidates:        candidates,
		AttemptTimeout:    gatewayRouteAttemptTimeout(group),
		FailureCooldown:   gatewayRouteFailureCooldown(group),
		tracker:           &gatewayRouteTracker{target: selected},
	}, true, nil
}

func (s *Server) gatewayRouteCandidates(group model.PlatformItem, status gatewayGroupStatus, protocol model.Protocol, advanceRoundRobin bool) []gatewayRouteTarget {
	targets := make([]gatewayRouteTarget, 0, len(status.Members))
	for _, member := range status.Members {
		if !member.Online || !gatewayRouteMemberSupportsProtocol(member, protocol) {
			continue
		}
		targets = append(targets, gatewayRouteTarget{ID: member.ID, Name: member.Name, Collection: member.Collection, Type: member.Type})
	}
	if status.SelectionMode == "round_robin" && len(targets) > 1 {
		index := s.gatewayRoutes.roundRobinIndex(group.ID, len(targets), advanceRoundRobin)
		targets = append(append([]gatewayRouteTarget(nil), targets[index:]...), targets[:index]...)
	}
	return targets
}

func (s *Server) completeGatewayRoute(route gatewayRouteDecision, protocol model.Protocol) (gatewayRouteDecision, error) {
	if strings.TrimSpace(route.GatewayGroupID) == "" {
		return route, nil
	}
	if len(route.Candidates) > 0 && route.tracker != nil {
		return route, nil
	}
	s.refreshAgentGatewayStatuses()
	groups, err := s.cfg.Store.ListPlatformItems("gateway_groups")
	if err != nil {
		return gatewayRouteDecision{}, err
	}
	group, ok := findGatewayGroup(groups, route.GatewayGroupID)
	if !ok {
		return gatewayRouteDecision{}, errors.New("gateway group not found")
	}
	statuses := s.gatewayGroupStatuses([]model.PlatformItem{group})
	if len(statuses) == 0 {
		return gatewayRouteDecision{}, errors.New("gateway group status is unavailable")
	}
	candidates := s.gatewayRouteCandidates(group, statuses[0], protocol, false)
	if len(candidates) == 0 {
		return gatewayRouteDecision{}, errors.New("gateway group has no compatible online gateway")
	}
	preferredID := strings.TrimSpace(route.GatewayID)
	if preferredID != "" {
		for index, candidate := range candidates {
			if !strings.EqualFold(candidate.ID, preferredID) {
				continue
			}
			candidates = append([]gatewayRouteTarget{candidate}, append(candidates[:index], candidates[index+1:]...)...)
			break
		}
	}
	selected := candidates[0]
	return gatewayRouteDecision{
		GatewayGroupID:    group.ID,
		GatewayGroupName:  group.Name,
		GatewayID:         selected.ID,
		GatewayName:       selected.Name,
		GatewayCollection: selected.Collection,
		GatewayType:       selected.Type,
		Candidates:        candidates,
		AttemptTimeout:    gatewayRouteAttemptTimeout(group),
		FailureCooldown:   gatewayRouteFailureCooldown(group),
		tracker:           &gatewayRouteTracker{target: selected},
	}, nil
}

func (route gatewayRouteDecision) currentTarget() gatewayRouteTarget {
	if route.tracker != nil {
		route.tracker.mu.RLock()
		target := route.tracker.target
		route.tracker.mu.RUnlock()
		if target.ID != "" {
			return target
		}
	}
	return gatewayRouteTarget{ID: route.GatewayID, Name: route.GatewayName, Collection: route.GatewayCollection, Type: route.GatewayType}
}

func (route gatewayRouteDecision) setCurrentTarget(target gatewayRouteTarget) {
	if route.tracker == nil {
		return
	}
	route.tracker.mu.Lock()
	route.tracker.target = target
	route.tracker.mu.Unlock()
}

func assetGatewayGroupRef(asset model.PlatformItem) string {
	return firstMetadataString(asset.Metadata, "gateway_group_id", "gatewayGroupId", "gateway_group", "gatewayGroup", "gateway_group_name")
}

func findGatewayGroup(groups []model.PlatformItem, ref string) (model.PlatformItem, bool) {
	ref = strings.TrimSpace(ref)
	for _, group := range groups {
		if strings.EqualFold(group.ID, ref) || strings.EqualFold(group.Name, ref) {
			return group, true
		}
	}
	return model.PlatformItem{}, false
}

func gatewayRouteMetadata(route gatewayRouteDecision) map[string]any {
	if route.GatewayGroupID == "" {
		return nil
	}
	target := route.currentTarget()
	return map[string]any{
		"gateway_group_id":   route.GatewayGroupID,
		"gateway_group_name": route.GatewayGroupName,
		"gateway_id":         target.ID,
		"gateway_name":       target.Name,
		"gateway_collection": target.Collection,
		"gateway_type":       target.Type,
	}
}

func applyGatewayRouteMetadata(metadata map[string]any, route gatewayRouteDecision) {
	for key, value := range gatewayRouteMetadata(route) {
		metadata[key] = value
	}
}

func applyGatewayRouteSession(session *model.ConnectionSession, route gatewayRouteDecision) {
	if route.GatewayGroupID == "" {
		return
	}
	session.GatewayGroupID = route.GatewayGroupID
	target := route.currentTarget()
	session.GatewayID = target.ID
	session.GatewayName = target.Name
	session.GatewayCollection = target.Collection
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
			if gateway.Online {
				if failure, unavailable := s.gatewayRoutes.health(group.ID, gateway.ID, now); unavailable {
					gateway.Online = false
					gateway.Status = "cooldown"
					gateway.Metadata["route_failure_count"] = failure.Count
					gateway.Metadata["route_last_error"] = failure.LastError
					gateway.Metadata["route_last_failure_at"] = failure.LastFailure.Format(time.RFC3339Nano)
					gateway.Metadata["route_unavailable_until"] = failure.Unavailable.Format(time.RFC3339Nano)
				}
			}
			status.Members = append(status.Members, gateway)
			if gateway.Online {
				status.Online++
			} else {
				status.Offline++
			}
		}
		switch status.SelectionMode {
		case "manual":
			sort.SliceStable(status.Members, func(i, j int) bool {
				return gatewayGroupManualOrder(status.MemberIDs, status.Members[i]) < gatewayGroupManualOrder(status.MemberIDs, status.Members[j])
			})
		case "least_sessions":
			sort.SliceStable(status.Members, func(i, j int) bool {
				left := status.Members[i]
				right := status.Members[j]
				if left.Online != right.Online {
					return left.Online
				}
				if left.ActiveSessions != right.ActiveSessions {
					return left.ActiveSessions < right.ActiveSessions
				}
				if left.LatencyMS != right.LatencyMS {
					return left.LatencyMS < right.LatencyMS
				}
				return left.Name < right.Name
			})
		case "round_robin":
			sort.SliceStable(status.Members, func(i, j int) bool {
				if status.Members[i].Online != status.Members[j].Online {
					return status.Members[i].Online
				}
				return status.Members[i].Name < status.Members[j].Name
			})
		default:
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
		onlineMembers := make([]gatewayGroupMember, 0, len(status.Members))
		for _, member := range status.Members {
			if !member.Online {
				continue
			}
			onlineMembers = append(onlineMembers, member)
		}
		if len(onlineMembers) > 0 {
			selectedIndex := 0
			if status.SelectionMode == "round_robin" {
				selectedIndex = s.gatewayRoutes.roundRobinIndex(group.ID, len(onlineMembers), false)
			}
			selected := onlineMembers[selectedIndex]
			status.SelectedGatewayID = selected.ID
			status.SelectedGateway = &selected
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
	case "round-robin", "round_robin", "roundrobin":
		return "round_robin"
	case "least-sessions", "least_sessions":
		return "least_sessions"
	case "least-latency", "least_latency":
		return "least_latency"
	case "auto", "automatic", "label", "labels", "capability", "capabilities":
		return "auto"
	default:
		return "manual"
	}
}

func gatewayRouteAttemptTimeout(group model.PlatformItem) time.Duration {
	seconds := metadataIntDefault(group.Metadata["attempt_timeout_seconds"], 5)
	return time.Duration(clampInt(seconds, 1, 20, 5)) * time.Second
}

func gatewayRouteFailureCooldown(group model.PlatformItem) time.Duration {
	seconds := metadataIntDefault(group.Metadata["failure_cooldown_seconds"], 30)
	return time.Duration(clampInt(seconds, 1, 300, 30)) * time.Second
}

func gatewayRouteMemberSupportsProtocol(member gatewayGroupMember, protocol model.Protocol) bool {
	if len(member.Capabilities) == 0 || protocol == "" {
		return true
	}
	wanted := strings.ToLower(strings.TrimSpace(string(protocol)))
	for _, capability := range member.Capabilities {
		value := strings.ToLower(strings.TrimSpace(capability))
		if value == "tcp" || value == wanted {
			return true
		}
		if wanted == "http" && (value == "https" || value == "web") {
			return true
		}
		if wanted == "database" && (value == "mysql" || value == "postgres" || value == "postgresql") {
			return true
		}
	}
	return false
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
