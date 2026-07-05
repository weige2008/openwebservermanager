package app

import (
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"openwebservermanager/internal/model"
)

func (s *Server) handleAccessStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	logs, err := s.cfg.Store.ListPlatformItems("access_logs")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	now := time.Now().UTC()
	items := buildAccessStatItems(logs, now)
	_ = s.audit(r, "access_stats.read", "access_stats", model.ProtocolHTTP, "computed access statistics")
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "generated_at": now})
}

func buildAccessStatItems(logs []model.PlatformItem, now time.Time) []model.PlatformItem {
	total := len(logs)
	statuses := map[string]int{}
	methods := map[string]int{}
	pages := map[string]int{}
	referrers := map[string]int{}
	assets := map[string]int{}
	users := map[string]bool{}
	ips := map[string]bool{}
	var trafficBytes int64
	var durationTotal int64
	var errors int
	var firstSeen time.Time
	var lastSeen time.Time

	for _, item := range logs {
		if firstSeen.IsZero() || item.CreatedAt.Before(firstSeen) {
			firstSeen = item.CreatedAt
		}
		if lastSeen.IsZero() || item.CreatedAt.After(lastSeen) {
			lastSeen = item.CreatedAt
		}
		statusCode := accessLogInt(item, "status_code")
		if statusCode == 0 {
			statusCode, _ = strconv.Atoi(strings.TrimSpace(item.Status))
		}
		if statusCode == 0 {
			statusCode = http.StatusOK
		}
		if statusCode >= 400 {
			errors++
		}
		statuses[strconv.Itoa(statusCode)]++

		method := strings.ToUpper(firstAccessLogString(item, "method"))
		if method == "" {
			method = strings.ToUpper(strings.TrimSpace(item.Type))
		}
		if method == "" {
			method = "UNKNOWN"
		}
		methods[method]++

		uri := normalizeAccessURI(firstAccessLogString(item, "uri"))
		if uri == "" {
			uri = item.Name
		}
		pages[uri]++

		referrer := normalizeReferrer(firstAccessLogString(item, "referer", "referrer"))
		referrers[referrer]++

		assetName := firstAccessLogString(item, "asset_name")
		if assetName == "" {
			assetName = item.TargetID
		}
		if assetName == "" {
			assetName = "unknown"
		}
		assets[assetName]++

		if item.OwnerID != "" {
			users[item.OwnerID] = true
		} else if user := firstAccessLogString(item, "user", "username"); user != "" {
			users[user] = true
		}
		if ip := firstAccessLogString(item, "client_ip", "ip"); ip != "" {
			ips[ip] = true
		}
		trafficBytes += accessLogInt64(item, "response_size", "bytes", "traffic")
		durationTotal += accessLogInt64(item, "duration_ms", "latency_ms")
	}

	avgDuration := int64(0)
	errorRate := 0.0
	if total > 0 {
		avgDuration = durationTotal / int64(total)
		errorRate = float64(errors) / float64(total)
	}
	return []model.PlatformItem{
		accessStatItem("access-stat-summary", "访问总览", "summary", now, map[string]any{
			"request_count":       total,
			"pv":                  total,
			"uv":                  len(users),
			"unique_ips":          len(ips),
			"traffic_bytes":       trafficBytes,
			"average_duration_ms": avgDuration,
			"error_count":         errors,
			"error_rate":          errorRate,
			"success_count":       total - errors,
			"first_seen":          firstSeen,
			"last_seen":           lastSeen,
		}),
		accessStatItem("access-stat-status", "状态码分布", "status_codes", now, map[string]any{"entries": topCounterEntries(statuses, 20)}),
		accessStatItem("access-stat-methods", "请求方法", "methods", now, map[string]any{"entries": topCounterEntries(methods, 20)}),
		accessStatItem("access-stat-pages", "热门页面", "top_pages", now, map[string]any{"entries": topCounterEntries(pages, 20)}),
		accessStatItem("access-stat-referrers", "来源统计", "referrers", now, map[string]any{"entries": topCounterEntries(referrers, 20)}),
		accessStatItem("access-stat-assets", "资产访问排行", "assets", now, map[string]any{"entries": topCounterEntries(assets, 20)}),
	}
}

func accessStatItem(id, name, kind string, now time.Time, metadata map[string]any) model.PlatformItem {
	return model.PlatformItem{
		ID:          id,
		Module:      "access_stats",
		Name:        name,
		Type:        kind,
		Status:      "computed",
		Protocol:    model.ProtocolHTTP,
		Description: "computed from access logs",
		Metadata:    metadata,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

func topCounterEntries(counter map[string]int, limit int) []map[string]any {
	type pair struct {
		Key   string
		Value int
	}
	pairs := make([]pair, 0, len(counter))
	for key, value := range counter {
		pairs = append(pairs, pair{Key: key, Value: value})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Value == pairs[j].Value {
			return pairs[i].Key < pairs[j].Key
		}
		return pairs[i].Value > pairs[j].Value
	})
	if limit > 0 && len(pairs) > limit {
		pairs = pairs[:limit]
	}
	result := make([]map[string]any, 0, len(pairs))
	for _, pair := range pairs {
		result = append(result, map[string]any{"key": pair.Key, "value": pair.Value})
	}
	return result
}

func normalizeAccessURI(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err == nil && parsed.Path != "" {
		return parsed.Path
	}
	return strings.Split(raw, "?")[0]
}

func normalizeReferrer(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "direct"
	}
	parsed, err := url.Parse(raw)
	if err == nil && parsed.Host != "" {
		return parsed.Host
	}
	return raw
}

func firstAccessLogString(item model.PlatformItem, keys ...string) string {
	for _, key := range keys {
		values := metadataStrings(item.Metadata[key])
		if len(values) == 0 {
			continue
		}
		if value := strings.TrimSpace(values[0]); value != "" {
			return value
		}
	}
	return ""
}

func accessLogInt(item model.PlatformItem, key string) int {
	value, _ := metadataInt(item.Metadata[key])
	return value
}

func accessLogInt64(item model.PlatformItem, keys ...string) int64 {
	for _, key := range keys {
		switch value := item.Metadata[key].(type) {
		case int:
			return int64(value)
		case int64:
			return value
		case float64:
			return int64(value)
		case string:
			parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			if err == nil {
				return parsed
			}
		}
	}
	return 0
}
