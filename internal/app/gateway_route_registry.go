package app

import (
	"strings"
	"sync"
	"time"
)

type gatewayRouteFailureState struct {
	Count       int
	LastFailure time.Time
	Unavailable time.Time
	LastError   string
}

type gatewayRouteRegistry struct {
	mu         sync.Mutex
	failures   map[string]gatewayRouteFailureState
	roundRobin map[string]uint64
}

func (r *gatewayRouteRegistry) failure(groupID, gatewayID, detail string, cooldown time.Duration, now time.Time) gatewayRouteFailureState {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failures == nil {
		r.failures = map[string]gatewayRouteFailureState{}
	}
	key := gatewayRouteRegistryKey(groupID, gatewayID)
	state := r.failures[key]
	state.Count++
	state.LastFailure = now
	state.Unavailable = now.Add(cooldown)
	state.LastError = strings.TrimSpace(detail)
	r.failures[key] = state
	return state
}

func (r *gatewayRouteRegistry) success(groupID, gatewayID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.failures, gatewayRouteRegistryKey(groupID, gatewayID))
}

func (r *gatewayRouteRegistry) health(groupID, gatewayID string, now time.Time) (gatewayRouteFailureState, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.failures[gatewayRouteRegistryKey(groupID, gatewayID)]
	if !ok {
		return gatewayRouteFailureState{}, false
	}
	if !state.Unavailable.After(now) {
		delete(r.failures, gatewayRouteRegistryKey(groupID, gatewayID))
		return gatewayRouteFailureState{}, false
	}
	return state, true
}

func (r *gatewayRouteRegistry) roundRobinIndex(groupID string, count int, advance bool) int {
	if count <= 0 {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.roundRobin == nil {
		r.roundRobin = map[string]uint64{}
	}
	key := strings.ToLower(strings.TrimSpace(groupID))
	value := r.roundRobin[key]
	if advance {
		r.roundRobin[key] = value + 1
	}
	return int(value % uint64(count))
}

func gatewayRouteRegistryKey(groupID, gatewayID string) string {
	return strings.ToLower(strings.TrimSpace(groupID)) + "\x00" + strings.ToLower(strings.TrimSpace(gatewayID))
}
