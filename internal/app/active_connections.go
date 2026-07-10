package app

import "sync"

type activeConnectionRegistry struct {
	mu      sync.Mutex
	nextID  uint64
	entries map[string]map[uint64]func() error
}

func (r *activeConnectionRegistry) register(sessionID string, closeConnection func() error) func() {
	if sessionID == "" || closeConnection == nil {
		return func() {}
	}
	r.mu.Lock()
	if r.entries == nil {
		r.entries = map[string]map[uint64]func() error{}
	}
	r.nextID++
	registrationID := r.nextID
	if r.entries[sessionID] == nil {
		r.entries[sessionID] = map[uint64]func() error{}
	}
	r.entries[sessionID][registrationID] = closeConnection
	r.mu.Unlock()

	return func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		connections := r.entries[sessionID]
		delete(connections, registrationID)
		if len(connections) == 0 {
			delete(r.entries, sessionID)
		}
	}
}

func (r *activeConnectionRegistry) disconnect(sessionID string) int {
	r.mu.Lock()
	connections := r.entries[sessionID]
	delete(r.entries, sessionID)
	callbacks := make([]func() error, 0, len(connections))
	for _, closeConnection := range connections {
		callbacks = append(callbacks, closeConnection)
	}
	r.mu.Unlock()

	for _, closeConnection := range callbacks {
		_ = closeConnection()
	}
	return len(callbacks)
}

func (r *activeConnectionRegistry) count(sessionID string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries[sessionID])
}
