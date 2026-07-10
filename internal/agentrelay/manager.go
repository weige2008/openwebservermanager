package agentrelay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"openwebservermanager/internal/model"
	"openwebservermanager/internal/store"
)

var (
	ErrClaimTimeout   = errors.New("agent relay claim timed out")
	ErrTunnelNotFound = errors.New("agent relay tunnel not found")
)

type DialRequest struct {
	GatewayID string
	SessionID string
	UserID    string
	Target    string
	Protocol  model.Protocol
	Timeout   time.Duration
}

type Manager struct {
	mu      sync.Mutex
	store   *store.Store
	pending map[string][]*tunnel
	signals map[string]chan struct{}
	tunnels map[string]*tunnel
}

type tunnel struct {
	id        string
	gatewayID string
	sessionID string
	userID    string
	target    string
	protocol  model.Protocol
	deadline  time.Time
	client    net.Conn
	peer      net.Conn
	ready     chan error
	connected chan struct{}
	readyOnce sync.Once
	closeOnce sync.Once
	closed    chan struct{}
	logItem   model.PlatformItem
	down      bool
	up        bool
}

type managedConn struct {
	net.Conn
	close      func()
	once       sync.Once
	remoteAddr net.Addr
}

func (c *managedConn) Close() error {
	c.once.Do(c.close)
	return nil
}

func (c *managedConn) RemoteAddr() net.Addr {
	if c.remoteAddr != nil {
		return c.remoteAddr
	}
	return c.Conn.RemoteAddr()
}

type relayAddr string

func (a relayAddr) Network() string { return "tcp" }
func (a relayAddr) String() string  { return string(a) }

func NewManager(st *store.Store) *Manager {
	return &Manager{
		store:   st,
		pending: map[string][]*tunnel{},
		signals: map[string]chan struct{}{},
		tunnels: map[string]*tunnel{},
	}
}

func (m *Manager) Dial(ctx context.Context, req DialRequest) (net.Conn, error) {
	if m == nil {
		return nil, errors.New("agent relay manager is unavailable")
	}
	req.GatewayID = strings.TrimSpace(req.GatewayID)
	req.SessionID = strings.TrimSpace(req.SessionID)
	req.UserID = strings.TrimSpace(req.UserID)
	req.Target = strings.TrimSpace(req.Target)
	if req.GatewayID == "" {
		return nil, errors.New("agent gateway id is required")
	}
	if err := validateTarget(req.Target); err != nil {
		return nil, err
	}
	if req.Timeout <= 0 {
		req.Timeout = 20 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()
	client, peer := net.Pipe()
	id, err := randomTunnelID()
	if err != nil {
		_ = client.Close()
		_ = peer.Close()
		return nil, err
	}
	t := &tunnel{
		id:        id,
		gatewayID: req.GatewayID,
		sessionID: req.SessionID,
		userID:    req.UserID,
		target:    req.Target,
		protocol:  req.Protocol,
		deadline:  time.Now().UTC().Add(req.Timeout),
		client:    client,
		peer:      peer,
		ready:     make(chan error, 1),
		connected: make(chan struct{}),
		closed:    make(chan struct{}),
	}
	if err := m.beginLog(t); err != nil {
		_ = client.Close()
		_ = peer.Close()
		return nil, err
	}
	m.enqueue(t)
	select {
	case err := <-t.ready:
		if err != nil {
			m.finish(t, "failed", err.Error())
			return nil, err
		}
		if err := m.updateLog(t, "connected", "agent relay connected"); err != nil {
			m.finish(t, "failed", err.Error())
			return nil, err
		}
		close(t.connected)
		return &managedConn{Conn: client, remoteAddr: relayAddr(req.Target), close: func() { m.finish(t, "closed", "manager connection closed") }}, nil
	case <-dialCtx.Done():
		err := fmt.Errorf("agent gateway %s did not open %s before timeout: %w", req.GatewayID, req.Target, dialCtx.Err())
		m.finish(t, "failed", err.Error())
		return nil, err
	}
}

func (m *Manager) Claim(ctx context.Context, gatewayID string) (Claim, error) {
	gatewayID = strings.TrimSpace(gatewayID)
	if gatewayID == "" {
		return Claim{}, errors.New("agent gateway id is required")
	}
	for {
		m.mu.Lock()
		queue := m.pending[gatewayID]
		for len(queue) > 0 {
			t := queue[0]
			queue = queue[1:]
			m.pending[gatewayID] = queue
			select {
			case <-t.closed:
				continue
			default:
			}
			m.mu.Unlock()
			return Claim{TunnelID: t.id, Target: t.target, Protocol: string(t.protocol), Deadline: t.deadline}, nil
		}
		signal := m.signalLocked(gatewayID)
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return Claim{}, ErrClaimTimeout
		case <-signal:
		}
	}
}

func (m *Manager) Ready(ctx context.Context, gatewayID, tunnelID string) error {
	t, err := m.authorizedTunnel(gatewayID, tunnelID)
	if err != nil {
		return err
	}
	t.readyOnce.Do(func() { t.ready <- nil })
	select {
	case <-t.connected:
		return nil
	case <-t.closed:
		return ErrTunnelNotFound
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) Fail(gatewayID, tunnelID string, relayErr error) error {
	t, err := m.authorizedTunnel(gatewayID, tunnelID)
	if err != nil {
		return err
	}
	if relayErr == nil {
		relayErr = errors.New("agent failed to open target")
	}
	t.readyOnce.Do(func() { t.ready <- relayErr })
	m.finish(t, "failed", relayErr.Error())
	return nil
}

func (m *Manager) CopyDown(ctx context.Context, gatewayID, tunnelID string, ready func(), dst io.Writer) error {
	t, err := m.startStream(gatewayID, tunnelID, "down")
	if err != nil {
		return err
	}
	if ready != nil {
		ready()
	}
	defer m.finish(t, "closed", "agent relay download stream closed")
	stop := context.AfterFunc(ctx, func() {
		m.finish(t, "closed", "agent relay download request canceled")
	})
	defer stop()
	_, err = io.Copy(dst, t.peer)
	return err
}

func (m *Manager) CopyUp(ctx context.Context, gatewayID, tunnelID string, src io.Reader) error {
	t, err := m.startStream(gatewayID, tunnelID, "up")
	if err != nil {
		return err
	}
	defer m.finish(t, "closed", "agent relay upload stream closed")
	stop := context.AfterFunc(ctx, func() {
		m.finish(t, "closed", "agent relay upload request canceled")
	})
	defer stop()
	_, err = io.Copy(t.peer, src)
	return err
}

func (m *Manager) enqueue(t *tunnel) {
	m.mu.Lock()
	m.tunnels[t.id] = t
	m.pending[t.gatewayID] = append(m.pending[t.gatewayID], t)
	signal := m.signalLocked(t.gatewayID)
	close(signal)
	m.signals[t.gatewayID] = make(chan struct{})
	m.mu.Unlock()
}

func (m *Manager) signalLocked(gatewayID string) chan struct{} {
	signal := m.signals[gatewayID]
	if signal == nil {
		signal = make(chan struct{})
		m.signals[gatewayID] = signal
	}
	return signal
}

func (m *Manager) authorizedTunnel(gatewayID, tunnelID string) (*tunnel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.tunnels[strings.TrimSpace(tunnelID)]
	if t == nil || strings.TrimSpace(gatewayID) != t.gatewayID {
		return nil, ErrTunnelNotFound
	}
	select {
	case <-t.closed:
		return nil, ErrTunnelNotFound
	default:
		return t, nil
	}
}

func (m *Manager) startStream(gatewayID, tunnelID, direction string) (*tunnel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.tunnels[strings.TrimSpace(tunnelID)]
	if t == nil || strings.TrimSpace(gatewayID) != t.gatewayID {
		return nil, ErrTunnelNotFound
	}
	switch direction {
	case "down":
		if t.down {
			return nil, errors.New("agent relay download stream already opened")
		}
		t.down = true
	case "up":
		if t.up {
			return nil, errors.New("agent relay upload stream already opened")
		}
		t.up = true
	default:
		return nil, errors.New("invalid agent relay stream direction")
	}
	return t, nil
}

func (m *Manager) finish(t *tunnel, status, detail string) {
	if t == nil {
		return
	}
	t.closeOnce.Do(func() {
		m.mu.Lock()
		delete(m.tunnels, t.id)
		queue := m.pending[t.gatewayID]
		for index, pending := range queue {
			if pending == t {
				queue = append(queue[:index], queue[index+1:]...)
				break
			}
		}
		if len(queue) == 0 {
			delete(m.pending, t.gatewayID)
		} else {
			m.pending[t.gatewayID] = queue
		}
		m.mu.Unlock()
		close(t.closed)
		_ = t.client.Close()
		_ = t.peer.Close()
		if err := m.updateLog(t, status, detail); err != nil && m.store != nil {
			_ = m.store.Audit(model.AuditLog{UserID: valueOr(t.userID, "system"), Action: "agent_relay.log.persist_failed", TargetID: t.sessionID, Protocol: t.protocol, Detail: err.Error()})
		}
		if m.store != nil {
			_ = m.store.Audit(model.AuditLog{UserID: valueOr(t.userID, "system"), Action: "agent_relay." + status, TargetID: t.sessionID, Protocol: t.protocol, Detail: detail})
		}
	})
}

func (m *Manager) beginLog(t *tunnel) error {
	if m.store == nil {
		return nil
	}
	item, err := m.store.CreatePlatformItem("operation_logs", model.PlatformItemRequest{
		Name:        "agent.relay",
		Type:        "agent_relay",
		Status:      "requested",
		Protocol:    t.protocol,
		TargetID:    t.sessionID,
		OwnerID:     valueOr(t.userID, "system"),
		Description: "agent relay requested",
		Metadata: map[string]any{
			"tunnel_id":  t.id,
			"gateway_id": t.gatewayID,
			"session_id": t.sessionID,
			"target":     t.target,
			"protocol":   t.protocol,
		},
	})
	if err != nil {
		return fmt.Errorf("persist agent relay operation log failed: %w", err)
	}
	t.logItem = item
	return nil
}

func (m *Manager) updateLog(t *tunnel, status, detail string) error {
	if m.store == nil || t.logItem.ID == "" {
		return nil
	}
	item := t.logItem
	item.Status = status
	item.Description = detail
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	item.Metadata["relay_status"] = status
	item.Metadata["relay_detail"] = detail
	item.Metadata["updated_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	saved, err := m.store.SavePlatformItem("operation_logs", item)
	if err != nil {
		return fmt.Errorf("persist agent relay operation log failed: %w", err)
	}
	t.logItem = saved
	return nil
}

func validateTarget(target string) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
		return errors.New("agent relay target must be host:port")
	}
	return nil
}

func randomTunnelID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate agent relay tunnel id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}
