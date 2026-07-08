package app

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"openwebservermanager/internal/model"
	"openwebservermanager/internal/store"
)

type RDPProxyManager struct {
	ctx    context.Context
	cancel context.CancelFunc
	store  *store.Store
	logger *slog.Logger

	mu       sync.Mutex
	listener net.Listener
	address  string
	target   string
	lastErr  string
	active   int64
}

func NewRDPProxyManager(ctx context.Context, st *store.Store, logger *slog.Logger) *RDPProxyManager {
	if logger == nil {
		logger = slog.Default()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	managerCtx, cancel := context.WithCancel(ctx)
	return &RDPProxyManager{ctx: managerCtx, cancel: cancel, store: st, logger: logger}
}

func (m *RDPProxyManager) Close() error {
	m.cancel()
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopLocked()
}

func (m *RDPProxyManager) Address() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.address
}

func (m *RDPProxyManager) Target() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.target
}

func (m *RDPProxyManager) LastError() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastErr
}

func (m *RDPProxyManager) ActiveConnections() int {
	return int(atomic.LoadInt64(&m.active))
}

func (m *RDPProxyManager) Reload() error {
	item, ok, err := m.proxySetting()
	if err != nil {
		m.setLastError(err.Error())
		return nil
	}
	metadata := map[string]any{}
	if ok && item.Metadata != nil {
		metadata = item.Metadata
	}
	enabled := proxyMetadataBool(metadata["rdp_proxy_enabled"])
	listenAddress := firstMetadataString(metadata, "rdp_listen_address")
	allowlist := metadataStrings(metadata["rdp_forward_allowlist"])
	if !enabled {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.lastErr = ""
		m.target = ""
		return m.stopLocked()
	}
	if err := validateRDPProxyConfig(listenAddress, allowlist); err != nil {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.lastErr = err.Error()
		m.target = ""
		return m.stopLocked()
	}
	target := strings.TrimSpace(allowlist[0])

	m.mu.Lock()
	if m.listener != nil && m.address == listenAddress && m.target == target {
		m.lastErr = ""
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()

	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.lastErr = err.Error()
		m.target = target
		return m.stopLocked()
	}

	m.mu.Lock()
	_ = m.stopLocked()
	m.listener = listener
	m.address = listener.Addr().String()
	m.target = target
	m.lastErr = ""
	m.mu.Unlock()

	m.logger.Info("rdp proxy listening", "addr", listener.Addr().String(), "target", target)
	go m.acceptLoop(listener, target)
	return nil
}

func (m *RDPProxyManager) proxySetting() (model.PlatformItem, bool, error) {
	items, err := m.store.ListPlatformItems("system_settings")
	if err != nil {
		return model.PlatformItem{}, false, err
	}
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item.Type), "proxy") {
			return m.store.GetPlatformItem("system_settings", item.ID)
		}
	}
	return model.PlatformItem{}, false, nil
}

func (m *RDPProxyManager) acceptLoop(listener net.Listener, target string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if m.ctx.Err() != nil || strings.Contains(strings.ToLower(err.Error()), "closed") {
				return
			}
			m.setLastError(err.Error())
			return
		}
		go m.handleConnection(conn, target)
	}
}

func (m *RDPProxyManager) handleConnection(client net.Conn, target string) {
	started := time.Now()
	remote := client.RemoteAddr().String()
	upstream, err := net.DialTimeout("tcp", target, 15*time.Second)
	if err != nil {
		_ = client.Close()
		m.auditConnection("failed", remote, target, 0, 0, time.Since(started), err.Error())
		return
	}
	atomic.AddInt64(&m.active, 1)
	defer atomic.AddInt64(&m.active, -1)

	done := make(chan struct{}, 2)
	var clientToTarget int64
	var targetToClient int64
	go func() {
		n, _ := io.Copy(upstream, client)
		atomic.AddInt64(&clientToTarget, n)
		_ = upstream.Close()
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(client, upstream)
		atomic.AddInt64(&targetToClient, n)
		_ = client.Close()
		done <- struct{}{}
	}()
	<-done
	_ = client.Close()
	_ = upstream.Close()
	<-done
	m.auditConnection("success", remote, target, atomic.LoadInt64(&clientToTarget), atomic.LoadInt64(&targetToClient), time.Since(started), "")
}

func (m *RDPProxyManager) auditConnection(status, remote, target string, clientToTarget, targetToClient int64, duration time.Duration, errorText string) {
	if m.store == nil {
		return
	}
	if _, err := m.store.CreatePlatformItem("operation_logs", model.PlatformItemRequest{
		Name:        "rdp_proxy.connect",
		Type:        "rdp_proxy",
		Status:      status,
		Protocol:    model.ProtocolRDP,
		TargetID:    target,
		Description: "proxied rdp TCP connection",
		Metadata: map[string]any{
			"client":                 remote,
			"target":                 target,
			"client_to_target_bytes": clientToTarget,
			"target_to_client_bytes": targetToClient,
			"duration_ms":            duration.Milliseconds(),
			"error":                  errorText,
		},
	}); err != nil {
		auditProxyLogPersistFailure(m.store, "rdp_proxy.log.persist_failed", model.ProtocolRDP, target, remote, "persist rdp proxy connection log failed: "+err.Error())
	}
}

func (m *RDPProxyManager) setLastError(value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastErr = value
}

func (m *RDPProxyManager) stopLocked() error {
	var err error
	if m.listener != nil {
		err = m.listener.Close()
	}
	m.listener = nil
	m.address = ""
	return err
}
