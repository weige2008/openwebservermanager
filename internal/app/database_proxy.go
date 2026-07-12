package app

import (
	"context"
	"fmt"
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

type DatabaseProxyManager struct {
	ctx    context.Context
	cancel context.CancelFunc
	store  *store.Store
	logger *slog.Logger

	mu      sync.Mutex
	routes  []proxyListenerRoute
	lastErr string
	active  int64
}

func NewDatabaseProxyManager(ctx context.Context, st *store.Store, logger *slog.Logger) *DatabaseProxyManager {
	if logger == nil {
		logger = slog.Default()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	managerCtx, cancel := context.WithCancel(ctx)
	return &DatabaseProxyManager{ctx: managerCtx, cancel: cancel, store: st, logger: logger}
}

func (m *DatabaseProxyManager) Close() error {
	m.cancel()
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopLocked()
}

func (m *DatabaseProxyManager) Address() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.routes) == 0 {
		return ""
	}
	return m.routes[0].ListenAddress
}

func (m *DatabaseProxyManager) Target() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.routes) == 0 {
		return ""
	}
	return m.routes[0].Target
}

func (m *DatabaseProxyManager) Routes() []proxyRouteStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return proxyRouteStatuses(m.routes)
}

func (m *DatabaseProxyManager) LastError() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastErr
}

func (m *DatabaseProxyManager) ActiveConnections() int {
	return int(atomic.LoadInt64(&m.active))
}

func (m *DatabaseProxyManager) Reload() error {
	item, ok, err := m.proxySetting()
	if err != nil {
		m.setLastError(err.Error())
		return nil
	}
	metadata := map[string]any{}
	if ok && item.Metadata != nil {
		metadata = item.Metadata
	}
	enabled := proxyMetadataBool(metadata["database_proxy_enabled"])
	listenAddress := firstMetadataString(metadata, "database_listen_address")
	allowlist := metadataStrings(metadata["database_forward_allowlist"])
	if !enabled {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.lastErr = ""
		return m.stopLocked()
	}
	if err := validateDatabaseProxyConfig(listenAddress, allowlist); err != nil {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.lastErr = err.Error()
		return m.stopLocked()
	}
	desired, err := buildSequentialProxyRoutes(listenAddress, allowlist)
	if err != nil {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.lastErr = err.Error()
		return m.stopLocked()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if proxyRoutesEqual(m.routes, desired) {
		m.lastErr = ""
		return nil
	}
	previous := proxyRouteStatuses(m.routes)
	_ = m.stopLocked()
	started, err := m.startRoutesLocked(desired)
	if err != nil {
		m.lastErr = err.Error()
		if len(previous) > 0 {
			restored, restoreErr := m.startRoutesLocked(previous)
			if restoreErr != nil {
				m.lastErr += "; restore previous routes: " + restoreErr.Error()
			} else {
				m.routes = restored
				for _, route := range restored {
					go m.acceptLoop(route.listener, route.Target)
				}
			}
		}
		return nil
	}
	m.routes = started
	m.lastErr = ""
	for _, route := range started {
		m.logger.Info("database proxy listening", "addr", route.ListenAddress, "target", route.Target)
		go m.acceptLoop(route.listener, route.Target)
	}
	return nil
}

func (m *DatabaseProxyManager) startRoutesLocked(routes []proxyRouteStatus) ([]proxyListenerRoute, error) {
	started := make([]proxyListenerRoute, 0, len(routes))
	for _, route := range routes {
		listener, err := net.Listen("tcp", route.ListenAddress)
		if err != nil {
			for _, item := range started {
				_ = item.listener.Close()
			}
			return nil, fmt.Errorf("listen database proxy route %s -> %s: %w", route.ListenAddress, route.Target, err)
		}
		started = append(started, proxyListenerRoute{proxyRouteStatus: proxyRouteStatus{ListenAddress: listener.Addr().String(), Target: route.Target}, listener: listener})
	}
	return started, nil
}

func (m *DatabaseProxyManager) proxySetting() (model.PlatformItem, bool, error) {
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

func (m *DatabaseProxyManager) acceptLoop(listener net.Listener, target string) {
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

func (m *DatabaseProxyManager) handleConnection(client net.Conn, target string) {
	started := time.Now()
	remote := client.RemoteAddr().String()
	auditItem, err := beginProxyConnectionAudit(m.store, proxyConnectionAuditSpec{
		Name:        "database_proxy.connect",
		Type:        "database_proxy",
		Description: "proxied database TCP connection",
		Protocol:    model.ProtocolDatabase,
	}, target, remote)
	if err != nil {
		_ = client.Close()
		auditProxyLogPersistFailure(m.store, "database_proxy.log.persist_failed", model.ProtocolDatabase, target, remote, "persist initial database proxy connection log failed: "+err.Error())
		return
	}
	upstream, err := net.DialTimeout("tcp", target, 15*time.Second)
	if err != nil {
		_ = client.Close()
		m.finishAuditConnection(auditItem, "failed", remote, target, 0, 0, time.Since(started), err.Error())
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
	m.finishAuditConnection(auditItem, "success", remote, target, atomic.LoadInt64(&clientToTarget), atomic.LoadInt64(&targetToClient), time.Since(started), "")
}

func (m *DatabaseProxyManager) finishAuditConnection(item model.PlatformItem, status, remote, target string, clientToTarget, targetToClient int64, duration time.Duration, errorText string) {
	if err := finishProxyConnectionAudit(m.store, item, status, clientToTarget, targetToClient, duration, errorText); err != nil {
		auditProxyLogPersistFailure(m.store, "database_proxy.log.finalize_failed", model.ProtocolDatabase, target, remote, "finalize database proxy connection log failed: "+err.Error())
	}
}

func (m *DatabaseProxyManager) setLastError(value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastErr = value
}

func (m *DatabaseProxyManager) stopLocked() error {
	var result error
	for _, route := range m.routes {
		if err := route.listener.Close(); err != nil && result == nil {
			result = err
		}
	}
	m.routes = nil
	return result
}
