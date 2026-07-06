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

type DatabaseProxyManager struct {
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
	return m.address
}

func (m *DatabaseProxyManager) Target() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.target
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
		m.target = ""
		return m.stopLocked()
	}
	if err := validateDatabaseProxyConfig(listenAddress, allowlist); err != nil {
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

	m.logger.Info("database proxy listening", "addr", listener.Addr().String(), "target", target)
	go m.acceptLoop(listener, target)
	return nil
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

func (m *DatabaseProxyManager) auditConnection(status, remote, target string, clientToTarget, targetToClient int64, duration time.Duration, errorText string) {
	if m.store == nil {
		return
	}
	_, _ = m.store.CreatePlatformItem("operation_logs", model.PlatformItemRequest{
		Name:        "database_proxy.connect",
		Type:        "database_proxy",
		Status:      status,
		TargetID:    target,
		Description: "proxied database TCP connection",
		Metadata: map[string]any{
			"client":                 remote,
			"target":                 target,
			"client_to_target_bytes": clientToTarget,
			"target_to_client_bytes": targetToClient,
			"duration_ms":            duration.Milliseconds(),
			"error":                  errorText,
		},
	})
}

func (m *DatabaseProxyManager) setLastError(value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastErr = value
}

func (m *DatabaseProxyManager) stopLocked() error {
	var err error
	if m.listener != nil {
		err = m.listener.Close()
	}
	m.listener = nil
	m.address = ""
	return err
}
