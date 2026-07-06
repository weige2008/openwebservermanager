package sshsession

import (
	"context"
	"log/slog"
	"strings"
	"sync"

	"openwebservermanager/internal/store"
)

type GatewayManager struct {
	mu              sync.Mutex
	ctx             context.Context
	store           *store.Store
	dataDir         string
	overrideAddress string
	logger          *slog.Logger
	gateway         *Gateway
	signature       string
	lastError       string
}

func NewGatewayManager(ctx context.Context, st *store.Store, dataDir, overrideAddress string, logger *slog.Logger) *GatewayManager {
	if ctx == nil {
		ctx = context.Background()
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &GatewayManager{
		ctx:             ctx,
		store:           st,
		dataDir:         dataDir,
		overrideAddress: overrideAddress,
		logger:          logger,
	}
}

func (m *GatewayManager) Reload() error {
	if m == nil {
		return nil
	}
	cfg, err := GatewayConfigFromStore(m.store, m.dataDir, m.overrideAddress)
	if err != nil {
		m.setLastError(err)
		return err
	}
	cfg.Logger = m.logger
	return m.apply(cfg)
}

func (m *GatewayManager) Address() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.gateway == nil {
		return ""
	}
	return m.gateway.Address()
}

func (m *GatewayManager) LastError() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastError
}

func (m *GatewayManager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	gateway := m.gateway
	m.gateway = nil
	m.signature = ""
	m.mu.Unlock()
	if gateway == nil {
		return nil
	}
	return gateway.Close()
}

func (m *GatewayManager) apply(cfg GatewayConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	signature := gatewayConfigSignature(cfg)
	if !cfg.Enabled {
		if m.gateway != nil {
			if err := m.gateway.Close(); err != nil {
				m.lastError = err.Error()
				return err
			}
		}
		m.gateway = nil
		m.signature = signature
		m.lastError = ""
		return nil
	}
	if m.gateway != nil && m.signature == signature {
		m.lastError = ""
		return nil
	}
	if m.gateway != nil {
		if err := m.gateway.Close(); err != nil {
			m.lastError = err.Error()
			return err
		}
		m.gateway = nil
	}
	gateway, err := StartGateway(m.ctx, cfg)
	if err != nil {
		m.signature = ""
		m.lastError = err.Error()
		return err
	}
	m.gateway = gateway
	m.signature = signature
	m.lastError = ""
	return nil
}

func (m *GatewayManager) setLastError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err == nil {
		m.lastError = ""
		return
	}
	m.lastError = err.Error()
}

func gatewayConfigSignature(cfg GatewayConfig) string {
	return strings.Join([]string{
		boolSignaturePart(cfg.Enabled),
		cfg.Address,
		boolSignaturePart(cfg.DisablePasswordAuth),
		cfg.HostKeyPEM,
		cfg.DataDir,
		cfg.KnownHostsPath,
	}, "\x00")
}

func boolSignaturePart(value bool) string {
	if value {
		return "1"
	}
	return "0"
}
