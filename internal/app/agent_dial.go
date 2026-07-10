package app

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"openwebservermanager/internal/agentrelay"
	"openwebservermanager/internal/guac"
	"openwebservermanager/internal/model"
	sshrunner "openwebservermanager/internal/ssh"
)

func (s *Server) sshSessionDialContext(session model.ConnectionSession) sshrunner.DialContextFunc {
	if strings.TrimSpace(session.GatewayGroupID) == "" {
		return nil
	}
	dialContext, err := s.agentGatewayDialContext(gatewayRouteDecision{
		GatewayGroupID:    session.GatewayGroupID,
		GatewayID:         session.GatewayID,
		GatewayName:       session.GatewayName,
		GatewayCollection: session.GatewayCollection,
	}, session.ID, session.UserID, model.ProtocolSSH)
	if err != nil {
		return func(context.Context, string, string) (net.Conn, error) { return nil, err }
	}
	return dialContext
}

func (s *Server) agentGatewayDialContext(route gatewayRouteDecision, sessionID, userID string, protocol model.Protocol) (sshrunner.DialContextFunc, error) {
	if strings.TrimSpace(route.GatewayGroupID) == "" {
		return nil, nil
	}
	if strings.TrimSpace(route.GatewayCollection) != "agent_gateways" {
		return nil, errors.New("selected gateway does not provide an agent relay data plane")
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			return nil, errors.New("agent gateway only supports tcp connections")
		}
		return s.agentRelay.Dial(ctx, agentrelay.DialRequest{
			GatewayID: route.GatewayID,
			SessionID: sessionID,
			UserID:    userID,
			Target:    address,
			Protocol:  protocol,
			Timeout:   20 * time.Second,
		})
	}, nil
}

type desktopAgentRelay struct {
	listener net.Listener
	cancel   context.CancelFunc
	mu       sync.Mutex
	local    net.Conn
	remote   net.Conn
	closed   bool
	once     sync.Once
}

func (s *Server) prepareDesktopAgentRelay(ctx context.Context, cfg guac.DesktopConfig) (guac.DesktopConfig, func(), error) {
	if strings.TrimSpace(cfg.Session.GatewayGroupID) == "" {
		return cfg, func() {}, nil
	}
	if strings.TrimSpace(cfg.Session.GatewayCollection) != "agent_gateways" {
		return guac.DesktopConfig{}, nil, errors.New("selected gateway does not provide an agent relay data plane")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return guac.DesktopConfig{}, nil, err
	}
	relayCtx, cancel := context.WithCancel(ctx)
	relay := &desktopAgentRelay{listener: listener, cancel: cancel}
	target := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	go relay.serve(relayCtx, func(dialCtx context.Context) (net.Conn, error) {
		return s.agentRelay.Dial(dialCtx, agentrelay.DialRequest{
			GatewayID: cfg.Session.GatewayID,
			SessionID: cfg.Session.ID,
			UserID:    cfg.Session.UserID,
			Target:    target,
			Protocol:  cfg.Protocol,
			Timeout:   20 * time.Second,
		})
	}, func(relayErr error) {
		now := time.Now().UTC()
		_, _ = s.cfg.Store.UpdateSession(cfg.Session.ID, func(item *model.ConnectionSession) {
			item.Status = model.SessionFailed
			item.Error = relayErr.Error()
			item.EndedAt = &now
		})
	})
	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		relay.Close()
		return guac.DesktopConfig{}, nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		relay.Close()
		return guac.DesktopConfig{}, nil, err
	}
	cfg.Host = host
	cfg.Port = port
	return cfg, relay.Close, nil
}

func (r *desktopAgentRelay) serve(ctx context.Context, dial func(context.Context) (net.Conn, error), failed func(error)) {
	local, err := r.listener.Accept()
	if err != nil {
		return
	}
	_ = r.listener.Close()
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		_ = local.Close()
		return
	}
	r.local = local
	r.mu.Unlock()
	remote, err := dial(ctx)
	if err != nil {
		_ = local.Close()
		if ctx.Err() == nil && failed != nil {
			failed(err)
		}
		return
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		_ = remote.Close()
		_ = local.Close()
		return
	}
	r.remote = remote
	r.mu.Unlock()
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(remote, local)
		closeConnWrite(remote)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(local, remote)
		closeConnWrite(local)
		done <- struct{}{}
	}()
	for completed := 0; completed < 2; completed++ {
		select {
		case <-done:
		case <-ctx.Done():
			r.Close()
			for remaining := 2 - completed; remaining > 0; remaining-- {
				<-done
			}
			return
		}
	}
	r.Close()
}

func closeConnWrite(conn net.Conn) {
	if halfCloser, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = halfCloser.CloseWrite()
	}
}

func (r *desktopAgentRelay) Close() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		r.cancel()
		_ = r.listener.Close()
		r.mu.Lock()
		r.closed = true
		local := r.local
		remote := r.remote
		r.mu.Unlock()
		if local != nil {
			_ = local.Close()
		}
		if remote != nil {
			_ = remote.Close()
		}
	})
}
