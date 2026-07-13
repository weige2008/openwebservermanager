package app

import (
	"context"
	"errors"
	"fmt"
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
	if len(route.Candidates) == 0 && strings.TrimSpace(route.GatewayCollection) != "" && strings.TrimSpace(route.GatewayCollection) != "agent_gateways" {
		return nil, errors.New("selected gateway does not provide an agent relay data plane")
	}
	completedRoute, err := s.completeGatewayRoute(route, protocol)
	if err != nil {
		return nil, err
	}
	route = completedRoute
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			return nil, errors.New("agent gateway only supports tcp connections")
		}
		attemptTimeout := route.AttemptTimeout
		if attemptTimeout <= 0 {
			attemptTimeout = 5 * time.Second
		}
		cooldown := route.FailureCooldown
		if cooldown <= 0 {
			cooldown = 30 * time.Second
		}
		initialTarget := route.currentTarget()
		attemptErrors := []error{}
		attemptedIDs := []string{}
		for index, candidate := range route.Candidates {
			if strings.TrimSpace(candidate.Collection) != "agent_gateways" {
				attemptErrors = append(attemptErrors, fmt.Errorf("gateway %s does not provide an agent relay data plane", candidate.Name))
				continue
			}
			attemptedIDs = append(attemptedIDs, candidate.ID)
			attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
			conn, dialErr := s.agentRelay.Dial(attemptCtx, agentrelay.DialRequest{
				GatewayID: candidate.ID,
				SessionID: sessionID,
				UserID:    userID,
				Target:    address,
				Protocol:  protocol,
				Timeout:   attemptTimeout,
			})
			cancel()
			if dialErr != nil {
				failure := s.gatewayRoutes.failure(route.GatewayGroupID, candidate.ID, dialErr.Error(), cooldown, time.Now().UTC())
				if logErr := s.recordGatewayRouteEvent("gateway.route.attempt_failed", "failed", route, candidate, sessionID, userID, protocol, address, map[string]any{
					"attempt":                 index + 1,
					"attempt_count":           len(route.Candidates),
					"failure_count":           failure.Count,
					"error":                   dialErr.Error(),
					"route_unavailable_until": failure.Unavailable,
				}); logErr != nil {
					return nil, errors.Join(dialErr, logErr)
				}
				attemptErrors = append(attemptErrors, fmt.Errorf("gateway %s: %w", candidate.Name, dialErr))
				continue
			}

			s.gatewayRoutes.success(route.GatewayGroupID, candidate.ID)
			route.setCurrentTarget(candidate)
			if len(attemptErrors) > 0 || !strings.EqualFold(initialTarget.ID, candidate.ID) {
				if logErr := s.recordGatewayRouteEvent("gateway.route.failover", "success", route, candidate, sessionID, userID, protocol, address, map[string]any{
					"from_gateway_id": initialTarget.ID,
					"to_gateway_id":   candidate.ID,
					"attempted_ids":   attemptedIDs,
					"failed_attempts": len(attemptErrors),
				}); logErr != nil {
					_ = conn.Close()
					return nil, logErr
				}
			}
			if err := s.persistGatewayRouteSession(sessionID, route); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return conn, nil
		}
		if len(attemptErrors) == 0 {
			return nil, errors.New("gateway group has no agent relay candidate")
		}
		return nil, fmt.Errorf("gateway group %s could not connect to %s: %w", route.GatewayGroupName, address, errors.Join(attemptErrors...))
	}, nil
}

func (s *Server) persistGatewayRouteSession(sessionID string, route gatewayRouteDecision) error {
	if strings.TrimSpace(sessionID) == "" {
		return nil
	}
	if _, ok := s.cfg.Store.GetSession(sessionID); !ok {
		return nil
	}
	_, err := s.cfg.Store.UpdateSession(sessionID, func(item *model.ConnectionSession) {
		applyGatewayRouteSession(item, route)
	})
	if err != nil {
		return fmt.Errorf("persist selected gateway route: %w", err)
	}
	return nil
}

func (s *Server) recordGatewayRouteEvent(name, status string, route gatewayRouteDecision, candidate gatewayRouteTarget, sessionID, userID string, protocol model.Protocol, address string, extra map[string]any) error {
	metadata := map[string]any{
		"gateway_group_id":   route.GatewayGroupID,
		"gateway_group_name": route.GatewayGroupName,
		"gateway_id":         candidate.ID,
		"gateway_name":       candidate.Name,
		"gateway_collection": candidate.Collection,
		"gateway_type":       candidate.Type,
		"session_id":         sessionID,
		"target":             address,
	}
	for key, value := range extra {
		metadata[key] = value
	}
	targetID := strings.TrimSpace(sessionID)
	if targetID == "" {
		targetID = route.GatewayGroupID
	}
	_, err := s.cfg.Store.CreatePlatformItem("operation_logs", model.PlatformItemRequest{
		Name:        name,
		Type:        "gateway_route",
		Status:      status,
		Protocol:    protocol,
		TargetID:    targetID,
		OwnerID:     valueOrDefault(userID, "system"),
		Description: name + " via " + candidate.Name,
		Metadata:    metadata,
	})
	if err != nil {
		detail := "persist " + name + " operation log: " + err.Error()
		_ = s.cfg.Store.Audit(model.AuditLog{UserID: valueOrDefault(userID, "system"), Action: "gateway.route.log.persist_failed", TargetID: targetID, Protocol: protocol, Detail: detail})
		return errors.New(detail)
	}
	return nil
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
	dialContext, err := s.agentGatewayDialContext(gatewayRouteDecision{
		GatewayGroupID:    cfg.Session.GatewayGroupID,
		GatewayID:         cfg.Session.GatewayID,
		GatewayName:       cfg.Session.GatewayName,
		GatewayCollection: cfg.Session.GatewayCollection,
	}, cfg.Session.ID, cfg.Session.UserID, cfg.Protocol)
	if err != nil {
		return guac.DesktopConfig{}, nil, err
	}
	if dialContext == nil {
		return guac.DesktopConfig{}, nil, errors.New("gateway group did not provide a relay dialer")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return guac.DesktopConfig{}, nil, err
	}
	relayCtx, cancel := context.WithCancel(ctx)
	relay := &desktopAgentRelay{listener: listener, cancel: cancel}
	target := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	go relay.serve(relayCtx, func(dialCtx context.Context) (net.Conn, error) {
		return dialContext(dialCtx, "tcp", target)
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
