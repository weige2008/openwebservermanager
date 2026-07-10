package agentrelay

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"openwebservermanager/internal/model"
)

func TestManagerRelaysBidirectionalTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo target: %v", err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	manager := NewManager(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	agentDone := make(chan error, 1)
	go func() {
		claim, claimErr := manager.Claim(ctx, "gateway-1")
		if claimErr != nil {
			agentDone <- claimErr
			return
		}
		target, dialErr := net.DialTimeout("tcp", claim.Target, time.Second)
		if dialErr != nil {
			agentDone <- dialErr
			return
		}
		defer target.Close()
		if readyErr := manager.Ready(ctx, "gateway-1", claim.TunnelID); readyErr != nil {
			agentDone <- readyErr
			return
		}
		streamCtx, streamCancel := context.WithCancel(ctx)
		defer streamCancel()
		streamDone := make(chan error, 2)
		go func() { streamDone <- manager.CopyDown(streamCtx, "gateway-1", claim.TunnelID, nil, target) }()
		go func() { streamDone <- manager.CopyUp(streamCtx, "gateway-1", claim.TunnelID, target) }()
		agentDone <- <-streamDone
	}()

	conn, err := manager.Dial(ctx, DialRequest{
		GatewayID: "gateway-1",
		SessionID: "session-1",
		UserID:    "user-1",
		Target:    listener.Addr().String(),
		Protocol:  model.ProtocolSSH,
		Timeout:   3 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	payload := []byte("agent relay echo")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write relay: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read relay: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("relay echo = %q, want %q", got, payload)
	}
	_ = conn.Close()
	select {
	case <-agentDone:
	case <-time.After(2 * time.Second):
		t.Fatal("agent relay streams did not stop after manager connection closed")
	}
}
func TestManagerDialTimesOutWithoutAgent(t *testing.T) {
	manager := NewManager(nil)
	started := time.Now()
	_, err := manager.Dial(context.Background(), DialRequest{
		GatewayID: "offline-gateway",
		SessionID: "session-timeout",
		Target:    "127.0.0.1:22",
		Protocol:  model.ProtocolSSH,
		Timeout:   50 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("relay dial unexpectedly succeeded without an agent")
	}
	if time.Since(started) > time.Second {
		t.Fatalf("relay dial timeout took too long: %s", time.Since(started))
	}
	manager.mu.Lock()
	pending := len(manager.pending["offline-gateway"])
	active := len(manager.tunnels)
	manager.mu.Unlock()
	if pending != 0 || active != 0 {
		t.Fatalf("timed out relay retained pending=%d active=%d tunnels", pending, active)
	}
}
