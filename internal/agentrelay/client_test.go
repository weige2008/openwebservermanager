package agentrelay

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientSendsImmediateHeartbeatWithHostMetrics(t *testing.T) {
	heartbeats := make(chan HeartbeatRequest, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer gateway-id.agent-secret" {
			t.Errorf("authorization = %q", got)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/agent/gateways/register":
			time.Sleep(15 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{}`)
		case "/api/agent/gateways/heartbeat":
			var request HeartbeatRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode heartbeat: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			heartbeats <- request
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{}`)
		case "/api/agent/gateways/claim":
			<-r.Context().Done()
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ServerURL:         server.URL,
		RegistrationToken: "gateway-id.agent-secret",
		Name:              "metrics-agent",
		Version:           "test-version",
		Workers:           1,
		HeartbeatInterval: time.Hour,
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		MetricsCollector: func(context.Context) (HostMetrics, error) {
			return HostMetrics{
				CPUPercent:       37.5,
				MemoryUsedBytes:  1024,
				MemoryTotalBytes: 4096,
				DiskUsedBytes:    2048,
				DiskTotalBytes:   8192,
				NetworkRXBytes:   12345,
				NetworkTXBytes:   67890,
				Details:          map[string]any{"collector": "test", "uptime_seconds": 42},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()

	select {
	case heartbeat := <-heartbeats:
		if heartbeat.LatencyMS < 1 {
			t.Fatalf("initial heartbeat latency = %d, want registration round-trip latency", heartbeat.LatencyMS)
		}
		if heartbeat.CPUPercent != 37.5 || heartbeat.MemoryUsedBytes != 1024 || heartbeat.MemoryTotalBytes != 4096 {
			t.Fatalf("heartbeat host metrics = %#v", heartbeat)
		}
		if heartbeat.DiskUsedBytes != 2048 || heartbeat.DiskTotalBytes != 8192 {
			t.Fatalf("heartbeat disk metrics = %#v", heartbeat)
		}
		if heartbeat.NetworkRXBytes != 12345 || heartbeat.NetworkTXBytes != 67890 {
			t.Fatalf("heartbeat network metrics = %#v", heartbeat)
		}
		if heartbeat.Metrics["collector"] != "test" {
			t.Fatalf("heartbeat details = %#v", heartbeat.Metrics)
		}
		if heartbeat.Metrics["host_network_rx_bytes"] != float64(12345) || heartbeat.Metrics["relay_rx_bytes"] != float64(0) {
			t.Fatalf("heartbeat network detail metrics = %#v", heartbeat.Metrics)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client did not send an immediate heartbeat after registration")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("client run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client did not stop after cancellation")
	}
}

func TestClientHeartbeatContinuesWhenMetricsCollectionIsPartial(t *testing.T) {
	heartbeat := make(chan HeartbeatRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/gateways/register":
			_, _ = io.WriteString(w, `{}`)
		case "/api/agent/gateways/heartbeat":
			var request HeartbeatRequest
			_ = json.NewDecoder(r.Body).Decode(&request)
			heartbeat <- request
			_, _ = io.WriteString(w, `{}`)
		case "/api/agent/gateways/claim":
			<-r.Context().Done()
		}
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ServerURL:         server.URL,
		RegistrationToken: "gateway-id.agent-secret",
		Workers:           1,
		HeartbeatInterval: time.Hour,
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		MetricsCollector: func(context.Context) (HostMetrics, error) {
			return HostMetrics{MemoryUsedBytes: 512, MemoryTotalBytes: 1024, Details: map[string]any{"collection_error": "cpu unavailable"}}, errors.New("cpu unavailable")
		},
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = client.Run(ctx) }()
	select {
	case request := <-heartbeat:
		if request.MemoryUsedBytes != 512 || request.MemoryTotalBytes != 1024 {
			t.Fatalf("partial heartbeat = %#v", request)
		}
		if request.Metrics["collection_error"] != "cpu unavailable" {
			t.Fatalf("partial heartbeat details = %#v", request.Metrics)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("partial metrics failure suppressed heartbeat")
	}
}

func TestCollectHostMetrics(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	metrics, err := CollectHostMetrics(ctx)
	if err != nil {
		t.Fatalf("collect host metrics: %v; partial=%#v", err, metrics)
	}
	if metrics.CPUPercent < 0 || metrics.CPUPercent > 100 {
		t.Fatalf("cpu percent = %v", metrics.CPUPercent)
	}
	if metrics.MemoryTotalBytes <= 0 || metrics.MemoryUsedBytes < 0 || metrics.MemoryUsedBytes > metrics.MemoryTotalBytes {
		t.Fatalf("memory metrics = %#v", metrics)
	}
	if metrics.DiskTotalBytes <= 0 || metrics.DiskUsedBytes < 0 || metrics.DiskUsedBytes > metrics.DiskTotalBytes {
		t.Fatalf("disk metrics = %#v", metrics)
	}
	if metrics.NetworkRXBytes < 0 || metrics.NetworkTXBytes < 0 {
		t.Fatalf("network metrics = %#v", metrics)
	}
	if metrics.Details["collector"] != "gopsutil" || metrics.Details["cpu_logical_count"] == nil || metrics.Details["uptime_seconds"] == nil {
		t.Fatalf("host metric details = %#v", metrics.Details)
	}
}

func TestMaxMetricCounter(t *testing.T) {
	for _, test := range []struct {
		host  int64
		relay int64
		want  int64
	}{
		{host: 100, relay: 25, want: 100},
		{host: 10, relay: 40, want: 40},
		{host: -1, relay: 7, want: 7},
		{host: 9, relay: -1, want: 9},
	} {
		if got := maxMetricCounter(test.host, test.relay); got != test.want {
			t.Fatalf("maxMetricCounter(%d, %d) = %d, want %d", test.host, test.relay, got, test.want)
		}
	}
}
