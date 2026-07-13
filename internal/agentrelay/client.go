package agentrelay

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ClientConfig struct {
	ServerURL          string
	RegistrationToken  string
	Name               string
	Version            string
	Capabilities       []string
	Workers            int
	HeartbeatInterval  time.Duration
	InsecureSkipVerify bool
	Logger             *slog.Logger
	DialContext        func(context.Context, string, string) (net.Conn, error)
	MetricsCollector   MetricsCollector
}
type Client struct {
	cfg       ClientConfig
	baseURL   *url.URL
	http      *http.Client
	stream    *http.Client
	active    atomic.Int64
	rx        atomic.Int64
	tx        atomic.Int64
	latencyMS atomic.Int64
	hostname  string
	closeOnce sync.Once
}

func NewClient(cfg ClientConfig) (*Client, error) {
	baseURL, err := url.Parse(strings.TrimSpace(cfg.ServerURL))
	if err != nil || (baseURL.Scheme != "http" && baseURL.Scheme != "https") || baseURL.Host == "" {
		return nil, errors.New("agent server URL must use http or https")
	}
	if strings.TrimSpace(cfg.RegistrationToken) == "" {
		return nil, errors.New("agent registration token is required")
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	if cfg.Workers > 64 {
		cfg.Workers = 64
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 30 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.DialContext == nil {
		dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
		cfg.DialContext = dialer.DialContext
	}
	if cfg.MetricsCollector == nil {
		cfg.MetricsCollector = CollectHostMetrics
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureSkipVerify}
	hostname, _ := os.Hostname()
	return &Client{
		cfg:      cfg,
		baseURL:  baseURL,
		http:     &http.Client{Transport: transport, Timeout: 40 * time.Second},
		stream:   &http.Client{Transport: transport},
		hostname: hostname,
	}, nil
}

func (c *Client) Run(ctx context.Context) error {
	if err := c.register(ctx); err != nil {
		return err
	}
	errCh := make(chan error, c.cfg.Workers+1)
	go func() { errCh <- c.heartbeatLoop(ctx) }()
	for worker := 0; worker < c.cfg.Workers; worker++ {
		go func() { errCh <- c.claimLoop(ctx) }()
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		if err == nil || errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
}

func (c *Client) register(ctx context.Context) error {
	payload := RegisterRequest{
		Name:         c.cfg.Name,
		Hostname:     c.hostname,
		Version:      c.cfg.Version,
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		Capabilities: c.cfg.Capabilities,
	}
	started := time.Now()
	if err := c.doJSON(ctx, http.MethodPost, "/api/agent/gateways/register", payload, nil); err != nil {
		return err
	}
	c.latencyMS.Store(durationMilliseconds(time.Since(started)))
	return nil
}

func (c *Client) heartbeatLoop(ctx context.Context) error {
	ticker := time.NewTicker(c.cfg.HeartbeatInterval)
	defer ticker.Stop()
	c.sendHeartbeat(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.sendHeartbeat(ctx)
		}
	}
}

func (c *Client) sendHeartbeat(ctx context.Context) {
	metricsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	metrics, metricsErr := c.cfg.MetricsCollector(metricsCtx)
	cancel()
	if metricsErr != nil && ctx.Err() == nil {
		c.cfg.Logger.Warn("agent host metrics collection incomplete", "error", metricsErr)
	}
	relayRX := c.rx.Load()
	relayTX := c.tx.Load()
	details := make(map[string]any, len(metrics.Details)+4)
	for key, value := range metrics.Details {
		details[key] = value
	}
	details["host_network_rx_bytes"] = metrics.NetworkRXBytes
	details["host_network_tx_bytes"] = metrics.NetworkTXBytes
	details["relay_rx_bytes"] = relayRX
	details["relay_tx_bytes"] = relayTX
	payload := HeartbeatRequest{
		Hostname:         c.hostname,
		Version:          c.cfg.Version,
		LatencyMS:        int(c.latencyMS.Load()),
		CPUPercent:       metrics.CPUPercent,
		MemoryUsedBytes:  metrics.MemoryUsedBytes,
		MemoryTotalBytes: metrics.MemoryTotalBytes,
		DiskUsedBytes:    metrics.DiskUsedBytes,
		DiskTotalBytes:   metrics.DiskTotalBytes,
		ActiveSessions:   int(c.active.Load()),
		NetworkRXBytes:   maxMetricCounter(metrics.NetworkRXBytes, relayRX),
		NetworkTXBytes:   maxMetricCounter(metrics.NetworkTXBytes, relayTX),
		Metrics:          details,
	}
	started := time.Now()
	if err := c.doJSON(ctx, http.MethodPost, "/api/agent/gateways/heartbeat", payload, nil); err != nil {
		if ctx.Err() == nil {
			c.cfg.Logger.Warn("agent heartbeat failed", "error", err)
		}
		return
	}
	c.latencyMS.Store(durationMilliseconds(time.Since(started)))
}

func durationMilliseconds(duration time.Duration) int64 {
	milliseconds := duration.Milliseconds()
	if milliseconds <= 0 && duration > 0 {
		return 1
	}
	return milliseconds
}

func maxMetricCounter(hostValue, relayValue int64) int64 {
	if hostValue < 0 {
		hostValue = 0
	}
	if relayValue < 0 {
		relayValue = 0
	}
	if hostValue >= relayValue {
		return hostValue
	}
	return relayValue
}

func (c *Client) claimLoop(ctx context.Context) error {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return nil
		}
		var claim Claim
		status, err := c.doJSONStatus(ctx, http.MethodPost, "/api/agent/gateways/claim", nil, &claim)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			c.cfg.Logger.Warn("agent relay claim failed", "error", err)
			if !sleepContext(ctx, backoff) {
				return nil
			}
			if backoff < 10*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		if status == http.StatusNoContent {
			continue
		}
		if claim.TunnelID == "" || claim.Target == "" {
			continue
		}
		go c.handleClaim(ctx, claim)
	}
}

func (c *Client) handleClaim(ctx context.Context, claim Claim) {
	dialCtx, cancelDial := context.WithTimeout(ctx, 15*time.Second)
	conn, err := c.cfg.DialContext(dialCtx, "tcp", claim.Target)
	cancelDial()
	if err != nil {
		_ = c.doJSON(ctx, http.MethodPost, "/api/agent/tunnels/"+url.PathEscape(claim.TunnelID)+"/fail", FailureRequest{Error: err.Error()}, nil)
		return
	}
	defer conn.Close()
	if err := c.doJSON(ctx, http.MethodPost, "/api/agent/tunnels/"+url.PathEscape(claim.TunnelID)+"/ready", map[string]any{}, nil); err != nil {
		return
	}
	c.active.Add(1)
	defer c.active.Add(-1)
	tunnelCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	result := make(chan error, 2)
	go func() { result <- c.upload(tunnelCtx, claim.TunnelID, conn) }()
	go func() { result <- c.download(tunnelCtx, claim.TunnelID, conn) }()
	err = <-result
	cancel()
	_ = conn.Close()
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
		c.cfg.Logger.Debug("agent relay stream closed", "tunnel", claim.TunnelID, "error", err)
	}
}

func (c *Client) upload(ctx context.Context, tunnelID string, conn net.Conn) error {
	reader, writer := io.Pipe()
	copyDone := make(chan error, 1)
	go func() {
		written, err := io.Copy(writer, conn)
		c.tx.Add(written)
		_ = writer.CloseWithError(err)
		copyDone <- err
	}()
	req, err := c.request(ctx, http.MethodPost, "/api/agent/tunnels/"+url.PathEscape(tunnelID)+"/up", reader)
	if err != nil {
		_ = reader.CloseWithError(err)
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := c.stream.Do(req)
	if err != nil {
		_ = reader.CloseWithError(err)
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return responseError(resp)
	}
	return <-copyDone
}

func (c *Client) download(ctx context.Context, tunnelID string, conn net.Conn) error {
	req, err := c.request(ctx, http.MethodGet, "/api/agent/tunnels/"+url.PathEscape(tunnelID)+"/down", nil)
	if err != nil {
		return err
	}
	resp, err := c.stream.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return responseError(resp)
	}
	written, err := io.Copy(conn, resp.Body)
	c.rx.Add(written)
	return err
}

func (c *Client) doJSON(ctx context.Context, method, path string, input, output any) error {
	_, err := c.doJSONStatus(ctx, method, path, input, output)
	return err
}

func (c *Client) doJSONStatus(ctx context.Context, method, path string, input, output any) (int, error) {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(data)
	}
	req, err := c.request(ctx, method, path, body)
	if err != nil {
		return 0, err
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, responseError(resp)
	}
	if output != nil {
		if err := json.NewDecoder(resp.Body).Decode(output); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

func (c *Client) request(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	endpoint := *c.baseURL
	endpoint.Path = strings.TrimRight(c.baseURL.Path, "/") + path
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.RegistrationToken)
	return req, nil
}

func responseError(resp *http.Response) error {
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var payload struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(data, &payload) == nil && payload.Error != "" {
		return fmt.Errorf("agent server returned %d: %s", resp.StatusCode, payload.Error)
	}
	return fmt.Errorf("agent server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
}

func sleepContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
