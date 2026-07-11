package app

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"openwebservermanager/internal/model"
)

const (
	defaultDNSPropagationTimeout  = 2 * time.Minute
	defaultDNSPropagationInterval = 5 * time.Second
)

type DNSProviderConfig struct {
	Provider            string
	Zone                string
	Token               string
	AccessKeyID         string
	APIBaseURL          string
	PropagationTimeout  time.Duration
	PropagationInterval time.Duration
	SkipPropagationWait bool
}

type DNSChallengeProvider interface {
	Present(context.Context, string, string) (ACMEChallengeCleanup, error)
}

type DNSChallengeProviderFactory interface {
	New(DNSProviderConfig) (DNSChallengeProvider, error)
}

type realDNSChallengeProviderFactory struct {
	client   *http.Client
	resolver dnsTXTResolver
}

func (f realDNSChallengeProviderFactory) New(cfg DNSProviderConfig) (DNSChallengeProvider, error) {
	client := f.client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	var provider DNSChallengeProvider
	switch normalizeDNSProviderName(cfg.Provider) {
	case "cloudflare":
		provider = &cloudflareDNSProvider{client: client, baseURL: defaultString(cfg.APIBaseURL, "https://api.cloudflare.com/client/v4"), zone: cfg.Zone, token: cfg.Token}
	case "alidns":
		provider = &aliDNSProvider{client: client, baseURL: defaultString(cfg.APIBaseURL, "https://alidns.aliyuncs.com/"), zone: cfg.Zone, accessKeyID: cfg.AccessKeyID, secret: cfg.Token}
	case "dnspod":
		provider = &dnsPodProvider{client: client, baseURL: defaultString(cfg.APIBaseURL, "https://dnsapi.cn"), zone: cfg.Zone, token: cfg.Token}
	default:
		return nil, fmt.Errorf("unsupported DNS provider %q", cfg.Provider)
	}
	if cfg.SkipPropagationWait {
		return provider, nil
	}
	resolver := f.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	timeout := cfg.PropagationTimeout
	if timeout <= 0 {
		timeout = defaultDNSPropagationTimeout
	}
	interval := cfg.PropagationInterval
	if interval <= 0 {
		interval = defaultDNSPropagationInterval
	}
	return &propagatingDNSProvider{provider: provider, resolver: resolver, timeout: timeout, interval: interval}, nil
}

type dnsTXTResolver interface {
	LookupTXT(context.Context, string) ([]string, error)
}

type propagatingDNSProvider struct {
	provider DNSChallengeProvider
	resolver dnsTXTResolver
	timeout  time.Duration
	interval time.Duration
}

func (p *propagatingDNSProvider) Present(ctx context.Context, fqdn, value string) (ACMEChallengeCleanup, error) {
	cleanup, err := p.provider.Present(ctx, fqdn, value)
	if err != nil {
		return nil, err
	}
	waitCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	if err := waitForDNSChallenge(waitCtx, p.resolver, fqdn, value, p.interval); err != nil {
		cleanupErr := cleanup(context.WithoutCancel(ctx))
		return nil, combineACMEChallengeError(err, cleanupErr)
	}
	return cleanup, nil
}

func waitForDNSChallenge(ctx context.Context, resolver dnsTXTResolver, fqdn, expected string, interval time.Duration) error {
	for {
		values, err := resolver.LookupTXT(ctx, fqdn)
		if err == nil {
			for _, value := range values {
				if value == expected {
					return nil
				}
			}
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("wait for DNS TXT propagation at %s: %w", fqdn, ctx.Err())
		case <-timer.C:
		}
	}
}

func (s *Server) dnsChallengeProvider(item model.PlatformItem) (DNSChallengeProvider, error) {
	raw, ok, err := s.cfg.Store.GetPlatformItem("system_settings", item.ID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("DNS provider not found")
	}
	encrypted := firstMetadataString(raw.Metadata, "dns_api_token_encrypted")
	if encrypted == "" {
		return nil, errors.New("DNS provider token is not configured")
	}
	token, err := s.cfg.Store.DecryptPlatformSecret(encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt DNS provider token: %w", err)
	}
	providerName := firstMetadataString(raw.Metadata, "provider")
	zone := normalizeDNSName(firstMetadataString(raw.Metadata, "zone"))
	if zone == "" {
		return nil, errors.New("DNS provider zone is required")
	}
	factory := s.dnsProviderFactory
	return factory.New(DNSProviderConfig{
		Provider:            providerName,
		Zone:                zone,
		Token:               token,
		AccessKeyID:         firstMetadataString(raw.Metadata, "access_key_id", "accessKeyId", "api_key_id"),
		APIBaseURL:          firstMetadataString(raw.Metadata, "api_base_url"),
		PropagationTimeout:  metadataDurationSeconds(raw.Metadata["propagation_timeout_seconds"]),
		PropagationInterval: metadataDurationSeconds(raw.Metadata["propagation_interval_seconds"]),
		SkipPropagationWait: metadataBoolDefault(raw.Metadata["skip_propagation_check"], false),
	})
}

func metadataDurationSeconds(value any) time.Duration {
	seconds, ok := metadataInt(value)
	if !ok || seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

func metadataBoolDefault(value any, fallback bool) bool {
	parsed, ok := metadataBoolValue(value)
	if !ok {
		return fallback
	}
	return parsed
}

func (s *Server) acmeChallengePresenter(provider DNSChallengeProvider) ACMEChallengePresenter {
	return func(ctx context.Context, challenge ACMEChallengePresentation) (ACMEChallengeCleanup, error) {
		switch challenge.Type {
		case "http-01":
			return s.acmeChallenges.presenter(ctx, challenge)
		case "dns-01":
			if provider == nil {
				return nil, errors.New("DNS provider is required for dns-01")
			}
			return provider.Present(ctx, dnsChallengeRecordName(challenge.Domain), challenge.Value)
		default:
			return nil, fmt.Errorf("unsupported ACME challenge type %q", challenge.Type)
		}
	}
}

func dnsChallengeRecordName(domain string) string {
	domain = strings.TrimPrefix(normalizeDNSName(domain), "*.")
	return "_acme-challenge." + domain
}

func normalizeDNSName(value string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
}

func normalizeDNSProviderName(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "cloudflare", "cf":
		return "cloudflare"
	case "aliyun", "ali", "alidns":
		return "alidns"
	case "dnspod", "tencent", "tencentcloud":
		return "dnspod"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func relativeDNSRecordName(fqdn, zone string) (string, error) {
	fqdn = normalizeDNSName(fqdn)
	zone = normalizeDNSName(zone)
	if fqdn == zone {
		return "@", nil
	}
	suffix := "." + zone
	if !strings.HasSuffix(fqdn, suffix) {
		return "", fmt.Errorf("DNS record %s is outside configured zone %s", fqdn, zone)
	}
	return strings.TrimSuffix(fqdn, suffix), nil
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimRight(strings.TrimSpace(value), "/")
}

type cloudflareDNSProvider struct {
	client  *http.Client
	baseURL string
	zone    string
	token   string
}

func (p *cloudflareDNSProvider) Present(ctx context.Context, fqdn, value string) (ACMEChallengeCleanup, error) {
	if strings.TrimSpace(p.token) == "" {
		return nil, errors.New("Cloudflare API token is required")
	}
	zoneID, err := p.zoneID(ctx)
	if err != nil {
		return nil, err
	}
	payload := map[string]any{"type": "TXT", "name": normalizeDNSName(fqdn), "content": value, "ttl": 60}
	var response struct {
		Success bool `json:"success"`
		Result  struct {
			ID string `json:"id"`
		} `json:"result"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := p.requestJSON(ctx, http.MethodPost, "/zones/"+url.PathEscape(zoneID)+"/dns_records", payload, &response); err != nil {
		return nil, err
	}
	if !response.Success || response.Result.ID == "" {
		return nil, errors.New("Cloudflare did not create the DNS TXT record")
	}
	recordID := response.Result.ID
	return func(cleanupCtx context.Context) error {
		var result struct {
			Success bool `json:"success"`
		}
		if err := p.requestJSON(cleanupCtx, http.MethodDelete, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(recordID), nil, &result); err != nil {
			return err
		}
		if !result.Success {
			return errors.New("Cloudflare did not delete the DNS TXT record")
		}
		return nil
	}, nil
}

func (p *cloudflareDNSProvider) zoneID(ctx context.Context) (string, error) {
	var response struct {
		Success bool `json:"success"`
		Result  []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	path := "/zones?name=" + url.QueryEscape(normalizeDNSName(p.zone)) + "&status=active&per_page=1"
	if err := p.requestJSON(ctx, http.MethodGet, path, nil, &response); err != nil {
		return "", err
	}
	if !response.Success || len(response.Result) != 1 || response.Result[0].ID == "" {
		return "", fmt.Errorf("Cloudflare zone %s was not found", p.zone)
	}
	return response.Result[0].ID, nil
}

func (p *cloudflareDNSProvider) requestJSON(ctx context.Context, method, path string, payload any, target any) error {
	return dnsJSONRequest(ctx, p.client, method, p.baseURL+path, payload, map[string]string{"Authorization": "Bearer " + p.token}, target)
}

type aliDNSProvider struct {
	client      *http.Client
	baseURL     string
	zone        string
	accessKeyID string
	secret      string
}

func (p *aliDNSProvider) Present(ctx context.Context, fqdn, value string) (ACMEChallengeCleanup, error) {
	if p.accessKeyID == "" || p.secret == "" {
		return nil, errors.New("AliDNS access key ID and secret are required")
	}
	rr, err := relativeDNSRecordName(fqdn, p.zone)
	if err != nil {
		return nil, err
	}
	params := map[string]string{"Action": "AddDomainRecord", "DomainName": p.zone, "RR": rr, "Type": "TXT", "Value": value, "TTL": "60"}
	var response struct {
		RecordID string `json:"RecordId"`
	}
	if err := p.request(ctx, params, &response); err != nil {
		return nil, err
	}
	if response.RecordID == "" {
		return nil, errors.New("AliDNS did not create the DNS TXT record")
	}
	return func(cleanupCtx context.Context) error {
		var ignored map[string]any
		return p.request(cleanupCtx, map[string]string{"Action": "DeleteDomainRecord", "RecordId": response.RecordID}, &ignored)
	}, nil
}

func (p *aliDNSProvider) request(ctx context.Context, action map[string]string, target any) error {
	params := map[string]string{
		"AccessKeyId": p.accessKeyID, "Format": "JSON", "SignatureMethod": "HMAC-SHA1", "SignatureNonce": randomHex(16),
		"SignatureVersion": "1.0", "Timestamp": time.Now().UTC().Format("2006-01-02T15:04:05Z"), "Version": "2015-01-09",
	}
	for key, value := range action {
		params[key] = value
	}
	canonical := canonicalAliQuery(params)
	signature := hmac.New(sha1.New, []byte(p.secret+"&"))
	_, _ = signature.Write([]byte("GET&%2F&" + aliPercentEncode(canonical)))
	params["Signature"] = base64.StdEncoding.EncodeToString(signature.Sum(nil))
	targetURL := strings.TrimRight(p.baseURL, "/") + "/?" + encodeAliQuery(params)
	return dnsJSONRequest(ctx, p.client, http.MethodGet, targetURL, nil, nil, target)
}

func canonicalAliQuery(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, aliPercentEncode(key)+"="+aliPercentEncode(params[key]))
	}
	return strings.Join(parts, "&")
}

func encodeAliQuery(params map[string]string) string { return canonicalAliQuery(params) }

func aliPercentEncode(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(url.QueryEscape(value), "+", "%20"), "*", "%2A"), "%7E", "~")
}

type dnsPodProvider struct {
	client  *http.Client
	baseURL string
	zone    string
	token   string
}

func (p *dnsPodProvider) Present(ctx context.Context, fqdn, value string) (ACMEChallengeCleanup, error) {
	if strings.TrimSpace(p.token) == "" {
		return nil, errors.New("DNSPod login token is required")
	}
	rr, err := relativeDNSRecordName(fqdn, p.zone)
	if err != nil {
		return nil, err
	}
	var response struct {
		Status struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"status"`
		Record struct {
			ID string `json:"id"`
		} `json:"record"`
	}
	if err := p.request(ctx, "/Record.Create", url.Values{"domain": {p.zone}, "sub_domain": {rr}, "record_type": {"TXT"}, "record_line": {"默认"}, "value": {value}, "ttl": {"60"}}, &response); err != nil {
		return nil, err
	}
	if response.Status.Code != "1" || response.Record.ID == "" {
		return nil, fmt.Errorf("DNSPod did not create the DNS TXT record: %s", response.Status.Message)
	}
	return func(cleanupCtx context.Context) error {
		var result struct {
			Status struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"status"`
		}
		if err := p.request(cleanupCtx, "/Record.Remove", url.Values{"domain": {p.zone}, "record_id": {response.Record.ID}}, &result); err != nil {
			return err
		}
		if result.Status.Code != "1" {
			return fmt.Errorf("DNSPod did not delete the DNS TXT record: %s", result.Status.Message)
		}
		return nil
	}, nil
}

func (p *dnsPodProvider) request(ctx context.Context, path string, values url.Values, target any) error {
	values.Set("login_token", p.token)
	values.Set("format", "json")
	values.Set("lang", "en")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(p.baseURL, "/")+path, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "openwebservermanager/1.0")
	return decodeDNSResponse(p.client, req, target)
}

func dnsJSONRequest(ctx context.Context, client *http.Client, method, endpoint string, payload any, headers map[string]string, target any) error {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = strings.NewReader(string(encoded))
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return decodeDNSResponse(client, req, target)
}

func decodeDNSResponse(client *http.Client, req *http.Request, target any) error {
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("DNS provider request failed: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 256*1024))
	if err != nil {
		return fmt.Errorf("read DNS provider response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("DNS provider returned HTTP %d: %s", response.StatusCode, truncateDNSProviderError(body))
	}
	if target == nil || len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("decode DNS provider response: %w", err)
	}
	return nil
}

func truncateDNSProviderError(body []byte) string {
	value := strings.TrimSpace(string(body))
	if len(value) > 512 {
		value = value[:512]
	}
	return value
}

func randomHex(bytesCount int) string {
	buffer := make([]byte, bytesCount)
	if _, err := rand.Read(buffer); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(buffer)
}
