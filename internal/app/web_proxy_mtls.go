package app

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"openwebservermanager/internal/model"
)

func (s *Server) webAssetProxyTransport(asset model.PlatformItem, target *url.URL) (http.RoundTripper, error) {
	certificateID := webAssetMTLSCertificateID(asset)
	if certificateID == "" {
		return nil, nil
	}
	if target == nil || target.Scheme != "https" {
		return nil, errors.New("web asset mTLS requires an https upstream")
	}
	certificate, ok, err := s.cfg.Store.GetPlatformItem("certificates", certificateID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("mTLS certificate %s not found", certificateID)
	}
	if err := certificateRuntimeUsable(certificate); err != nil {
		return nil, fmt.Errorf("mTLS certificate %s is not usable: %w", certificateID, err)
	}
	if err := s.decryptCertificatePrivateKey(&certificate); err != nil {
		return nil, err
	}
	if enabled, _ := metadataBoolByKeys(certificate.Metadata, "mtls_enabled", "mTLS", "mutual_tls_enabled"); !enabled {
		return nil, fmt.Errorf("mTLS certificate %s is not enabled for mTLS", certificateID)
	}
	certPEM := firstMetadataString(certificate.Metadata, "certificate", "cert", "certificate_pem")
	keyPEM := firstMetadataString(certificate.Metadata, "private_key", "privateKey", "key", "private_key_pem")
	if strings.TrimSpace(certPEM) == "" || strings.TrimSpace(keyPEM) == "" {
		return nil, fmt.Errorf("mTLS certificate %s must include certificate and private key", certificateID)
	}
	if chainPEM := firstMetadataString(certificate.Metadata, "chain", "certificate_chain", "chain_pem"); chainPEM != "" {
		certPEM = strings.TrimRight(certPEM, "\r\n") + "\n" + strings.TrimLeft(chainPEM, "\r\n")
	}
	clientCert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("parse mTLS certificate %s: %w", certificateID, err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS12,
	}
	if rootCAs, err := webAssetMTLSRootCAs(asset, certificate); err != nil {
		return nil, err
	} else if rootCAs != nil {
		tlsConfig.RootCAs = rootCAs
	}
	if serverName := firstMetadataString(asset.Metadata, "tls_server_name", "server_name", "serverName", "mtls_server_name"); serverName != "" {
		tlsConfig.ServerName = serverName
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	return transport, nil
}

func webAssetMTLSCertificateID(asset model.PlatformItem) string {
	return firstMetadataString(asset.Metadata,
		"mtls_certificate_id",
		"mtlsCertificateId",
		"client_certificate_id",
		"clientCertificateId",
		"certificate_id",
		"certificateId",
		"cert_id",
	)
}

func webAssetMTLSRootCAs(asset, certificate model.PlatformItem) (*x509.CertPool, error) {
	candidates := []string{
		firstMetadataString(asset.Metadata, "mtls_ca", "tls_ca", "ca_certificate", "caCertificate", "root_ca", "trusted_ca"),
		firstMetadataString(certificate.Metadata, "mtls_client_ca", "client_ca", "mtls_ca", "tls_ca", "ca_certificate", "root_ca"),
	}
	var pool *x509.CertPool
	for _, candidate := range candidates {
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		if pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(candidate)) {
			return nil, errors.New("mTLS CA bundle is invalid")
		}
	}
	return pool, nil
}
