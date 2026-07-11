package app

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

const acmeIssueTimeout = 5 * time.Minute

type ACMEIssueRequest struct {
	DirectoryURL  string
	Email         string
	Domains       []string
	ChallengeType string
	PrivateKeyPEM string
}

type ACMEIssueResult struct {
	CertificatePEM string
	ChainPEM       string
	PrivateKeyPEM  string
	CertificateURL string
	ExpiresAt      time.Time
}

type ACMEChallengePresenter func(token, keyAuthorization string) func()

type ACMEIssuer interface {
	Issue(context.Context, ACMEIssueRequest, ACMEChallengePresenter) (ACMEIssueResult, error)
}

type realACMEIssuer struct{}

func (realACMEIssuer) Issue(ctx context.Context, req ACMEIssueRequest, present ACMEChallengePresenter) (ACMEIssueResult, error) {
	if strings.ToLower(strings.TrimSpace(req.ChallengeType)) != "http-01" {
		return ACMEIssueResult{}, errors.New("real ACME issuance currently supports http-01 only")
	}
	domains := uniqueNonEmptyStrings(req.Domains)
	if len(domains) == 0 {
		return ACMEIssueResult{}, errors.New("at least one ACME domain is required")
	}
	for _, domain := range domains {
		if strings.HasPrefix(domain, "*.") {
			return ACMEIssueResult{}, errors.New("wildcard certificates require dns-01, which is not configured")
		}
	}
	key, keyPEM, err := acmePrivateKey(req.PrivateKeyPEM)
	if err != nil {
		return ACMEIssueResult{}, err
	}
	client := &acme.Client{Key: key, DirectoryURL: strings.TrimSpace(req.DirectoryURL)}
	account := &acme.Account{}
	if email := strings.TrimSpace(req.Email); email != "" {
		account.Contact = []string{"mailto:" + email}
	}
	if _, err := client.Register(ctx, account, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return ACMEIssueResult{}, fmt.Errorf("register ACME account: %w", err)
	}
	identifiers := make([]acme.AuthzID, 0, len(domains))
	for _, domain := range domains {
		identifiers = append(identifiers, acme.AuthzID{Type: "dns", Value: domain})
	}
	order, err := client.AuthorizeOrder(ctx, identifiers)
	if err != nil {
		return ACMEIssueResult{}, fmt.Errorf("create ACME order: %w", err)
	}
	for _, authorizationURL := range order.AuthzURLs {
		authorization, err := client.GetAuthorization(ctx, authorizationURL)
		if err != nil {
			return ACMEIssueResult{}, fmt.Errorf("fetch ACME authorization: %w", err)
		}
		if authorization.Status == acme.StatusValid {
			continue
		}
		challenge := findACMEChallenge(authorization.Challenges, "http-01")
		if challenge == nil {
			return ACMEIssueResult{}, fmt.Errorf("ACME authorization for %s does not offer http-01", authorization.Identifier.Value)
		}
		response, err := client.HTTP01ChallengeResponse(challenge.Token)
		if err != nil {
			return ACMEIssueResult{}, fmt.Errorf("build ACME challenge response: %w", err)
		}
		cleanup := present(challenge.Token, response)
		if cleanup == nil {
			cleanup = func() {}
		}
		if _, err := client.Accept(ctx, challenge); err != nil {
			cleanup()
			return ACMEIssueResult{}, fmt.Errorf("accept ACME challenge: %w", err)
		}
		_, err = client.WaitAuthorization(ctx, authorizationURL)
		cleanup()
		if err != nil {
			return ACMEIssueResult{}, fmt.Errorf("validate ACME authorization for %s: %w", authorization.Identifier.Value, err)
		}
	}
	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return ACMEIssueResult{}, fmt.Errorf("wait for ACME order: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}, key)
	if err != nil {
		return ACMEIssueResult{}, fmt.Errorf("create ACME CSR: %w", err)
	}
	certificates, certificateURL, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return ACMEIssueResult{}, fmt.Errorf("finalize ACME order: %w", err)
	}
	if len(certificates) == 0 {
		return ACMEIssueResult{}, errors.New("ACME server returned an empty certificate chain")
	}
	leaf, err := x509.ParseCertificate(certificates[0])
	if err != nil {
		return ACMEIssueResult{}, fmt.Errorf("parse issued ACME certificate: %w", err)
	}
	return ACMEIssueResult{
		CertificatePEM: encodeCertificateDER(certificates[:1]),
		ChainPEM:       encodeCertificateDER(certificates[1:]),
		PrivateKeyPEM:  keyPEM,
		CertificateURL: certificateURL,
		ExpiresAt:      leaf.NotAfter.UTC(),
	}, nil
}

func findACMEChallenge(challenges []*acme.Challenge, challengeType string) *acme.Challenge {
	for _, challenge := range challenges {
		if challenge != nil && strings.EqualFold(challenge.Type, challengeType) {
			return challenge
		}
	}
	return nil
}

func acmePrivateKey(existing string) (crypto.Signer, string, error) {
	if strings.TrimSpace(existing) != "" {
		block, _ := pem.Decode([]byte(existing))
		if block == nil {
			return nil, "", errors.New("decode existing ACME private key: invalid PEM")
		}
		var parsed any
		var err error
		switch block.Type {
		case "PRIVATE KEY":
			parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			parsed, err = x509.ParseECPrivateKey(block.Bytes)
		case "RSA PRIVATE KEY":
			parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		default:
			err = fmt.Errorf("unsupported private key PEM type %q", block.Type)
		}
		if err != nil {
			return nil, "", fmt.Errorf("parse existing ACME private key: %w", err)
		}
		signer, ok := parsed.(crypto.Signer)
		if !ok {
			return nil, "", errors.New("existing ACME private key is not a signer")
		}
		return signer, existing, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate ACME private key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", fmt.Errorf("encode ACME private key: %w", err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

func encodeCertificateDER(certificates [][]byte) string {
	var builder strings.Builder
	for _, certificate := range certificates {
		builder.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}))
	}
	return builder.String()
}

type acmeChallengeValue struct {
	KeyAuthorization string
	ExpiresAt        time.Time
}

type acmeChallengeRegistry struct {
	mu     sync.Mutex
	values map[string]acmeChallengeValue
}

func (r *acmeChallengeRegistry) present(token, keyAuthorization string) func() {
	r.mu.Lock()
	if r.values == nil {
		r.values = map[string]acmeChallengeValue{}
	}
	r.values[token] = acmeChallengeValue{KeyAuthorization: keyAuthorization, ExpiresAt: time.Now().UTC().Add(acmeIssueTimeout)}
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		delete(r.values, token)
		r.mu.Unlock()
	}
}

func (r *acmeChallengeRegistry) get(token string) (string, bool) {
	now := time.Now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	for candidate, value := range r.values {
		if !value.ExpiresAt.After(now) {
			delete(r.values, candidate)
		}
	}
	value, ok := r.values[token]
	return value.KeyAuthorization, ok
}
