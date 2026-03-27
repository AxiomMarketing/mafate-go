// Package mafate provides a Go client for the MAFATE Encryption-as-a-Service API.
//
// Basic usage:
//
//	client := mafate.New("eaas_sk_...")
//
//	encrypted, err := client.Encrypt(ctx, "données sensibles", keyID)
//	plaintext, err := client.Decrypt(ctx, encrypted)
package mafate

import (
	"context"
	"net/http"
	"time"
)

const defaultBaseURL = "https://api.mafate.io"
const defaultTimeout = 30 * time.Second

// Client is the top-level MAFATE API client.
// Use New() to construct one.
type Client struct {
	http    *httpClient
	Keys    *KeysService
	ApiKeys *ApiKeysService
	Audit   *AuditService
}

// config holds resolved constructor options.
type config struct {
	baseURL string
	timeout time.Duration
}

// Option is a functional option for configuring a Client.
type Option func(*config)

// WithBaseURL overrides the default API base URL.
func WithBaseURL(u string) Option {
	return func(c *config) {
		c.baseURL = u
	}
}

// WithTimeout sets the HTTP client timeout. Defaults to 30 s.
func WithTimeout(d time.Duration) Option {
	return func(c *config) {
		c.timeout = d
	}
}

// New constructs a new Client with the given API key and optional Options.
func New(apiKey string, opts ...Option) *Client {
	cfg := &config{
		baseURL: defaultBaseURL,
		timeout: defaultTimeout,
	}
	for _, o := range opts {
		o(cfg)
	}

	transport := &http.Transport{}
	hc := newHTTPClient(cfg.baseURL, apiKey, transport, cfg.timeout)

	c := &Client{
		http: hc,
	}
	c.Keys = &KeysService{http: hc}
	c.ApiKeys = &ApiKeysService{http: hc}
	c.Audit = &AuditService{http: hc}
	return c
}

// Health calls GET /health and returns the service status.
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	var out HealthResponse
	if err := c.http.get(ctx, "/health", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Encrypt encodes plaintext to base64 and calls POST /v1/encrypt.
// The returned EncryptedData can be passed directly to Decrypt.
func (c *Client) Encrypt(ctx context.Context, plaintext string, keyID string) (*EncryptedData, error) {
	return encrypt(ctx, c.http, plaintext, keyID)
}

// Decrypt calls POST /v1/decrypt and base64-decodes the result to a UTF-8 string.
func (c *Client) Decrypt(ctx context.Context, data *EncryptedData) (string, error) {
	return decrypt(ctx, c.http, data)
}
