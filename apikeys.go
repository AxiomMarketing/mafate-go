package mafate

import (
	"context"
	"fmt"
)

// ApiKeysService provides methods for the /v1/api-keys resource.
type ApiKeysService struct {
	http *httpClient
}

// List returns all API keys for the authenticated tenant (secrets are not included).
func (s *ApiKeysService) List(ctx context.Context) ([]ApiKey, error) {
	var resp ListApiKeysResponse
	if err := s.http.get(ctx, "/v1/api-keys", nil, &resp); err != nil {
		return nil, err
	}
	return resp.ApiKeys, nil
}

// Create provisions a new API key. The secret is only returned once in the response.
func (s *ApiKeysService) Create(ctx context.Context, req CreateApiKeyRequest) (*ApiKeyWithSecret, error) {
	var out ApiKeyWithSecret
	if err := s.http.post(ctx, "/v1/api-keys", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Update changes the permissions or expiry of an existing API key.
func (s *ApiKeysService) Update(ctx context.Context, id string, req UpdateApiKeyRequest) (*ApiKey, error) {
	var out ApiKey
	if err := s.http.patch(ctx, fmt.Sprintf("/v1/api-keys/%s", id), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Revoke permanently revokes an API key. Revoked keys cannot be reinstated.
func (s *ApiKeysService) Revoke(ctx context.Context, id string) error {
	return s.http.delete(ctx, fmt.Sprintf("/v1/api-keys/%s", id))
}
