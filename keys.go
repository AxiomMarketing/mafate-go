package mafate

import (
	"context"
	"fmt"
)

// KeysService provides methods for the /v1/keys resource.
type KeysService struct {
	http *httpClient
}

// List returns all keys for the authenticated tenant.
func (s *KeysService) List(ctx context.Context) ([]Key, error) {
	var resp ListKeysResponse
	if err := s.http.get(ctx, "/v1/keys", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Keys, nil
}

// Get returns the full detail of a single key including its version history.
func (s *KeysService) Get(ctx context.Context, id string) (*KeyDetail, error) {
	var out KeyDetail
	if err := s.http.get(ctx, fmt.Sprintf("/v1/keys/%s", id), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Create provisions a new encryption key.
func (s *KeysService) Create(ctx context.Context, req CreateKeyRequest) (*Key, error) {
	var out Key
	if err := s.http.post(ctx, "/v1/keys", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Rotate creates a new version of the key, making it the active version.
func (s *KeysService) Rotate(ctx context.Context, id string) (*Key, error) {
	var out Key
	if err := s.http.post(ctx, fmt.Sprintf("/v1/keys/%s/rotate", id), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Disable marks a key as disabled. Disabled keys cannot be used for new
// encrypt operations but retained ciphertexts can still be decrypted.
func (s *KeysService) Disable(ctx context.Context, id string) error {
	return s.http.delete(ctx, fmt.Sprintf("/v1/keys/%s", id))
}

// Export retrieves the raw DEK material for a key.
// Use this when migrating away from MAFATE to decrypt your data independently.
// WARNING: Handle exported keys with extreme care. Store in a secure vault.
func (s *KeysService) Export(ctx context.Context, id string) (*KeyExportResponse, error) {
	var out KeyExportResponse
	if err := s.http.post(ctx, fmt.Sprintf("/v1/keys/%s/export", id), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SetRotationPolicy configures automatic rotation for a key.
// Pass nil for intervalDays to remove the rotation policy.
func (s *KeysService) SetRotationPolicy(ctx context.Context, id string, intervalDays *int) error {
	body := map[string]interface{}{"interval_days": intervalDays}
	return s.http.patch(ctx, "/v1/keys/"+id+"/rotation", body, nil)
}
