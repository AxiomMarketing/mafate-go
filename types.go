package mafate

// HealthResponse is returned by GET /health.
type HealthResponse struct {
	Status   string `json:"status"`
	Database string `json:"database"`
	Cache    string `json:"cache"`
	HSM      string `json:"hsm"`
}

// Key represents an encryption key (summary form).
type Key struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Algorithm      string `json:"algorithm"`
	Status         string `json:"status"`
	CurrentVersion int    `json:"current_version"`
	CreatedAt      string `json:"created_at"`
}

// KeyVersion represents a single version of a key.
type KeyVersion struct {
	Version   int    `json:"version"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

// KeyDetail extends Key with version history.
type KeyDetail struct {
	Key
	UpdatedAt string       `json:"updated_at"`
	Versions  []KeyVersion `json:"versions"`
}

// CreateKeyRequest is the payload for POST /v1/keys.
type CreateKeyRequest struct {
	Name      string `json:"name"`
	Algorithm string `json:"algorithm,omitempty"`
}

// ListKeysResponse is the envelope returned by GET /v1/keys.
type ListKeysResponse struct {
	Keys  []Key `json:"keys"`
	Count int   `json:"count"`
}

// KeyExportResponse is returned by POST /v1/keys/{id}/export.
type KeyExportResponse struct {
	KeyID      string               `json:"key_id"`
	Name       string               `json:"name"`
	Algorithm  string               `json:"algorithm"`
	Versions   []ExportedKeyVersion `json:"versions"`
	ExportedAt string               `json:"exported_at"`
	Warning    string               `json:"warning"`
}

// ExportedKeyVersion holds the raw DEK material for a single key version.
type ExportedKeyVersion struct {
	Version int    `json:"version"`
	DEKHex  string `json:"dek_hex"`
	Status  string `json:"status"`
}

// EncryptedData holds all fields returned by POST /v1/encrypt and
// needed as input to POST /v1/decrypt.
type EncryptedData struct {
	Ciphertext string `json:"ciphertext"`
	WrappedKey string `json:"wrapped_key"`
	IV         string `json:"iv"`
	KeyID      string `json:"key_id"`
	KeyVersion int    `json:"key_version"`
}

// decryptResponse is the raw response from POST /v1/decrypt.
type decryptResponse struct {
	Plaintext string `json:"plaintext"`
}

// HashResponse is returned by POST /v1/hash.
type HashResponse struct {
	Hash  string `json:"hash"`
	KeyID string `json:"key_id"`
}

// ApiKey represents an API key (summary form, no secret).
type ApiKey struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Prefix      string   `json:"prefix"`
	Permissions []string `json:"permissions"`
	Status      string   `json:"status"`
	CreatedAt   string   `json:"created_at"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
}

// ApiKeyWithSecret extends ApiKey and is only returned on creation.
type ApiKeyWithSecret struct {
	ApiKey
	Secret string `json:"secret"`
}

// CreateApiKeyRequest is the payload for POST /v1/api-keys.
type CreateApiKeyRequest struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
}

// UpdateApiKeyRequest is the payload for PATCH /v1/api-keys/{id}.
// Use a pointer for ExpiresAt so an explicit null can be sent to clear it.
type UpdateApiKeyRequest struct {
	Permissions []string `json:"permissions,omitempty"`
	ExpiresAt   *string  `json:"expires_at,omitempty"`
}

// ListApiKeysResponse is the envelope returned by GET /v1/api-keys.
type ListApiKeysResponse struct {
	ApiKeys []ApiKey `json:"api_keys"`
	Count   int      `json:"count"`
}

// AuditEntry represents a single audit log record.
type AuditEntry struct {
	ID         int                    `json:"id"`
	TenantID   string                 `json:"tenant_id"`
	Action     string                 `json:"action"`
	KeyID      string                 `json:"key_id,omitempty"`
	KeyVersion int                    `json:"key_version,omitempty"`
	Actor      string                 `json:"actor"`
	IPAddress  string                 `json:"ip_address,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt  string                 `json:"created_at"`
}

// AuditFilters holds optional query parameters for GET /v1/audit.
type AuditFilters struct {
	Action   string
	KeyID    string
	DateFrom string
	DateTo   string
	Limit    int
	Offset   int
}

// ListAuditResponse is the envelope returned by GET /v1/audit.
type ListAuditResponse struct {
	Logs   []AuditEntry `json:"logs"`
	Count  int          `json:"count"`
	Total  int          `json:"total"`
	Limit  int          `json:"limit"`
	Offset int          `json:"offset"`
}

// AuditChainVerification is returned by GET /v1/audit/verify.
type AuditChainVerification struct {
	Valid           bool `json:"valid"`
	TotalEntries    int  `json:"total_entries"`
	VerifiedEntries int  `json:"verified_entries"`
	BrokenAt        *int `json:"broken_at,omitempty"`
}
