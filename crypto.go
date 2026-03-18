package mafate

import (
	"context"
	"encoding/base64"
	"fmt"
)

// encrypt is the shared implementation used by Client.Encrypt.
// It encodes plaintext as standard base64 before sending it to the API.
func encrypt(ctx context.Context, hc *httpClient, plaintext string, keyID string) (*EncryptedData, error) {
	if plaintext == "" {
		return nil, &MafateError{Message: "plaintext must not be empty"}
	}
	if keyID == "" {
		return nil, &MafateError{Message: "keyID must not be empty"}
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(plaintext))

	payload := map[string]string{
		"plaintext": encoded,
		"key_id":    keyID,
	}

	var out EncryptedData
	if err := hc.post(ctx, "/v1/encrypt", payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Hash calls POST /v1/hash and returns the hash string.
func (c *Client) Hash(ctx context.Context, value, keyID string) (string, error) {
	body := map[string]string{"value": value, "key_id": keyID}
	var res HashResponse
	err := c.http.post(ctx, "/v1/hash", body, &res)
	if err != nil {
		return "", err
	}
	return res.Hash, nil
}

// decrypt is the shared implementation used by Client.Decrypt.
// The API returns plaintext as base64; this function decodes it back to UTF-8.
func decrypt(ctx context.Context, hc *httpClient, data *EncryptedData) (string, error) {
	if data == nil {
		return "", &MafateError{Message: "encrypted data must not be nil"}
	}

	payload := map[string]interface{}{
		"ciphertext":  data.Ciphertext,
		"wrapped_key": data.WrappedKey,
		"iv":          data.IV,
		"key_id":      data.KeyID,
		"key_version": data.KeyVersion,
	}

	var raw decryptResponse
	if err := hc.post(ctx, "/v1/decrypt", payload, &raw); err != nil {
		return "", err
	}

	decoded, err := base64.StdEncoding.DecodeString(raw.Plaintext)
	if err != nil {
		return "", &MafateError{Message: fmt.Sprintf("decode plaintext base64: %s", err)}
	}
	return string(decoded), nil
}
