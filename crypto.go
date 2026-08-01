package mafate

import (
	"context"
	"encoding/base64"
	"fmt"
	"unicode/utf8"
)

// encryptBytes chiffre des OCTETS bruts. Primitive symétrique de decryptBytes :
// une charge binaire doit pouvoir faire l'aller-retour complet.
func encryptBytes(ctx context.Context, hc *httpClient, plaintext []byte, keyID string) (*EncryptedData, error) {
	if len(plaintext) == 0 {
		return nil, &MafateError{Message: "plaintext must not be empty"}
	}
	if keyID == "" {
		return nil, &MafateError{Message: "keyID must not be empty"}
	}

	encoded := base64.StdEncoding.EncodeToString(plaintext)

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

// decryptBytes renvoie les OCTETS bruts du clair.
//
// C'est la primitive : toute charge binaire (PDF, image, archive, protobuf) doit
// passer par ici. decrypt() est une surcouche qui exige de l'UTF-8 valide.
func decryptBytes(ctx context.Context, hc *httpClient, data *EncryptedData) ([]byte, error) {
	if data == nil {
		return nil, &MafateError{Message: "encrypted data must not be nil"}
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
		return nil, err
	}

	decoded, err := base64.StdEncoding.DecodeString(raw.Plaintext)
	if err != nil {
		return nil, &MafateError{Message: fmt.Sprintf("decode plaintext base64: %s", err)}
	}
	return decoded, nil
}

// decrypt renvoie le clair en UTF-8 valide.
//
// ⚠️ CHANGEMENT DE COMPORTEMENT ASSUMÉ. Go était le seul des trois SDK à ne rien
// perdre : `string([]byte)` copie les octets verbatim, une chaîne Go n'ayant pas à
// être de l'UTF-8 valide. Un appelant qui faisait transiter du binaire par
// Decrypt() récupérait donc ses octets intacts, et cette validation le lui refuse
// désormais.
//
// C'est délibéré. Node corrompait en silence (U+FFFD) et Python levait une
// exception portant le clair : aligner les trois sur « decrypt() rend du texte,
// DecryptBytes() rend des octets » vaut mieux que trois comportements distincts
// pour une même signature. Le correctif est DecryptBytes, pas un contournement.
func decrypt(ctx context.Context, hc *httpClient, data *EncryptedData) (string, error) {
	decoded, err := decryptBytes(ctx, hc, data)
	if err != nil {
		return "", err
	}

	if !utf8.Valid(decoded) {
		return "", &MafateError{
			Message: "le clair déchiffré n'est pas de l'UTF-8 valide. " +
				"Utilisez DecryptBytes() pour récupérer les octets bruts.",
		}
	}

	return string(decoded), nil
}
