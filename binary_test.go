package mafate

// Une charge binaire fait l'aller-retour, et Decrypt() refuse au lieu de rendre
// une chaîne qui n'est pas du texte.
//
// ⚠️ Go était le SEUL des trois SDK à ne rien perdre ici : string([]byte) copie
// les octets verbatim, une chaîne Go n'ayant pas à être de l'UTF-8 valide. Node
// corrompait en silence (U+FFFD), Python levait une exception portant le clair.
// La validation ajoutée est donc un CHANGEMENT DE COMPORTEMENT pour Go,
// délibéré : trois comportements distincts derrière une même signature valent
// moins qu'un contrat unique, et DecryptBytes est le correctif — pas un
// contournement.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

// Charge binaire réaliste : en-tête PDF, octet nul, séquences UTF-8 invalides.
var binaryPayload = []byte{
	0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x37, 0x0a, 0x00, 0x01, 0xff, 0xfe, 0x20,
	0x53, 0x45, 0x43, 0x52, 0x45, 0x54, 0x20, 0x80, 0x81, 0xfd,
}

var testEnvelope = &EncryptedData{
	Ciphertext: "c",
	WrappedKey: "w",
	IV:         "i",
	KeyID:      "key_abc",
	KeyVersion: 1,
}

// stubServer répond à /v1/decrypt avec raw encodé en base64, et enregistre le
// dernier corps reçu pour les assertions sur ce qui a été ENVOYÉ.
func stubServer(raw []byte, lastBody *string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if lastBody != nil {
			*lastBody = string(body)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"plaintext": base64.StdEncoding.EncodeToString(raw),
		})
	}))
}

func TestDecryptRefusesNonUTF8(t *testing.T) {
	srv := stubServer(binaryPayload, nil)
	defer srv.Close()

	c := New("eaas_sk_test", WithBaseURL(srv.URL))

	_, err := c.Decrypt(context.Background(), testEnvelope)
	if err == nil {
		t.Fatal("un clair non-UTF-8 doit produire une erreur, pas une chaîne qui n'est pas du texte")
	}
	// L'erreur doit être actionnable, sinon l'appelant contourne au lieu de corriger.
	if !strings.Contains(err.Error(), "DecryptBytes") {
		t.Errorf("le message doit orienter vers DecryptBytes, obtenu : %q", err.Error())
	}
	// Et ne doit pas recracher le clair.
	if strings.Contains(err.Error(), "SECRET") {
		t.Errorf("le message d'erreur contient le clair : %q", err.Error())
	}
}

func TestDecryptBytesRoundTripsBinaryExactly(t *testing.T) {
	srv := stubServer(binaryPayload, nil)
	defer srv.Close()

	c := New("eaas_sk_test", WithBaseURL(srv.URL))

	got, err := c.DecryptBytes(context.Background(), testEnvelope)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if string(got) != string(binaryPayload) {
		t.Errorf("octets altérés : %d reçus contre %d envoyés", len(got), len(binaryPayload))
	}
}

// Verrouille la prémisse de tout ce fichier : la charge de test EST bien
// non-UTF-8. Si elle devenait valide, les tests ci-dessus passeraient sans plus
// rien prouver.
func TestBinaryPayloadIsActuallyInvalidUTF8(t *testing.T) {
	if utf8.Valid(binaryPayload) {
		t.Fatal("la charge de test est de l'UTF-8 valide : les tests de refus ne prouvent plus rien")
	}
}

func TestEncryptBytesSendsExactBytes(t *testing.T) {
	var sent string
	srv := stubServer([]byte("peu importe"), &sent)
	defer srv.Close()

	c := New("eaas_sk_test", WithBaseURL(srv.URL))

	if _, err := c.EncryptBytes(context.Background(), binaryPayload, "key_abc"); err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}

	var payload struct {
		Plaintext string `json:"plaintext"`
	}
	if err := json.Unmarshal([]byte(sent), &payload); err != nil {
		t.Fatalf("corps envoyé illisible : %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(payload.Plaintext)
	if err != nil {
		t.Fatalf("base64 envoyé illisible : %v", err)
	}
	if string(decoded) != string(binaryPayload) {
		t.Error("les octets envoyés doivent être ceux fournis, sans transformation")
	}
}

func TestDecryptStillReturnsTextForValidUTF8(t *testing.T) {
	const texte = "données sensibles — accentué, émoji 🔐"

	srv := stubServer([]byte(texte), nil)
	defer srv.Close()

	c := New("eaas_sk_test", WithBaseURL(srv.URL))

	got, err := c.Decrypt(context.Background(), testEnvelope)
	if err != nil {
		t.Fatalf("erreur inattendue sur une charge UTF-8 valide : %v", err)
	}
	if got != texte {
		t.Errorf("clair = %q, attendu %q", got, texte)
	}
}
