package mafate

// Conformité au corpus de vecteurs webhook PARTAGÉ.
//
// Ce fichier consomme ../test-vectors/webhook-v1.json, le même que les SDK Node et
// Python. Une divergence de contrat entre les trois fait rougir au moins un des
// trois.
//
// Le corpus est chargé sans filet : s'il est introuvable, ces tests ÉCHOUENT.
// Un t.Skip serait un garde décoratif — il rendrait l'absence du corpus
// indiscernable de sa satisfaction.
//
// Le corpus voyage AVEC le paquet (testdata/), donc `go test` fonctionne aussi
// dans le miroir public. Ce n'était pas le cas en v0.2.0.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type vectorCase struct {
	Name                   string  `json:"name"`
	TimestampOffsetSeconds *int64  `json:"timestamp_offset_seconds"`
	TimestampLiteral       *string `json:"timestamp_literal"`
	Signature              string  `json:"signature"`
	SignatureLiteral       *string `json:"signature_literal"`
	SignaturePrefix        string  `json:"signature_prefix"`
	VerifiedPayload        *string `json:"verified_payload"`
	Expected               bool    `json:"expected"`
}

type vectorFile struct {
	Secret  string `json:"secret"`
	Payload string `json:"payload"`
	Frozen  struct {
		Timestamp string `json:"timestamp"`
		Signature string `json:"signature"`
	} `json:"frozen"`
	Cases []vectorCase `json:"cases"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()

	// ⚠️ Corpus lu depuis testdata/, copie locale au paquet — PAS depuis
	// packages/test-vectors/ du monorepo. Le subtree split n'emporte que le
	// contenu de packages/sdk-go/, et un chemin remontant hors du paquet casse
	// `go test` dans le miroir public. `testdata/` est en outre la convention Go :
	// le compilateur ignore ce répertoire.
	path := filepath.Join("testdata", "webhook-v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("corpus de vecteurs partagé illisible (%s) : %v", path, err)
	}

	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("corpus de vecteurs partagé illisible : %v", err)
	}
	if len(v.Cases) == 0 {
		t.Fatal("le corpus partagé ne contient aucun cas — un corpus vide passerait tout")
	}
	return v
}

func signVector(timestamp, payload, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + "." + payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// resolve transforme un cas du corpus en arguments concrets.
//
// La signature est TOUJOURS calculée sur le payload canonique ; VerifiedPayload
// est ce qui parvient au vérificateur. C'est ce qui distingue une altération en
// transit d'un message légitimement re-signé.
func (c vectorCase) resolve(t *testing.T, v vectorFile) (payload, signature, timestamp string) {
	t.Helper()

	payload = v.Payload
	if c.VerifiedPayload != nil {
		payload = *c.VerifiedPayload
	}

	switch {
	case c.TimestampLiteral != nil:
		timestamp = *c.TimestampLiteral
	case c.TimestampOffsetSeconds != nil:
		timestamp = strconv.FormatInt(time.Now().Unix()+*c.TimestampOffsetSeconds, 10)
	default:
		t.Fatalf("cas %q : ni timestamp_literal ni timestamp_offset_seconds", c.Name)
	}

	if c.SignatureLiteral != nil {
		return payload, *c.SignatureLiteral, timestamp
	}

	switch c.Signature {
	case "@correct":
		signature = signVector(timestamp, v.Payload, v.Secret)
	case "@correct_uppercase":
		signature = strings.ToUpper(signVector(timestamp, v.Payload, v.Secret))
	case "@correct_wrong_secret":
		signature = signVector(timestamp, v.Payload, "whsec_un_autre_secret")
	case "@payload_only":
		// Exactement ce que calculait le repli supprimé : HMAC du payload SEUL,
		// sans le préfixe d'horodatage.
		mac := hmac.New(sha256.New, []byte(v.Secret))
		mac.Write([]byte(v.Payload))
		signature = hex.EncodeToString(mac.Sum(nil))
	default:
		t.Fatalf("cas %q : spécification de signature inconnue %q", c.Name, c.Signature)
	}

	return payload, c.SignaturePrefix + signature, timestamp
}

func TestSharedWebhookVectors(t *testing.T) {
	v := loadVectors(t)

	for _, c := range v.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			payload, signature, timestamp := c.resolve(t, v)

			got := VerifyWebhookWithTimestamp(payload, signature, v.Secret, timestamp, 300)

			if got != c.Expected {
				t.Errorf("attendu %v, obtenu %v — ce cas est partagé avec les SDK Node et Python, "+
					"une divergence ici est une divergence de contrat", c.Expected, got)
			}
		})
	}
}

// Le vecteur figé, point d'ancrage de la conformité croisée.
//
// La tolérance est calculée depuis l'âge réel du vecteur : la fenêtre anti-rejeu
// est neutralisée volontairement — elle est couverte par les cas relatifs — et le
// test ne peut pas pourrir avec le temps.
func TestSharedFrozenVector(t *testing.T) {
	v := loadVectors(t)

	ts, err := strconv.ParseInt(v.Frozen.Timestamp, 10, 64)
	if err != nil {
		t.Fatalf("horodatage figé illisible : %v", err)
	}
	age := time.Now().Unix() - ts
	if age < 0 {
		age = -age
	}

	if !VerifyWebhookWithTimestamp(v.Payload, v.Frozen.Signature, v.Secret, v.Frozen.Timestamp, int(age)+3600) {
		t.Error("VerifyWebhookWithTimestamp doit accepter le vecteur figé partagé avec les SDK Node et Python")
	}
}

// VerifyWebhook déléguait avec timestamp="" et ne pouvait donc valider aucun
// webhook légitime. Ce test verrouille le fait qu'elle transmet désormais
// l'horodatage qu'on lui donne.
func TestVerifyWebhookForwardsTimestamp(t *testing.T) {
	v := loadVectors(t)

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := signVector(ts, v.Payload, v.Secret)

	if !VerifyWebhook(v.Payload, sig, v.Secret, ts) {
		t.Error("VerifyWebhook doit accepter une signature fraîche quand l'horodatage lui est fourni")
	}
	if VerifyWebhook(v.Payload, sig, v.Secret, "") {
		t.Error("VerifyWebhook doit refuser un horodatage vide, jamais retomber sur la signature du payload seul")
	}
}
