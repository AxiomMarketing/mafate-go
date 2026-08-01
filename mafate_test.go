package mafate

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Les valeurs attendues sont des LITTÉRAUX, pas les constantes defaultBaseURL et
// defaultTimeout.
//
// Comparer `c.http.baseURL != defaultBaseURL` serait tautologique : les deux côtés
// de l'égalité viennent de la même constante, donc la modifier ferait bouger les
// deux et le test ne pourrait jamais échouer. Vérifié par mutation — la première
// version de ce test laissait passer un changement de `defaultTimeout`.
//
// Ces deux valeurs sont un contrat public : les changer casse les intégrations
// existantes, donc le test doit les épingler explicitement.
func TestNewAppliesDefaults(t *testing.T) {
	c := New("eaas_sk_test")

	if c.http.baseURL != "https://api.mafate.io" {
		t.Errorf("baseURL par défaut = %q, attendu \"https://api.mafate.io\"", c.http.baseURL)
	}
	if c.http.httpClient.Timeout != 30*time.Second {
		t.Errorf("timeout par défaut = %v, attendu 30s", c.http.httpClient.Timeout)
	}
	if c.Keys == nil || c.ApiKeys == nil || c.Audit == nil {
		t.Error("les services Keys, ApiKeys et Audit doivent tous être instanciés")
	}
}

func TestWithBaseURLStripsTrailingSlash(t *testing.T) {
	c := New("eaas_sk_test", WithBaseURL("https://gw.exemple.fr/mafate/"))

	if c.http.baseURL != "https://gw.exemple.fr/mafate" {
		t.Errorf("baseURL = %q, le slash final aurait dû être retiré", c.http.baseURL)
	}
}

func TestWithTimeoutIsApplied(t *testing.T) {
	c := New("eaas_sk_test", WithTimeout(5*time.Second))

	if c.http.httpClient.Timeout != 5*time.Second {
		t.Errorf("timeout = %v, attendu 5s", c.http.httpClient.Timeout)
	}
}

// buildURL concatène baseURL et path. Ce test verrouille le comportement : un
// préfixe de chemin dans baseURL (passerelle d'entreprise) doit être CONSERVÉ.
func TestBuildURLPreservesPathPrefix(t *testing.T) {
	c := newHTTPClient("https://gw.exemple.fr/mafate", "k", &http.Transport{}, time.Second)

	got, err := c.buildURL("/v1/keys", nil)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if got != "https://gw.exemple.fr/mafate/v1/keys" {
		t.Errorf("URL = %q, le préfixe de chemin a été perdu", got)
	}
}

func TestBuildURLAppendsQueryParams(t *testing.T) {
	c := newHTTPClient("https://api.mafate.io", "k", &http.Transport{}, time.Second)

	got, err := c.buildURL("/v1/audit", map[string]string{"action": "key.export"})
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if !strings.Contains(got, "action=key.export") {
		t.Errorf("URL = %q, le paramètre de requête est absent", got)
	}
}

func TestApiErrorFormatting(t *testing.T) {
	withDetail := &ApiError{Status: 403, Title: "Forbidden", Detail: "missing permission"}
	if got := withDetail.Error(); got != "[403] Forbidden: missing permission" {
		t.Errorf("Error() = %q", got)
	}

	withoutDetail := &ApiError{Status: 404, Title: "Not Found"}
	if got := withoutDetail.Error(); got != "[404] Not Found" {
		t.Errorf("Error() sans détail = %q", got)
	}
}

// Exerce le contrat que les clients utilisent réellement : envelopper l'erreur du
// SDK dans la leur, puis la récupérer typée avec errors.As pour lire le statut.
//
// ⚠️ La première version se contentait de `err.Error() != ""`. Error() étant un
// fmt.Sprintf, il ne rend JAMAIS la chaîne vide : l'assertion ne pouvait pas
// échouer, et le commentaire invoquait errors.As sans que le test l'exerce.
func TestApiErrorIsRecoverableWithErrorsAs(t *testing.T) {
	wrapped := fmt.Errorf("appel de l'API MAFATE : %w", &ApiError{
		Status: 403,
		Title:  "Forbidden",
		Detail: "missing permission: keys:export",
	})

	var apiErr *ApiError
	if !errors.As(wrapped, &apiErr) {
		t.Fatal("errors.As doit récupérer *ApiError à travers l'enveloppe")
	}
	if apiErr.Status != 403 {
		t.Errorf("Status récupéré = %d, attendu 403", apiErr.Status)
	}
	if apiErr.Title != "Forbidden" {
		t.Errorf("Title récupéré = %q, attendu \"Forbidden\"", apiErr.Title)
	}
}

// ─── Vérification de signature de webhook ────────────────────────────────────

const (
	testPayload = `{"event":"key.rotated","key_id":"key_abc123"}`
	testSecret  = "whsec_test_do_not_use_in_production"
)

// signAt produit la signature attendue pour un horodatage donné, avec la
// primitive standard. Utilisé pour les tests dépendants de la fenêtre anti-rejeu :
// un horodatage figé serait une bombe à retardement, le test cassant le jour où
// le vecteur sort de la tolérance.
func signAt(timestamp, payload, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + "." + payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func nowTimestamp() string {
	return strconv.FormatInt(time.Now().Unix(), 10)
}

func TestVerifyWebhookAcceptsValidSignature(t *testing.T) {
	ts := nowTimestamp()

	if !VerifyWebhookWithTimestamp(testPayload, signAt(ts, testPayload, testSecret), testSecret, ts, 300) {
		t.Error("une signature valide et fraîche doit être acceptée")
	}
}

func TestVerifyWebhookAcceptsSha256Prefix(t *testing.T) {
	ts := nowTimestamp()

	if !VerifyWebhookWithTimestamp(testPayload, "sha256="+signAt(ts, testPayload, testSecret), testSecret, ts, 300) {
		t.Error("le préfixe sha256= doit être toléré")
	}
}

func TestVerifyWebhookRejectsAlteredPayload(t *testing.T) {
	ts := nowTimestamp()
	sig := signAt(ts, testPayload, testSecret)
	altered := strings.Replace(testPayload, "key_abc123", "key_abc124", 1)

	if VerifyWebhookWithTimestamp(altered, sig, testSecret, ts, 300) {
		t.Error("un payload altéré doit être rejeté")
	}
}

func TestVerifyWebhookRejectsWrongSecret(t *testing.T) {
	ts := nowTimestamp()
	sig := signAt(ts, testPayload, testSecret)

	if VerifyWebhookWithTimestamp(testPayload, sig, "whsec_wrong", ts, 300) {
		t.Error("un mauvais secret doit être rejeté")
	}
}

func TestVerifyWebhookRejectsExpiredTimestamp(t *testing.T) {
	old := strconv.FormatInt(time.Now().Unix()-3600, 10)

	if VerifyWebhookWithTimestamp(testPayload, signAt(old, testPayload, testSecret), testSecret, old, 300) {
		t.Error("un horodatage vieux d'une heure doit être refusé avec une tolérance de 300 s")
	}
}

func TestVerifyWebhookRejectsFutureTimestamp(t *testing.T) {
	future := strconv.FormatInt(time.Now().Unix()+3600, 10)

	if VerifyWebhookWithTimestamp(testPayload, signAt(future, testPayload, testSecret), testSecret, future, 300) {
		t.Error("un horodatage dans le futur doit être refusé")
	}
}

// La signature est CALCULÉE pour l'horodatage invalide, de sorte que le HMAC
// corresponde. Le seul motif de refus possible est donc le garde de parsing.
//
// ⚠️ La première version passait une signature bidon ("deadbeef") : elle était
// rejetée par l'échec du HMAC, que le garde existe ou non — un test décoratif.
func TestVerifyWebhookRejectsNonNumericTimestamp(t *testing.T) {
	const bad = "pas-un-nombre"

	if VerifyWebhookWithTimestamp(testPayload, signAt(bad, testPayload, testSecret), testSecret, bad, 300) {
		t.Error("la signature correspond : seul le garde de parsing peut justifier le refus")
	}
}

// Vecteur FIGÉ, passé à VerifyWebhookWithTimestamp — l'implémentation du SDK, pas
// l'auxiliaire du test.
//
// ⚠️ La première version comparait signAt(...) à la constante. Elle ne testait que
// la stdlib : la fonction du SDK n'était jamais appelée, donc le test ne pouvait
// échouer que si crypto/hmac changeait.
//
// La tolérance est calculée depuis l'âge réel du vecteur : la fenêtre anti-rejeu
// est neutralisée volontairement — elle est testée ailleurs — et le test ne peut
// pas pourrir avec le temps.
func TestFrozenVectorIsAcceptedByVerify(t *testing.T) {
	const (
		frozenTimestamp = "1767225600"
		frozenSignature = "fe7e1fbb7d1058733accb6d105d8accdb136b763175fe2db12db9e6f9a919aed"
	)

	ts, err := strconv.ParseInt(frozenTimestamp, 10, 64)
	if err != nil {
		t.Fatalf("horodatage figé illisible : %v", err)
	}
	age := time.Now().Unix() - ts
	if age < 0 {
		age = -age
	}

	if !VerifyWebhookWithTimestamp(testPayload, frozenSignature, testSecret, frozenTimestamp, int(age)+3600) {
		t.Error("VerifyWebhookWithTimestamp doit accepter le vecteur figé partagé avec les SDK Node et Python")
	}
}
