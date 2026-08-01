package mafate

// Sémantique du null sur Update() — les TROIS états, côté client.
//
// Jumeaux nommés pareil dans les suites Node et Python. Le serveur distingue
// « absent », « null » et « valeur » ; ces tests vérifient que le SDK sait
// produire les trois — ce qu'un *string seul ne permet PAS.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func captureUpdateBody(t *testing.T, req UpdateApiKeyRequest) map[string]interface{} {
	t.Helper()

	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"apk_1","name":"k","prefix":"eaas_","permissions":[],"status":"active","created_at":"2026-01-01T00:00:00Z"}`))
	}))
	defer srv.Close()

	c := New("eaas_sk_test", WithBaseURL(srv.URL))
	if _, err := c.ApiKeys.Update(context.Background(), "apk_1", req); err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("corps envoyé illisible (%s) : %v", raw, err)
	}
	return body
}

func TestNullSemanticsOmittedFieldIsAbsentFromBody(t *testing.T) {
	body := captureUpdateBody(t, UpdateApiKeyRequest{Permissions: []string{"encrypt"}})

	if _, present := body["expires_at"]; present {
		t.Errorf("expires_at ne doit pas figurer dans le corps : %v", body)
	}
	if _, present := body["allowed_ips"]; present {
		t.Errorf("allowed_ips ne doit pas figurer dans le corps : %v", body)
	}
}

func TestNullSemanticsClearFlagSendsExplicitNull(t *testing.T) {
	body := captureUpdateBody(t, UpdateApiKeyRequest{
		ClearExpiresAt:  true,
		ClearAllowedIPs: true,
	})

	// La clé doit être PRÉSENTE et nulle : absente, le serveur conserverait.
	v, present := body["expires_at"]
	if !present {
		t.Fatal("expires_at doit être PRÉSENT dans le corps pour effacer")
	}
	if v != nil {
		t.Errorf("expires_at = %v, attendu null", v)
	}
	v, present = body["allowed_ips"]
	if !present {
		t.Fatal("allowed_ips doit être PRÉSENT dans le corps pour effacer")
	}
	if v != nil {
		t.Errorf("allowed_ips = %v, attendu null", v)
	}
}

func TestNullSemanticsValueIsSentAsIs(t *testing.T) {
	exp := "2031-06-15T12:00:00Z"
	body := captureUpdateBody(t, UpdateApiKeyRequest{
		ExpiresAt:  &exp,
		AllowedIPs: []string{"1.2.3.4"},
	})

	if body["expires_at"] != exp {
		t.Errorf("expires_at = %v, attendu %q", body["expires_at"], exp)
	}
	ips, _ := body["allowed_ips"].([]interface{})
	if len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Errorf("allowed_ips = %v, attendu [1.2.3.4]", body["allowed_ips"])
	}
}

// LE test qui verrouille la conception. Un *string nil ne doit RIEN envoyer.
//
// Retirer `omitempty` — ce que prescrivait la fiche APEX — aurait produit
// `"expires_at": null` à chaque appel : combiné au correctif serveur, un client
// mettant à jour ses seules permissions aurait EFFACÉ l'expiration de sa clé.
// Mesuré. C'est pour ça que le corps est construit par buildBody().
func TestNullSemanticsNilPointerDoesNotClear(t *testing.T) {
	body := captureUpdateBody(t, UpdateApiKeyRequest{
		Permissions: []string{"encrypt"},
		ExpiresAt:   nil, // explicitement nil
	})

	if _, present := body["expires_at"]; present {
		t.Error("un pointeur nil ne doit RIEN envoyer, sinon il effacerait l'expiration")
	}
}

// L'effacement l'emporte sur la valeur : demander les deux est une contradiction
// de l'appelant, et le drapeau exprime une intention explicite.
func TestNullSemanticsClearWinsOverValue(t *testing.T) {
	exp := "2031-06-15T12:00:00Z"
	body := captureUpdateBody(t, UpdateApiKeyRequest{
		ExpiresAt:      &exp,
		ClearExpiresAt: true,
	})

	if body["expires_at"] != nil {
		t.Errorf("expires_at = %v, attendu null : le drapeau d'effacement prime", body["expires_at"])
	}
}
