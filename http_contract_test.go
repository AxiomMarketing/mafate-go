package mafate

// Contrat HTTP : les comportements que les trois SDK doivent partager.
//
// Chaque cas a un jumeau nommé pareil dans les suites Node et Python. Une
// divergence de contrat fait rougir au moins un des trois.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ─── (a) préfixe de chemin conservé ──────────────────────────────────────────

func TestContractBaseURLPathPrefixIsPreserved(t *testing.T) {
	var receivedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	}))
	defer srv.Close()

	c := New("eaas_sk_test", WithBaseURL(srv.URL+"/mafate"))

	if _, err := c.Health(context.Background()); err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if receivedPath != "/mafate/health" {
		t.Errorf("le préfixe de chemin a été perdu : le serveur a reçu %q", receivedPath)
	}
}

// ─── (b) le délai couvre la lecture du corps ─────────────────────────────────

func TestContractTruncatedBodyTimesOutInsteadOfHanging(t *testing.T) {
	// Répond 200 avec les en-têtes, écrit un début de corps, puis se tait.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"stat`))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		time.Sleep(3 * time.Second)
	}))
	defer srv.Close()

	c := New("eaas_sk_test", WithBaseURL(srv.URL), WithTimeout(500*time.Millisecond))

	started := time.Now()
	_, err := c.Health(context.Background())
	if err == nil {
		t.Fatal("un corps interrompu doit produire une erreur")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Errorf("l'appel a duré %v : le délai ne couvre pas la lecture du corps", elapsed)
	}
}

// ─── (c) hiérarchie d'erreurs uniforme ───────────────────────────────────────

func TestContractTimeoutRaisesSDKTimeoutError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
	}))
	defer srv.Close()

	c := New("eaas_sk_test", WithBaseURL(srv.URL), WithTimeout(300*time.Millisecond))

	_, err := c.Health(context.Background())
	if err == nil {
		t.Fatal("un dépassement de délai doit produire une erreur")
	}

	var te *TimeoutError
	if !errors.As(err, &te) {
		t.Fatalf("attendu *TimeoutError, obtenu %T : %v", err, err)
	}

	// La hiérarchie : un TimeoutError EST une erreur du SDK. C'est ce que
	// l'incorporation + Unwrap() reproduisent, faute d'héritage en Go.
	var me *MafateError
	if !errors.As(err, &me) {
		t.Error("errors.As doit aussi récupérer *MafateError : la hiérarchie est rompue")
	}
}

func TestContractUnreachableHostRaisesSDKConnectionError(t *testing.T) {
	// Port fermé : la connexion TCP échoue immédiatement.
	c := New("eaas_sk_test", WithBaseURL("http://127.0.0.1:1"), WithTimeout(2*time.Second))

	_, err := c.Health(context.Background())
	if err == nil {
		t.Fatal("un hôte injoignable doit produire une erreur")
	}

	var ce *ConnectionError
	if !errors.As(err, &ce) {
		t.Fatalf("attendu *ConnectionError, obtenu %T : %v", err, err)
	}

	var me *MafateError
	if !errors.As(err, &me) {
		t.Error("errors.As doit aussi récupérer *MafateError : la hiérarchie est rompue")
	}
}

// Verrouille la distinction entre les deux : un délai n'est pas un échec de
// connexion. Les confondre pousse à réessayer là où il faut corriger une
// configuration, ou l'inverse.
func TestContractTimeoutAndConnectionErrorsAreDistinct(t *testing.T) {
	var ce *ConnectionError
	timeoutErr := translateTransportError(&net.DNSError{IsTimeout: true}, time.Second)
	if errors.As(timeoutErr, &ce) {
		t.Error("un dépassement de délai ne doit pas être classé en ConnectionError")
	}

	var te *TimeoutError
	connErr := translateTransportError(errors.New("connection refused"), time.Second)
	if errors.As(connErr, &te) {
		t.Error("un échec de connexion ne doit pas être classé en TimeoutError")
	}
}

func TestContractNonJSONErrorBodyPreservesStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("<html>502 Bad Gateway</html>"))
	}))
	defer srv.Close()

	c := New("eaas_sk_test", WithBaseURL(srv.URL))

	_, err := c.Health(context.Background())
	if err == nil {
		t.Fatal("un 500 doit produire une erreur")
	}

	var apiErr *ApiError
	if !errors.As(err, &apiErr) {
		t.Fatalf("attendu *ApiError, obtenu %T", err)
	}
	if apiErr.Status != 500 {
		t.Errorf("statut = %d, doit survivre à un corps non-JSON", apiErr.Status)
	}
}

// ─── échappement des identifiants de chemin ──────────────────────────────────

func TestContractHostileKeyIDStaysInItsPathSegment(t *testing.T) {
	var receivedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"k"}`))
	}))
	defer srv.Close()

	c := New("eaas_sk_test", WithBaseURL(srv.URL))

	_, _ = c.Keys.Get(context.Background(), "../../v1/keys")

	// ⚠️ L'assertion évidente — « le chemin ne contient pas ../.. » — est
	// DÉCORATIVE : la normalisation d'URL fait disparaître ../.. que
	// l'échappement soit là ou non. Vérifié par mutation côté Node.
	//
	// Ce qu'il faut vérifier est plus grave : sans échappement,
	// /v1/keys/../../v1/keys se normalise en /v1/keys, soit l'endpoint de LISTE.
	// Un identifiant hostile n'échoue pas, il invoque un AUTRE appel.
	if receivedPath == "/v1/keys" {
		t.Error("traversée de chemin : l'appel a atterri sur l'endpoint de LISTE au lieu du GET ciblé")
	}
	if !strings.HasPrefix(receivedPath, "/v1/keys/") || len(receivedPath) <= len("/v1/keys/") {
		t.Errorf("l'identifiant doit rester un segment sous /v1/keys/ ; reçu %q", receivedPath)
	}
}
