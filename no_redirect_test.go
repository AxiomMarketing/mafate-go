package mafate

// Le SDK ne suit AUCUNE redirection, et ne rejoue jamais le corps.
//
// L'assertion qui compte n'est pas « le SDK renvoie une erreur » — un SDK cassé en
// renverrait une aussi. C'est que le SERVEUR DE DESTINATION ne reçoit RIEN : c'est
// lui qui, dans le scénario réel, récupérerait le clair (aujourd'hui) ou la DEK
// (en mode enveloppe).
//
// Deux serveurs httptest distincts, donc deux origines : on reproduit la
// redirection vers un hôte tiers, pas un aller-retour sur soi-même.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type sinkRequest struct {
	Method        string
	Path          string
	Body          string
	Authorization string
}

type sink struct {
	mu       sync.Mutex
	received []sinkRequest
	server   *httptest.Server
}

func newSink() *sink {
	s := &sink{}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.received = append(s.received, sinkRequest{
			Method:        r.Method,
			Path:          r.URL.Path,
			Body:          string(body),
			Authorization: r.Header.Get("Authorization"),
		})
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ciphertext":"pwned"}`))
	}))
	return s
}

func (s *sink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.received)
}

func (s *sink) dump() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(s.received)
	return string(b)
}

func newRedirector(target string, status int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target+"/v1/encrypt")
		w.WriteHeader(status)
	}))
}

// 307 et 308 sont les deux codes qui REJOUENT le corps. 301/302/303 le
// transforment en GET, moins grave mais toujours une fuite de la requête vers un
// hôte tiers — les quatre doivent échouer identiquement.
func TestRedirectIsRefusedAndBodyNeverReplayed(t *testing.T) {
	for _, status := range []int{301, 302, 307, 308} {
		status := status
		t.Run(http.StatusText(status), func(t *testing.T) {
			sk := newSink()
			defer sk.server.Close()

			red := newRedirector(sk.server.URL, status)
			defer red.Close()

			c := New("eaas_sk_test_secret", WithBaseURL(red.URL))

			_, err := c.Encrypt(context.Background(), "données confidentielles", "key_abc")
			if err == nil {
				t.Fatal("une redirection doit produire une erreur, pas un succès silencieux")
			}

			apiErr, ok := err.(*ApiError)
			if !ok {
				t.Fatalf("attendu *ApiError, obtenu %T : %v", err, err)
			}
			if apiErr.Status != status {
				t.Errorf("statut = %d, attendu %d", apiErr.Status, status)
			}
			if !strings.Contains(strings.ToLower(apiErr.Title), "redirection") {
				t.Errorf("titre = %q, devrait nommer la redirection", apiErr.Title)
			}

			// L'assertion CENTRALE.
			if n := sk.count(); n != 0 {
				t.Errorf("la cible de la redirection a reçu %d requête(s) : %s", n, sk.dump())
			}
		})
	}
}

// Prouve que le serveur bouchon SAIT capturer — sinon le test ci-dessus passerait
// même avec un enregistreur inerte, et « 0 requête reçue » ne distinguerait pas
// « rien n'a été rejoué » de « l'enregistreur est cassé ».
func TestSinkWouldCaptureThePlaintext(t *testing.T) {
	sk := newSink()
	defer sk.server.Close()

	req, err := http.NewRequest(http.MethodPost, sk.server.URL+"/v1/encrypt",
		strings.NewReader(`{"plaintext":"ZG9ubmVlcw=="}`))
	if err != nil {
		t.Fatalf("construction de la requête : %v", err)
	}
	req.Header.Set("Authorization", "Bearer eaas_sk_test_secret")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("appel direct de la cible : %v", err)
	}
	defer resp.Body.Close()

	if sk.count() != 1 {
		t.Fatalf("l'enregistreur du bouchon ne capture rien (%d requêtes)", sk.count())
	}
	sk.mu.Lock()
	got := sk.received[0]
	sk.mu.Unlock()

	if !strings.Contains(got.Body, "plaintext") {
		t.Errorf("corps capturé = %q, devrait contenir le payload", got.Body)
	}
	if got.Authorization != "Bearer eaas_sk_test_secret" {
		t.Errorf("Authorization capturé = %q", got.Authorization)
	}
}
