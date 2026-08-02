package mafate

// Mode enveloppe côté Go — ce que les vecteurs figés ne couvrent PAS.
//
// `envelope_vectors_test.go` prouve la CONFORMITÉ : les octets produits ici sont
// identiques à ceux de Node et Python. Il ne prouve rien sur la validation des
// entrées ni sur la composition avec `/wrap` et `/unwrap`, tous ses vecteurs
// étant bien formés par construction — constaté par mutation côté Node, où
// retirer les contrôles de longueur laissait les 15 vecteurs verts.
//
// S'y ajoute le point PROPRE À GO : l'effacement de la DEK, seule garantie réelle
// des trois SDK, qui doit donc être prouvée et pas seulement annoncée.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

// --- Validation des entrées --------------------------------------------------

func TestSealEnvelope_RejectsKeyOfWrongLength(t *testing.T) {
	iv, _ := GenerateIV()
	for _, n := range []int{0, 15, 16, 24, 31, 33, 64} {
		if _, err := SealEnvelope(make([]byte, n), iv, []byte("x")); err == nil {
			t.Errorf("une clé de %d octets a été acceptée : AES-256 en exige %d, et "+
				"une clé plus courte dégraderait silencieusement la force annoncée",
				n, EnvelopeKeyLength)
		}
	}
}

func TestSealEnvelope_RejectsIVOfWrongLength(t *testing.T) {
	key, _ := GenerateDEK()
	for _, n := range []int{0, 8, 11, 13, 16, 32} {
		if _, err := SealEnvelope(key, make([]byte, n), []byte("x")); err == nil {
			t.Errorf("un IV de %d octets a été accepté : le format figé impose %d "+
				"octets, et GCM dériverait sinon en interne un IV produisant un "+
				"chiffré illisible par Node et Python", n, EnvelopeIVLength)
		}
	}
}

func TestOpenEnvelope_RejectsCiphertextShorterThanTheTag(t *testing.T) {
	key, _ := GenerateDEK()
	iv, _ := GenerateIV()
	for _, n := range []int{0, 1, EnvelopeTagLength - 1} {
		if _, err := OpenEnvelope(key, iv, make([]byte, n)); err == nil {
			t.Errorf("un chiffré de %d octets a été accepté alors que le seul tag "+
				"en fait %d", n, EnvelopeTagLength)
		}
	}
}

// --- Propriétés cryptographiques ---------------------------------------------

// La convention de Go EST celle du format figé : gcm.Seal concatène nativement.
// Vérifié, pas supposé.
func TestSealEnvelope_TagIsAppended(t *testing.T) {
	key, _ := GenerateDEK()
	iv, _ := GenerateIV()

	for _, size := range []int{0, 1, 16, 1000} {
		sealed, err := SealEnvelope(key, iv, bytes.Repeat([]byte("A"), size))
		if err != nil {
			t.Fatalf("scellement en échec : %v", err)
		}
		if len(sealed) != size+EnvelopeTagLength {
			t.Errorf("clair de %d octets → chiffré de %d : le tag n'est pas concaténé, "+
				"la donnée serait illisible depuis Node et Python", size, len(sealed))
		}
	}
}

// ⚠️ Exigence explicite de la fiche : 1 000 opérations → 1 000 IV distincts.
//
// La réutilisation d'IV en GCM est la faute classique, et elle est SILENCIEUSE :
// tout continue de fonctionner, les déchiffrements réussissent, et la
// confidentialité est perdue sans le moindre signal.
func TestGenerateIV_ThousandOperationsGiveThousandDistinctIVs(t *testing.T) {
	const n = 1000
	seen := make(map[string]bool, n)

	for i := 0; i < n; i++ {
		iv, err := GenerateIV()
		if err != nil {
			t.Fatalf("tirage en échec à l'itération %d : %v", i, err)
		}
		if len(iv) != EnvelopeIVLength {
			t.Fatalf("IV de %d octets à l'itération %d", len(iv), i)
		}
		key := string(iv)
		if seen[key] {
			t.Fatalf("IV réutilisé à l'itération %d : la confidentialité de GCM est "+
				"perdue, et rien ne le signale", i)
		}
		seen[key] = true
	}
	if len(seen) != n {
		t.Errorf("%d IV distincts sur %d", len(seen), n)
	}
}

func TestGenerateDEK_ThousandOperationsGiveThousandDistinctKeys(t *testing.T) {
	const n = 1000
	seen := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		dek, err := GenerateDEK()
		if err != nil {
			t.Fatalf("tirage en échec : %v", err)
		}
		if len(dek) != EnvelopeKeyLength {
			t.Fatalf("DEK de %d octets", len(dek))
		}
		seen[string(dek)] = true
	}
	if len(seen) != n {
		t.Errorf("%d DEK distinctes sur %d", len(seen), n)
	}
}

func TestOpenEnvelope_RejectsTamperedCiphertext(t *testing.T) {
	key, _ := GenerateDEK()
	iv, _ := GenerateIV()
	sealed, err := SealEnvelope(key, iv, []byte("donnée sensible"))
	if err != nil {
		t.Fatalf("scellement : %v", err)
	}

	for _, idx := range []int{0, len(sealed) / 2, len(sealed) - 1} {
		tampered := append([]byte(nil), sealed...)
		tampered[idx] ^= 0xFF
		if _, err := OpenEnvelope(key, iv, tampered); err == nil {
			t.Errorf("l'octet %d a été modifié et le déchiffrement a RÉUSSI : "+
				"GCM n'authentifie donc rien", idx)
		}
	}
}

func TestOpenEnvelope_RejectsADifferentDEK(t *testing.T) {
	iv, _ := GenerateIV()
	right, _ := GenerateDEK()
	wrong, _ := GenerateDEK()

	sealed, _ := SealEnvelope(right, iv, []byte("donnée"))
	if _, err := OpenEnvelope(wrong, iv, sealed); err == nil {
		t.Error("une DEK différente a déchiffré le message")
	}
}

// ⚠️ LE POINT PROPRE À GO, et le seul des trois SDK qui soit une GARANTIE.
//
// `Zero` efface réellement, et `defer Zero(dek)` s'exécute quel que soit le
// chemin de sortie. Node ne peut qu'approcher cela (V8 a pu copier), Python pas
// du tout (`bytes` immuable). L'annoncer sans le prouver n'aurait aucune valeur.
func TestZero_ActuallyErasesTheBuffer(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("tirage : %v", err)
	}

	nonZero := false
	for _, b := range dek {
		if b != 0 {
			nonZero = true
			break
		}
	}
	if !nonZero {
		t.Fatal("la DEK tirée était déjà nulle : le test ne prouverait rien")
	}

	Zero(dek)
	for i, b := range dek {
		if b != 0 {
			t.Fatalf("l'octet %d vaut %d après Zero : l'effacement annoncé comme "+
				"GARANTI en Go ne fonctionne pas", i, b)
		}
	}
}

// L'effacement doit avoir lieu SUR TOUS LES CHEMINS, y compris quand l'emballage
// échoue : c'est précisément là qu'une implémentation naïve laisserait la DEK en
// clair, l'appelant étant occupé à remonter l'erreur.
//
// ⚠️ UNE PREMIÈRE VERSION DE CE TEST ÉTAIT DÉCORATIVE. Elle ne vérifiait que la
// remontée de l'erreur 500 : retirer `defer Zero(dek)` la laissait VERTE,
// constaté par mutation. La couture `generateDEKFn` existe pour capturer le
// tampon EXACT et prouver qu'il est nul au retour.
func TestEncryptLocal_ZeroesTheDEKOnEveryPath(t *testing.T) {
	var captured []byte
	original := generateDEKFn
	generateDEKFn = func() ([]byte, error) {
		dek, err := GenerateDEK()
		captured = dek // même tampon sous-jacent, pas une copie
		return dek, err
	}
	t.Cleanup(func() { generateDEKFn = original })

	assertZeroed := func(t *testing.T, path string) {
		t.Helper()
		if len(captured) != EnvelopeKeyLength {
			t.Fatalf("%s : DEK non capturée", path)
		}
		for i, b := range captured {
			if b != 0 {
				t.Fatalf("%s : l'octet %d de la DEK vaut %d au retour. La DEK reste en "+
					"clair en mémoire, alors que l'effacement garanti est précisément "+
					"ce que Go apporte et que Node et Python ne peuvent pas tenir.",
					path, i, b)
			}
		}
	}

	t.Run("chemin nominal", func(t *testing.T) {
		srv, _ := newWrapServer(t)
		c := New("eaas_sk_test", WithBaseURL(srv.URL))

		if _, err := c.EncryptLocal(context.Background(), []byte("secret"), "key-1"); err != nil {
			t.Fatalf("chiffrement : %v", err)
		}
		assertZeroed(t, "succès")
	})

	t.Run("chemin d'erreur : /wrap répond 500", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"error":"Internal","message":"boom"}`)
		}))
		defer srv.Close()

		c := New("eaas_sk_test", WithBaseURL(srv.URL))
		if _, err := c.EncryptLocal(context.Background(), []byte("secret"), "key-1"); err == nil {
			t.Fatal("une erreur 500 sur /wrap n'a pas été remontée")
		}
		assertZeroed(t, "erreur réseau")
	})
}

// --- Composition avec /wrap et /unwrap ---------------------------------------

type wrapVault struct {
	tokens map[string]string
	seen   []string
	dekLen []int
	seq    int
}

// newWrapServer monte un serveur d'emballage minimal, au contrat d'ENV-03.
//
// ⚠️ Il ne rejoue PAS la cryptographie du serveur : il conserve la DEK en
// mémoire, indexée par un jeton opaque. Ce test vise la COMPOSITION du SDK,
// l'emballage lui-même étant couvert par les tests du serveur.
func newWrapServer(t *testing.T) (*httptest.Server, *wrapVault) {
	t.Helper()
	v := &wrapVault{tokens: map[string]string{}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		v.seen = append(v.seen, r.URL.Path+" "+string(body))

		var payload map[string]string
		_ = json.Unmarshal(body, &payload)
		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.HasSuffix(r.URL.Path, "/wrap"):
			v.seq++
			token := fmt.Sprintf("wrapped-%d", v.seq)
			v.tokens[token] = payload["dek"]
			raw, _ := base64.StdEncoding.DecodeString(payload["dek"])
			v.dekLen = append(v.dekLen, len(raw))
			_ = json.NewEncoder(w).Encode(wrapResponse{WrappedKey: token, KeyVersion: 1})

		case strings.HasSuffix(r.URL.Path, "/unwrap"):
			dek, ok := v.tokens[payload["wrapped_key"]]
			if !ok {
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, `{"error":"Forbidden","message":"unknown token"}`)
				return
			}
			_ = json.NewEncoder(w).Encode(unwrapResponse{DEK: dek})

		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":"Not Found","message":"?"}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, v
}

func TestEncryptLocal_RoundTripOnVariousPayloads(t *testing.T) {
	srv, vault := newWrapServer(t)
	c := New("eaas_sk_test", WithBaseURL(srv.URL))
	ctx := context.Background()

	cases := []struct {
		name      string
		plaintext []byte
	}{
		{"clair vide", []byte{}},
		{"ASCII", []byte("hello")},
		{"UTF-8 multi-octets", []byte("héllo, 日本語 🔐")},
		// ⚠️ Le cas qui compte : une charge binaire NON-UTF-8.
		{"binaire non-UTF-8", []byte{0x00, 0xff, 0xfe, 0x80, 0x01, 0x7f}},
		{"1 Mo", bytes.Repeat([]byte("A"), 1024*1024)},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			env, err := c.EncryptLocal(ctx, tc.plaintext, "key-1")
			if err != nil {
				t.Fatalf("chiffrement local : %v", err)
			}

			if env.EnvelopeVersion != EnvelopeVersion {
				t.Errorf("version d'enveloppe = %d", env.EnvelopeVersion)
			}
			if env.KeyID != "key-1" {
				t.Errorf("key_id = %q", env.KeyID)
			}
			iv, _ := base64.StdEncoding.DecodeString(env.IV)
			if len(iv) != EnvelopeIVLength {
				t.Errorf("IV de %d octets", len(iv))
			}
			ct, _ := base64.StdEncoding.DecodeString(env.Ciphertext)
			if len(ct) != len(tc.plaintext)+EnvelopeTagLength {
				t.Errorf("chiffré de %d octets pour un clair de %d : le tag n'est pas "+
					"concaténé, la donnée serait illisible depuis Node et Python",
					len(ct), len(tc.plaintext))
			}

			back, err := c.DecryptLocalBytes(ctx, env)
			if err != nil {
				t.Fatalf("déchiffrement local : %v", err)
			}
			if !bytes.Equal(back, tc.plaintext) {
				t.Error("aller-retour : le clair rendu diffère de l'original")
			}
		})
	}

	for _, n := range vault.dekLen {
		if n != EnvelopeKeyLength {
			t.Errorf("une DEK de %d octets a été envoyée à /wrap ; le serveur d'ENV-03 "+
				"n'accepte que %d", n, EnvelopeKeyLength)
		}
	}
}

// La propriété que le mode enveloppe existe pour tenir.
func TestEncryptLocal_ThePlaintextNeverTravels(t *testing.T) {
	srv, vault := newWrapServer(t)
	c := New("eaas_sk_test", WithBaseURL(srv.URL))
	ctx := context.Background()

	const secret = "MOT-DE-PASSE-TRES-RECONNAISSABLE-42"
	env, err := c.EncryptLocal(ctx, []byte(secret), "key-1")
	if err != nil {
		t.Fatalf("chiffrement : %v", err)
	}
	if _, err := c.DecryptLocalBytes(ctx, env); err != nil {
		t.Fatalf("déchiffrement : %v", err)
	}

	if len(vault.seen) == 0 {
		t.Fatal("aucune requête observée : le test ne vérifie rien")
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	for _, line := range vault.seen {
		if strings.Contains(line, secret) {
			t.Fatalf("le clair est parti vers le serveur : %.120s", line)
		}
		if strings.Contains(line, encoded) {
			t.Fatalf("le clair est parti en base64 : %.120s", line)
		}
	}
}

func TestDecryptLocal_RejectsBinaryInsteadOfCorruptingIt(t *testing.T) {
	srv, _ := newWrapServer(t)
	c := New("eaas_sk_test", WithBaseURL(srv.URL))
	ctx := context.Background()

	binary := []byte{0x00, 0xff, 0xfe, 0x80}
	if utf8.Valid(binary) {
		t.Fatal("la charge de test est de l'UTF-8 valide : elle ne prouverait rien")
	}

	env, err := c.EncryptLocal(ctx, binary, "key-1")
	if err != nil {
		t.Fatalf("chiffrement : %v", err)
	}

	if _, err := c.DecryptLocal(ctx, env); err == nil {
		t.Error("une charge binaire a été rendue en chaîne sans erreur")
	}

	back, err := c.DecryptLocalBytes(ctx, env)
	if err != nil {
		t.Fatalf("déchiffrement en octets : %v", err)
	}
	if !bytes.Equal(back, binary) {
		t.Error("la version octets n'a pas rendu la charge intacte")
	}
}

func TestDecryptLocal_RejectsWrongIVLengthBeforeAnyNetworkCall(t *testing.T) {
	srv, vault := newWrapServer(t)
	c := New("eaas_sk_test", WithBaseURL(srv.URL))
	ctx := context.Background()

	env, err := c.EncryptLocal(ctx, []byte("donnée"), "key-1")
	if err != nil {
		t.Fatalf("chiffrement : %v", err)
	}

	before := len(vault.seen)
	env.IV = base64.StdEncoding.EncodeToString(make([]byte, 16))
	if _, err := c.DecryptLocalBytes(ctx, env); err == nil {
		t.Fatal("un IV de 16 octets a été accepté")
	}
	if len(vault.seen) != before {
		t.Error("un appel réseau a eu lieu malgré un IV manifestement invalide")
	}
}

func TestEncryptLocal_TwoEncryptionsOfTheSamePlaintextDiffer(t *testing.T) {
	srv, _ := newWrapServer(t)
	c := New("eaas_sk_test", WithBaseURL(srv.URL))
	ctx := context.Background()

	a, err := c.EncryptLocal(ctx, []byte("même donnée"), "key-1")
	if err != nil {
		t.Fatalf("chiffrement : %v", err)
	}
	b, err := c.EncryptLocal(ctx, []byte("même donnée"), "key-1")
	if err != nil {
		t.Fatalf("chiffrement : %v", err)
	}

	if a.IV == b.IV {
		t.Error("l'IV a été réutilisé entre deux appels")
	}
	if a.Ciphertext == b.Ciphertext {
		t.Error("deux chiffrements du même clair sont identiques : soit la DEK, " +
			"soit l'IV est réutilisé, et la confidentialité de GCM est perdue")
	}
}
