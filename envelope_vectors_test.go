package mafate

// Conformité aux vecteurs d'enveloppe PARTAGÉS.
//
// ⚠️ CE HARNAIS ÉCHOUE AUJOURD'HUI, ET C'EST LE RÉSULTAT ATTENDU D'ENV-01.
//
// Il est écrit AVANT que le SDK sache chiffrer en local (ENV-07). Le format
// d'enveloppe est un CONTRAT PUBLIC : il se fige avant l'implémentation, pas
// après. Le pire scénario du lot serait trois SDK chiffrant chacun légèrement
// différemment — une donnée écrite ici illisible depuis Node, défaut qui ne se
// voit qu'à la première lecture croisée, chez un client, des mois plus tard.
//
// Les vecteurs sont DÉJÀ validés : le harnais serveur les reproduit avec la
// crypto de référence. Ce harnais-ci vise donc une cible vérifiée.
//
// ⚠️ Go est le langage dont la convention EST le format retenu : `gcm.Seal`
// concatène nativement le tag. C'est donc l'implémentation la plus simple des
// trois — et celle qui doit rester la référence quand les deux autres divergent.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type envVectorCase struct {
	Name            string `json:"name"`
	KeyB64          string `json:"key_b64"`
	IVB64           string `json:"iv_b64"`
	PlaintextB64    string `json:"plaintext_b64"`
	PlaintextRepeat *struct {
		ByteHex string `json:"byte_hex"`
		Length  int    `json:"length"`
	} `json:"plaintext_repeat"`
	CiphertextB64    string `json:"ciphertext_b64"`
	CiphertextSHA256 string `json:"ciphertext_sha256"`
	Expect           string `json:"expect"`
}

type envVectorFile struct {
	Algorithm string          `json:"algorithm"`
	Cases     []envVectorCase `json:"cases"`
}

// Copie LOCALE au paquet, pas un chemin remontant vers packages/test-vectors/ :
// un tel chemin a fait échouer trois publications le 02/08, le `subtree split`
// du miroir n'emportant que le contenu du paquet.
func loadEnvVectors(t *testing.T) envVectorFile {
	t.Helper()

	path := filepath.Join("testdata", "envelope-v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("vecteurs d'enveloppe illisibles (%s) : %v", path, err)
	}
	var v envVectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("vecteurs d'enveloppe illisibles : %v", err)
	}
	if len(v.Cases) == 0 {
		t.Fatal("aucun cas dans les vecteurs — un corpus vide passerait tout")
	}
	return v
}

func (c envVectorCase) plaintext(t *testing.T) []byte {
	t.Helper()

	// PRÉCÉDENCE : `plaintext_repeat` PRIME sur `plaintext_b64`. Identique dans
	// les 4 implémentations, cf. `reading_rules` du corpus.
	if c.PlaintextRepeat != nil {
		b, err := hex.DecodeString(c.PlaintextRepeat.ByteHex)
		if err != nil || len(b) != 1 {
			t.Fatalf("cas %q : byte_hex illisible", c.Name)
		}
		return bytes.Repeat(b, c.PlaintextRepeat.Length)
	}
	pt, err := base64.StdEncoding.DecodeString(c.PlaintextB64)
	if err != nil {
		t.Fatalf("cas %q : plaintext_b64 illisible : %v", c.Name, err)
	}
	return pt
}

// envelopeFuncs décrit l'API que ENV-07 devra fournir.
//
// Ces deux fonctions n'existent PAS encore : c'est ce qui fait échouer ce
// harnais, et c'est voulu. Elles sont nommées ici pour que l'implémentation ait
// une cible explicite plutôt qu'une interprétation.
//
// La vérification passe par des variables de paquet plutôt que par un appel
// direct : appeler une fonction inexistante ne compilerait pas, et un paquet qui
// ne compile pas empêcherait TOUS les autres tests de tourner — l'échec ne serait
// plus ciblé.
var (
	sealEnvelopeFn func(key, iv, plaintext []byte) ([]byte, error)
	openEnvelopeFn func(key, iv, ciphertext []byte) ([]byte, error)
)

func requireEnvelopeAPI(t *testing.T) {
	t.Helper()

	if sealEnvelopeFn == nil {
		t.Fatal("ENV-01 : le SDK ne sait pas encore sceller une enveloppe en local. " +
			"ENV-07 doit exposer SealEnvelope(key, iv, plaintext []byte) ([]byte, error), " +
			"avec le tag GCM concaténé — ce que gcm.Seal fait nativement — puis brancher " +
			"sealEnvelopeFn dessus.")
	}
	if openEnvelopeFn == nil {
		t.Fatal("ENV-01 : le SDK ne sait pas encore ouvrir une enveloppe en local. " +
			"ENV-07 doit exposer OpenEnvelope(key, iv, ciphertext []byte) ([]byte, error), " +
			"qui renvoie une ERREUR si le tag ne correspond pas.")
	}
}

func TestEnvelopeVectors_SDKEncryptMatchesFrozen(t *testing.T) {
	v := loadEnvVectors(t)

	for _, c := range v.Cases {
		if c.Expect != "ok" {
			continue
		}
		c := c
		t.Run(c.Name, func(t *testing.T) {
			requireEnvelopeAPI(t)

			key, _ := base64.StdEncoding.DecodeString(c.KeyB64)
			iv, _ := base64.StdEncoding.DecodeString(c.IVB64)

			got, err := sealEnvelopeFn(key, iv, c.plaintext(t))
			if err != nil {
				t.Fatalf("scellement en échec : %v", err)
			}

			if c.CiphertextSHA256 != "" {
				sum := sha256.Sum256(got)
				if hex.EncodeToString(sum[:]) != c.CiphertextSHA256 {
					t.Errorf("empreinte du chiffré différente du vecteur figé")
				}
				return
			}

			want, _ := base64.StdEncoding.DecodeString(c.CiphertextB64)
			if !bytes.Equal(got, want) {
				t.Error("chiffré différent du vecteur figé — une donnée écrite ici " +
					"serait illisible par les SDK Node et Python")
			}
		})
	}
}

func TestEnvelopeVectors_SDKDecryptAndAuthFailures(t *testing.T) {
	v := loadEnvVectors(t)

	for _, c := range v.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			requireEnvelopeAPI(t)

			key, _ := base64.StdEncoding.DecodeString(c.KeyB64)
			iv, _ := base64.StdEncoding.DecodeString(c.IVB64)

			var ct []byte
			if c.CiphertextB64 == "" {
				var err error
				ct, err = sealEnvelopeFn(key, iv, c.plaintext(t))
				if err != nil {
					t.Fatalf("scellement en échec : %v", err)
				}
			} else {
				ct, _ = base64.StdEncoding.DecodeString(c.CiphertextB64)
			}

			got, err := openEnvelopeFn(key, iv, ct)

			if c.Expect == "auth_failure" {
				if err == nil {
					t.Fatal("le déchiffrement a RÉUSSI sur un chiffré altéré — " +
						"GCM n'authentifie donc rien")
				}
				return
			}
			if err != nil {
				t.Fatalf("déchiffrement en échec sur un cas valide : %v", err)
			}
			if !bytes.Equal(got, c.plaintext(t)) {
				t.Error("clair différent du vecteur")
			}
		})
	}
}

// Les trois tests suivants ne dépendent d'AUCUNE implémentation : ils passent dès
// aujourd'hui et vérifient que les VECTEURS restent conformes.

func TestEnvelopeVectors_SDKFrozenFormat(t *testing.T) {
	v := loadEnvVectors(t)

	if v.Algorithm != "AES-256-GCM" {
		t.Errorf("algorithme = %q, attendu AES-256-GCM", v.Algorithm)
	}
	for _, c := range v.Cases {
		key, _ := base64.StdEncoding.DecodeString(c.KeyB64)
		iv, _ := base64.StdEncoding.DecodeString(c.IVB64)
		if len(key) != 32 {
			t.Errorf("cas %q : clé de %d octets, AES-256 en exige 32", c.Name, len(key))
		}
		if len(iv) != 12 {
			t.Errorf("cas %q : IV de %d octets, le format figé impose 12 (96 bits)", c.Name, len(iv))
		}
	}
}

func TestEnvelopeVectors_SDKTagIsAppended(t *testing.T) {
	v := loadEnvVectors(t)

	for _, c := range v.Cases {
		if c.Expect != "ok" || c.CiphertextB64 == "" {
			continue
		}
		pt := c.plaintext(t)
		ct, _ := base64.StdEncoding.DecodeString(c.CiphertextB64)
		if len(ct) != len(pt)+16 {
			t.Errorf("cas %q : chiffré de %d octets pour un clair de %d — attendu %d",
				c.Name, len(ct), len(pt), len(pt)+16)
		}
	}
}

// ⚠️ Ce test vient d'un vrai défaut. Une première version du corpus omettait
// `plaintext_b64` sur le cas « clair vide » — conséquence d'un `omitempty` côté
// générateur — et les trois implémentations réagissaient DIFFÉREMMENT au même
// vecteur : Node lisait une chaîne vide, Python levait un KeyError, Go prenait le
// zéro de son type. Un corpus ambigu produit exactement la divergence qu'il est
// censé empêcher.
func TestEnvelopeVectors_SDKCorpusIsWellFormed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "envelope-v1.json"))
	if err != nil {
		t.Fatalf("vecteurs illisibles : %v", err)
	}

	// Décodage générique : une structure typée masquerait justement les clés
	// absentes, en leur substituant le zéro du type.
	var generic struct {
		Cases []map[string]json.RawMessage `json:"cases"`
	}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("vecteurs illisibles : %v", err)
	}

	required := []string{"name", "key_b64", "iv_b64", "plaintext_b64", "ciphertext_b64", "expect"}
	for _, c := range generic.Cases {
		name := string(c["name"])
		for _, k := range required {
			if _, ok := c[k]; !ok {
				t.Errorf("%s : clé %q absente. Toutes les clés doivent être présentes, "+
					"éventuellement à chaîne vide — sinon chaque implémentation interprète "+
					"l'absence à sa façon.", name, k)
			}
		}
	}
}
