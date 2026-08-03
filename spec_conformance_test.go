package mafate

// La SPÉCIFICATION PUBLIÉE doit décrire le code, pas une intention.
//
// `ENVELOPE-SPEC.md` est publié : un lecteur extérieur s'en sert pour
// réimplémenter le format, ou pour vérifier ce que fait le SDK. **Une spec fausse
// vaut moins qu'aucune spec** : elle donne une confiance imméritée, et le lecteur
// n'a aucun moyen de savoir qu'elle a divergé.
//
// Ce test lit la spec publiée et la confronte aux constantes du code. Il échoue
// si l'une change sans l'autre, dans un sens comme dans l'autre.
//
// ⚠️ Il porte volontairement sur la COPIE du paquet, pas sur le canonique de
// `packages/test-vectors/` : c'est cette copie qui part dans le miroir public, et
// c'est donc elle que lira un utilisateur. Un garde d'identité en CI vérifie
// séparément que les copies ne dérivent pas du canonique.

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func readSpec(t *testing.T) string {
	t.Helper()

	raw, err := os.ReadFile("ENVELOPE-SPEC.md")
	if err != nil {
		t.Fatalf("ENVELOPE-SPEC.md illisible : %v.\n"+
			"La spec est PUBLIÉE avec ce paquet : son absence signifie que le miroir "+
			"public n'en a pas, alors que le README y renvoie.", err)
	}
	return string(raw)
}

// specDeclaredLength extrait une longueur annoncée dans le tableau de la section 2.
func specDeclaredLength(t *testing.T, spec, label string) int {
	t.Helper()

	re := regexp.MustCompile(`\|\s*` + regexp.QuoteMeta(label) + `\s*\|\s*(\d+)\s*octets`)
	m := re.FindStringSubmatch(spec)
	if m == nil {
		t.Fatalf("la spec ne déclare aucune longueur pour %q. Le tableau de la "+
			"section 2 a changé de forme, et ce garde ne vérifie donc plus rien.", label)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("longueur illisible pour %q : %v", label, err)
	}
	return n
}

func TestSpec_DeclaredLengthsMatchTheCode(t *testing.T) {
	spec := readSpec(t)

	cases := []struct {
		label string
		code  int
	}{
		{"Longueur de clé", EnvelopeKeyLength},
		{"Longueur d'IV", EnvelopeIVLength},
		{"Longueur de tag", EnvelopeTagLength},
	}

	for _, c := range cases {
		declared := specDeclaredLength(t, spec, c.label)
		if declared != c.code {
			t.Errorf("%s : la spec publiée annonce %d octets, le code en impose %d. "+
				"Un lecteur qui réimplémente le format d'après la spec produira des "+
				"données que ce SDK ne saura pas lire.", c.label, declared, c.code)
		}
	}
}

func TestSpec_DeclaresTheAlgorithmActuallyUsed(t *testing.T) {
	spec := readSpec(t)

	if !strings.Contains(spec, "AES-256-GCM") {
		t.Error("la spec ne nomme pas AES-256-GCM, qui est l'algorithme employé")
	}
	// Le format v1 n'a PAS d'AAD, et la spec doit le dire : un réimplémenteur qui
	// en ajouterait une produirait un chiffré illisible ici, sans comprendre pourquoi.
	if !strings.Contains(spec, "aucune en v1") {
		t.Error("la spec ne dit pas que le format v1 est SANS données authentifiées " +
			"additionnelles. Une réimplémentation qui en ajouterait produirait un " +
			"chiffré illisible par ce SDK.")
	}
}

func TestSpec_DeclaresTheEnvelopeVersionOfTheCode(t *testing.T) {
	spec := readSpec(t)

	re := regexp.MustCompile(`"envelope_version":\s*(\d+)`)
	m := re.FindStringSubmatch(spec)
	if m == nil {
		t.Fatal("la spec ne montre aucun `envelope_version` dans son exemple JSON")
	}
	declared, _ := strconv.Atoi(m[1])
	if declared != EnvelopeVersion {
		t.Errorf("la spec annonce envelope_version=%d, le code produit %d",
			declared, EnvelopeVersion)
	}
}

// La spec affirme qu'un chiffré vaut le clair PLUS le tag. C'est la propriété la
// plus facile à vérifier pour un réimplémenteur, et donc celle qu'il faut tenir.
func TestSpec_CiphertextLengthClaimHolds(t *testing.T) {
	spec := readSpec(t)

	if !strings.Contains(spec, "len(clair) + 16") {
		t.Error("la spec n'énonce plus la longueur attendue du chiffré, qui est la " +
			"propriété la plus simple à vérifier pour une réimplémentation")
	}

	key, _ := GenerateDEK()
	iv, _ := GenerateIV()

	for _, n := range []int{0, 1, 15, 16, 1000} {
		sealed, err := SealEnvelope(key, iv, make([]byte, n))
		if err != nil {
			t.Fatalf("scellement : %v", err)
		}
		if len(sealed) != n+EnvelopeTagLength {
			t.Errorf("clair de %d octets → chiffré de %d, la spec en annonce %d",
				n, len(sealed), n+EnvelopeTagLength)
		}
	}
}

// La spec affirme que les primitives ne font AUCUN appel réseau, ce qui est la
// base de l'argument « utilisable sans MAFATE ». Le vérifier par les imports du
// paquet serait fragile ; on vérifie plutôt le comportement observable : les
// primitives fonctionnent sans client, sans configuration et sans jeton.
func TestSpec_PrimitivesWorkWithoutAnyClient(t *testing.T) {
	spec := readSpec(t)

	if !strings.Contains(spec, "sans MAFATE") {
		t.Error("la spec n'affirme plus que le format est utilisable sans MAFATE")
	}

	key, err := GenerateDEK()
	if err != nil {
		t.Fatalf("génération de clé : %v", err)
	}
	iv, err := GenerateIV()
	if err != nil {
		t.Fatalf("génération d'IV : %v", err)
	}

	// Aucun Client construit, aucune URL, aucune clé d'API.
	sealed, err := SealEnvelope(key, iv, []byte("donnée"))
	if err != nil {
		t.Fatalf("scellement sans client : %v", err)
	}
	back, err := OpenEnvelope(key, iv, sealed)
	if err != nil {
		t.Fatalf("ouverture sans client : %v", err)
	}
	if string(back) != "donnée" {
		t.Error("aller-retour incorrect sans client")
	}
}

// La spec est publiée sous licence : sans fichier LICENSE dans le paquet, elle
// est publiée sans conditions d'usage, ce qui bloque toute revue juridique côté
// utilisateur.
func TestSpec_PackageShipsItsLicense(t *testing.T) {
	raw, err := os.ReadFile("LICENSE")
	if err != nil {
		t.Fatalf("LICENSE absent du paquet : %v.\n"+
			"Le paquet se déclare MIT ; sans le texte, une revue juridique côté "+
			"utilisateur ne peut pas conclure.", err)
	}
	if !strings.Contains(string(raw), "MIT License") {
		t.Error("le fichier LICENSE ne porte pas la licence MIT annoncée")
	}
}
