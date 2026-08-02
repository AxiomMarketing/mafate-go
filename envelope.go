package mafate

// Primitives de chiffrement LOCAL du mode enveloppe.
//
// Ces fonctions ne parlent à personne : ni réseau, ni client, ni configuration.
// C'est ce qui permet aux vecteurs partagés d'ENV-01 de les confronter aux trois
// autres implémentations sans monter de serveur.
//
// # Go est le plus simple des trois, et c'est structurel
//
// `gcm.Seal` CONCATÈNE nativement le tag au chiffré, ce qu'impose le format figé
// par ENV-00. Go n'a donc pas le piège de Node, dont `getAuthTag()` rend le tag
// séparément et exige une concaténation explicite. La convention du serveur EST
// déjà la bonne.
//
// C'est aussi pour cela que Go reste la RÉFÉRENCE quand les trois divergent :
// les vecteurs figés ont été produits par la cryptographie du serveur, écrite en
// Go, avec ces mêmes primitives standard.
//
// # Go est le SEUL des trois à pouvoir garantir l'effacement de la DEK
//
// `Zero()` remplit le tampon de zéros, et ce tampon est le seul exemplaire :
// Go n'a pas de ramasse-miettes compactant qui recopierait un `[]byte` ailleurs
// derrière notre dos.
//
//	Go      garantit         (defer Zero(dek))
//	Node    approche         (fill(0), mais V8 a pu copier)
//	Python  ne peut pas      (os.urandom rend un `bytes` IMMUABLE)
//
// Trois langages, trois niveaux. À dire tels quels : c'est un argument réel en
// faveur de Go pour un service sensible, et le taire ne servirait personne.
//
// # Zéro dépendance
//
// `crypto/aes` et `crypto/cipher` sont dans la bibliothèque standard. Le SDK Go
// conserve donc ses ZÉRO dépendances runtime, actif rare que la CI protège par
// un garde dédié.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"unicode/utf8"
)

const (
	// EnvelopeVersion est la version du format d'enveloppe. Contrat public figé
	// par ENV-00 : le changer casse les données déjà chiffrées des clients.
	EnvelopeVersion = 1

	// EnvelopeIVLength vaut 96 bits, la taille NATIVE de GCM. Toute autre
	// longueur force une dérivation interne et fragilise l'unicité de l'IV.
	EnvelopeIVLength = 12

	// EnvelopeKeyLength : AES-256.
	EnvelopeKeyLength = 32

	// EnvelopeTagLength : longueur du tag GCM, concaténé au chiffré.
	EnvelopeTagLength = 16
)

func checkLength(name string, value []byte, expected int) error {
	if len(value) != expected {
		return &MafateError{Message: fmt.Sprintf(
			"%s doit faire exactement %d octets, reçu %d. Le format d'enveloppe v%d "+
				"est un contrat public : l'assouplir rendrait illisibles les données "+
				"déjà chiffrées.", name, expected, len(value), EnvelopeVersion)}
	}
	return nil
}

// SealEnvelope chiffre plaintext sous key avec iv, et rend le chiffré AVEC LE
// TAG CONCATÉNÉ — ce que `gcm.Seal` fait nativement.
//
// L'IV est un paramètre, jamais tiré ici : cette fonction doit rester
// reproductible pour que les vecteurs figés puissent la confronter aux trois
// autres implémentations. Le tirage est le rôle de GenerateIV, et EncryptLocal
// s'en charge pour l'appelant.
func SealEnvelope(key, iv, plaintext []byte) ([]byte, error) {
	if err := checkLength("key", key, EnvelopeKeyLength); err != nil {
		return nil, err
	}
	if err := checkLength("iv", iv, EnvelopeIVLength); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if gcm.NonceSize() != EnvelopeIVLength {
		return nil, &MafateError{Message: fmt.Sprintf(
			"taille de nonce GCM inattendue : %d", gcm.NonceSize())}
	}

	// `dst` nil : le tag est concaténé au chiffré par gcm.Seal lui-même.
	return gcm.Seal(nil, iv, plaintext, nil), nil
}

// OpenEnvelope déchiffre ciphertext (tag concaténé) sous key avec iv.
//
// Rend une erreur si le tag ne correspond pas : c'est l'authentification de GCM.
// Un déchiffrement qui « réussirait » sur un chiffré altéré signifierait que
// rien n'est authentifié.
func OpenEnvelope(key, iv, ciphertext []byte) ([]byte, error) {
	if err := checkLength("key", key, EnvelopeKeyLength); err != nil {
		return nil, err
	}
	if err := checkLength("iv", iv, EnvelopeIVLength); err != nil {
		return nil, err
	}
	if len(ciphertext) < EnvelopeTagLength {
		return nil, &MafateError{Message: fmt.Sprintf(
			"ciphertext fait %d octets, moins que les %d octets du seul tag GCM : "+
				"il ne peut pas provenir du format d'enveloppe v%d",
			len(ciphertext), EnvelopeTagLength, EnvelopeVersion)}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// gcm.Open lit le tag EN PLACE, à la fin du chiffré. Aucun découpage n'est
	// nécessaire, contrairement à Node dont `setAuthTag` exige le tag séparé.
	return gcm.Open(nil, iv, ciphertext, nil)
}

// generateDEKFn est une COUTURE DE TEST, et elle a une raison précise.
//
// L'effacement de la DEK est la seule garantie que Go apporte et que les deux
// autres SDK ne peuvent pas tenir. L'annoncer sans le prouver n'aurait aucune
// valeur — or une première version du test ne vérifiait que la remontée
// d'erreur : retirer `defer Zero(dek)` la laissait VERTE, constaté par mutation.
//
// Cette indirection permet au test de capturer le tampon EXACT et de vérifier
// qu'il est nul au retour, sur le chemin nominal comme sur le chemin d'erreur.
var generateDEKFn = GenerateDEK

// GenerateDEK tire une DEK de 32 octets.
//
// L'appelant DOIT l'effacer avec Zero, idéalement en `defer`. Go est le seul des
// trois SDK où cet effacement est une GARANTIE et non un effort.
func GenerateDEK() ([]byte, error) {
	dek := make([]byte, EnvelopeKeyLength)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	return dek, nil
}

// GenerateIV tire un IV de 12 octets.
//
// ⚠️ À appeler à CHAQUE opération, et JAMAIS depuis un compteur. Réutiliser un
// IV sous la même clé casse la confidentialité de GCM SANS AUCUN SIGNAL : tout
// continue de fonctionner, les déchiffrements réussissent, et la donnée est
// perdue.
func GenerateIV() ([]byte, error) {
	iv := make([]byte, EnvelopeIVLength)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	return iv, nil
}

// Zero efface un tampon.
//
// Contrairement à Node et Python, c'est ici une GARANTIE : le tampon est le seul
// exemplaire, Go n'ayant pas de ramasse-miettes compactant qui en recopierait le
// contenu ailleurs. Voir l'en-tête du fichier.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// encryptLocal chiffre EN LOCAL et ne fait emballer que la clé de données.
//
// Le clair ne quitte JAMAIS ce processus : MAFATE reçoit la DEK, jamais la
// donnée. Et ne détenant pas le chiffré, MAFATE compromis seul ne peut rien
// déchiffrer — il faudrait aussi compromettre la base de l'appelant.
func encryptLocal(ctx context.Context, hc *httpClient, plaintext []byte, keyID string) (*EnvelopeData, error) {
	if keyID == "" {
		return nil, &MafateError{Message: "keyID must not be empty"}
	}

	dek, err := generateDEKFn()
	if err != nil {
		return nil, err
	}
	// ⚠️ LA GARANTIE PROPRE À GO. Le `defer` s'exécute quel que soit le chemin de
	// sortie, y compris sur une erreur réseau de l'emballage : la DEK ne reste
	// jamais en clair en mémoire. Node ne peut qu'approcher cela, Python pas du
	// tout.
	defer Zero(dek)

	iv, err := GenerateIV()
	if err != nil {
		return nil, err
	}

	ciphertext, err := SealEnvelope(dek, iv, plaintext)
	if err != nil {
		return nil, err
	}

	payload := map[string]string{"dek": base64.StdEncoding.EncodeToString(dek)}

	var wrapped wrapResponse
	path := fmt.Sprintf("/v1/keys/%s/wrap", pathSegment(keyID))
	if err := hc.post(ctx, path, payload, &wrapped); err != nil {
		return nil, err
	}

	return &EnvelopeData{
		Ciphertext:      base64.StdEncoding.EncodeToString(ciphertext),
		WrappedKey:      wrapped.WrappedKey,
		IV:              base64.StdEncoding.EncodeToString(iv),
		KeyID:           keyID,
		KeyVersion:      wrapped.KeyVersion,
		EnvelopeVersion: EnvelopeVersion,
	}, nil
}

// decryptLocal déchiffre EN LOCAL et renvoie les OCTETS bruts.
func decryptLocal(ctx context.Context, hc *httpClient, data *EnvelopeData) ([]byte, error) {
	if data == nil {
		return nil, &MafateError{Message: "envelope data must not be nil"}
	}

	iv, err := base64.StdEncoding.DecodeString(data.IV)
	if err != nil {
		return nil, &MafateError{Message: fmt.Sprintf("decode iv base64: %s", err)}
	}
	if len(iv) != EnvelopeIVLength {
		return nil, &MafateError{Message: fmt.Sprintf(
			"iv fait %d octets, le format d'enveloppe en impose %d. Cette donnée ne "+
				"vient pas de EncryptLocal().", len(iv), EnvelopeIVLength)}
	}

	ciphertext, err := base64.StdEncoding.DecodeString(data.Ciphertext)
	if err != nil {
		return nil, &MafateError{Message: fmt.Sprintf("decode ciphertext base64: %s", err)}
	}

	var res unwrapResponse
	path := fmt.Sprintf("/v1/keys/%s/unwrap", pathSegment(data.KeyID))
	if err := hc.post(ctx, path, map[string]string{"wrapped_key": data.WrappedKey}, &res); err != nil {
		return nil, err
	}

	dek, err := base64.StdEncoding.DecodeString(res.DEK)
	if err != nil {
		return nil, &MafateError{Message: fmt.Sprintf("decode dek base64: %s", err)}
	}
	defer Zero(dek)

	return OpenEnvelope(dek, iv, ciphertext)
}

// decryptLocalToString déchiffre EN LOCAL et renvoie le clair en UTF-8 valide.
//
// ⚠️ La contrepartie octets s'appelle DecryptLocalBytes et porte le nom le PLUS
// COURT côté Node et Python, où la variante texte a corrompu du binaire en
// silence. En Go le risque est moindre — `string([]byte)` copie verbatim — mais
// la validation est conservée pour que les trois SDK se comportent pareil : une
// même signature qui perd des octets dans un langage et pas dans l'autre est
// exactement ce que SDK-05 a corrigé.
func decryptLocalToString(ctx context.Context, hc *httpClient, data *EnvelopeData) (string, error) {
	decoded, err := decryptLocal(ctx, hc, data)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(decoded) {
		return "", &MafateError{
			Message: "le clair déchiffré n'est pas de l'UTF-8 valide. " +
				"Utilisez DecryptLocalBytes() pour récupérer les octets bruts.",
		}
	}
	return string(decoded), nil
}
