package mafate

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"strconv"
	"strings"
	"time"
)

// VerifyWebhook verifies a MAFATE webhook signature with the default replay
// tolerance of 300 seconds.
//
// timestamp is the X-Mafate-Timestamp header and is REQUIRED.
//
// Ce paramètre a été AJOUTÉ : la fonction prenait auparavant trois arguments et
// déléguait avec timestamp="", ce qui faisait signer le payload seul. Or
// l'émetteur signe TOUJOURS "{timestamp}.{payload}" et envoie toujours l'en-tête
// (webhook_service.ts:51-53 et :67), donc cette variante ne pouvait valider AUCUN
// webhook MAFATE légitime : elle renvoyait faux dans tous les cas réels.
//
// Ce n'était pas un contournement de l'anti-rejeu — sans le secret, personne ne
// forge — mais une branche morte portant le nom le plus évident, celui qu'on
// essaie en premier. Le risque réel est le développeur qui désactive la
// vérification faute de comprendre pourquoi rien ne passe.
//
// Le changement de signature provoque une erreur de compilation chez l'appelant.
// C'est voulu : elle pointe l'endroit exact où fournir l'en-tête déjà reçu, là où
// un repli silencieux aurait laissé le faux négatif en place.
func VerifyWebhook(payload, signature, secret, timestamp string) bool {
	return VerifyWebhookWithTimestamp(payload, signature, secret, timestamp, 300)
}

// VerifyWebhookWithTimestamp verifies a MAFATE webhook signature with replay
// protection. timestamp is the X-Mafate-Timestamp header, tolerance is max age in
// seconds. An empty timestamp is rejected.
func VerifyWebhookWithTimestamp(payload, signature, secret, timestamp string, tolerance int) bool {
	if timestamp == "" {
		return false
	}

	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	age := time.Now().Unix() - ts
	if math.Abs(float64(age)) > float64(tolerance) {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + "." + payload))
	expected := mac.Sum(nil)

	received := strings.TrimPrefix(signature, "sha256=")

	// Décodage AVANT comparaison.
	//
	// L'ancienne version comparait les REPRÉSENTATIONS hexadécimales sous forme
	// d'octets de chaîne, ce qui rejetait une signature en majuscules pourtant
	// équivalente. Node et Python décodent l'hexadécimal ; comparer les octets
	// décodés aligne les trois SDK sur la même sémantique, la casse d'un
	// hexadécimal ne portant aucun sens.
	//
	// hex.DecodeString refuse toute entrée non hexadécimale ou de longueur impaire,
	// ce qui écarte au passage les signatures non-ASCII qui faisaient lever une
	// exception en Node et en Python. Go n'a jamais paniqué ici — hmac.Equal gère
	// des longueurs différentes — mais la validation explicite rend les trois
	// comportements identiques plutôt que seulement compatibles par accident.
	receivedBytes, err := hex.DecodeString(received)
	if err != nil || len(receivedBytes) != sha256.Size {
		return false
	}

	return hmac.Equal(expected, receivedBytes)
}
