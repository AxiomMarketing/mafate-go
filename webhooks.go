package mafate

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"time"
)

// VerifyWebhook verifies a MAFATE webhook signature.
// payload is the raw request body, signature is the X-Mafate-Signature header,
// secret is your webhook endpoint secret.
func VerifyWebhook(payload, signature, secret string) bool {
	return VerifyWebhookWithTimestamp(payload, signature, secret, "", 300)
}

// VerifyWebhookWithTimestamp verifies a MAFATE webhook signature with replay protection.
// timestamp is the X-Mafate-Timestamp header, tolerance is max age in seconds.
func VerifyWebhookWithTimestamp(payload, signature, secret, timestamp string, tolerance int) bool {
	// Replay protection
	if timestamp != "" {
		ts, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			return false
		}
		age := time.Now().Unix() - ts
		if math.Abs(float64(age)) > float64(tolerance) {
			return false
		}
	}

	var sigPayload string
	if timestamp != "" {
		sigPayload = fmt.Sprintf("%s.%s", timestamp, payload)
	} else {
		sigPayload = payload
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(sigPayload))
	expected := hex.EncodeToString(mac.Sum(nil))

	// Remove prefix if present
	received := signature
	if len(received) > 7 && received[:7] == "sha256=" {
		received = received[7:]
	}

	return hmac.Equal([]byte(expected), []byte(received))
}
