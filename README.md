# mafate-go

Official Go SDK for the [MAFATE](https://mafate.io) Encryption-as-a-Service API.

Zero dependencies — uses only the Go standard library (`net/http`, `encoding/json`, `encoding/base64`).

## Requirements

Go 1.21 or later.

## Install

```bash
go get github.com/AxiomMarketing/mafate-go
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    mafate "github.com/AxiomMarketing/mafate-go"
)

func main() {
    client := mafate.New("eaas_sk_...")
    // Optional: custom base URL or timeout
    // client := mafate.New("eaas_sk_...",
    //     mafate.WithBaseURL("https://api.your-domain.io"),
    //     mafate.WithTimeout(10*time.Second),
    // )

    ctx := context.Background()

    // Encrypt
    encrypted, err := client.Encrypt(ctx, "données sensibles", "key-id-here")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("ciphertext:", encrypted.Ciphertext)

    // Decrypt — pass the EncryptedData back directly
    plaintext, err := client.Decrypt(ctx, encrypted)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("plaintext:", plaintext)
}
```

## Configuration

| Option | Default | Description |
|---|---|---|
| `WithBaseURL(url)` | `https://api.mafate.io` | Override the API base URL |
| `WithTimeout(d)` | `30s` | HTTP request timeout |

## Services

### Encryption

```go
// Encrypt a UTF-8 string (base64 encoding is handled automatically)
encrypted, err := client.Encrypt(ctx, "my secret", keyID)

// Decrypt back to a UTF-8 string
plaintext, err := client.Decrypt(ctx, encrypted)
```

### Keys — `client.Keys`

```go
// List all keys
keys, err := client.Keys.List(ctx)

// Get key detail with version history
detail, err := client.Keys.Get(ctx, "key-id")

// Create a key (algorithm is optional, defaults to AES-256-GCM server-side)
key, err := client.Keys.Create(ctx, mafate.CreateKeyRequest{
    Name:      "my-key",
    Algorithm: "AES-256-GCM",
})

// Rotate — creates a new key version
key, err = client.Keys.Rotate(ctx, "key-id")

// Disable a key
err = client.Keys.Disable(ctx, "key-id")
```

### API Keys — `client.ApiKeys`

```go
// List (secrets are never returned in list responses)
apiKeys, err := client.ApiKeys.List(ctx)

// Create — secret is only returned once
created, err := client.ApiKeys.Create(ctx, mafate.CreateApiKeyRequest{
    Name:        "ci-deploy",
    Permissions: []string{"encrypt", "decrypt"},
})
fmt.Println("save this secret:", created.Secret)

// Update permissions or expiry — TROIS états par champ :
//   rien passé            -> le serveur CONSERVE
//   Clear<Champ> = true   -> le serveur EFFACE
//   <Champ> = &valeur     -> le serveur POSE
expires := "2027-01-01T00:00:00Z"
updated, err := client.ApiKeys.Update(ctx, created.ID, mafate.UpdateApiKeyRequest{
    Permissions: []string{"encrypt"},
    ExpiresAt:   &expires,
})

// L'expiration est RETIRÉE ; les permissions et les adresses autorisées, absentes
// de la requête, sont CONSERVÉES.
updated, err = client.ApiKeys.Update(ctx, created.ID, mafate.UpdateApiKeyRequest{
    ClearExpiresAt: true,
})

// Un ExpiresAt nil n'envoie RIEN : il ne peut pas effacer par inadvertance.

// Revoke permanently
err = client.ApiKeys.Revoke(ctx, created.ID)
```

### Audit — `client.Audit`

```go
// All logs (no filter)
logs, err := client.Audit.List(ctx, nil)

// Filtered
logs, err = client.Audit.List(ctx, &mafate.AuditFilters{
    Action:   "encrypt",
    KeyID:    "key-id",
    DateFrom: "2026-01-01T00:00:00Z",
    Limit:    50,
    Offset:   0,
})
```

### Health

```go
health, err := client.Health(ctx)
fmt.Println(health.Status) // "healthy" | "degraded"
```

## Error Handling

All methods return a standard Go `error`. Two concrete types are available:

```go
import (
    "errors"
    mafate "github.com/AxiomMarketing/mafate-go"
)

_, err := client.Keys.Get(ctx, "bad-id")
if err != nil {
    var apiErr *mafate.ApiError
    if errors.As(err, &apiErr) {
        fmt.Println(apiErr.Status) // e.g. 404
        fmt.Println(apiErr.Title)  // e.g. "Not Found"
        fmt.Println(apiErr.Detail) // RFC 7807 detail string
    }
    // mafate.MafateError covers network / serialisation errors
}
```

## License

MIT — Copyright (c) 2026 UNIVILE SAS

## Licence et spécification

Ce SDK est publié sous **licence MIT** (voir `LICENSE`). Son code source est
public : https://github.com/AxiomMarketing/mafate-go

Le **format d'enveloppe** produit par le mode local est spécifié dans
[`ENVELOPE-SPEC.md`](./ENVELOPE-SPEC.md). C'est un contrat public et figé : il
décrit assez précisément le format pour qu'un tiers puisse le réimplémenter, ou
déchiffrer ses propres données sans MAFATE.

Les vecteurs de test figés qui accompagnent la spec sont consommés à l'identique
par les trois SDK. Une réimplémentation qui les reproduit octet pour octet est
conforme.

⚠️ **Ce qui est ouvert, et ce qui ne l'est pas.** Le SDK et le format le sont ;
le serveur MAFATE ne l'est pas. Concrètement, vous pouvez vérifier et
réimplémenter la partie qui manipule vos données, mais pas celle qui garde vos
clés.
