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
    client := mafate.New("eaas_dev_sk_...",
        mafate.WithBaseURL("http://localhost:8080"),
        // mafate.WithTimeout(10*time.Second), // optional, default 30 s
    )

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

// Update permissions or expiry
expires := "2027-01-01T00:00:00Z"
updated, err := client.ApiKeys.Update(ctx, created.ID, mafate.UpdateApiKeyRequest{
    Permissions: []string{"encrypt"},
    ExpiresAt:   &expires,
})

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
