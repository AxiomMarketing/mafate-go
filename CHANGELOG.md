# Journal des modifications

## v0.2.3 — 2026-08-02

### Correction de publication

Aucun changement de code. Les 0.2.1 et 0.2.2 n'ont jamais atteint le registre :
la configuration du workflow empêchait l'échange OIDC, de deux façons opposées.


## v0.2.2 — 2026-08-02

### Correction de publication

Aucun changement de code. La 0.2.1 n'a jamais atteint le registre : la
configuration du workflow court-circuitait le Trusted Publishing OIDC.


## v0.2.1 — 2026-08-02

### Correction de distribution

Le corpus de vecteurs de conformité voyage désormais **avec le paquet**. Il était
lu depuis un chemin remontant hors du paquet, ce qui fonctionnait dans le
monorepo mais **cassait les tests du dépôt public** — et a fait échouer la
publication de la 0.2.0.

⚠️ La v0.2.0 est publiée et **reste utilisable** — `go get` et le code
fonctionnent. Seul `go test ./...` du module lui-même y échoue. Un tag Go étant
immuable dans le cache du proxy, la correction ne pouvait passer que par une
version suivante.

Aucun changement de code applicatif : la 0.2.1 est fonctionnellement identique à
la 0.2.0.

## v0.2.0 — 2026-08-02

### Changements incompatibles

Plusieurs corrections **changent des signatures exportées**. Les erreurs de
compilation qui en découlent sont voulues : elles pointent exactement les endroits
à adapter, là où un changement silencieux vous aurait laissé un défaut ouvert.

#### `VerifyWebhook` — un paramètre ajouté

```go
// avant
mafate.VerifyWebhook(payload, signature, secret)

// maintenant
mafate.VerifyWebhook(payload, signature, secret, timestamp)
```

La variante à trois arguments déléguait avec `timestamp=""`, ce qui faisait signer
le payload seul. Or l'émetteur signe **toujours** `{timestamp}.{payload}` : cette
fonction ne pouvait valider **aucun** webhook légitime. Elle portait pourtant le
nom le plus évident, celui qu'on essaie en premier.

#### `UpdateApiKeyRequest` — restructurée

Trois états par champ, exprimés avec deux champs Go :

```go
// rien passé              -> le serveur CONSERVE
// ClearExpiresAt = true   -> le serveur EFFACE
// ExpiresAt = &valeur     -> le serveur POSE

_, err := client.ApiKeys.Update(ctx, id, mafate.UpdateApiKeyRequest{
    Permissions: []string{"encrypt"},   // expiration CONSERVÉE
})

_, err = client.ApiKeys.Update(ctx, id, mafate.UpdateApiKeyRequest{
    ClearExpiresAt: true,               // expiration EFFACÉE
})
```

⚠️ Un simple retrait d'`omitempty` sur un pointeur aurait produit
`"expires_at": null` à **chaque appel** : un client mettant à jour ses seules
permissions aurait effacé l'expiration de sa clé. Un `*string` ne distingue pas
« absent » de « null ».

#### `Decrypt` refuse un clair non textuel

```go
texte,  err := client.Decrypt(ctx, enveloppe)       // UTF-8 valide exigé
octets, err := client.DecryptBytes(ctx, enveloppe)  // charge binaire
```

⚠️ **Changement de comportement assumé.** Go était le seul des trois SDK à ne rien
perdre — `string([]byte)` copie les octets verbatim, une chaîne Go n'ayant pas à
être de l'UTF-8 valide. Node corrompait en silence, Python levait une exception
portant le clair.

Un contrat unique vaut mieux que trois comportements derrière une même signature.
`DecryptBytes` est le correctif, pas un contournement. `EncryptBytes` complète la
symétrie.

#### Les redirections HTTP ne sont plus suivies

Toute réponse 3xx produit une `ApiError`. Sur un 307/308, le corps de la requête
était **rejoué vers l'hôte indiqué par `Location`**.

Second défaut fermé au passage : `shouldCopyHeaderOnRedirect` ne compare que le
**domaine**, pas le schéma — une redirection vers un sous-domaine en `http://`
conservait l'en-tête `Authorization`, envoyant le Bearer en clair.

### Autres changements

- **Nouvelles erreurs `TimeoutError` et `ConnectionError`.** Faute d'héritage en
  Go, la hiérarchie est reproduite par incorporation et `Unwrap()` :

  ```go
  var te *mafate.TimeoutError
  errors.As(err, &te)          // le cas précis

  var me *mafate.MafateError
  errors.As(err, &me)          // « une erreur du SDK », quelle qu'elle soit
  ```

- **Une `baseURL` avec préfixe de chemin est conservée.**
- **Les identifiants sont échappés** dans les chemins d'URL.
- **`AllowedIPs`** exposé en création, lecture et mise à jour. Le serveur applique
  cette restriction depuis toujours ; aucun SDK ne l'exposait.

### Corrections

- Le chemin de module déclaré dans le dépôt source pointait une organisation
  **inexistante**. `go get` fonctionnait — les clients tirent du dépôt publié —
  mais publier un tag depuis la source aurait cassé l'installation
  **définitivement** : un tag Go est immuable dans le cache de `proxy.golang.org`.

  Un test du paquet vérifie désormais ce chemin à chaque exécution de `go test`.
