# Format d'enveloppe MAFATE, version 1

Spécification publique du format produit par le mode enveloppe des SDK MAFATE.

Ce document décrit un format, pas un service. Il est publié pour que quiconque
puisse vérifier ce que font les SDK, réimplémenter le format dans un autre
langage, ou déchiffrer ses propres données sans MAFATE.

**Statut : figé.** Le changer casserait les données déjà chiffrées des clients.
Toute évolution passera par une version 2 et un nouveau champ `envelope_version`.

---

## 1. Ce que le format couvre, et ce qu'il ne couvre pas

Le format décrit **le chiffrement local d'une donnée sous une clé de données**.

Il ne décrit **pas** le jeton `wrapped_key` rendu par le serveur MAFATE. Ce jeton
est **opaque** : son contenu et sa structure sont un détail d'implémentation du
serveur, ils peuvent changer, et rien dans un SDK ne doit tenter de l'interpréter.
Seule sa présentation à `POST /v1/keys/{id}/unwrap` est stable.

Conséquence utile : **un utilisateur peut se servir de ce format sans MAFATE.**
Il génère sa clé, chiffre, et la conserve lui-même. Les primitives des SDK ne
font aucun appel réseau.

---

## 2. Algorithme

| | |
|---|---|
| Chiffrement | AES-256-GCM |
| Longueur de clé | 32 octets (256 bits) |
| Longueur d'IV | 12 octets (96 bits) |
| Longueur de tag | 16 octets (128 bits) |
| Données authentifiées additionnelles | aucune en v1 |

**L'IV fait 96 bits parce que c'est la taille native de GCM.** Toute autre
longueur force la spécification à dériver l'IV en interne, ce qui fragilise son
unicité et fait diverger les implémentations.

---

## 3. Disposition des octets

Le chiffré est la **concaténation du texte chiffré et du tag GCM**, dans cet
ordre :

```
chiffré = AES-256-GCM(clé, iv, clair)  ||  tag
          <------- len(clair) ------>     <-16->
```

Un chiffré valide fait donc exactement `len(clair) + 16` octets. Un clair vide
produit un chiffré de 16 octets, qui est le tag seul : c'est valide.

### ⚠️ Le point où les implémentations divergent naturellement

Go (`cipher.AEAD.Seal`) et Python (`AESGCM.encrypt`) **concatènent le tag
nativement**. Node **ne le fait pas** : `cipher.getAuthTag()` rend le tag
séparément, et la concaténation doit être explicite.

C'est le seul endroit où le format ne suit pas le comportement par défaut d'une
des trois bibliothèques standard, et l'erreur est **invisible tant qu'on ne teste
qu'une implémentation contre elle-même**. Un chiffré produit par un Node fautif
se déchiffre parfaitement en Node, et pas du tout ailleurs.

Le déchiffrement porte le piège symétrique : `decipher.setAuthTag()` exige le tag
détaché de la fin du chiffré, là où Go et Python le lisent en place.

---

## 4. Unicité de l'IV

**Un IV doit être tiré aléatoirement à chaque opération de chiffrement, et jamais
dérivé d'un compteur.**

Réutiliser un IV sous la même clé casse la confidentialité de GCM, et le fait
**sans aucun signal** : les déchiffrements continuent de réussir, rien n'échoue,
rien n'est journalisé. C'est la faute la plus coûteuse que puisse commettre une
implémentation de ce format.

Les trois SDK vérifient cette propriété par un compteur d'IV distincts sur
1 000 opérations, et la conformité croisée refuse tout jeu de cas où deux IV
coïncident.

---

## 5. Représentation JSON

Quand une enveloppe est sérialisée, les champs sont :

```json
{
  "ciphertext": "<base64 standard, tag concaténé>",
  "wrapped_key": "<jeton opaque du serveur>",
  "iv": "<base64 standard, 12 octets>",
  "key_id": "<identifiant de la clé MAFATE>",
  "key_version": 1,
  "envelope_version": 1
}
```

L'encodage est le **base64 standard** (RFC 4648 §4), avec remplissage. Ni base64url,
ni base64 sans remplissage.

`envelope_version` vaut `1` et permet de distinguer une enveloppe d'un chiffré
produit par le mode serveur, qui ne porte pas ce champ.

---

## 6. Vecteurs de test

`envelope-v1.json`, dans ce répertoire, contient des cas figés : clé, IV, clair
et chiffré attendu. Ils sont produits par la cryptographie de référence et
consommés à l'identique par les trois SDK.

Une réimplémentation qui reproduit ces vecteurs octet pour octet est conforme.
Le jeu couvre le clair vide, l'ASCII, l'UTF-8 multi-octets, une charge binaire
non-UTF-8, un clair de 1 Mo, et deux cas d'altération qui **doivent** échouer.

Le fichier porte un bloc `reading_rules` qui lève les ambiguïtés de lecture.
Il vient d'un vrai défaut : une version antérieure omettait un champ sur le cas
vide, et les trois langages l'interprétaient différemment.

---

## 7. Ce que le format ne protège pas

- **Il ne protège pas un poste compromis.** Un attaquant qui exécute du code chez
  vous voit le clair avant chiffrement.
- **Il ne protège pas d'un mauvais stockage.** Chiffré et clé au même endroit
  sans contrôle d'accès, et le chiffrement ne sert plus à rien.
- **Il ne dispense d'aucune obligation réglementaire.** Chiffrer réduit l'impact
  d'une violation, cela ne supprime ni registres ni analyses d'impact.

---

## 8. Effacement de la clé en mémoire

Trois langages, trois niveaux, et il vaut mieux le dire que le laisser découvrir :

| | Garantie | Pourquoi |
|---|---|---|
| Go | garanti | le tampon est le seul exemplaire, pas de ramasse-miettes compactant |
| Node | partiel | `fill(0)` efface le tampon, mais V8 a pu en copier le contenu |
| Python | impossible | `os.urandom` rend un `bytes` immuable, rien ne peut l'effacer |

Ce n'est pas une lacune des SDK, c'est une propriété des langages.

---

## 9. Licence

Ce document et les vecteurs de test sont publiés sous licence MIT, comme les
SDK qui les consomment. Voir `LICENSE`.
