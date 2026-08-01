package mafate

// Garde-fou de publication : le chemin de module doit correspondre au dépôt
// public qui sert réellement les clients.
//
// ⚠️ POURQUOI CE TEST EXISTE, et pourquoi il ne peut pas être un simple
// commentaire. Un tag Go est IMMUABLE dans le cache de proxy.golang.org : une
// version publiée avec un mauvais `go.mod` ne se corrige pas, elle se contourne
// par une version suivante — et tous les `go get ...@v0.1.1` déjà lancés
// resteront cassés.
//
// Le défaut était déjà là, latent, pendant quatre mois : le monorepo déclarait
// `github.com/mafate-security/mafate-go` (organisation qui N'EXISTE PAS) tandis
// que le dépôt publié déclarait `github.com/AxiomMarketing/mafate-go`. `go get`
// fonctionnait — parce que les clients tirent du dépôt publié, pas du monorepo.
// Publier depuis le monorepo aurait cassé l'installation pour de bon.
//
// Ce test vit dans le paquet plutôt que dans la CI : il tourne partout où
// `go test` tourne, y compris sur le miroir public, sans câblage supplémentaire.

import (
	"os"
	"strings"
	"testing"
)

// canonicalModulePath est le chemin servi par proxy.golang.org pour v0.1.0,
// vérifié le 01/08/2026. C'est le dépôt PUBLIC, celui que les clients tirent.
const canonicalModulePath = "github.com/AxiomMarketing/mafate-go"

func TestGoModDeclaresCanonicalModulePath(t *testing.T) {
	raw, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("go.mod illisible : %v", err)
	}

	var declared string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			declared = strings.TrimSpace(strings.TrimPrefix(line, "module "))
			break
		}
	}

	if declared == "" {
		t.Fatal("aucune directive `module` dans go.mod")
	}

	if declared != canonicalModulePath {
		t.Fatalf(
			"go.mod déclare %q, attendu %q.\n\n"+
				"Publier un tag avec ce chemin casserait `go get` DÉFINITIVEMENT : "+
				"un tag Go est immuable dans le cache de proxy.golang.org, une version "+
				"publiée ne se corrige pas.\n\n"+
				"Si le dépôt canonique a réellement changé, mettre à jour "+
				"canonicalModulePath dans ce fichier — délibérément, pas par réflexe.",
			declared, canonicalModulePath,
		)
	}
}

// L'organisation `mafate-security` n'existe pas sur GitHub (404 en organisation
// ET en utilisateur, vérifié le 31/07/2026). Toute référence dans le paquet
// publié enverrait un client sur une page inexistante.
//
// Le module PRIVÉ du serveur EaaS (`github.com/mafate-security/eaas-server`)
// conserve délibérément ce chemin : jamais publié, jamais résolu sur le réseau,
// le renommer serait ~50 fichiers modifiés pour zéro bénéfice. Il n'est pas dans
// ce paquet, donc hors de portée de ce test.
func TestNoReferenceToNonExistentOrganisation(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("répertoire illisible : %v", err)
	}

	var offenders []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !(strings.HasSuffix(name, ".go") || name == "go.mod" || name == "README.md") {
			continue
		}
		raw, err := os.ReadFile(name)
		if err != nil {
			continue
		}
		// Ce fichier-ci cite le nom fautif pour l'expliquer : on l'exclut.
		if name == "module_path_test.go" {
			continue
		}
		if strings.Contains(string(raw), "mafate-security") {
			offenders = append(offenders, name)
		}
	}

	if len(offenders) > 0 {
		t.Errorf("l'organisation inexistante `mafate-security` est citée dans : %v", offenders)
	}
}
