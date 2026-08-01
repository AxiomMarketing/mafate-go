package mafate

import "fmt"

// MafateError is the base error type for all SDK errors.
type MafateError struct {
	Message string
}

func (e *MafateError) Error() string {
	return e.Message
}

// ApiError is returned when the server responds with a non-2xx status.
// The fields map to the RFC 7807 problem detail JSON body.
type ApiError struct {
	Status int
	Title  string
	Detail string
}

func (e *ApiError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("[%d] %s: %s", e.Status, e.Title, e.Detail)
	}
	return fmt.Sprintf("[%d] %s", e.Status, e.Title)
}

// TimeoutError est renvoyée quand le délai imparti expire.
//
// Go n'a pas d'héritage : la hiérarchie « MafateError > TimeoutError » des SDK
// Node et Python est reproduite par INCORPORATION plus Unwrap(). Les deux
// écritures fonctionnent donc, comme dans les deux autres langages :
//
//	var te *mafate.TimeoutError
//	errors.As(err, &te)          // le cas précis
//
//	var me *mafate.MafateError
//	errors.As(err, &me)          // « une erreur du SDK », quelle qu'elle soit
type TimeoutError struct {
	MafateError
	TimeoutSeconds float64
}

// Unwrap expose le MafateError incorporé, sans quoi errors.As ne saurait pas
// qu'un TimeoutError EST une erreur du SDK — l'incorporation seule promeut les
// méthodes mais ne crée aucun lien pour errors.As.
func (e *TimeoutError) Unwrap() error {
	return &e.MafateError
}

// ConnectionError est renvoyée quand l'API n'a pas pu être jointe : DNS, TCP,
// TLS, ou coupure en cours de transfert.
//
// Distincte d'ApiError : le serveur n'a rien répondu, il n'y a donc ni statut ni
// corps à interpréter. Les confondre pousse à réessayer là où il faut corriger
// une configuration, ou l'inverse.
type ConnectionError struct {
	MafateError
	Cause error
}

func (e *ConnectionError) Unwrap() error {
	return &e.MafateError
}

// problemDetail is the internal struct used to decode RFC 7807 bodies.
type problemDetail struct {
	Title  string `json:"title"`
	Detail string `json:"detail"`
}
