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

// problemDetail is the internal struct used to decode RFC 7807 bodies.
type problemDetail struct {
	Title  string `json:"title"`
	Detail string `json:"detail"`
}
