package authz

import (
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
)

// Error is an authorization failure. It matches auth.ErrForbidden or
// auth.ErrUnauthenticated with errors.Is and carries the HTTP status the
// contract assigns to it. It implements huma.StatusError and
// huma.HeadersError; huma writes the exported fields as an
// application/problem+json body, so the PDP cause is never sent to the
// client.
type Error struct {
	Title  string `json:"title,omitempty"`
	Status int    `json:"status,omitempty"`
	Detail string `json:"detail,omitempty"`

	sentinel error
	cause    error
}

var (
	_ huma.StatusError       = (*Error)(nil)
	_ huma.HeadersError      = (*Error)(nil)
	_ huma.ContentTypeFilter = (*Error)(nil)
)

func newError(status int, sentinel error, detail string, cause error) *Error {
	return &Error{
		Title:    http.StatusText(status),
		Status:   status,
		Detail:   detail,
		sentinel: sentinel,
		cause:    cause,
	}
}

// unauthenticated is the 401 for a request without a verified identity.
func unauthenticated() *Error {
	return newError(http.StatusUnauthorized, auth.ErrUnauthenticated, "authentication is required", nil)
}

// forbidden is the 403 for a denied operation.
func forbidden(detail string) *Error {
	return newError(http.StatusForbidden, auth.ErrForbidden, detail, nil)
}

// notFound is the 404 for a denied read, so existence is not disclosed.
func notFound(detail string) *Error {
	return newError(http.StatusNotFound, auth.ErrForbidden, detail, nil)
}

// unavailable is the 503 for a PDP that could not decide. It is still a
// denial and matches auth.ErrForbidden.
func unavailable(cause error) *Error {
	return newError(http.StatusServiceUnavailable, auth.ErrForbidden, "authorization service unavailable", cause)
}

// Error returns the detail only. Callers such as the batch apply endpoint
// return it to the client, so it must not carry the cause (the PDP's address,
// transport errors); the PEP logs the cause, and errors.Is / errors.As still
// reach it.
func (e *Error) Error() string {
	if e.Detail == "" {
		return e.Title
	}
	return e.Detail
}

// Unwrap exposes the auth sentinel and the cause to errors.Is / errors.As.
func (e *Error) Unwrap() []error {
	out := make([]error, 0, 2)
	if e.sentinel != nil {
		out = append(out, e.sentinel)
	}
	if e.cause != nil {
		out = append(out, e.cause)
	}
	return out
}

// GetStatus implements huma.StatusError.
func (e *Error) GetStatus() int { return e.Status }

// GetHeaders implements huma.HeadersError: a 401 carries a Bearer challenge.
func (e *Error) GetHeaders() http.Header {
	if e.Status == http.StatusUnauthorized {
		return http.Header{"WWW-Authenticate": []string{"Bearer"}}
	}
	return http.Header{}
}

// ContentType implements huma.ContentTypeFilter, as huma.ErrorModel does.
func (e *Error) ContentType(ct string) string {
	if ct == "application/json" {
		return "application/problem+json"
	}
	if ct == "application/cbor" {
		return "application/problem+cbor"
	}
	return ct
}

// StatusOf returns the HTTP status of an authorization error, or 0.
func StatusOf(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}
