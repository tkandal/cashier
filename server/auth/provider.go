package auth

import (
	"golang.org/x/oauth2"
	"net/http"
)

const (
	SessionName = "session"
)

// Provider is an abstraction of different auth methods.
type Provider interface {
	Name() string
	StartSession(string, http.ResponseWriter, *http.Request) string
	Exchange(string, *http.Request) (*oauth2.Token, error)
	Username(*oauth2.Token) string
	Valid(*oauth2.Token) bool
	Revoke(*oauth2.Token) error
}
