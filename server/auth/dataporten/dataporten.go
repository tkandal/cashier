package dataporten

import (
	"github.com/nsheridan/cashier/server/config"
	"golang.org/x/oauth2"
	"time"
)

const (
	name = "dataporten"
)

// Config is an implementation of `auth.Provider` for authenticating using a
// Gitlab account.
type Config struct {
	config    *oauth2.Config
	groups    []string
	whitelist map[string]bool
	allusers  bool
	apiurl    string
	log       bool
}

// New creates a new provider.
func New(c *config.Auth) (*Config, error) {
	return &Config{}, nil
}

// Name returns the name of the provider.
func (c *Config) Name() string {
	return name
}

// Valid validates the oauth token.
func (c *Config) Valid(token *oauth2.Token) bool {
	return true
}

// Revoke disables the access token.
func (c *Config) Revoke(token *oauth2.Token) error {
	return nil
}

// StartSession retrieves an authentication endpoint.
func (c *Config) StartSession(state string) string {
	return "https://www.example.com/auth"
}

// Exchange authorizes the session and returns an access token.
func (c *Config) Exchange(code string) (*oauth2.Token, error) {
	return &oauth2.Token{
		AccessToken: "token",
		Expiry:      time.Now().Add(1 * time.Hour),
	}, nil
}

// Username retrieves the username portion of the user's email address.
func (c *Config) Username(token *oauth2.Token) string {
	return "test"
}
