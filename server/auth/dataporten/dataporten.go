package dataporten

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"github.com/tkandal/cashier/server/auth"
	"github.com/tkandal/cashier/server/config"
	"golang.org/x/oauth2"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	name            = "dataporten"
	feidePrefix     = "feide:"
	defaultTimeout  = 20 * time.Second
	issuer          = "https://auth.dataporten.no"
	challengeLen    = 32
	codeChallenge   = "code_challenge"
	challengeMethod = "code_challenge_method"
	hashMethod      = "S256"
	codeVerifier    = "code_verifier"
)

var (
	oidcScopes = []string{
		oidc.ScopeOpenID,
		"userid-feide",
	}
)

// Config is an implementation of `auth.Provider` for authenticating using a
// Gitlab account.
type Config struct {
	config      *oauth2.Config
	provider    *oidc.Provider
	cookieStore *sessions.CookieStore
	log         bool
}

// New creates a new provider.
func New(c *config.Auth, cs *sessions.CookieStore) (*Config, error) {
	logOpt, err := strconv.ParseBool(c.ProviderOpts["log"])
	if err != nil {
		logOpt = false
	}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(defaultTimeout))
	defer cancel()

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		log.Printf("dataporten: get OIDC provider failed; error = %v\n", err)
		return nil, err
	}
	oauth2Config := &oauth2.Config{
		ClientID:     c.OauthClientID,
		ClientSecret: c.OauthClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  c.OauthCallbackURL,
		Scopes:       oidcScopes,
	}

	return &Config{
		config:      oauth2Config,
		provider:    provider,
		cookieStore: cs,
		log:         logOpt,
	}, nil
}

// Name returns the name of the provider.
func (c *Config) Name() string {
	return name
}

// Valid validates the oauth token.
func (c *Config) Valid(token *oauth2.Token) bool {
	return token.Valid()
}

// Revoke disables the access token.
func (c *Config) Revoke(_ *oauth2.Token) error {
	return nil
}

// StartSession retrieves an authentication endpoint.
func (c *Config) StartSession(state string, w http.ResponseWriter, r *http.Request) string {
	verifier, challenge, err := generateChallenge(challengeLen)
	if err != nil {
		return ""
	}

	sess, err := c.cookieStore.Get(r, auth.SessionName)
	if err != nil {
		log.Printf("get session failed; error = %v\n", err)
		return ""
	}
	sess.Values[codeVerifier] = verifier
	if err = sess.Save(r, w); err != nil {
		log.Printf("save session failed; error = %v\n", err)
		return ""
	}

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam(codeChallenge, challenge),
		oauth2.SetAuthURLParam(challengeMethod, hashMethod),
	}
	return c.config.AuthCodeURL(state, opts...)
}

// Exchange authorizes the session and returns an access token.
func (c *Config) Exchange(code string, r *http.Request) (*oauth2.Token, error) {
	sess, err := c.cookieStore.Get(r, auth.SessionName)
	verifier, ok := sess.Values[codeVerifier].(string)
	if !ok {
		return nil, errors.Wrap(err, "could not get verifier token")
	}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(defaultTimeout))
	defer cancel()
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam(codeVerifier, verifier),
	}

	oauth2Token, err := c.config.Exchange(ctx, code, opts...)
	if err != nil {
		c.logMsg(fmt.Errorf("dataporten: get access-token failed; error = %v", err))
		return nil, err
	}
	return oauth2Token, nil
}

// Username retrieves the username portion of the user's email address.
func (c *Config) Username(token *oauth2.Token) string {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(defaultTimeout))
	defer cancel()

	userInfo, err := c.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		c.logMsg(fmt.Errorf("dataporten: get user-info failed; error = %v", err))
		return ""
	}

	claims := &Claims{}
	if err := userInfo.Claims(claims); err != nil {
		c.logMsg(fmt.Errorf("dataporten: deserialise claims failed; error = %v", err))
		return ""
	}

	var user string
	if len(claims.DataportenUserID) > 0 && len(claims.DataportenUserID[0]) > len(feidePrefix) {
		user = strings.ReplaceAll(claims.DataportenUserID[0], feidePrefix, "")
	}
	if len(user) == 0 && len(claims.ConnectUserID) > 0 && len(claims.ConnectUserID[0]) > len(feidePrefix) {
		user = strings.ReplaceAll(claims.ConnectUserID[0], feidePrefix, "")
	}
	if len(user) == 0 {
		c.logMsg(fmt.Errorf("dataporten: no username was found"))
		user = ""
	}
	if idx := strings.IndexByte(user, '@'); idx > -1 {
		user = user[:idx]
	}
	return user
}

func (c *Config) logMsg(message error) {
	if c.log {
		log.Print(message)
	}
}

// Claims is a datatype for the claims returned from Dataporten.
type Claims struct {
	ConnectUserID    []string `json:"connect-userid_sec,omitempty"`
	DataportenUserID []string `json:"dataporten-userid_sec,omitempty"`
	Email            string   `json:"email,omitempty"`
	EmailVerified    bool     `json:"email_verified,omitempty"`
	Sub              string   `json:"sub,omitempty"`
}

func (c Claims) String() string {
	str := &strings.Builder{}
	if err := json.NewEncoder(str).Encode(c); err != nil {
		return ""
	}
	return str.String()
}

func generateChallenge(n int) (string, string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", "", err
	}
	verifier := base64.RawURLEncoding.EncodeToString(b)

	h := sha256.New()
	if _, err := h.Write([]byte(verifier)); err != nil {
		return "", "", err
	}
	challenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return verifier, challenge, nil
}
