package config

import (
	"os"
	"strconv"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/homemade/scl"
	"github.com/pkg/errors"
	"github.com/tkandal/cashier/server/helpers/vault"
)

// Config holds the final server configuration.
type Config struct {
	Server *Server `hcl:"server"`
	Auth   *Auth   `hcl:"auth"`
	SSH    *SSH    `hcl:"ssh"`
	AWS    *AWS    `hcl:"aws"`
	Vault  *Vault  `hcl:"vault"`
}

// Database holds database configuration.
type Database map[string]string

// Server holds the configuration specific to the web server and sessions.
type Server struct {
	UseTLS                bool     `hcl:"use_tls"`
	TLSKey                string   `hcl:"tls_key"`
	TLSCert               string   `hcl:"tls_cert"`
	LetsEncryptServername string   `hcl:"letsencrypt_servername"`
	LetsEncryptCache      string   `hcl:"letsencrypt_cachedir"`
	Addr                  string   `hcl:"address"`
	Port                  int      `hcl:"port"`
	User                  string   `hcl:"user"`
	CookieSecret          string   `hcl:"cookie_secret"`
	CSRFSecret            string   `hcl:"csrf_secret"`
	HTTPLogFile           string   `hcl:"http_logfile"`
	Database              Database `hcl:"database"`
	RequireReason         bool     `hcl:"require_reason"`
}

// Auth holds the configuration specific to the OAuth provider.
type Auth struct {
	OauthClientID     string            `hcl:"oauth_client_id"`
	OauthClientSecret string            `hcl:"oauth_client_secret"`
	OauthCallbackURL  string            `hcl:"oauth_callback_url"`
	Provider          string            `hcl:"provider"`
	ProviderOpts      map[string]string `hcl:"provider_opts"`
	UsersWhitelist    []string          `hcl:"users_whitelist"`
}

// SSH holds the configuration specific to signing ssh keys.
type SSH struct {
	SigningKey           string   `hcl:"signing_key"`
	AdditionalPrincipals []string `hcl:"additional_principals"`
	MaxAge               string   `hcl:"max_age"`
	Permissions          []string `hcl:"permissions"`
}

// AWS holds Amazon AWS configuration.
// AWS can also be configured using SDK methods.
type AWS struct {
	Region    string `hcl:"region"`
	AccessKey string `hcl:"access_key"`
	SecretKey string `hcl:"secret_key"`
}

// Vault holds Hashicorp Vault configuration.
type Vault struct {
	Address string `hcl:"address"`
	Token   string `hcl:"token"`
}

func verifyConfig(c *Config) error {
	var err error
	if c.SSH == nil {
		err = multierror.Append(err, errors.New("missing ssh config section"))
	}
	if c.Auth == nil {
		err = multierror.Append(err, errors.New("missing auth config section"))
	}
	if c.Server == nil {
		err = multierror.Append(err, errors.New("missing server config section"))
	}
	return err
}

func setFromEnvironment(c *Config) {
	port, err := strconv.Atoi(os.Getenv("PORT"))
	if err == nil {
		c.Server.Port = port
	}
	if os.Getenv("OAUTH_CLIENT_ID") != "" {
		c.Auth.OauthClientID = os.Getenv("OAUTH_CLIENT_ID")
	}
	if os.Getenv("OAUTH_CLIENT_SECRET") != "" {
		c.Auth.OauthClientSecret = os.Getenv("OAUTH_CLIENT_SECRET")
	}
	if os.Getenv("CSRF_SECRET") != "" {
		c.Server.CSRFSecret = os.Getenv("CSRF_SECRET")
	}
	if os.Getenv("COOKIE_SECRET") != "" {
		c.Server.CookieSecret = os.Getenv("COOKIE_SECRET")
	}
}

func setFromVault(c *Config) error {
	if c.Vault == nil || c.Vault.Token == "" || c.Vault.Address == "" {
		return nil
	}
	v, err := vault.NewClient(c.Vault.Address, c.Vault.Token)
	if err != nil {
		return errors.Wrap(err, "vault error")
	}
	var errs error
	get := func(value string) string {
		if strings.HasPrefix(value, "/vault/") {
			s, err := v.Read(value)
			if err != nil {
				errs = multierror.Append(errs, err)
			}
			return s
		}
		return value
	}
	c.Auth.OauthClientID = get(c.Auth.OauthClientID)
	c.Auth.OauthClientSecret = get(c.Auth.OauthClientSecret)
	c.Server.CSRFSecret = get(c.Server.CSRFSecret)
	c.Server.CookieSecret = get(c.Server.CookieSecret)
	if len(c.Server.Database) != 0 {
		c.Server.Database["password"] = get(c.Server.Database["password"])
	}
	if c.AWS != nil {
		c.AWS.AccessKey = get(c.AWS.AccessKey)
		c.AWS.SecretKey = get(c.AWS.SecretKey)
	}
	return errors.Wrap(errs, "errors reading from vault")
}

// ReadConfig parses a hcl configuration file into a Config struct.
func ReadConfig(f string) (*Config, error) {
	config := &Config{}
	if err := scl.DecodeFile(config, f); err != nil {
		return nil, errors.Wrapf(err, "unable to load config from file %s", f)
	}
	if err := setFromVault(config); err != nil {
		return nil, err
	}
	setFromEnvironment(config)
	if err := verifyConfig(config); err != nil {
		return nil, errors.Wrap(err, "unable to verify config")
	}
	return config, nil
}
