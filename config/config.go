package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

type Config struct {
	SCHEME   string
	HOSTNAME string
	PORT     string

	WEBAUTHN_RP_DISPLAY_NAME string
	WEBAUTHN_RP_ORIGIN       string
	DATABASE_DRIVER          string
	DATABASE_DSN             string
	Metadata                 Metadata    `toml:"METADATA"`
	OAuth                    OAuthConfig `toml:"OAUTH"`
}

// OAuth is opt-in. HMAC key material comes from the OAUTH_HMAC_SECRET
// environment variable, encoded using unpadded base64url.
type OAuthConfig struct {
	Enabled        bool   `toml:"ENABLED"`
	Issuer         string `toml:"ISSUER"`
	SigningKeyFile string `toml:"SIGNING_KEY_FILE"`
	SigningKeyID   string `toml:"SIGNING_KEY_ID"`
}

type Contact struct {
	Name  string `toml:"name" json:"name"`
	Email string `toml:"email" json:"email"`
}

type Metadata struct {
	NodeName   string    `toml:"NODE_NAME" json:"nodeName"`
	NodeDomain string    `toml:"NODE_DOMAIN" json:"nodeDomain"`
	NodeAdmins []Contact `toml:"NODE_ADMINS" json:"nodeAdmins"`
	Maintainer []Contact `toml:"MAINTAINER" json:"maintainer"`
}

func LoadConfig(fn string) (*Config, error) {
	data, err := os.ReadFile(fn)
	if err != nil {
		return nil, err
	}
	conf := &Config{DATABASE_DRIVER: "sqlite", DATABASE_DSN: "auth.db?_busy_timeout=5000&_foreign_keys=on&_txlock=immediate"}
	_, err = toml.Decode(string(data), conf)
	if err != nil {
		return nil, err
	}
	var sections struct {
		Host struct {
			Scheme, Hostname, Port *string
		} `toml:"HOST"`
		WebAuthn struct {
			RPDisplayName *string `toml:"RP_DISPLAY_NAME"`
			RPOrigin      *string `toml:"RP_ORIGIN"`
		} `toml:"WEBAUTHN"`
		Database struct {
			Driver *string `toml:"DATABASE_DRIVER"`
			DSN    *string `toml:"DATABASE_DSN"`
		} `toml:"DATABASE"`
	}
	if _, err := toml.Decode(string(data), &sections); err != nil {
		return nil, err
	}
	for _, field := range []struct {
		src *string
		dst *string
	}{
		{sections.Host.Scheme, &conf.SCHEME},
		{sections.Host.Hostname, &conf.HOSTNAME},
		{sections.Host.Port, &conf.PORT},
		{sections.WebAuthn.RPDisplayName, &conf.WEBAUTHN_RP_DISPLAY_NAME},
		{sections.WebAuthn.RPOrigin, &conf.WEBAUTHN_RP_ORIGIN},
		{sections.Database.Driver, &conf.DATABASE_DRIVER},
		{sections.Database.DSN, &conf.DATABASE_DSN},
	} {
		if field.src != nil {
			*field.dst = *field.src
		}
	}
	if err := conf.Validate(); err != nil {
		return nil, err
	}
	return conf, nil
}

func (c *Config) Origin() string {
	if c.WEBAUTHN_RP_ORIGIN != "" {
		return c.WEBAUTHN_RP_ORIGIN
	}
	return c.SCHEME + c.HOSTNAME + c.PORT
}

func (c *Config) Validate() error {
	switch c.DATABASE_DRIVER {
	case "", "sqlite", "postgres":
	default:
		return fmt.Errorf("DATABASE_DRIVER must be sqlite or postgres")
	}
	u, err := url.Parse(c.Origin())
	if err != nil || c.HOSTNAME == "" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("invalid WebAuthn origin")
	}
	if u.Hostname() != c.HOSTNAME && !strings.HasSuffix(u.Hostname(), "."+c.HOSTNAME) {
		return fmt.Errorf("WebAuthn origin must belong to HOSTNAME")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && u.Hostname() == "localhost" && c.HOSTNAME == "localhost") {
		return fmt.Errorf("WebAuthn requires HTTPS (HTTP is allowed for localhost)")
	}
	port, err := strconv.Atoi(strings.TrimPrefix(c.PORT, ":"))
	if err != nil || !strings.HasPrefix(c.PORT, ":") || port < 1 || port > 65535 || c.WEBAUTHN_RP_DISPLAY_NAME == "" || c.DATABASE_DSN == "" {
		return fmt.Errorf("PORT, WEBAUTHN_RP_DISPLAY_NAME and DATABASE_DSN are required")
	}
	return nil
}
