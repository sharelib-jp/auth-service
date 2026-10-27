package config

import (
	"fmt"
	"net/url"
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
}

func LoadConfig(fn string) (*Config, error) {
	conf := &Config{DATABASE_DRIVER: "sqlite", DATABASE_DSN: "auth.db?_busy_timeout=5000&_foreign_keys=on&_txlock=immediate"}
	_, err := toml.DecodeFile(fn, conf)
	if err != nil {
		return nil, err
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
