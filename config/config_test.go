package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	content := `[ HOST ]
SCHEME = "http://"
HOSTNAME = "auth-dev-sharelib.luca.hij1.local.sasakulab.com"
PORT = ":8080"

[ WEBAUTHN ]
RP_DISPLAY_NAME = "auth-dev-sharelib.luca.hij1.local.sasakulab.com"
RP_ORIGIN = "https://auth-dev-sharelib.luca.hij1.local.sasakulab.com"

[ DATABASE ]
DATABASE_DRIVER = "postgres"
DATABASE_DSN = "host=localhost port=5432 dbname=auth sslmode=disable"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	conf, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if conf.SCHEME != "http://" || conf.HOSTNAME != "auth-dev-sharelib.luca.hij1.local.sasakulab.com" || conf.PORT != ":8080" ||
		conf.WEBAUTHN_RP_DISPLAY_NAME != conf.HOSTNAME || conf.Origin() != "https://"+conf.HOSTNAME ||
		conf.DATABASE_DRIVER != "postgres" || conf.DATABASE_DSN != "host=localhost port=5432 dbname=auth sslmode=disable" {
		t.Fatal("sectioned config was not loaded correctly")
	}
}

func TestDatabaseConfiguration(t *testing.T) {
	for _, test := range []struct {
		driver string
		valid  bool
	}{
		{"", true}, {"sqlite", true}, {"postgres", true}, {"mysql", false},
	} {
		t.Run(test.driver, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			content := `SCHEME = "http://"
HOSTNAME = "localhost"
PORT = ":8080"
WEBAUTHN_RP_DISPLAY_NAME = "Test"
`
			if test.driver != "" {
				content += "DATABASE_DRIVER = \"" + test.driver + "\"\n"
				content += "DATABASE_DSN = \"postgres://localhost/auth_test?sslmode=disable\"\n"
			}
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			conf, err := LoadConfig(path)
			if (err == nil) != test.valid {
				t.Fatalf("LoadConfig() = %v, want valid=%v", err, test.valid)
			}
			if err == nil {
				driver := test.driver
				if driver == "" {
					driver = "sqlite"
				}
				if conf.DATABASE_DRIVER != driver || conf.DATABASE_DSN == "" {
					t.Fatalf("unexpected database config: %+v", conf)
				}
			}
		})
	}
}

func TestOriginValidation(t *testing.T) {
	for _, test := range []struct {
		host, origin string
		valid        bool
	}{
		{"localhost", "http://localhost:8080", true},
		{"example.com", "https://auth.example.com", true},
		{"auth.example.com", "https://auth.example.com", true},
		{"example.com", "http://example.com:8080", false},
		{"example.com", "https://example.com.attacker.example", false},
		{"example.com", "https://attacker.example", false},
		{"example.com", "https://example.com/path", false},
		{"example.com", "https://user@example.com", false},
		{"example.com", "https://example.com?query=1", false},
		{"example.com", "https://example.com#fragment", false},
		{"example.com", "://invalid", false},
	} {
		t.Run(test.origin, func(t *testing.T) {
			conf := &Config{HOSTNAME: test.host, PORT: ":8080", WEBAUTHN_RP_ORIGIN: test.origin, WEBAUTHN_RP_DISPLAY_NAME: "Test", DATABASE_DSN: "test.db"}
			if err := conf.Validate(); (err == nil) != test.valid {
				t.Fatalf("Validate() = %v, want valid=%v", err, test.valid)
			}
		})
	}
}
