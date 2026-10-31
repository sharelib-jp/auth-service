package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/sharelib-jp/auth-service/dao"

	"github.com/sharelib-jp/auth-service/internal/oauth"
	"github.com/sharelib-jp/auth-service/internal/testdb"
)

func TestOperatorRegistrationCommands(t *testing.T) {
	driver, dsn := testdb.Config(t)
	dir := t.TempDir()
	configuration := filepath.Join(dir, "config.toml")
	content := fmt.Sprintf("[HOST]\nSCHEME = %q\nHOSTNAME = %q\nPORT = %q\n[WEBAUTHN]\nRP_DISPLAY_NAME = %q\n[DATABASE]\nDATABASE_DRIVER = %q\nDATABASE_DSN = %q\n", "http://", "localhost", ":8080", "Test", driver, dsn)
	if err := os.WriteFile(configuration, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	originalArgs, originalStdin := os.Args, os.Stdin
	t.Cleanup(func() { os.Args, os.Stdin = originalArgs, originalStdin })
	invoke := func(command, input string) {
		t.Helper()
		inputPath := filepath.Join(dir, "input.json")
		if err := os.WriteFile(inputPath, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(inputPath)
		if err != nil {
			t.Fatal(err)
		}
		os.Stdin = file
		os.Args = []string{"oauthctl", "-config", configuration, command}
		err = run()
		file.Close()
		if err != nil {
			t.Fatalf("%s: %v", command, err)
		}
	}
	invoke("resource", `{"id":"b","identifier":"https://b.example/api","name":"B"}`)
	invoke("scope", `{"id":"read","resource_id":"b","name":"b.orders.read","description":"Read orders","purpose_code":"orders","policy_version":1}`)
	invoke("client", `{"id":"c","name":"C","public":true,"redirect_uris":["https://c.example/callback"],"grant_types":["authorization_code"],"scopes":["openid","b.orders.read"],"audience":["https://b.example/api"]}`)
	invoke("status", `{"kind":"client","id":"c","status":"disabled"}`)
	db, err := dao.OpenWithDriver(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	defer sqlDB.Close()
	var client oauth.Client
	if err := db.First(&client, "id = ?", "c").Error; err != nil || client.Status != "disabled" {
		t.Fatalf("client: %+v %v", client, err)
	}
}
