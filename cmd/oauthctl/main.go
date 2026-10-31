// oauthctl provisions trusted OAuth configuration directly in the service DB.
// It is intended to be run by an operator with database access.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"
	"github.com/sharelib-jp/auth-service/config"
	"github.com/sharelib-jp/auth-service/internal/authorization"
	"github.com/sharelib-jp/auth-service/internal/database"
	"github.com/sharelib-jp/auth-service/internal/oauth"
)

func decode(v any) error {
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("expected one JSON object")
	}
	return nil
}

func run() error {
	flags := flag.NewFlagSet("oauthctl", flag.ContinueOnError)
	configPath := flags.String("config", "./config.toml", "configuration file")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("expected one command: resource, scope, client, client-update, resource-credential, status, scope-policy, role-binding, or policy")
	}
	conf, err := config.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	db, err := database.OpenWithDriver(conf.DATABASE_DRIVER, conf.DATABASE_DSN)
	if err != nil {
		return err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	defer sqlDB.Close()
	catalog := oauth.NewCatalog(db)
	ctx := context.Background()
	switch flags.Arg(0) {
	case "resource":
		var in struct {
			ID         string `json:"id"`
			Identifier string `json:"identifier"`
			Name       string `json:"name"`
		}
		if err := decode(&in); err != nil {
			return err
		}
		return catalog.RegisterResource(ctx, oauth.Resource{ID: in.ID, Identifier: in.Identifier, Name: in.Name})
	case "scope":
		var in struct {
			ID            string `json:"id"`
			ResourceID    string `json:"resource_id"`
			Name          string `json:"name"`
			Description   string `json:"description"`
			PurposeCode   string `json:"purpose_code"`
			PolicyVersion uint   `json:"policy_version"`
		}
		if err := decode(&in); err != nil {
			return err
		}
		return catalog.RegisterScope(ctx, oauth.Scope{ID: in.ID, ResourceID: in.ResourceID, Name: in.Name, Description: in.Description, PurposeCode: in.PurposeCode, PolicyVersion: in.PolicyVersion})
	case "client", "client-update":
		var in struct {
			ID           string   `json:"id"`
			Name         string   `json:"name"`
			Public       bool     `json:"public"`
			RedirectURIs []string `json:"redirect_uris"`
			GrantTypes   []string `json:"grant_types"`
			Scopes       []string `json:"scopes"`
			Audience     []string `json:"audience"`
		}
		if err := decode(&in); err != nil {
			return err
		}
		client := oauth.Client{ID: in.ID, Name: in.Name, Public: in.Public, RedirectURIs: in.RedirectURIs, GrantTypes: in.GrantTypes, Scopes: in.Scopes, Audience: in.Audience}
		if flags.Arg(0) == "client-update" {
			return catalog.UpdateClient(ctx, client, os.Getenv("OAUTH_CLIENT_SECRET"))
		}
		return catalog.RegisterClient(ctx, client, os.Getenv("OAUTH_CLIENT_SECRET"))
	case "resource-credential":
		var in struct {
			ID         string `json:"id"`
			ResourceID string `json:"resource_id"`
		}
		if err := decode(&in); err != nil {
			return err
		}
		return catalog.RegisterResourceCredential(ctx, in.ID, in.ResourceID, os.Getenv("OAUTH_RESOURCE_SECRET"))
	case "status":
		var in struct {
			Kind   string `json:"kind"`
			ID     string `json:"id"`
			Status string `json:"status"`
		}
		if err := decode(&in); err != nil {
			return err
		}
		return catalog.SetStatus(ctx, in.Kind, in.ID, in.Status)
	case "scope-policy":
		var in struct {
			ID          string `json:"id"`
			Description string `json:"description"`
			PurposeCode string `json:"purpose_code"`
		}
		if err := decode(&in); err != nil {
			return err
		}
		return catalog.UpdateScopePolicy(ctx, in.ID, in.Description, in.PurposeCode)
	case "role-binding":
		var in struct {
			ResourceID string    `json:"resource_id"`
			UserID     uuid.UUID `json:"user_id"`
			Role       string    `json:"role"`
			Status     string    `json:"status"`
		}
		if err := decode(&in); err != nil {
			return err
		}
		return authorization.NewService(db).SetBinding(ctx, authorization.RoleBinding{ResourceID: in.ResourceID, UserID: in.UserID, Role: in.Role, Status: in.Status})
	case "policy":
		var in struct {
			ResourceID string `json:"resource_id"`
			Role       string `json:"role"`
			Object     string `json:"object"`
			Action     string `json:"action"`
			Status     string `json:"status"`
		}
		if err := decode(&in); err != nil {
			return err
		}
		return authorization.NewService(db).SetPolicy(ctx, authorization.Policy{ResourceID: in.ResourceID, Role: in.Role, Object: in.Object, Action: in.Action, Status: in.Status})
	default:
		return errors.New("unknown command")
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "oauthctl:", err)
		os.Exit(1)
	}
}
