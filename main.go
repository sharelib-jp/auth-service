package main

import (
	"log"
	"net/http"
	"time"

	"github.com/sharelib-jp/auth-service/config"
	"github.com/sharelib-jp/auth-service/handlers/api"
	"github.com/sharelib-jp/auth-service/handlers/web"
	"github.com/sharelib-jp/auth-service/internal/database"
)

func main() {
	conf, err := config.LoadConfig("./config.toml")
	if err != nil {
		log.Fatal(err)
	}

	db, err := database.OpenWithDriver(conf.DATABASE_DRIVER, conf.DATABASE_DSN)
	if err != nil {
		log.Fatal("Failed to initialize database: ", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatal(err)
	}
	defer sqlDB.Close()

	router, err := api.NewRouter(conf, db)
	if err != nil {
		log.Fatal("Failed to initialize authentication: ", err)
	}
	web.Register(router, "handlers/web/dist")

	server := &http.Server{
		Addr: conf.PORT, Handler: router,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
	}
	log.Printf("Listening on %s (WebAuthn origin: %s)", conf.PORT, conf.Origin())
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal("Failed to start server: ", err)
	}
}
