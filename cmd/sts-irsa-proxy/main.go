package main

import (
	"log"
	"net/http"

	"github.com/vanstee/sts-irsa-proxy/internal/config"
	"github.com/vanstee/sts-irsa-proxy/internal/server"
)

func main() {
	configPath := "config.yaml"
	c, err := config.ParseFile("config.yaml")
	if err != nil {
		log.Fatalf("failed to read config at path %s: %v", configPath, err)
	}

	s, err := server.NewServer(c)
	if err != nil {
		log.Fatalf("failed initializing server: %v", err)
	}

	log.Println("starting server on :8080")
	if err := http.ListenAndServe(":8080", s); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
