package main

import (
	"log"
	"net/http"
	"os"

	"github.com/go-jose/go-jose/v4"
	"github.com/vanstee/sts-irsa-proxy/internal/server"
)

func main() {
	issuerURL := "http://localhost:8000"

	clientID := "https://kubernetes.default.svc.cluster.local"

	data, err := os.ReadFile("priv.json")
	if err != nil {
		log.Fatalf("failed to read priv.json: %v", err)
	}

	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(data); err != nil {
		log.Fatalf("failed to unmarshal priv.json: %v", err)
	}

	s, err := server.NewServer(issuerURL, clientID, &jwk)
	if err != nil {
		log.Fatalf("failed initializing server: %v", err)
	}

	log.Println("starting server on :8080")
	if err := http.ListenAndServe(":8080", s); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
