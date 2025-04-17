package main

import (
	"crypto/x509"
	"encoding/pem"
	"log"
	"net/http"
	"os"

	"github.com/vanstee/sts-irsa-proxy/internal/server"
)

func main() {
	issuerURL := "http://localhost:8000"

	clientID := "https://kubernetes.default.svc.cluster.local"

	// TODO: verify this against jwks in well known configuration
	privateKeyFile, err := os.ReadFile("private.key")
	if err != nil {
		log.Fatalf("failed reading private key file: %v", err)
	}

	block, _ := pem.Decode(privateKeyFile)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		log.Fatalf("failed decoding private key: %v", err)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("failed parsing private key: %v", err)
	}

	// TODO: fix this
	keyID := "DEADBEEF"
	alg := "RS256"

	s, err := server.NewServer(issuerURL, clientID, privateKey, keyID, alg)
	if err != nil {
		log.Fatalf("failed initializing server: %v", err)
	}

	log.Println("starting server on :8080")
	if err := http.ListenAndServe(":8080", s); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
