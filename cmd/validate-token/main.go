package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
)

func main() {
	issuerURL := "http://localhost:8000"
	clientID := "https://kubernetes.default.svc.cluster.local"

	ctx := context.Background()

	// TODO: remove this
	ctx = oidc.InsecureIssuerURLContext(ctx, issuerURL)

	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		log.Fatal(err)
	}
	oidcConfig := &oidc.Config{
		ClientID:        clientID,
		SkipIssuerCheck: true, // TODO: remove this
	}
	verifier := provider.Verifier(oidcConfig)

	tokenBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("failed to read token: %v", err)
	}
	tokenString := string(tokenBytes)

	token, err := verifier.Verify(ctx, tokenString)
	if err != nil {
		log.Fatalf("failed to verify token: %v", err)
	}

	claims := jwt.RegisteredClaims{}
	if err := token.Claims(&claims); err != nil {
		log.Fatalf("failed to parse claims: %v", err)
	}

	claimsJSON, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		log.Fatalf("failed to marshal claims: %v", err)
	}

	fmt.Printf("Token claims:\n%s\n", string(claimsJSON))
}
