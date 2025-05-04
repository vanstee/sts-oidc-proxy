package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"

	"github.com/vanstee/sts-irsa-proxy/internal/config"
)

func TestRewrite(t *testing.T) {
	veriferConfig := &oidc.Config{
		SkipClientIDCheck:          true,
		SkipExpiryCheck:            true,
		SkipIssuerCheck:            true,
		InsecureSkipSignatureCheck: true,
	}
	verifier := oidc.NewVerifier("sts-oidc-proxy.example.com", nil, veriferConfig)

	rsaTestKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signerKey := jose.SigningKey{
		Key: &jose.JSONWebKey{
			Key:   rsaTestKey,
			KeyID: "rsa-test-key",
		},
		Algorithm: jose.RS256,
	}
	signer, err := jose.NewSigner(signerKey, &jose.SignerOptions{})

	server := &Server{
		STSEndpoint: "sts.example.com",
		Verifiers: map[*oidc.IDTokenVerifier]*config.ConfigOIDCProvider{
			verifier: &config.ConfigOIDCProvider{
				ClusterName:    "test-cluster",
				RewriteSubject: true,
			},
		},
		Signer: signer,
	}

	form := url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"WebIdentityToken": {"aGVhZGVy.eyJzdWIiOiJzdWJqZWN0In0K.signature"}, // header.{"sub":"subject"}.signature
	}

	in, err := http.NewRequest("POST", "sts-oidc-proxy.example.com", strings.NewReader(form.Encode()))
	in.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		t.Fatalf("unexpected error created proxy request: %v", err)
	}

	r := &httputil.ProxyRequest{In: in, Out: in.Clone(context.Background())}
	server.Rewrite(r)

	if r.Out.URL.String() != "sts.example.com" {
		t.Errorf("proxied request does not have updated url, expected: %s, actual: %s", "sts.localhost", r.Out.Host)
	}

	r.Out.ParseForm()
	if r.Out.FormValue("Action") != "AssumeRoleWithWebIdentity" {
		t.Errorf("proxied request changed action unexpectedly, expected: %s, actual: %s", "AssumeRoleWithWebIdentity", r.Out.FormValue("Action"))
	}

	token := r.Out.FormValue("WebIdentityToken")
	segments := strings.SplitN(token, ".", 3)
	bytes, err := base64.RawStdEncoding.DecodeString(segments[1])
	if err != nil {
		t.Fatalf("unexpectedly failed to decode web identity token: %v", err)
	}

	type claims struct {
		Subject string `json:"sub"`
	}

	c := &claims{}
	if err = json.Unmarshal(bytes, c); err != nil {
		t.Fatalf("unexpectedly failed to parse web identity token claims: %v", err)
	}

	if c.Subject != "test-cluster/subject" {
		t.Errorf("proxied request contains unexpected token, expected: %s, actual: %s", "test-cluster/subject", c.Subject)
	}
}
