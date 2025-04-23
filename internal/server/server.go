package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/vanstee/sts-irsa-proxy/internal/config"
)

var (
	defaultSTSEndpoint = MustParseURL("https://sts.amazonaws.com")
)

type Server struct {
	ReverseProxy *httputil.ReverseProxy
	STSEndpoint  string
	Provider     *oidc.Provider
	Verifiers    map[*oidc.IDTokenVerifier]*config.ConfigOIDCProvider
	Signer       jose.Signer
}

func NewServer(c *config.Config) (*Server, error) {
	ctx := context.Background()

	verifiers := map[*oidc.IDTokenVerifier]*config.ConfigOIDCProvider{}
	for _, providerConfig := range c.OIDCProviders {
		issuerURL := MustParseURL(providerConfig.IssuerURL)
		if issuerURL.Scheme != "https" {
			log.Printf("warning: oidc provider %s is configured with an insecure issuer url", providerConfig.IssuerURL)
			ctx = oidc.InsecureIssuerURLContext(ctx, providerConfig.IssuerURL)
		}

		provider, err := oidc.NewProvider(ctx, providerConfig.IssuerURL)
		if err != nil {
			return nil, fmt.Errorf("failed to create oidc provider for issuer url %s: %v", providerConfig.IssuerURL, err)
		}

		oidcConfig := &oidc.Config{
			ClientID:        providerConfig.ClientID,
			SkipIssuerCheck: providerConfig.SkipIssuerCheck,
		}

		verifier := provider.Verifier(oidcConfig)
		verifiers[verifier] = &providerConfig
	}

	data, err := os.ReadFile(c.PrivateJWKPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", c.PrivateJWKPath, err)
	}

	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s: %v", c.PrivateJWKPath, err)
	}

	if !jwk.Valid() {
		return nil, fmt.Errorf("invalid jwk")
	}

	if jwk.IsPublic() {
		return nil, fmt.Errorf("jwk cannot be public for signing")
	}

	signingKey := jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
		Key:       jwk,
	}
	opts := (&jose.SignerOptions{}).WithType("JWT")
	signer, err := jose.NewSigner(signingKey, opts)
	if err != nil {
		return nil, fmt.Errorf("failed creating signer: %v", err)
	}

	server := &Server{
		STSEndpoint: c.STSEndpoint,
		Verifiers:   verifiers,
		Signer:      signer,
	}

	server.ReverseProxy = &httputil.ReverseProxy{
		Rewrite: server.Rewrite,
	}

	return server, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.ReverseProxy.ServeHTTP(w, r)
}

func (s *Server) Rewrite(r *httputil.ProxyRequest) {
	ctx := context.Background()

	if r.In.Method != "POST" {
		log.Printf("Method is not POST, skipping rewrite")
		return
	}

	buf := bytes.Buffer{}
	r.In.Body = io.NopCloser(io.TeeReader(r.In.Body, &buf))

	r.In.ParseForm()
	if r.In.FormValue("Action") != "AssumeRoleWithWebIdentity" {
		log.Printf("Action is not AssumeRoleWithWebIdentity, skipping rewrite")
		return
	}

	tokenString := r.In.FormValue("WebIdentityToken")
	if tokenString == "" {
		log.Printf("missing web identity token, skipping rewrite")
		return
	}

	var token *oidc.IDToken
	var providerConfig *config.ConfigOIDCProvider
	var errs []error
	for verifier, config := range s.Verifiers {
		t, err := verifier.Verify(ctx, tokenString)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		token = t
		providerConfig = config
		break
	}
	if token == nil {
		log.Printf("failed to verify token: %v", errors.Join(errs...))
		return
	}

	claims := jwt.RegisteredClaims{}
	if err := token.Claims(&claims); err != nil {
		log.Printf("failed to parse claims: %v", err)
		return
	}

	if providerConfig.RewriteSubject {
		claims.Subject = providerConfig.ClusterName + "/" + claims.Subject
	}

	marshalledClaims, err := json.Marshal(claims)
	if err != nil {
		log.Printf("failed marshaling claims: %v", err)
		return
	}

	sig, err := s.Signer.Sign([]byte(marshalledClaims))
	if err != nil {
		log.Printf("failed signing claims: %v", err)
		return
	}

	jwt, err := sig.CompactSerialize()
	if err != nil {
		log.Printf("failed serializing jwt: %v", err)
		return
	}

	r.SetURL(MustParseURL(s.STSEndpoint))

	// reset in request body to satisfy Rewrite requirements
	r.In.Body = io.NopCloser(&buf)

	form := r.In.Form
	form.Set("WebIdentityToken", jwt)
	body := form.Encode()
	r.Out.ContentLength = int64(len(body))
	r.Out.Body = io.NopCloser(strings.NewReader(body))
}

func MustParseURL(rawUrl string) *url.URL {
	parsedUrl, err := url.Parse(rawUrl)
	if err != nil {
		log.Printf("failed to parse url: %v", err)
	}
	return parsedUrl
}
