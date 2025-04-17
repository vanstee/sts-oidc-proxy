package server

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

var (
	defaultProxyURL = MustParseURL("https://sts.amazonaws.com")
)

type Server struct {
	ReverseProxy *httputil.ReverseProxy
	ProxyURL     *url.URL
	IssuerURL    string
	ClientID     string
	Provider     *oidc.Provider
	OIDCConfig   *oidc.Config
	Verifier     *oidc.IDTokenVerifier
	Signer       jose.Signer
}

func NewServer(issuerURL string, clientID string, priv crypto.PrivateKey, keyID, alg string) (*Server, error) {
	ctx := context.Background()
	ctx = oidc.InsecureIssuerURLContext(ctx, issuerURL) // TODO: remove this

	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, err
	}

	oidcConfig := &oidc.Config{
		ClientID:        clientID,
		SkipIssuerCheck: true, // TODO: remove this
	}

	verifier := provider.Verifier(oidcConfig)

	key := jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(alg),
		Key:       priv,
	}

	opts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderKey("kid"): keyID,
		},
	}

	signer, err := jose.NewSigner(key, opts)
	if err != nil {
		return nil, fmt.Errorf("failed creating signer: %v", err)
	}

	server := &Server{
		ProxyURL:   defaultProxyURL,
		IssuerURL:  issuerURL,
		ClientID:   clientID,
		Provider:   provider,
		OIDCConfig: oidcConfig,
		Verifier:   verifier,
		Signer:     signer,
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

	token, err := s.Verifier.Verify(ctx, tokenString)
	if err != nil {
		log.Printf("failed to verify token: %v", err)
		return
	}

	claims := jwt.RegisteredClaims{}
	if err := token.Claims(&claims); err != nil {
		log.Printf("failed to parse claims: %v", err)
		return
	}

	// TODO: verify audience is sts.amazonaws.com
	// TODO: consider updating sub to <cluster>/system:serviceaccount:<namespace>:<serviceaccount>

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

	form := r.In.Form
	form.Set("WebIdentityToken", jwt)

	r.SetURL(s.ProxyURL)
	r.Out.Body = io.NopCloser(&buf)
}

func MustParseURL(rawUrl string) *url.URL {
	parsedUrl, err := url.Parse(rawUrl)
	if err != nil {
		log.Printf("failed to parse url: %v", err)
	}
	return parsedUrl
}
