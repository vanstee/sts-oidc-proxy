package config

import (
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	STSEndpoint    string               `yaml:"stsEndpoint"`
	PrivateJWKPath string               `yaml:"privateJWKPath"`
	OIDCProviders  []ConfigOIDCProvider `yaml:"oidcProviders"`
}

type ConfigOIDCProvider struct {
	IssuerURL       string `yaml:"issuerURL"`
	SkipIssuerCheck bool   `yaml:"skipIssuerCheck"`
	ClientID        string `yaml:"clientID"`
	Audience        string `yaml:"audience"`

	ClusterName    string `yaml:"clusterName"`
	RewriteSubject bool   `yaml:"rewriteSubject"`
}

func ParseFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return Parse(f)
}

func Parse(r io.Reader) (*Config, error) {
	var c Config
	if err := yaml.NewDecoder(r).Decode(&c); err != nil {
		return nil, err
	}

	return &c, nil
}
