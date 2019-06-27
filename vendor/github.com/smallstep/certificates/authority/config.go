package authority

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/cli/crypto/tlsutil"
	"github.com/smallstep/cli/crypto/x509util"
)

var (
	// DefaultTLSOptions represents the default TLS version as well as the cipher
	// suites used in the TLS certificates.
	DefaultTLSOptions = tlsutil.TLSOptions{
		CipherSuites: x509util.CipherSuites{
			"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		},
		MinVersion:    1.2,
		MaxVersion:    1.2,
		Renegotiation: false,
	}
	defaultDisableRenewal   = false
	globalProvisionerClaims = provisioner.Claims{
		MinTLSDur:      &provisioner.Duration{Duration: 5 * time.Minute},
		MaxTLSDur:      &provisioner.Duration{Duration: 24 * time.Hour},
		DefaultTLSDur:  &provisioner.Duration{Duration: 24 * time.Hour},
		DisableRenewal: &defaultDisableRenewal,
	}
)

// Config represents the CA configuration and it's mapped to a JSON object.
type Config struct {
	Root             multiString         `json:"root"`
	FederatedRoots   []string            `json:"federatedRoots"`
	IntermediateCert string              `json:"crt"`
	IntermediateKey  string              `json:"key"`
	Address          string              `json:"address"`
	DNSNames         []string            `json:"dnsNames"`
	Logger           json.RawMessage     `json:"logger,omitempty"`
	DB               *db.Config          `json:"db,omitempty"`
	Monitoring       json.RawMessage     `json:"monitoring,omitempty"`
	AuthorityConfig  *AuthConfig         `json:"authority,omitempty"`
	TLS              *tlsutil.TLSOptions `json:"tls,omitempty"`
	Password         string              `json:"password,omitempty"`
}

// AuthConfig represents the configuration options for the authority.
type AuthConfig struct {
	Provisioners         provisioner.List    `json:"provisioners"`
	Template             *x509util.ASN1DN    `json:"template,omitempty"`
	Claims               *provisioner.Claims `json:"claims,omitempty"`
	DisableIssuedAtCheck bool                `json:"disableIssuedAtCheck,omitempty"`
}

// Validate validates the authority configuration.
func (c *AuthConfig) Validate(audiences provisioner.Audiences) error {
	if c == nil {
		return errors.New("authority cannot be undefined")
	}
	if len(c.Provisioners) == 0 {
		return errors.New("authority.provisioners cannot be empty")
	}

	// Merge global and configuration claims
	claimer, err := provisioner.NewClaimer(c.Claims, globalProvisionerClaims)
	if err != nil {
		return err
	}

	// Initialize provisioners
	config := provisioner.Config{
		Claims:    claimer.Claims(),
		Audiences: audiences,
	}
	for _, p := range c.Provisioners {
		if err := p.Init(config); err != nil {
			return err
		}
	}

	if c.Template == nil {
		c.Template = &x509util.ASN1DN{}
	}
	return nil
}

// LoadConfiguration parses the given filename in JSON format and returns the
// configuration struct.
func LoadConfiguration(filename string) (*Config, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, errors.Wrapf(err, "error opening %s", filename)
	}
	defer f.Close()

	var c Config
	if err := json.NewDecoder(f).Decode(&c); err != nil {
		return nil, errors.Wrapf(err, "error parsing %s", filename)
	}

	return &c, nil
}

// Save saves the configuration to the given filename.
func (c *Config) Save(filename string) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return errors.Wrapf(err, "error opening %s", filename)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "\t")
	return errors.Wrapf(enc.Encode(c), "error writing %s", filename)
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	switch {
	case c.Address == "":
		return errors.New("address cannot be empty")

	case c.Root.HasEmpties():
		return errors.New("root cannot be empty")

	case c.IntermediateCert == "":
		return errors.New("crt cannot be empty")

	case c.IntermediateKey == "":
		return errors.New("key cannot be empty")

	case len(c.DNSNames) == 0:
		return errors.New("dnsNames cannot be empty")
	}

	// Validate address (a port is required)
	if _, _, err := net.SplitHostPort(c.Address); err != nil {
		return errors.Errorf("invalid address %s", c.Address)
	}

	if c.TLS == nil {
		c.TLS = &DefaultTLSOptions
	} else {
		if len(c.TLS.CipherSuites) == 0 {
			c.TLS.CipherSuites = DefaultTLSOptions.CipherSuites
		}
		if c.TLS.MaxVersion == 0 {
			c.TLS.MaxVersion = DefaultTLSOptions.MaxVersion
		}
		if c.TLS.MinVersion == 0 {
			c.TLS.MinVersion = c.TLS.MaxVersion
		}
		if c.TLS.MinVersion > c.TLS.MaxVersion {
			return errors.New("tls minVersion cannot exceed tls maxVersion")
		}
		c.TLS.Renegotiation = c.TLS.Renegotiation || DefaultTLSOptions.Renegotiation
	}

	return c.AuthorityConfig.Validate(c.getAudiences())
}

// getAudiences returns the legacy and possible urls without the ports that will
// be used as the default provisioner audiences. The CA might have proxies in
// front so we cannot rely on the port.
func (c *Config) getAudiences() provisioner.Audiences {
	audiences := provisioner.Audiences{
		Sign:   []string{legacyAuthority},
		Revoke: []string{legacyAuthority},
	}

	for _, name := range c.DNSNames {
		audiences.Sign = append(audiences.Sign,
			fmt.Sprintf("https://%s/sign", name), fmt.Sprintf("https://%s/1.0/sign", name))
		audiences.Revoke = append(audiences.Revoke,
			fmt.Sprintf("https://%s/revoke", name), fmt.Sprintf("https://%s/1.0/revoke", name))
	}

	return audiences
}
