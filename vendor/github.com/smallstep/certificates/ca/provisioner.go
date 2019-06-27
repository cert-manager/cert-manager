package ca

import (
	"encoding/json"
	"net/url"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/token"
	"github.com/smallstep/cli/token/provision"
)

const tokenLifetime = 5 * time.Minute

// Provisioner is an authorized entity that can sign tokens necessary for
// signature requests.
type Provisioner struct {
	*Client
	name          string
	kid           string
	audience      string
	fingerprint   string
	jwk           *jose.JSONWebKey
	tokenLifetime time.Duration
}

// NewProvisioner loads and decrypts key material from the CA for the named
// provisioner. The key identified by `kid` will be used if specified. If `kid`
// is the empty string we'll use the first key for the named provisioner that
// decrypts using `password`.
func NewProvisioner(name, kid, caURL string, password []byte, opts ...ClientOption) (*Provisioner, error) {
	client, err := NewClient(caURL, opts...)
	if err != nil {
		return nil, err
	}

	// Get the fingerprint of the current connection
	fp, err := client.RootFingerprint()
	if err != nil {
		return nil, err
	}

	var jwk *jose.JSONWebKey
	switch {
	case name == "":
		return nil, errors.New("provisioner name cannot be empty")
	case kid == "":
		jwk, err = loadProvisionerJWKByName(client, name, password)
	default:
		jwk, err = loadProvisionerJWKByKid(client, kid, password)
	}
	if err != nil {
		return nil, err
	}
	return &Provisioner{
		Client:        client,
		name:          name,
		kid:           jwk.KeyID,
		audience:      client.endpoint.ResolveReference(&url.URL{Path: "/1.0/sign"}).String(),
		fingerprint:   fp,
		jwk:           jwk,
		tokenLifetime: tokenLifetime,
	}, nil
}

// Name returns the provisioner's name.
func (p *Provisioner) Name() string {
	return p.name
}

// Kid returns the provisioners key ID.
func (p *Provisioner) Kid() string {
	return p.kid
}

// SetFingerprint overwrites the default fingerprint used.
func (p *Provisioner) SetFingerprint(sum string) {
	p.fingerprint = sum
}

// Token generates a bootstrap token for a subject.
func (p *Provisioner) Token(subject string, sans ...string) (string, error) {
	if len(sans) == 0 {
		sans = []string{subject}
	}

	// A random jwt id will be used to identify duplicated tokens
	jwtID, err := randutil.Hex(64) // 256 bits
	if err != nil {
		return "", err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(tokenLifetime)
	tokOptions := []token.Options{
		token.WithJWTID(jwtID),
		token.WithKid(p.kid),
		token.WithIssuer(p.name),
		token.WithAudience(p.audience),
		token.WithValidity(notBefore, notAfter),
		token.WithSANS(sans),
	}

	if p.fingerprint != "" {
		tokOptions = append(tokOptions, token.WithSHA(p.fingerprint))
	}

	tok, err := provision.New(subject, tokOptions...)
	if err != nil {
		return "", err
	}

	return tok.SignedString(p.jwk.Algorithm, p.jwk.Key)
}

func decryptProvisionerJWK(encryptedKey string, password []byte) (*jose.JSONWebKey, error) {
	enc, err := jose.ParseEncrypted(encryptedKey)
	if err != nil {
		return nil, err
	}
	data, err := enc.Decrypt(password)
	if err != nil {
		return nil, err
	}
	jwk := new(jose.JSONWebKey)
	if err := json.Unmarshal(data, jwk); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling provisioning key")
	}
	return jwk, nil
}

// loadProvisionerJWKByKid retrieves a provisioner key from the CA by key ID and
// decrypts it using the specified password.
func loadProvisionerJWKByKid(client *Client, kid string, password []byte) (*jose.JSONWebKey, error) {
	encrypted, err := getProvisionerKey(client, kid)
	if err != nil {
		return nil, err
	}

	return decryptProvisionerJWK(encrypted, password)
}

// loadProvisionerJWKByName retrieves the list of provisioners and encrypted key then
// returns the key of the first provisioner with a matching name that can be successfully
// decrypted with the specified password.
func loadProvisionerJWKByName(client *Client, name string, password []byte) (key *jose.JSONWebKey, err error) {
	provisioners, err := getProvisioners(client)
	if err != nil {
		err = errors.Wrap(err, "error getting the provisioners")
		return
	}

	for _, provisioner := range provisioners {
		if provisioner.GetName() == name {
			if _, encryptedKey, ok := provisioner.GetEncryptedKey(); ok {
				key, err = decryptProvisionerJWK(encryptedKey, password)
				if err == nil {
					return
				}
			}
		}
	}
	return nil, errors.Errorf("provisioner '%s' not found (or your password is wrong)", name)
}

// getProvisioners returns the list of provisioners using the configured client.
func getProvisioners(client *Client) (provisioner.List, error) {
	var cursor string
	var provisioners provisioner.List
	for {
		resp, err := client.Provisioners(WithProvisionerCursor(cursor), WithProvisionerLimit(100))
		if err != nil {
			return nil, err
		}
		provisioners = append(provisioners, resp.Provisioners...)
		if resp.NextCursor == "" {
			return provisioners, nil
		}
		cursor = resp.NextCursor
	}
}

// getProvisionerKey returns the encrypted provisioner key for the given kid.
func getProvisionerKey(client *Client, kid string) (string, error) {
	resp, err := client.ProvisionerKey(kid)
	if err != nil {
		return "", err
	}
	return resp.Key, nil
}
