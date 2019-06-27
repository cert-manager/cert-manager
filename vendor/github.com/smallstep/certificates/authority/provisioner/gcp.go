package provisioner

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/jose"
)

// gcpCertsURL is the url that serves Google OAuth2 public keys.
const gcpCertsURL = "https://www.googleapis.com/oauth2/v3/certs"

// gcpIdentityURL is the base url for the identity document in GCP.
const gcpIdentityURL = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity"

// gcpPayload extends jwt.Claims with custom GCP attributes.
type gcpPayload struct {
	jose.Claims
	AuthorizedParty string           `json:"azp"`
	Email           string           `json:"email"`
	EmailVerified   bool             `json:"email_verified"`
	Google          gcpGooglePayload `json:"google"`
}

type gcpGooglePayload struct {
	ComputeEngine gcpComputeEnginePayload `json:"compute_engine"`
}

type gcpComputeEnginePayload struct {
	InstanceID                string            `json:"instance_id"`
	InstanceName              string            `json:"instance_name"`
	InstanceCreationTimestamp *jose.NumericDate `json:"instance_creation_timestamp"`
	ProjectID                 string            `json:"project_id"`
	ProjectNumber             int64             `json:"project_number"`
	Zone                      string            `json:"zone"`
	LicenseID                 []string          `json:"license_id"`
}

type gcpConfig struct {
	CertsURL    string
	IdentityURL string
}

func newGCPConfig() *gcpConfig {
	return &gcpConfig{
		CertsURL:    gcpCertsURL,
		IdentityURL: gcpIdentityURL,
	}
}

// GCP is the provisioner that supports identity tokens created by the Google
// Cloud Platform metadata API.
//
// If DisableCustomSANs is true, only the internal DNS and IP will be added as a
// SAN. By default it will accept any SAN in the CSR.
//
// If DisableTrustOnFirstUse is true, multiple sign request for this provisioner
// with the same instance will be accepted. By default only the first request
// will be accepted.
//
// If InstanceAge is set, only the instances with an instance_creation_timestamp
// within the given period will be accepted.
//
// Google Identity docs are available at
// https://cloud.google.com/compute/docs/instances/verifying-instance-identity
type GCP struct {
	Type                   string   `json:"type"`
	Name                   string   `json:"name"`
	ServiceAccounts        []string `json:"serviceAccounts"`
	ProjectIDs             []string `json:"projectIDs"`
	DisableCustomSANs      bool     `json:"disableCustomSANs"`
	DisableTrustOnFirstUse bool     `json:"disableTrustOnFirstUse"`
	InstanceAge            Duration `json:"instanceAge,omitempty"`
	Claims                 *Claims  `json:"claims,omitempty"`
	claimer                *Claimer
	config                 *gcpConfig
	keyStore               *keyStore
	audiences              Audiences
}

// GetID returns the provisioner unique identifier. The name should uniquely
// identify any GCP provisioner.
func (p *GCP) GetID() string {
	return "gcp/" + p.Name
}

// GetTokenID returns the identifier of the token. The default value for GCP the
// SHA256 of "provisioner_id.instance_id", but if DisableTrustOnFirstUse is set
// to true, then it will be the SHA256 of the token.
func (p *GCP) GetTokenID(token string) (string, error) {
	jwt, err := jose.ParseSigned(token)
	if err != nil {
		return "", errors.Wrap(err, "error parsing token")
	}

	// If TOFU is disabled create an ID for the token, so it cannot be reused.
	if p.DisableTrustOnFirstUse {
		sum := sha256.Sum256([]byte(token))
		return strings.ToLower(hex.EncodeToString(sum[:])), nil
	}

	// Get claims w/out verification.
	var claims gcpPayload
	if err = jwt.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return "", errors.Wrap(err, "error verifying claims")
	}

	// Create unique ID for Trust On First Use (TOFU). Only the first instance
	// per provisioner is allowed as we don't have a way to trust the given
	// sans.
	unique := fmt.Sprintf("%s.%s", p.GetID(), claims.Google.ComputeEngine.InstanceID)
	sum := sha256.Sum256([]byte(unique))
	return strings.ToLower(hex.EncodeToString(sum[:])), nil
}

// GetName returns the name of the provisioner.
func (p *GCP) GetName() string {
	return p.Name
}

// GetType returns the type of provisioner.
func (p *GCP) GetType() Type {
	return TypeGCP
}

// GetEncryptedKey is not available in a GCP provisioner.
func (p *GCP) GetEncryptedKey() (kid string, key string, ok bool) {
	return "", "", false
}

// GetIdentityURL returns the url that generates the GCP token.
func (p *GCP) GetIdentityURL(audience string) string {
	// Initialize config if required
	p.assertConfig()

	q := url.Values{}
	q.Add("audience", audience)
	q.Add("format", "full")
	q.Add("licenses", "FALSE")
	return fmt.Sprintf("%s?%s", p.config.IdentityURL, q.Encode())
}

// GetIdentityToken does an HTTP request to the identity url.
func (p *GCP) GetIdentityToken(caURL string) (string, error) {
	audience, err := generateSignAudience(caURL, p.GetID())
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("GET", p.GetIdentityURL(audience), http.NoBody)
	if err != nil {
		return "", errors.Wrap(err, "error creating identity request")
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error doing identity request, are you in a GCP VM?")
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "error on identity request")
	}
	if resp.StatusCode >= 400 {
		return "", errors.Errorf("error on identity request: status=%d, response=%s", resp.StatusCode, b)
	}
	return string(bytes.TrimSpace(b)), nil
}

// Init validates and initializes the GCP provisioner.
func (p *GCP) Init(config Config) error {
	var err error
	switch {
	case p.Type == "":
		return errors.New("provisioner type cannot be empty")
	case p.Name == "":
		return errors.New("provisioner name cannot be empty")
	case p.InstanceAge.Value() < 0:
		return errors.New("provisioner instanceAge cannot be negative")
	}
	// Initialize config
	p.assertConfig()
	// Update claims with global ones
	if p.claimer, err = NewClaimer(p.Claims, config.Claims); err != nil {
		return err
	}
	// Initialize key store
	p.keyStore, err = newKeyStore(p.config.CertsURL)
	if err != nil {
		return err
	}

	p.audiences = config.Audiences.WithFragment(p.GetID())
	return nil
}

// AuthorizeSign validates the given token and returns the sign options that
// will be used on certificate creation.
func (p *GCP) AuthorizeSign(token string) ([]SignOption, error) {
	claims, err := p.authorizeToken(token)
	if err != nil {
		return nil, err
	}
	ce := claims.Google.ComputeEngine

	// Enforce default DNS if configured.
	// By default we we'll accept the SANs in the CSR.
	// There's no way to trust them other than TOFU.
	var so []SignOption
	if p.DisableCustomSANs {
		so = append(so, dnsNamesValidator([]string{
			fmt.Sprintf("%s.c.%s.internal", ce.InstanceName, ce.ProjectID),
			fmt.Sprintf("%s.%s.c.%s.internal", ce.InstanceName, ce.Zone, ce.ProjectID),
		}))
	}

	return append(so,
		commonNameValidator(ce.InstanceName),
		profileDefaultDuration(p.claimer.DefaultTLSCertDuration()),
		newProvisionerExtensionOption(TypeGCP, p.Name, claims.Subject),
		newValidityValidator(p.claimer.MinTLSCertDuration(), p.claimer.MaxTLSCertDuration()),
	), nil
}

// AuthorizeRenewal returns an error if the renewal is disabled.
func (p *GCP) AuthorizeRenewal(cert *x509.Certificate) error {
	if p.claimer.IsDisableRenewal() {
		return errors.Errorf("renew is disabled for provisioner %s", p.GetID())
	}
	return nil
}

// AuthorizeRevoke returns an error because revoke is not supported on GCP
// provisioners.
func (p *GCP) AuthorizeRevoke(token string) error {
	return errors.New("revoke is not supported on a GCP provisioner")
}

// assertConfig initializes the config if it has not been initialized.
func (p *GCP) assertConfig() {
	if p.config == nil {
		p.config = newGCPConfig()
	}
}

// authorizeToken performs common jwt authorization actions and returns the
// claims for case specific downstream parsing.
// e.g. a Sign request will auth/validate different fields than a Revoke request.
func (p *GCP) authorizeToken(token string) (*gcpPayload, error) {
	jwt, err := jose.ParseSigned(token)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing token")
	}
	if len(jwt.Headers) == 0 {
		return nil, errors.New("error parsing token: header is missing")
	}

	var found bool
	var claims gcpPayload
	kid := jwt.Headers[0].KeyID
	keys := p.keyStore.Get(kid)
	for _, key := range keys {
		if err := jwt.Claims(key.Public(), &claims); err == nil {
			found = true
			break
		}
	}
	if !found {
		return nil, errors.Errorf("failed to validate payload: cannot find key for kid %s", kid)
	}

	// According to "rfc7519 JSON Web Token" acceptable skew should be no
	// more than a few minutes.
	now := time.Now().UTC()
	if err = claims.ValidateWithLeeway(jose.Expected{
		Issuer: "https://accounts.google.com",
		Time:   now,
	}, time.Minute); err != nil {
		return nil, errors.Wrapf(err, "invalid token")
	}

	// validate audiences with the defaults
	if !matchesAudience(claims.Audience, p.audiences.Sign) {
		return nil, errors.New("invalid token: invalid audience claim (aud)")
	}

	// validate subject (service account)
	if len(p.ServiceAccounts) > 0 {
		var found bool
		for _, sa := range p.ServiceAccounts {
			if sa == claims.Subject || sa == claims.Email {
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("invalid token: invalid subject claim")
		}
	}

	// validate projects
	if len(p.ProjectIDs) > 0 {
		var found bool
		for _, pi := range p.ProjectIDs {
			if pi == claims.Google.ComputeEngine.ProjectID {
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("invalid token: invalid project id")
		}
	}

	// validate instance age
	if d := p.InstanceAge.Value(); d > 0 {
		if now.Sub(claims.Google.ComputeEngine.InstanceCreationTimestamp.Time()) > d {
			return nil, errors.New("token google.compute_engine.instance_creation_timestamp is too old")
		}
	}

	switch {
	case claims.Google.ComputeEngine.InstanceID == "":
		return nil, errors.New("token google.compute_engine.instance_id cannot be empty")
	case claims.Google.ComputeEngine.InstanceName == "":
		return nil, errors.New("token google.compute_engine.instance_name cannot be empty")
	case claims.Google.ComputeEngine.ProjectID == "":
		return nil, errors.New("token google.compute_engine.project_id cannot be empty")
	case claims.Google.ComputeEngine.Zone == "":
		return nil, errors.New("token google.compute_engine.zone cannot be empty")
	}

	return &claims, nil
}
