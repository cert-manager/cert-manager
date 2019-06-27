package provisioner

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/jose"
)

// azureOIDCBaseURL is the base discovery url for Microsoft Azure tokens.
const azureOIDCBaseURL = "https://login.microsoftonline.com"

// azureIdentityTokenURL is the URL to get the identity token for an instance.
const azureIdentityTokenURL = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F"

// azureDefaultAudience is the default audience used.
const azureDefaultAudience = "https://management.azure.com/"

// azureXMSMirIDRegExp is the regular expression used to parse the xms_mirid claim.
// Using case insensitive as resourceGroups appears as resourcegroups.
var azureXMSMirIDRegExp = regexp.MustCompile(`(?i)^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft.Compute/virtualMachines/([^/]+)$`)

type azureConfig struct {
	oidcDiscoveryURL string
	identityTokenURL string
}

func newAzureConfig(tenantID string) *azureConfig {
	return &azureConfig{
		oidcDiscoveryURL: azureOIDCBaseURL + "/" + tenantID + "/.well-known/openid-configuration",
		identityTokenURL: azureIdentityTokenURL,
	}
}

type azureIdentityToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ClientID     string `json:"client_id"`
	ExpiresIn    int64  `json:"expires_in,string"`
	ExpiresOn    int64  `json:"expires_on,string"`
	ExtExpiresIn int64  `json:"ext_expires_in,string"`
	NotBefore    int64  `json:"not_before,string"`
	Resource     string `json:"resource"`
	TokenType    string `json:"token_type"`
}

type azurePayload struct {
	jose.Claims
	AppID            string `json:"appid"`
	AppIDAcr         string `json:"appidacr"`
	IdentityProvider string `json:"idp"`
	ObjectID         string `json:"oid"`
	TenantID         string `json:"tid"`
	Version          string `json:"ver"`
	XMSMirID         string `json:"xms_mirid"`
}

// Azure is the provisioner that supports identity tokens created from the
// Microsoft Azure Instance Metadata service.
//
// The default audience is "https://management.azure.com/".
//
// If DisableCustomSANs is true, only the internal DNS and IP will be added as a
// SAN. By default it will accept any SAN in the CSR.
//
// If DisableTrustOnFirstUse is true, multiple sign request for this provisioner
// with the same instance will be accepted. By default only the first request
// will be accepted.
//
// Microsoft Azure identity docs are available at
// https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/how-to-use-vm-token
// and https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service
type Azure struct {
	Type                   string   `json:"type"`
	Name                   string   `json:"name"`
	TenantID               string   `json:"tenantId"`
	ResourceGroups         []string `json:"resourceGroups"`
	Audience               string   `json:"audience,omitempty"`
	DisableCustomSANs      bool     `json:"disableCustomSANs"`
	DisableTrustOnFirstUse bool     `json:"disableTrustOnFirstUse"`
	Claims                 *Claims  `json:"claims,omitempty"`
	claimer                *Claimer
	config                 *azureConfig
	oidcConfig             openIDConfiguration
	keyStore               *keyStore
}

// GetID returns the provisioner unique identifier.
func (p *Azure) GetID() string {
	return p.TenantID
}

// GetTokenID returns the identifier of the token. The default value for Azure
// the SHA256 of "xms_mirid", but if DisableTrustOnFirstUse is set to true, then
// it will be the token kid.
func (p *Azure) GetTokenID(token string) (string, error) {
	jwt, err := jose.ParseSigned(token)
	if err != nil {
		return "", errors.Wrap(err, "error parsing token")
	}

	// Get claims w/out verification. We need to look up the provisioner
	// key in order to verify the claims and we need the issuer from the claims
	// before we can look up the provisioner.
	var claims azurePayload
	if err = jwt.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return "", errors.Wrap(err, "error verifying claims")
	}

	// If TOFU is disabled create return the token kid
	if p.DisableTrustOnFirstUse {
		return claims.ID, nil
	}

	sum := sha256.Sum256([]byte(claims.XMSMirID))
	return strings.ToLower(hex.EncodeToString(sum[:])), nil
}

// GetName returns the name of the provisioner.
func (p *Azure) GetName() string {
	return p.Name
}

// GetType returns the type of provisioner.
func (p *Azure) GetType() Type {
	return TypeAzure
}

// GetEncryptedKey is not available in an Azure provisioner.
func (p *Azure) GetEncryptedKey() (kid string, key string, ok bool) {
	return "", "", false
}

// GetIdentityToken retrieves from the metadata service the identity token and
// returns it.
func (p *Azure) GetIdentityToken() (string, error) {
	// Initialize the config if this method is used from the cli.
	p.assertConfig()

	req, err := http.NewRequest("GET", p.config.identityTokenURL, http.NoBody)
	if err != nil {
		return "", errors.Wrap(err, "error creating request")
	}
	req.Header.Set("Metadata", "true")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error getting identity token, are you in a Azure VM?")
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "error reading identity token response")
	}
	if resp.StatusCode >= 400 {
		return "", errors.Errorf("error getting identity token: status=%d, response=%s", resp.StatusCode, b)
	}

	var identityToken azureIdentityToken
	if err := json.Unmarshal(b, &identityToken); err != nil {
		return "", errors.Wrap(err, "error unmarshaling identity token response")
	}

	return identityToken.AccessToken, nil
}

// Init validates and initializes the Azure provisioner.
func (p *Azure) Init(config Config) (err error) {
	switch {
	case p.Type == "":
		return errors.New("provisioner type cannot be empty")
	case p.Name == "":
		return errors.New("provisioner name cannot be empty")
	case p.TenantID == "":
		return errors.New("provisioner tenantId cannot be empty")
	case p.Audience == "": // use default audience
		p.Audience = azureDefaultAudience
	}
	// Initialize config
	p.assertConfig()

	// Update claims with global ones
	if p.claimer, err = NewClaimer(p.Claims, config.Claims); err != nil {
		return err
	}

	// Decode and validate openid-configuration endpoint
	if err := getAndDecode(p.config.oidcDiscoveryURL, &p.oidcConfig); err != nil {
		return err
	}
	if err := p.oidcConfig.Validate(); err != nil {
		return errors.Wrapf(err, "error parsing %s", p.config.oidcDiscoveryURL)
	}
	// Get JWK key set
	if p.keyStore, err = newKeyStore(p.oidcConfig.JWKSetURI); err != nil {
		return err
	}

	return nil
}

// AuthorizeSign validates the given token and returns the sign options that
// will be used on certificate creation.
func (p *Azure) AuthorizeSign(token string) ([]SignOption, error) {
	jwt, err := jose.ParseSigned(token)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing token")
	}
	if len(jwt.Headers) == 0 {
		return nil, errors.New("error parsing token: header is missing")
	}

	var found bool
	var claims azurePayload
	keys := p.keyStore.Get(jwt.Headers[0].KeyID)
	for _, key := range keys {
		if err := jwt.Claims(key.Public(), &claims); err == nil {
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("cannot validate token")
	}

	if err := claims.ValidateWithLeeway(jose.Expected{
		Audience: []string{p.Audience},
		Issuer:   p.oidcConfig.Issuer,
		Time:     time.Now(),
	}, 1*time.Minute); err != nil {
		return nil, errors.Wrap(err, "failed to validate payload")
	}

	// Validate TenantID
	if claims.TenantID != p.TenantID {
		return nil, errors.New("validation failed: invalid tenant id claim (tid)")
	}

	re := azureXMSMirIDRegExp.FindStringSubmatch(claims.XMSMirID)
	if len(re) != 4 {
		return nil, errors.Errorf("error parsing xms_mirid claim: %s", claims.XMSMirID)
	}
	group, name := re[2], re[3]

	// Filter by resource group
	if len(p.ResourceGroups) > 0 {
		var found bool
		for _, g := range p.ResourceGroups {
			if g == group {
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("validation failed: invalid resource group")
		}
	}

	// Enforce default DNS if configured.
	// By default we'll accept the SANs in the CSR.
	// There's no way to trust them other than TOFU.
	var so []SignOption
	if p.DisableCustomSANs {
		// name will work only inside the virtual network
		so = append(so, dnsNamesValidator([]string{name}))
	}

	return append(so,
		commonNameValidator(name),
		profileDefaultDuration(p.claimer.DefaultTLSCertDuration()),
		newProvisionerExtensionOption(TypeAzure, p.Name, p.TenantID),
		newValidityValidator(p.claimer.MinTLSCertDuration(), p.claimer.MaxTLSCertDuration()),
	), nil
}

// AuthorizeRenewal returns an error if the renewal is disabled.
func (p *Azure) AuthorizeRenewal(cert *x509.Certificate) error {
	if p.claimer.IsDisableRenewal() {
		return errors.Errorf("renew is disabled for provisioner %s", p.GetID())
	}
	return nil
}

// AuthorizeRevoke returns an error because revoke is not supported on Azure
// provisioners.
func (p *Azure) AuthorizeRevoke(token string) error {
	return errors.New("revoke is not supported on a Azure provisioner")
}

// assertConfig initializes the config if it has not been initialized
func (p *Azure) assertConfig() {
	if p.config == nil {
		p.config = newAzureConfig(p.TenantID)
	}
}
