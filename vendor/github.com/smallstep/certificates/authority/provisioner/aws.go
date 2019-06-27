package provisioner

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/jose"
)

// awsIssuer is the string used as issuer in the generated tokens.
const awsIssuer = "ec2.amazonaws.com"

// awsIdentityURL is the url used to retrieve the instance identity document.
const awsIdentityURL = "http://169.254.169.254/latest/dynamic/instance-identity/document"

// awsSignatureURL is the url used to retrieve the instance identity signature.
const awsSignatureURL = "http://169.254.169.254/latest/dynamic/instance-identity/signature"

// awsCertificate is the certificate used to validate the instance identity
// signature.
const awsCertificate = `-----BEGIN CERTIFICATE-----
MIIDIjCCAougAwIBAgIJAKnL4UEDMN/FMA0GCSqGSIb3DQEBBQUAMGoxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdTZWF0dGxlMRgw
FgYDVQQKEw9BbWF6b24uY29tIEluYy4xGjAYBgNVBAMTEWVjMi5hbWF6b25hd3Mu
Y29tMB4XDTE0MDYwNTE0MjgwMloXDTI0MDYwNTE0MjgwMlowajELMAkGA1UEBhMC
VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1NlYXR0bGUxGDAWBgNV
BAoTD0FtYXpvbi5jb20gSW5jLjEaMBgGA1UEAxMRZWMyLmFtYXpvbmF3cy5jb20w
gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAIe9GN//SRK2knbjySG0ho3yqQM3
e2TDhWO8D2e8+XZqck754gFSo99AbT2RmXClambI7xsYHZFapbELC4H91ycihvrD
jbST1ZjkLQgga0NE1q43eS68ZeTDccScXQSNivSlzJZS8HJZjgqzBlXjZftjtdJL
XeE4hwvo0sD4f3j9AgMBAAGjgc8wgcwwHQYDVR0OBBYEFCXWzAgVyrbwnFncFFIs
77VBdlE4MIGcBgNVHSMEgZQwgZGAFCXWzAgVyrbwnFncFFIs77VBdlE4oW6kbDBq
MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHU2Vh
dHRsZTEYMBYGA1UEChMPQW1hem9uLmNvbSBJbmMuMRowGAYDVQQDExFlYzIuYW1h
em9uYXdzLmNvbYIJAKnL4UEDMN/FMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEF
BQADgYEAFYcz1OgEhQBXIwIdsgCOS8vEtiJYF+j9uO6jz7VOmJqO+pRlAbRlvY8T
C1haGgSI/A1uZUKs/Zfnph0oEI0/hu1IIJ/SKBDtN5lvmZ/IzbOPIJWirlsllQIQ
7zvWbGd9c9+Rm3p04oTvhup99la7kZqevJK0QRdD/6NpCKsqP/0=
-----END CERTIFICATE-----`

// awsSignatureAlgorithm is the signature algorithm used to verify the identity
// document signature.
const awsSignatureAlgorithm = x509.SHA256WithRSA

type awsConfig struct {
	identityURL        string
	signatureURL       string
	certificate        *x509.Certificate
	signatureAlgorithm x509.SignatureAlgorithm
}

func newAWSConfig() (*awsConfig, error) {
	block, _ := pem.Decode([]byte(awsCertificate))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("error decoding AWS certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing AWS certificate")
	}
	return &awsConfig{
		identityURL:        awsIdentityURL,
		signatureURL:       awsSignatureURL,
		certificate:        cert,
		signatureAlgorithm: awsSignatureAlgorithm,
	}, nil
}

type awsPayload struct {
	jose.Claims
	Amazon   awsAmazonPayload `json:"amazon"`
	SANs     []string         `json:"sans"`
	document awsInstanceIdentityDocument
}

type awsAmazonPayload struct {
	Document  []byte `json:"document"`
	Signature []byte `json:"signature"`
}

type awsInstanceIdentityDocument struct {
	AccountID          string    `json:"accountId"`
	Architecture       string    `json:"architecture"`
	AvailabilityZone   string    `json:"availabilityZone"`
	BillingProducts    []string  `json:"billingProducts"`
	DevpayProductCodes []string  `json:"devpayProductCodes"`
	ImageID            string    `json:"imageId"`
	InstanceID         string    `json:"instanceId"`
	InstanceType       string    `json:"instanceType"`
	KernelID           string    `json:"kernelId"`
	PendingTime        time.Time `json:"pendingTime"`
	PrivateIP          string    `json:"privateIp"`
	RamdiskID          string    `json:"ramdiskId"`
	Region             string    `json:"region"`
	Version            string    `json:"version"`
}

// AWS is the provisioner that supports identity tokens created from the Amazon
// Web Services Instance Identity Documents.
//
// If DisableCustomSANs is true, only the internal DNS and IP will be added as a
// SAN. By default it will accept any SAN in the CSR.
//
// If DisableTrustOnFirstUse is true, multiple sign request for this provisioner
// with the same instance will be accepted. By default only the first request
// will be accepted.
//
// If InstanceAge is set, only the instances with a pendingTime within the given
// period will be accepted.
//
// Amazon Identity docs are available at
// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html
type AWS struct {
	Type                   string   `json:"type"`
	Name                   string   `json:"name"`
	Accounts               []string `json:"accounts"`
	DisableCustomSANs      bool     `json:"disableCustomSANs"`
	DisableTrustOnFirstUse bool     `json:"disableTrustOnFirstUse"`
	InstanceAge            Duration `json:"instanceAge,omitempty"`
	Claims                 *Claims  `json:"claims,omitempty"`
	claimer                *Claimer
	config                 *awsConfig
	audiences              Audiences
}

// GetID returns the provisioner unique identifier.
func (p *AWS) GetID() string {
	return "aws/" + p.Name
}

// GetTokenID returns the identifier of the token.
func (p *AWS) GetTokenID(token string) (string, error) {
	payload, err := p.authorizeToken(token)
	if err != nil {
		return "", err
	}
	// If TOFU is disabled create an ID for the token, so it cannot be reused.
	// The timestamps, document and signatures should be mostly unique.
	if p.DisableTrustOnFirstUse {
		sum := sha256.Sum256([]byte(token))
		return strings.ToLower(hex.EncodeToString(sum[:])), nil
	}
	return payload.ID, nil
}

// GetName returns the name of the provisioner.
func (p *AWS) GetName() string {
	return p.Name
}

// GetType returns the type of provisioner.
func (p *AWS) GetType() Type {
	return TypeAWS
}

// GetEncryptedKey is not available in an AWS provisioner.
func (p *AWS) GetEncryptedKey() (kid string, key string, ok bool) {
	return "", "", false
}

// GetIdentityToken retrieves the identity document and it's signature and
// generates a token with them.
func (p *AWS) GetIdentityToken(caURL string) (string, error) {
	// Initialize the config if this method is used from the cli.
	if err := p.assertConfig(); err != nil {
		return "", err
	}

	var idoc awsInstanceIdentityDocument
	doc, err := p.readURL(p.config.identityURL)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving identity document, are you in an AWS VM?")
	}
	if err := json.Unmarshal(doc, &idoc); err != nil {
		return "", errors.Wrap(err, "error unmarshaling identity document")
	}
	sig, err := p.readURL(p.config.signatureURL)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving identity document signature, are you in an AWS VM?")
	}
	signature, err := base64.StdEncoding.DecodeString(string(sig))
	if err != nil {
		return "", errors.Wrap(err, "error decoding identity document signature")
	}
	if err := p.checkSignature(doc, signature); err != nil {
		return "", err
	}

	audience, err := generateSignAudience(caURL, p.GetID())
	if err != nil {
		return "", err
	}

	// Create unique ID for Trust On First Use (TOFU). Only the first instance
	// per provisioner is allowed as we don't have a way to trust the given
	// sans.
	unique := fmt.Sprintf("%s.%s", p.GetID(), idoc.InstanceID)
	sum := sha256.Sum256([]byte(unique))

	// Create a JWT from the identity document
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: signature},
		new(jose.SignerOptions).WithType("JWT"),
	)
	if err != nil {
		return "", errors.Wrap(err, "error creating signer")
	}

	now := time.Now()
	payload := awsPayload{
		Claims: jose.Claims{
			Issuer:    awsIssuer,
			Subject:   idoc.InstanceID,
			Audience:  []string{audience},
			Expiry:    jose.NewNumericDate(now.Add(5 * time.Minute)),
			NotBefore: jose.NewNumericDate(now),
			IssuedAt:  jose.NewNumericDate(now),
			ID:        strings.ToLower(hex.EncodeToString(sum[:])),
		},
		Amazon: awsAmazonPayload{
			Document:  doc,
			Signature: signature,
		},
	}

	tok, err := jose.Signed(signer).Claims(payload).CompactSerialize()
	if err != nil {
		return "", errors.Wrap(err, "error serialiazing token")
	}

	return tok, nil
}

// Init validates and initializes the AWS provisioner.
func (p *AWS) Init(config Config) (err error) {
	switch {
	case p.Type == "":
		return errors.New("provisioner type cannot be empty")
	case p.Name == "":
		return errors.New("provisioner name cannot be empty")
	case p.InstanceAge.Value() < 0:
		return errors.New("provisioner instanceAge cannot be negative")
	}
	// Update claims with global ones
	if p.claimer, err = NewClaimer(p.Claims, config.Claims); err != nil {
		return err
	}
	// Add default config
	if p.config, err = newAWSConfig(); err != nil {
		return err
	}
	p.audiences = config.Audiences.WithFragment(p.GetID())
	return nil
}

// AuthorizeSign validates the given token and returns the sign options that
// will be used on certificate creation.
func (p *AWS) AuthorizeSign(token string) ([]SignOption, error) {
	payload, err := p.authorizeToken(token)
	if err != nil {
		return nil, err
	}
	doc := payload.document

	// Enforce default DNS and IP if configured.
	// By default we'll accept the SANs in the CSR.
	// There's no way to trust them other than TOFU.
	var so []SignOption
	if p.DisableCustomSANs {
		so = append(so, dnsNamesValidator([]string{
			fmt.Sprintf("ip-%s.%s.compute.internal", strings.Replace(doc.PrivateIP, ".", "-", -1), doc.Region),
		}))
		so = append(so, ipAddressesValidator([]net.IP{
			net.ParseIP(doc.PrivateIP),
		}))
	}

	return append(so,
		commonNameValidator(doc.InstanceID),
		profileDefaultDuration(p.claimer.DefaultTLSCertDuration()),
		newProvisionerExtensionOption(TypeAWS, p.Name, doc.AccountID),
		newValidityValidator(p.claimer.MinTLSCertDuration(), p.claimer.MaxTLSCertDuration()),
	), nil
}

// AuthorizeRenewal returns an error if the renewal is disabled.
func (p *AWS) AuthorizeRenewal(cert *x509.Certificate) error {
	if p.claimer.IsDisableRenewal() {
		return errors.Errorf("renew is disabled for provisioner %s", p.GetID())
	}
	return nil
}

// AuthorizeRevoke returns an error because revoke is not supported on AWS
// provisioners.
func (p *AWS) AuthorizeRevoke(token string) error {
	return errors.New("revoke is not supported on a AWS provisioner")
}

// assertConfig initializes the config if it has not been initialized
func (p *AWS) assertConfig() (err error) {
	if p.config != nil {
		return
	}
	p.config, err = newAWSConfig()
	return err
}

// checkSignature returns an error if the signature is not valid.
func (p *AWS) checkSignature(signed, signature []byte) error {
	if err := p.config.certificate.CheckSignature(p.config.signatureAlgorithm, signed, signature); err != nil {
		return errors.Wrap(err, "error validating identity document signature")
	}
	return nil
}

// readURL does a GET request to the given url and returns the body. It's not
// using pkg/errors to avoid verbose errors, the caller should use it and write
// the appropriate error.
func (p *AWS) readURL(url string) ([]byte, error) {
	r, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// authorizeToken performs common jwt authorization actions and returns the
// claims for case specific downstream parsing.
// e.g. a Sign request will auth/validate different fields than a Revoke request.
func (p *AWS) authorizeToken(token string) (*awsPayload, error) {
	jwt, err := jose.ParseSigned(token)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing token")
	}
	if len(jwt.Headers) == 0 {
		return nil, errors.New("error parsing token: header is missing")
	}

	var unsafeClaims awsPayload
	if err := jwt.UnsafeClaimsWithoutVerification(&unsafeClaims); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling claims")
	}

	var payload awsPayload
	if err := jwt.Claims(unsafeClaims.Amazon.Signature, &payload); err != nil {
		return nil, errors.Wrap(err, "error verifying claims")
	}

	// Validate identity document signature
	if err := p.checkSignature(payload.Amazon.Document, payload.Amazon.Signature); err != nil {
		return nil, err
	}

	var doc awsInstanceIdentityDocument
	if err := json.Unmarshal(payload.Amazon.Document, &doc); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling identity document")
	}

	switch {
	case doc.AccountID == "":
		return nil, errors.New("identity document accountId cannot be empty")
	case doc.InstanceID == "":
		return nil, errors.New("identity document instanceId cannot be empty")
	case doc.PrivateIP == "":
		return nil, errors.New("identity document privateIp cannot be empty")
	case doc.Region == "":
		return nil, errors.New("identity document region cannot be empty")
	}

	// According to "rfc7519 JSON Web Token" acceptable skew should be no
	// more than a few minutes.
	now := time.Now().UTC()
	if err = payload.ValidateWithLeeway(jose.Expected{
		Issuer:  awsIssuer,
		Subject: doc.InstanceID,
		Time:    now,
	}, time.Minute); err != nil {
		return nil, errors.Wrapf(err, "invalid token")
	}

	// validate audiences with the defaults
	if !matchesAudience(payload.Audience, p.audiences.Sign) {
		fmt.Println(payload.Audience, "vs", p.audiences.Sign)
		return nil, errors.New("invalid token: invalid audience claim (aud)")
	}

	// validate accounts
	if len(p.Accounts) > 0 {
		var found bool
		for _, sa := range p.Accounts {
			if sa == doc.AccountID {
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("invalid identity document: accountId is not valid")
		}
	}

	// validate instance age
	if d := p.InstanceAge.Value(); d > 0 {
		if now.Sub(doc.PendingTime) > d {
			return nil, errors.New("identity document pendingTime is too old")
		}
	}

	payload.document = doc
	return &payload, nil
}
