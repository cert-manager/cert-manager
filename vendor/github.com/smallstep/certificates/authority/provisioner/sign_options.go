package provisioner

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"reflect"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/x509util"
)

// Options contains the options that can be passed to the Sign method.
type Options struct {
	NotAfter  TimeDuration `json:"notAfter"`
	NotBefore TimeDuration `json:"notBefore"`
}

// SignOption is the interface used to collect all extra options used in the
// Sign method.
type SignOption interface{}

// CertificateValidator is the interface used to validate a X.509 certificate.
type CertificateValidator interface {
	SignOption
	Valid(crt *x509.Certificate) error
}

// CertificateRequestValidator is the interface used to validate a X.509
// certificate request.
type CertificateRequestValidator interface {
	SignOption
	Valid(req *x509.CertificateRequest) error
}

// ProfileModifier is the interface used to add custom options to the profile
// constructor. The options are used to modify the final certificate.
type ProfileModifier interface {
	SignOption
	Option(o Options) x509util.WithOption
}

// profileWithOption is a wrapper against x509util.WithOption to conform the
// interface.
type profileWithOption x509util.WithOption

func (v profileWithOption) Option(Options) x509util.WithOption {
	return x509util.WithOption(v)
}

// profileDefaultDuration is a wrapper against x509util.WithOption to conform the
// interface.
type profileDefaultDuration time.Duration

func (v profileDefaultDuration) Option(so Options) x509util.WithOption {
	return x509util.WithNotBeforeAfterDuration(so.NotBefore.Time(), so.NotAfter.Time(), time.Duration(v))
}

// emailOnlyIdentity is a CertificateRequestValidator that checks that the only
// SAN provided is the given email address.
type emailOnlyIdentity string

func (e emailOnlyIdentity) Valid(req *x509.CertificateRequest) error {
	switch {
	case len(req.DNSNames) > 0:
		return errors.New("certificate request cannot contain DNS names")
	case len(req.IPAddresses) > 0:
		return errors.New("certificate request cannot contain IP addresses")
	case len(req.URIs) > 0:
		return errors.New("certificate request cannot contain URIs")
	case len(req.EmailAddresses) == 0:
		return errors.New("certificate request does not contain any email address")
	case len(req.EmailAddresses) > 1:
		return errors.New("certificate request does not contain too many email addresses")
	case req.EmailAddresses[0] == "":
		return errors.New("certificate request cannot contain an empty email address")
	case req.EmailAddresses[0] != string(e):
		return errors.Errorf("certificate request does not contain the valid email address, got %s, want %s", req.EmailAddresses[0], e)
	default:
		return nil
	}
}

// commonNameValidator validates the common name of a certificate request.
type commonNameValidator string

// Valid checks that certificate request common name matches the one configured.
func (v commonNameValidator) Valid(req *x509.CertificateRequest) error {
	if req.Subject.CommonName == "" {
		return errors.New("certificate request cannot contain an empty common name")
	}
	if req.Subject.CommonName != string(v) {
		return errors.Errorf("certificate request does not contain the valid common name, got %s, want %s", req.Subject.CommonName, v)
	}
	return nil
}

// dnsNamesValidator validates the DNS names SAN of a certificate request.
type dnsNamesValidator []string

// Valid checks that certificate request DNS Names match those configured in
// the bootstrap (token) flow.
func (v dnsNamesValidator) Valid(req *x509.CertificateRequest) error {
	want := make(map[string]bool)
	for _, s := range v {
		want[s] = true
	}
	got := make(map[string]bool)
	for _, s := range req.DNSNames {
		got[s] = true
	}
	if !reflect.DeepEqual(want, got) {
		return errors.Errorf("certificate request does not contain the valid DNS names - got %v, want %v", req.DNSNames, v)
	}
	return nil
}

// ipAddressesValidator validates the IP addresses SAN of a certificate request.
type ipAddressesValidator []net.IP

// Valid checks that certificate request IP Addresses match those configured in
// the bootstrap (token) flow.
func (v ipAddressesValidator) Valid(req *x509.CertificateRequest) error {
	want := make(map[string]bool)
	for _, ip := range v {
		want[ip.String()] = true
	}
	got := make(map[string]bool)
	for _, ip := range req.IPAddresses {
		got[ip.String()] = true
	}
	if !reflect.DeepEqual(want, got) {
		return errors.Errorf("IP Addresses claim failed - got %v, want %v", req.IPAddresses, v)
	}
	return nil
}

// validityValidator validates the certificate temporal validity settings.
type validityValidator struct {
	min time.Duration
	max time.Duration
}

// newValidityValidator return a new validity validator.
func newValidityValidator(min, max time.Duration) *validityValidator {
	return &validityValidator{min: min, max: max}
}

// Validate validates the certificate temporal validity settings.
func (v *validityValidator) Valid(crt *x509.Certificate) error {
	var (
		na  = crt.NotAfter
		nb  = crt.NotBefore
		d   = na.Sub(nb)
		now = time.Now()
	)

	if na.Before(now) {
		return errors.Errorf("NotAfter: %v cannot be in the past", na)
	}
	if na.Before(nb) {
		return errors.Errorf("NotAfter: %v cannot be before NotBefore: %v", na, nb)
	}
	if d < v.min {
		return errors.Errorf("requested duration of %v is less than the authorized minimum certificate duration of %v",
			d, v.min)
	}
	if d > v.max {
		return errors.Errorf("requested duration of %v is more than the authorized maximum certificate duration of %v",
			d, v.max)
	}
	return nil
}

var (
	stepOIDRoot        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64}
	stepOIDProvisioner = append(asn1.ObjectIdentifier(nil), append(stepOIDRoot, 1)...)
)

type stepProvisionerASN1 struct {
	Type         int
	Name         []byte
	CredentialID []byte
}

type provisionerExtensionOption struct {
	Type         int
	Name         string
	CredentialID string
}

func newProvisionerExtensionOption(typ Type, name, credentialID string) *provisionerExtensionOption {
	return &provisionerExtensionOption{
		Type:         int(typ),
		Name:         name,
		CredentialID: credentialID,
	}
}

func (o *provisionerExtensionOption) Option(Options) x509util.WithOption {
	return func(p x509util.Profile) error {
		crt := p.Subject()
		ext, err := createProvisionerExtension(o.Type, o.Name, o.CredentialID)
		if err != nil {
			return err
		}
		crt.ExtraExtensions = append(crt.ExtraExtensions, ext)
		return nil
	}
}

func createProvisionerExtension(typ int, name, credentialID string) (pkix.Extension, error) {
	b, err := asn1.Marshal(stepProvisionerASN1{
		Type:         typ,
		Name:         []byte(name),
		CredentialID: []byte(credentialID),
	})
	if err != nil {
		return pkix.Extension{}, errors.Wrapf(err, "error marshaling provisioner extension")
	}
	return pkix.Extension{
		Id:       stepOIDProvisioner,
		Critical: false,
		Value:    b,
	}, nil
}

func init() {
	// Avoid dead-code warning in profileWithOption
	_ = profileWithOption(nil)
}
