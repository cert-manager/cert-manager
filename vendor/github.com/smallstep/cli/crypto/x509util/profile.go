package x509util

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/crypto/pemutil"
	stepx509 "github.com/smallstep/cli/pkg/x509"
	"github.com/smallstep/cli/utils"
)

var (
	// DefaultCertValidity is the minimum validity of an end-entity (not root or intermediate) certificate.
	DefaultCertValidity = 24 * time.Hour

	// DefaultTLSMinVersion default minimum version of TLS.
	DefaultTLSMinVersion = TLSVersion(1.2)
	// DefaultTLSMaxVersion default maximum version of TLS.
	DefaultTLSMaxVersion = TLSVersion(1.2)
	// DefaultTLSRenegotiation default TLS connection renegotiation policy.
	DefaultTLSRenegotiation = false // Never regnegotiate.
	// DefaultTLSCipherSuites specifies default step ciphersuite(s).
	DefaultTLSCipherSuites = CipherSuites{
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	}
	// ApprovedTLSCipherSuites smallstep approved ciphersuites.
	ApprovedTLSCipherSuites = CipherSuites{
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
	}
)

// Profile is an interface that certificate profiles (e.g. leaf,
// intermediate, root) must implement.
type Profile interface {
	Issuer() *x509.Certificate
	Subject() *x509.Certificate
	SubjectPrivateKey() interface{}
	SubjectPublicKey() interface{}
	SetIssuer(*x509.Certificate)
	SetSubject(*x509.Certificate)
	SetSubjectPrivateKey(interface{})
	SetSubjectPublicKey(interface{})
	SetIssuerPrivateKey(interface{})
	CreateCertificate() ([]byte, error)
	GenerateKeyPair(string, string, int) error
	DefaultDuration() time.Duration
	CreateWriteCertificate(crtOut, keyOut, pass string) ([]byte, error)
}

type base struct {
	iss     *x509.Certificate
	sub     *x509.Certificate
	subPub  interface{}
	subPriv interface{}
	issPriv interface{}
}

// WithOption is a modifier function on base.
type WithOption func(Profile) error

// GenerateKeyPair returns a Profile modifier that generates a public/private
// key pair for a profile.
func GenerateKeyPair(kty, crv string, size int) WithOption {
	return func(p Profile) error {
		return p.GenerateKeyPair(kty, crv, size)
	}
}

// GenerateDefaultKeyPair generates a new public/private key pair using the
// default values and sets them in the given profile.
func GenerateDefaultKeyPair(p Profile) error {
	pub, priv, err := keys.GenerateDefaultKeyPair()
	if err != nil {
		return err
	}
	p.SetSubjectPublicKey(pub)
	p.SetSubjectPrivateKey(priv)
	return nil
}

// WithPublicKey returns a Profile modifier that sets the public key for a profile.
func WithPublicKey(pub interface{}) WithOption {
	return func(p Profile) error {
		p.SetSubjectPublicKey(pub)
		return nil
	}
}

// WithSubject returns a Profile modifier that sets the Subject for a x509
// Certificate.
func WithSubject(sub pkix.Name) WithOption {
	return func(p Profile) error {
		crt := p.Subject()
		crt.Subject = sub
		return nil
	}
}

// WithIssuer returns a Profile modifier that sets the Subject for a x509
// Certificate.
func WithIssuer(iss pkix.Name) WithOption {
	return func(p Profile) error {
		crt := p.Subject()
		crt.Issuer = iss
		return nil
	}
}

// WithNotBeforeAfterDuration returns a Profile modifier that sets the
// `NotBefore` and `NotAfter` attributes of the subject x509 Certificate.
func WithNotBeforeAfterDuration(nb, na time.Time, d time.Duration) WithOption {
	return func(p Profile) error {
		crt := p.Subject()

		now := time.Now()
		if nb.IsZero() {
			nb = now
		}
		if na.IsZero() {
			if d == 0 {
				na = nb.Add(p.DefaultDuration())
			} else {
				na = nb.Add(d)
			}
		}

		crt.NotBefore = nb
		crt.NotAfter = na
		return nil
	}
}

func appendIfMissingString(slice []string, s string) []string {
	for _, e := range slice {
		if e == s {
			return slice
		}
	}
	return append(slice, s)
}

func appendIfMissingIP(ips []net.IP, ip net.IP) []net.IP {
	for _, e := range ips {
		if ip.Equal(e) {
			return ips
		}
	}
	return append(ips, ip)
}

// WithDNSNames returns a Profile modifier which sets the DNS Names
// that will be bound to the subject alternative name extension of the Certificate.
func WithDNSNames(dns []string) WithOption {
	return func(p Profile) error {
		crt := p.Subject()
		crt.DNSNames = dns
		return nil
	}
}

// WithIPAddresses returns a Profile modifier which sets the IP Addresses
// that will be bound to the subject alternative name extension of the Certificate.
func WithIPAddresses(ips []net.IP) WithOption {
	return func(p Profile) error {
		crt := p.Subject()
		crt.IPAddresses = ips
		return nil
	}
}

// WithHosts returns a Profile modifier which sets the DNS Names and IP Addresses
// that will be bound to the subject Certificate.
//
// `hosts` should be a comma separated string of DNS Names and IP Addresses.
// e.g. `127.0.0.1,internal.smallstep.com,blog.smallstep.com,1.1.1.1`.
func WithHosts(hosts string) WithOption {
	return func(p Profile) error {
		hostsL := strings.Split(hosts, ",")
		crt := p.Subject()
		for _, h := range hostsL {
			if h == "" {
				continue
			} else if ip := net.ParseIP(h); ip != nil {
				crt.IPAddresses = appendIfMissingIP(crt.IPAddresses, ip)
			} else {
				crt.DNSNames = appendIfMissingString(crt.DNSNames, h)
			}
		}

		return nil
	}
}

// newProfile initializes the given profile.
//
// If the public/private key pair of the subject identity are not set by
// the optional modifiers then a pair will be generated using sane defaults.
func newProfile(p Profile, sub, iss *x509.Certificate, issPriv crypto.PrivateKey, withOps ...WithOption) (Profile, error) {
	if p == nil {
		return nil, errors.New("profile cannot be nil")
	}
	if sub == nil {
		return nil, errors.New("subject certificate cannot be nil")
	}
	if iss == nil {
		return nil, errors.New("issuing certificate cannot be nil")
	}

	p.SetSubject(sub)
	p.SetIssuer(iss)
	p.SetIssuerPrivateKey(issPriv)

	for _, op := range withOps {
		if err := op(p); err != nil {
			return nil, err
		}
	}

	if p.SubjectPublicKey() == nil {
		if err := GenerateDefaultKeyPair(p); err != nil {
			return nil, err
		}
	}

	if sub.SubjectKeyId == nil {
		pubBytes, err := stepx509.MarshalPKIXPublicKey(p.SubjectPublicKey())
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal public key to bytes")
		}
		hash := sha1.Sum(pubBytes)
		sub.SubjectKeyId = hash[:] // takes slice over the whole array
	}

	if sub.SerialNumber == nil {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		sn, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to generate serial number for "+
				"certificate with common name '%s'", sub.Subject.CommonName)
		}
		sub.SerialNumber = sn
	}

	return p, nil
}

func (b *base) Issuer() *x509.Certificate {
	return b.iss
}

func (b *base) Subject() *x509.Certificate {
	return b.sub
}

func (b *base) SubjectPrivateKey() interface{} {
	return b.subPriv
}

func (b *base) SubjectPublicKey() interface{} {
	return b.subPub
}

func (b *base) SetIssuer(iss *x509.Certificate) {
	b.iss = iss
}

func (b *base) SetSubject(sub *x509.Certificate) {
	b.sub = sub
}

func (b *base) SetSubjectPrivateKey(priv interface{}) {
	b.subPriv = priv
}

func (b *base) SetIssuerPrivateKey(priv interface{}) {
	b.issPriv = priv
}

func (b *base) SetSubjectPublicKey(pub interface{}) {
	b.subPub = pub
}

func (b *base) DefaultDuration() time.Duration {
	return DefaultCertValidity
}

func (b *base) GenerateKeyPair(kty, crv string, size int) error {
	pub, priv, err := keys.GenerateKeyPair(kty, crv, size)
	if err != nil {
		return err
	}
	b.SetSubjectPublicKey(pub)
	b.SetSubjectPrivateKey(priv)
	return nil
}

func (b *base) GenerateDefaultKeyPair() error {
	pub, priv, err := keys.GenerateDefaultKeyPair()
	if err != nil {
		return err
	}
	b.SetSubjectPublicKey(pub)
	b.SetSubjectPrivateKey(priv)
	return nil
}

// CreateCertificate creates an x509 Certificate using the configuration stored
// in the profile.
func (b *base) CreateCertificate() ([]byte, error) {
	if b.SubjectPublicKey() == nil {
		return nil, errors.Errorf("Profile does not have subject public key. Need to call 'profile.GenerateKeyPair(...)' or use setters to populate keys")
	}
	if b.issPriv == nil {
		return nil, errors.Errorf("Profile does not have issuer private key. Use setters to populate this field.")
	}

	sub := ToStepX509Certificate(b.Subject())
	iss := ToStepX509Certificate(b.Issuer())

	// Using stepx509 to be able to create certs with ed25519
	bytes, err := stepx509.CreateCertificate(rand.Reader, sub, iss, b.SubjectPublicKey(), b.issPriv)
	return bytes, errors.WithStack(err)
}

// Create Certificate from profile and write the certificate and private key
// to disk.
func (b *base) CreateWriteCertificate(crtOut, keyOut, pass string) ([]byte, error) {
	crtBytes, err := b.CreateCertificate()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if err := utils.WriteFile(crtOut, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crtBytes,
	}), 0600); err != nil {
		return nil, errors.WithStack(err)
	}

	_, err = pemutil.Serialize(b.SubjectPrivateKey(),
		pemutil.WithPassword([]byte(pass)), pemutil.ToFile(keyOut, 0600))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return crtBytes, nil
}
