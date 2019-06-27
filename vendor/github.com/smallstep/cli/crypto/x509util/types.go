package x509util

import (
	"crypto/tls"
	"fmt"

	"github.com/pkg/errors"
)

// ASN1DN contains ASN1.DN attributes that are used in Subject and Issuer
// x509 Certificate blocks.
type ASN1DN struct {
	Country            string `json:"country,omitempty" step:"country"`
	Organization       string `json:"organization,omitempty" step:"organization"`
	OrganizationalUnit string `json:"organizationalUnit,omitempty" step:"organizationalUnit"`
	Locality           string `json:"locality,omitempty" step:"locality"`
	Province           string `json:"province,omitempty" step:"province"`
	StreetAddress      string `json:"streetAddress,omitempty" step:"streetAddress"`
	CommonName         string `json:"commonName,omitempty" step:"commonName"`
}

// TLSVersion represents a TLS version number.
type TLSVersion float64

// Validate implements models.Validator and checks that a cipher suite is
// valid.
func (v TLSVersion) Validate() error {
	if _, ok := tlsVersions[v]; ok {
		return nil
	}
	return errors.Errorf("%f is not a valid tls version", v)
}

// Value returns the Go constant for the TLSVersion.
func (v TLSVersion) Value() uint16 {
	return tlsVersions[v]
}

// String returns the Go constant for the TLSVersion.
func (v TLSVersion) String() string {
	k := v.Value()
	switch k {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	default:
		return fmt.Sprintf("unexpected value: %d", k)
	}
}

// tlsVersions has the list of supported tls version.
var tlsVersions = map[TLSVersion]uint16{
	// Defaults to TLS 1.2
	0: tls.VersionTLS12,
	// Options
	1.0: tls.VersionTLS10,
	1.1: tls.VersionTLS11,
	1.2: tls.VersionTLS12,
}

// CipherSuites represents an array of string codes representing the cipher
// suites.
type CipherSuites []string

// Validate implements models.Validator and checks that a cipher suite is
// valid.
func (c CipherSuites) Validate() error {
	for _, s := range c {
		if _, ok := cipherSuites[s]; !ok {
			return errors.Errorf("%s is not a valid cipher suite", s)
		}
	}
	return nil
}

// Value returns an []uint16 for the cipher suites.
func (c CipherSuites) Value() []uint16 {
	values := make([]uint16, len(c))
	for i, s := range c {
		values[i] = cipherSuites[s]
	}
	return values
}

// cipherSuites has the list of supported cipher suites.
var cipherSuites = map[string]uint16{
	"TLS_RSA_WITH_RC4_128_SHA":                tls.TLS_RSA_WITH_RC4_128_SHA,
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":           tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"TLS_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"TLS_RSA_WITH_AES_128_CBC_SHA256":         tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	"TLS_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":        tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":     tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
}
