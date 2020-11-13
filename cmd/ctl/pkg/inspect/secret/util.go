package secret

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"

	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const validForTemplate = `Valid for:
	DNS Names: %s
	URIs: %s
	IP Addresses: %s
	Email Addresses: %s
	Usages: %s`

const validityPeriodTemplate = `Validity period:
	Not Before: %s
	Not After: %s`

const issuedByTemplate = `Issued By:
	Common Name		%s
	Organization		%s
	OrganizationalUnit	%s
	Country: 		%s`

const issuedForTemplate = `Issued By:
	Common Name		%s
	Organization		%s
	OrganizationalUnit	%s
	Country: 		%s`

// TODO: implement these
const template = `
Certificate:
	Signing Algorithm:
	Public Key Algorithm:
	Serial Number:
	Fingerprints:
	Is a CA certificate:

OCSP:
	

Debugging:
	Trusted by this computer: no
`

// DescribeCertificate retutring describing a PEM encoded X.509 certificate
func DescribeCertificate(certData []byte) (string, error) {
	x509Cert, err := pki.DecodeX509CertificateBytes(certData)
	if err != nil {
		return "", fmt.Errorf("error when parsing 'tls.crt': %w", err)
	}

	out := []string{
		describeValidFor(x509Cert),
		describeValidityPeriod(x509Cert),
		describeIssuedBy(x509Cert),
		describeIssuedFor(x509Cert),
	}

	return strings.Join(out, "\n\n"), nil
}

func describeValidFor(cert *x509.Certificate) string {
	return fmt.Sprintf(validForTemplate,
		printSlice(cert.DNSNames),
		printSlice(pki.URLsToString(cert.URIs)),
		printSlice(pki.IPAddressesToString(cert.IPAddresses)),
		printSlice(cert.EmailAddresses),
		printKeyUsage(pki.BuildCertManagerKeyUsages(cert.KeyUsage, cert.ExtKeyUsage)),
	)
}

func describeValidityPeriod(cert *x509.Certificate) string {
	return fmt.Sprintf(validityPeriodTemplate,
		cert.NotBefore.Format(time.RFC1123),
		cert.NotAfter.Format(time.RFC1123),
	)
}

func describeIssuedBy(cert *x509.Certificate) string {
	return fmt.Sprintf(issuedByTemplate,
		printOrNone(cert.Issuer.CommonName),
		printSliceOrOne(cert.Issuer.Organization),
		printSliceOrOne(cert.Issuer.OrganizationalUnit),
		printSliceOrOne(cert.Issuer.Country),
	)
}

func describeIssuedFor(cert *x509.Certificate) string {
	return fmt.Sprintf(issuedForTemplate,
		printOrNone(cert.Subject.CommonName),
		printSliceOrOne(cert.Subject.Organization),
		printSliceOrOne(cert.Subject.OrganizationalUnit),
		printSliceOrOne(cert.Subject.Country),
	)
}

func printSlice(in []string) string {
	if len(in) < 1 {
		return "<none>"
	}

	return "\n\t\t- " + strings.Trim(strings.Join(in, "\n\t\t- "), " ")
}

func printSliceOrOne(in []string) string {
	if len(in) < 1 {
		return "<none>"
	} else if len(in) == 1 {
		return in[0]
	}

	return "\n\t\t- " + strings.Trim(strings.Join(in, "\n\t\t- "), " ")
}

func printOrNone(in string) string {
	if in == "" {
		return "<none>"
	}

	return in
}

func printKeyUsage(in []cmapi.KeyUsage) string {
	if len(in) < 1 {
		return " <none>"
	}

	var usageStrings []string
	for _, usage := range in {
		usageStrings = append(usageStrings, string(usage))
	}

	return "\n\t\t- " + strings.Trim(strings.Join(usageStrings, "\n\t\t- "), " ")
}
