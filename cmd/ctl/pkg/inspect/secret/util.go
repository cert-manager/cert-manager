package secret

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"

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

const issuedForTemplate = `Issued For:
	Common Name		%s
	Organization		%s
	OrganizationalUnit	%s
	Country: 		%s`

const certificateTemplate = `Certificate:
	Signing Algorithm:	%s
	Public Key Algorithm: 	%s
	Serial Number:	%s
	Fingerprints: 	%s
	Is a CA certificate: %v
	CRL:	%s
	OCSP:	%s`

const debuggingTemplate = `Debugging:
	Trusted by this computer:	%s
	CRL Status:	%s
	OCSP Status:	%s`

// DescribeCertificate retutring describing a PEM encoded X.509 certificate
func DescribeCertificate(certData []byte, ca []byte) (string, error) {

	certs := [][]byte(nil)
	for {
		block, rest := pem.Decode(certData)
		if block == nil {
			break // got no more certs to decode
		}
		// ignore private key data
		if block.Type == "CERTIFICATE" {
			buf := bytes.NewBuffer(nil)
			err := pem.Encode(buf, block)
			if err != nil {
				return "", fmt.Errorf("error when reencoding PEM: %s", err)
			}
			certs = append(certs, buf.Bytes())

		}
		certData = rest
	}

	if len(certs) < 1 {
		return "", errors.New("no PEM data found in secret")
	}

	// we only want to inspect the leaf
	x509Cert, err := pki.DecodeX509CertificateBytes(certs[0])
	if err != nil {
		return "", fmt.Errorf("error when parsing 'tls.crt': %w", err)
	}

	intermediates := [][]byte(nil)
	if len(certs) > 1 {
		intermediates = certs[1:]
	}

	out := []string{
		describeValidFor(x509Cert),
		describeValidityPeriod(x509Cert),
		describeIssuedBy(x509Cert),
		describeIssuedFor(x509Cert),
		describeCertificate(x509Cert),
		describeDebugging(x509Cert, intermediates, ca),
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

func describeCertificate(cert *x509.Certificate) string {
	return fmt.Sprintf(certificateTemplate,
		cert.SignatureAlgorithm.String(),
		cert.PublicKeyAlgorithm.String(),
		cert.SerialNumber.String(),
		fingerprint(cert),
		cert.IsCA,
		printSliceOrOne(cert.CRLDistributionPoints),
		printSliceOrOne(cert.OCSPServer),
	)
}

func describeDebugging(cert *x509.Certificate, intermediates [][]byte, ca []byte) string {
	return fmt.Sprintf(debuggingTemplate,
		describeTrusted(cert, intermediates),
		describeCRL(cert),
		describeOCSP(cert, intermediates, ca),
	)
}

func describeCRL(cert *x509.Certificate) string {
	if len(cert.CRLDistributionPoints) < 1 {
		return "No CRL endpoints set"
	}

	hasChecked := false
	for _, crlURL := range cert.CRLDistributionPoints {
		u, err := url.Parse(crlURL)
		if err != nil {
			continue // not a valid URL
		}
		if u.Scheme != "ldap" && u.Scheme != "https" {
			continue
		}

		valid, err := checkCRLValidCert(cert, crlURL)
		if err != nil {
			return fmt.Sprintf("Cannot check CRL: %s", err.Error())
		}
		if !valid {
			return fmt.Sprintf("Revoked by %s", crlURL)
		}
	}

	if !hasChecked {
		return "No CRL endpoints we support found"
	}

	return "Valid"
}

func describeOCSP(cert *x509.Certificate, intermediates [][]byte, ca []byte) string {
	if len(ca) > 1 {
		intermediates = append([][]byte{ca}, intermediates...)
	}
	if len(intermediates) < 1 {
		return "Cannot check OCSP, does not have a CA or intermediate certificate provided"
	}
	issuerCert, err := pki.DecodeX509CertificateBytes(intermediates[len(intermediates)-1])
	if err != nil {
		return fmt.Sprintf("Cannot parse intermediate certificate: %s", err.Error())
	}

	valid, err := checkOCSPValidCert(cert, issuerCert)
	if err != nil {
		return fmt.Sprintf("Cannot check OCSP: %s", err.Error())
	}

	if !valid {
		return "Marked as revoked"
	}

	return "valid"
}

func describeTrusted(cert *x509.Certificate, intermediates [][]byte) string {
	systemPool, err := x509.SystemCertPool()
	for _, intermediate := range intermediates {
		systemPool.AppendCertsFromPEM(intermediate)
	}
	if err != nil {
		return fmt.Sprintf("error loading system CA trusts: %s", err.Error())
	}
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:       systemPool,
		CurrentTime: time.Now(),
	})
	if err == nil {
		return "yes"
	}
	return fmt.Sprintf("no: %s", err.Error())
}

func fingerprint(cert *x509.Certificate) string {
	fingerprint := sha256.Sum256(cert.Raw)

	var buf bytes.Buffer
	for i, f := range fingerprint {
		if i > 0 {
			fmt.Fprintf(&buf, ":")
		}
		fmt.Fprintf(&buf, "%02X", f)
	}

	return buf.String()
}

func checkOCSPValidCert(leafCert, issuerCert *x509.Certificate) (bool, error) {
	if len(leafCert.OCSPServer) < 1 {
		return false, errors.New("No OCSP Server set")
	}
	buffer, err := ocsp.CreateRequest(leafCert, issuerCert, &ocsp.RequestOptions{Hash: crypto.SHA1})
	if err != nil {
		return false, fmt.Errorf("error creating OCSP request: %w", err)
	}

	for _, ocspServer := range leafCert.OCSPServer {
		httpRequest, err := http.NewRequest(http.MethodPost, ocspServer, bytes.NewBuffer(buffer))
		if err != nil {
			return false, fmt.Errorf("error creating HTTP request: %w", err)
		}
		ocspUrl, err := url.Parse(ocspServer)
		if err != nil {
			return false, fmt.Errorf("error parsing OCSP URL: %w", err)
		}
		httpRequest.Header.Add("Content-Type", "application/ocsp-request")
		httpRequest.Header.Add("Accept", "application/ocsp-response")
		httpRequest.Header.Add("Host", ocspUrl.Host)
		httpClient := &http.Client{}
		httpResponse, err := httpClient.Do(httpRequest)
		if err != nil {
			return false, fmt.Errorf("error making HTTP request: %w", err)
		}
		defer httpResponse.Body.Close()
		output, err := ioutil.ReadAll(httpResponse.Body)
		if err != nil {
			return false, fmt.Errorf("error reading HTTP body: %w", err)
		}
		ocspResponse, err := ocsp.ParseResponse(output, issuerCert)
		if err != nil {
			return false, fmt.Errorf("error reading OCSP response: %w", err)
		}

		if ocspResponse.Status == ocsp.Revoked {
			// one OCSP revoked it do not trust
			return false, nil
		}
	}

	return true, nil
}

func checkCRLValidCert(cert *x509.Certificate, url string) (bool, error) {
	resp, err := http.Get(url)
	if err != nil {
		return false, fmt.Errorf("error getting HTTP response: %w", err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("error reading HTTP body: %w", err)
	}
	resp.Body.Close()

	crl, err := x509.ParseCRL(body)
	if err != nil {
		return false, fmt.Errorf("error parsing HTTP body: %w", err)
	}

	// TODO: check CRL signature

	for _, revoked := range crl.TBSCertList.RevokedCertificates {
		if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
			return false, nil
		}
	}

	return true, nil
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
