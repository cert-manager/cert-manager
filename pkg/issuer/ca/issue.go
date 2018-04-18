package ca

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	errorGetCertKeyPair = "ErrGetCertKeyPair"
	errorIssueCert      = "ErrIssueCert"

	successCertIssued = "CertIssueSuccess"

	messageErrorGetCertKeyPair = "Error getting keypair for certificate: "
	messageErrorIssueCert      = "Error issuing TLS certificate: "

	messageCertIssued = "Certificate issued successfully"
)

const (
	// certificateDuration of 1 year
	certificateDuration = time.Hour * 24 * 365
	defaultOrganization = "cert-manager"
)

func (c *CA) Issue(ctx context.Context, crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	signeeKey, err := kube.SecretTLSKey(c.secretsLister, crt.Namespace, crt.Spec.SecretName)

	if k8sErrors.IsNotFound(err) || errors.IsInvalidData(err) {
		signeeKey, err = pki.GenerateRSAPrivateKey(2048)
	}

	if err != nil {
		s := messageErrorGetCertKeyPair + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorGetCertKeyPair, s, false)
		return nil, nil, err
	}

	certPem, err := c.obtainCertificate(crt, &signeeKey.PublicKey)

	if err != nil {
		s := messageErrorIssueCert + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorIssueCert, s, false)
		return nil, nil, err
	}

	crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionTrue, successCertIssued, messageCertIssued, true)

	return pki.EncodePKCS1PrivateKey(signeeKey), certPem, nil
}

func (c *CA) obtainCertificate(crt *v1alpha1.Certificate, signeeKey interface{}) ([]byte, error) {
	commonName := crt.Spec.CommonName
	altNames := crt.Spec.DNSNames
	if len(commonName) == 0 && len(altNames) == 0 {
		return nil, fmt.Errorf("no domains specified on certificate")
	}

	signerCert, err := kube.SecretTLSCert(c.secretsLister, c.issuerResourcesNamespace, c.issuer.GetSpec().CA.SecretName)
	if err != nil {
		return nil, fmt.Errorf("error getting issuer certificate: %s", err.Error())
	}

	signerKey, err := kube.SecretTLSKey(c.secretsLister, c.issuerResourcesNamespace, c.issuer.GetSpec().CA.SecretName)
	if err != nil {
		return nil, fmt.Errorf("error getting issuer private key: %s", err.Error())
	}

	crtPem, _, err := signCertificate(crt, signerCert, signeeKey, signerKey)
	if err != nil {
		return nil, err
	}

	return crtPem, nil
}

func createCertificateTemplate(publicKey interface{}, commonName string, altNames ...string) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err.Error())
	}
	if len(commonName) == 0 && len(altNames) > 0 {
		commonName = altNames[0]
	}
	cert := &x509.Certificate{
		Version:               3,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		PublicKey:             publicKey,
		Subject: pkix.Name{
			Organization: []string{defaultOrganization},
			CommonName:   commonName,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(certificateDuration),
		// see http://golang.org/pkg/crypto/x509/#KeyUsage
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames: altNames,
	}
	return cert, nil
}

// signCertificate returns a signed x509.Certificate object for the given
// *v1alpha1.Certificate crt.
// publicKey is the public key of the signee, and signerKey is the private
// key of the signer.
func signCertificate(crt *v1alpha1.Certificate, issuerCert *x509.Certificate, publicKey interface{}, signerKey interface{}) ([]byte, *x509.Certificate, error) {
	cn := pki.CommonNameForCertificate(crt)
	dnsNames := pki.DNSNamesForCertificate(crt)

	template, err := createCertificateTemplate(publicKey, cn, dnsNames...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating x509 certificate template: %s", err.Error())
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, issuerCert, publicKey, signerKey)

	if err != nil {
		return nil, nil, fmt.Errorf("error creating x509 certificate: %s", err.Error())
	}

	cert, err := pki.DecodeDERCertificateBytes(derBytes)

	if err != nil {
		return nil, nil, fmt.Errorf("error decoding DER certificate bytes: %s", err.Error())
	}

	pemBytes := bytes.NewBuffer([]byte{})
	err = pem.Encode(pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		return nil, nil, fmt.Errorf("error encoding certificate PEM: %s", err.Error())
	}

	// bundle the CA
	err = pem.Encode(pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: issuerCert.Raw})
	if err != nil {
		return nil, nil, fmt.Errorf("error encoding issuer cetificate PEM: %s", err.Error())
	}

	return pemBytes.Bytes(), cert, err
}
