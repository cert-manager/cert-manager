package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/acme"
	api "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack-experimental/cert-manager/pkg/log"
)

func (a *Acme) getCertificatePrivateKey(crt *v1alpha1.Certificate) ([]byte, crypto.Signer, error) {
	crtSecret, err := a.factory.Core().V1().Secrets().Lister().Secrets(crt.Namespace).Get(crt.Spec.SecretName)
	if err != nil {
		if !k8sErrors.IsNotFound(err) {
			return nil, nil, fmt.Errorf("error reading certificate private key for certificate '%s': %s", crt.Name, err.Error())
		}
		return generatePrivateKey(2048)
	}
	var keyBytes []byte
	var ok bool
	if keyBytes, ok = crtSecret.Data[api.TLSPrivateKeyKey]; !ok {
		return generatePrivateKey(2048)
	}
	block, _ := pem.Decode(keyBytes)
	der, err := x509.DecryptPEMBlock(block, nil)
	if err != nil {
		return generatePrivateKey(2048)
	}
	privKey, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return generatePrivateKey(2048)
	}
	return keyBytes, privKey, nil
}

func (a *Acme) obtainCertificate(crt *v1alpha1.Certificate) (privateKeyPem []byte, certPem []byte, err error) {
	if crt.Spec.ACME == nil {
		return nil, nil, fmt.Errorf("acme config must be specified")
	}
	domains := crt.Spec.Domains

	if len(domains) == 0 {
		return nil, nil, fmt.Errorf("no domains specified")
	}

	privKey, err := a.account.privateKey()

	if err != nil {
		return nil, nil, fmt.Errorf("error getting acme account private key: %s", err.Error())
	}

	cl := &acme.Client{
		Key:          privKey,
		DirectoryURL: a.account.server(),
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: domains[0],
		},
	}

	if len(domains) > 1 {
		template.DNSNames = domains
	}

	privateKeyPem, privateKey, err := a.getCertificatePrivateKey(crt)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating private key for certificiate '%s': %s", crt.Name, err)
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating certificate request: %s", err)
	}

	certSlice, certURL, err := cl.CreateCert(
		context.Background(),
		csr,
		0,
		true,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting certificate for acme server: %s", err)
	}

	certBuffer := bytes.NewBuffer([]byte{})
	for _, cert := range certSlice {
		pem.Encode(certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	}

	log.Printf("successfully got certificate: domains=%+v url=%s", domains, certURL)

	return privateKeyPem, certBuffer.Bytes(), nil
}

func (a *Acme) Issue(crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	return a.obtainCertificate(crt)
}
