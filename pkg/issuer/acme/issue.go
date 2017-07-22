package acme

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/acme"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func (a *Acme) Issue(crt *v1alpha1.Certificate) ([]byte, []byte, error) {
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

	privateKeyPem, privateKey, err := generatePrivateKey(2048)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating private key for certificiate '%s': %s", crt.Name, err)
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error certificate request: %s", err)
	}

	certSlice, certUrl, err := cl.CreateCert(
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

	a.ctx.Logger.Printf("successfully got certificate: domains=%+v url=%s", domains, certUrl)

	return privateKeyPem, certBuffer.Bytes(), nil
}
