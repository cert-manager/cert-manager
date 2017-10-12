package acme

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"

	"golang.org/x/crypto/acme"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack-experimental/cert-manager/pkg/util/kube"
	"github.com/jetstack-experimental/cert-manager/pkg/util/pki"
)

const (
	errorIssueCert = "ErrIssueCert"

	successCertIssued = "CertIssueSuccess"

	messageErrorIssueCert = "Error issuing TLS certificate: "

	messageCertIssued = "Certificate issued successfully"
)

func (a *Acme) obtainCertificate(ctx context.Context, crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	if crt.Spec.ACME == nil {
		return nil, nil, fmt.Errorf("acme config must be specified")
	}
	domains := crt.Spec.Domains

	if len(domains) == 0 {
		return nil, nil, fmt.Errorf("no domains specified")
	}

	acmePrivKey, err := kube.SecretTLSKey(a.secretsLister, a.resourceNamespace, a.issuer.GetSpec().ACME.PrivateKey)

	if err != nil {
		return nil, nil, fmt.Errorf("error getting acme account private key: %s", err.Error())
	}

	cl := &acme.Client{
		Key:          acmePrivKey,
		DirectoryURL: a.issuer.GetSpec().ACME.Server,
	}

	key, err := kube.SecretTLSKey(a.secretsLister, crt.Namespace, crt.Spec.SecretName)

	if k8sErrors.IsNotFound(err) {
		key, err = pki.GenerateRSAPrivateKey(2048)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating private key: %s", err.Error())
		}
	}

	if err != nil {
		return nil, nil, fmt.Errorf("error getting certificate private key: %s", err.Error())
	}

	template := pki.GenerateCSR(domains)
	csr, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating certificate request: %s", err)
	}

	certSlice, certURL, err := cl.CreateCert(
		ctx,
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

	return pki.EncodePKCS1PrivateKey(key), certBuffer.Bytes(), nil
}

func (a *Acme) Issue(ctx context.Context, crt *v1alpha1.Certificate) (v1alpha1.CertificateStatus, []byte, []byte, error) {
	update := crt.DeepCopy()
	key, cert, err := a.obtainCertificate(ctx, crt)
	if err != nil {
		s := messageErrorIssueCert + err.Error()
		update.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorIssueCert, s)
		return update.Status, nil, nil, err
	}

	update.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionTrue, successCertIssued, messageCertIssued)

	return update.Status, key, cert, err
}
