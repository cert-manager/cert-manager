package acme

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/golang/glog"
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
	commonName := crt.Spec.CommonName
	altNames := crt.Spec.AltNames
	if len(commonName) == 0 || len(altNames) == 0 {
		return nil, nil, fmt.Errorf("no domains specified on certificate")
	}

	cl, err := a.acmeClient()
	if err != nil {
		return nil, nil, fmt.Errorf("error creating ACME client: %s", err.Error())
	}

	// get existing certificate private key
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

	// generate a csr
	template := pki.GenerateCSR(commonName, altNames...)
	csr, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating certificate request: %s", err)
	}

	// obtain a certificate from the acme server
	certSlice, certURL, err := cl.CreateCert(
		ctx,
		csr,
		0,
		true,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting certificate for acme server: %s", err)
	}

	// encode the retrieved certificate
	certBuffer := bytes.NewBuffer([]byte{})
	for _, cert := range certSlice {
		pem.Encode(certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	}

	glog.V(2).Infof("successfully got certificate: cn=%q altNames=%+v url=%q", commonName, altNames, certURL)
	// encode the private key and return
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
