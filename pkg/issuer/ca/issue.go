package ca

import (
	"context"
	"fmt"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	errorGetCertKeyPair   = "ErrGetCertKeyPair"
	errorIssueCert        = "ErrIssueCert"
	errorGetPublicKey     = "ErrGetPublicKey"
	errorEncodePrivateKey = "ErrEncodePrivateKey"

	successCertIssued = "CertIssueSuccess"

	messageErrorGetCertKeyPair   = "Error getting keypair for certificate: "
	messageErrorIssueCert        = "Error issuing TLS certificate: "
	messageErrorPublicKey        = "Error getting public key from private key: "
	messageErrorEncodePrivateKey = "Error encoding private key: "

	messageCertIssued = "Certificate issued successfully"
)

func (c *CA) Issue(ctx context.Context, crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	signeeKey, err := kube.SecretTLSKey(c.secretsLister, crt.Namespace, crt.Spec.SecretName)

	if k8sErrors.IsNotFound(err) || errors.IsInvalidData(err) {
		signeeKey, err = pki.GeneratePrivateKeyForCertificate(crt)
	}

	if err != nil {
		s := messageErrorGetCertKeyPair + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorGetCertKeyPair, s, false)
		return nil, nil, err
	}

	publicKey, err := pki.PublicKeyForPrivateKey(signeeKey)
	if err != nil {
		s := messageErrorPublicKey + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorGetPublicKey, s, false)
		return nil, nil, err
	}

	certPem, err := c.obtainCertificate(crt, publicKey)

	if err != nil {
		s := messageErrorIssueCert + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorIssueCert, s, false)
		return nil, nil, err
	}

	crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionTrue, successCertIssued, messageCertIssued, true)

	keyPem, err := pki.EncodePrivateKey(signeeKey)
	if err != nil {
		s := messageErrorEncodePrivateKey + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorEncodePrivateKey, s, false)
		return nil, nil, err
	}

	return keyPem, certPem, nil
}

func (c *CA) obtainCertificate(crt *v1alpha1.Certificate, signeeKey interface{}) ([]byte, error) {
	commonName := crt.Spec.CommonName
	altNames := crt.Spec.DNSNames
	if len(commonName) == 0 && len(altNames) == 0 {
		return nil, fmt.Errorf("no domains specified on certificate")
	}

	signerCert, err := kube.SecretTLSCert(c.secretsLister, c.resourceNamespace, c.issuer.GetSpec().CA.SecretName)
	if err != nil {
		return nil, fmt.Errorf("error getting issuer certificate: %s", err.Error())
	}

	signerKey, err := kube.SecretTLSKey(c.secretsLister, c.resourceNamespace, c.issuer.GetSpec().CA.SecretName)
	if err != nil {
		return nil, fmt.Errorf("error getting issuer private key: %s", err.Error())
	}

	template, err := pki.GenerateTemplate(c.issuer, crt, nil)
	if err != nil {
		return nil, err
	}

	crtPem, _, err := pki.SignCertificate(template, signerCert, signeeKey, signerKey)
	if err != nil {
		return nil, err
	}

	return crtPem, nil
}
