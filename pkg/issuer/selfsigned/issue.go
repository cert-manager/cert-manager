package selfsigned

import (
	"context"
	"crypto/rsa"
	"time"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	errorGetCertKeyPair = "ErrGetKey"
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

func (c *SelfSigned) Issue(ctx context.Context, crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	signeeKey, err := kube.SecretTLSKey(c.secretsLister, crt.Namespace, crt.Spec.SecretName)

	if k8sErrors.IsNotFound(err) || errors.IsInvalidData(err) {
		signeeKey, err = pki.GenerateRSAPrivateKey(2048)
	}

	if err != nil {
		s := messageErrorGetCertKeyPair + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorGetCertKeyPair, s, false)
		return nil, nil, err
	}

	certPem, err := c.obtainCertificate(crt, signeeKey)

	if err != nil {
		s := messageErrorIssueCert + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorIssueCert, s, false)
		return nil, nil, err
	}

	crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionTrue, successCertIssued, messageCertIssued, true)

	return pki.EncodePKCS1PrivateKey(signeeKey), certPem, nil
}

func (c *SelfSigned) obtainCertificate(crt *v1alpha1.Certificate, privateKey *rsa.PrivateKey) ([]byte, error) {
	publicKey := privateKey.Public()

	template, err := pki.GenerateTemplate(c.issuer, crt, nil)
	if err != nil {
		return nil, err
	}

	crtPem, _, err := pki.SignCertificate(template, template, publicKey, privateKey)
	if err != nil {
		return nil, err
	}

	return crtPem, nil
}
