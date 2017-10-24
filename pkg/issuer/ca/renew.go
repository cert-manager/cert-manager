package ca

import (
	"context"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	errorRenewCert = "ErrRenewCert"

	successCertRenewed = "CertIssueSuccess"

	messageErrorRenewCert = "Error issuing TLS certificate: "

	messageCertRenewed = "Certificate issued successfully"
)

func (c *CA) Renew(ctx context.Context, crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	signeeKey, err := kube.SecretTLSKey(c.secretsLister, crt.Namespace, crt.Spec.SecretName)

	if err != nil {
		s := messageErrorGetCertKeyPair + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorGetCertKeyPair, s)
		return nil, nil, err
	}

	certPem, err := c.obtainCertificate(crt, signeeKey)

	if err != nil {
		s := messageErrorRenewCert + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorRenewCert, s)
		return nil, nil, err
	}

	crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionTrue, successCertRenewed, messageCertRenewed)

	return pki.EncodePKCS1PrivateKey(signeeKey), certPem, nil
}
