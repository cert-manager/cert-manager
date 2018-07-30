package cfssl

import (
	"context"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

const (
	errorRenewCert        = "ErrRenewCert"
	messageErrorRenewCert = "Error renewing TLS certificate: "

	successCertRenewed = "CertRenewSuccess"
	messageCertRenewed = "Certificate renewed successfully"
)

func (c *CFSSL) Renew(ctx context.Context, crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	keyPem, certPem, err := c.obtainCertificate(ctx, crt)

	if err != nil {
		s := messageErrorRenewCert + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorRenewCert, s, false)
		return nil, nil, err
	}

	crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionTrue, successCertRenewed, messageCertRenewed, true)

	return keyPem, certPem, nil
}
