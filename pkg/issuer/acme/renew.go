package acme

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

func (a *Acme) Renew(ctx context.Context, crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	key, cert, err := a.obtainCertificate(ctx, crt)
	if err != nil {
		s := messageErrorIssueCert + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorRenewCert, s)
		return nil, nil, err
	}

	crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionTrue, successCertRenewed, messageCertRenewed)

	return key, cert, err
}
