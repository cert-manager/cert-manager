package acme

import (
	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
)

const (
	errorRenewCert        = "ErrRenewCert"
	messageErrorRenewCert = "Error renewing TLS certificate: "

	successCertRenewed = "CertRenewSuccess"
	messageCertRenewed = "Certificate renewed successfully"
)

func (a *Acme) Renew(crt *v1alpha1.Certificate) (v1alpha1.CertificateStatus, []byte, []byte, error) {
	update := crt.DeepCopy()
	key, cert, err := a.obtainCertificate(crt)
	if err != nil {
		s := messageErrorIssueCert + err.Error()
		update.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorRenewCert, s)
		return update.Status, nil, nil, err
	}

	update.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionTrue, successCertRenewed, messageCertRenewed)

	return update.Status, key, cert, err
}
