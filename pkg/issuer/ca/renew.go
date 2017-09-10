package ca

import (
	"github.com/golang/glog"
	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack-experimental/cert-manager/pkg/util/kube"
	"github.com/jetstack-experimental/cert-manager/pkg/util/pki"
	"k8s.io/api/core/v1"
)

const (
	errorRenewCert = "ErrRenewCert"

	successCertRenewed = "CertIssueSuccess"

	messageErrorRenewCert = "Error issuing TLS certificate: "

	messageCertRenewed = "Certificate issued successfully"
)

func (c *CA) Renew(crt *v1alpha1.Certificate) (v1alpha1.CertificateStatus, []byte, []byte, error) {
	update := crt.DeepCopy()

	signeeKey, err := kube.SecretTLSKey(c.secretsLister, c.issuer.Namespace, crt.Spec.SecretName)

	if err != nil {
		s := messageErrorGetCertKeyPair + err.Error()
		glog.Info(s)
		c.recorder.Event(update, v1.EventTypeWarning, errorGetCertKeyPair, s)
		update.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorGetCertKeyPair, s)
		return update.Status, nil, nil, err
	}

	certPem, err := c.obtainCertificate(crt, signeeKey)

	if err != nil {
		s := messageErrorRenewCert + err.Error()
		glog.Info(s)
		c.recorder.Event(update, v1.EventTypeWarning, errorRenewCert, s)
		update.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorRenewCert, s)
		return update.Status, nil, nil, err
	}

	s := messageCertRenewed
	glog.Info(s)
	c.recorder.Event(update, v1.EventTypeNormal, successCertRenewed, s)
	update.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionTrue, successCertRenewed, s)

	return update.Status, pki.EncodePKCS1PrivateKey(signeeKey), certPem, nil
}
