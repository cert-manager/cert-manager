package acme

import (
	"github.com/golang/glog"
	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
	"k8s.io/api/core/v1"
)

func (a *Acme) Renew(crt *v1alpha1.Certificate) (v1alpha1.CertificateStatus, []byte, []byte, error) {
	update := crt.DeepCopy()
	key, cert, err := a.obtainCertificate(crt)
	if err != nil {
		s := messageErrorIssueCert + err.Error()
		glog.Info(s)
		a.recorder.Event(update, v1.EventTypeWarning, errorIssueCert, s)
		update.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorIssueCert, s)
		return update.Status, nil, nil, err
	}

	s := messageCertIssued
	glog.Info(s)
	a.recorder.Event(update, v1.EventTypeNormal, successCertIssued, s)
	update.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionTrue, successCertIssued, s)

	return update.Status, key, cert, err
}
