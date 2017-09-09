package acme

import (
	"k8s.io/api/core/v1"

	"github.com/golang/glog"
	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
)

const (
	errorAccountRegistrationFailed = "ErrorRegisteringACMEAccount"
	errorAccountVerificationFailed = "ErrorVerifyingACMEAccount"

	successAccountRegistered = "ACMEAccountRegistered"
	successAccountVerified   = "ACMEAccountVerified"

	messageAccountRegistrationFailed = "Failed to register ACME account: "
	messageAccountVerificationFailed = "Failed to verify ACME account: "
	messageAccountRegistered         = "The ACME account was registered with the ACME server"
	messageAccountVerified           = "The ACME account was verified with the ACME server"
)

func (a *Acme) Setup() (v1alpha1.IssuerStatus, error) {
	err := a.verifyAccount()

	if err == nil {
		glog.V(4).Info(messageAccountVerified)
		a.recorder.Event(a.issuer, v1.EventTypeNormal, successAccountVerified, messageAccountVerified)
		update := v1alpha1.UpdateIssuerStatusCondition(a.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionTrue, successAccountVerified, messageAccountVerified)
		return update.Status, nil
	}

	s := messageAccountVerificationFailed + err.Error()
	glog.Info(s)
	a.recorder.Event(a.issuer, v1.EventTypeWarning, errorAccountVerificationFailed, s)

	uri, err := a.registerAccount()

	if err != nil {
		s := messageAccountRegistrationFailed + err.Error()
		glog.Info(s)
		a.recorder.Event(a.issuer, v1.EventTypeWarning, errorAccountRegistrationFailed, s)
		update := v1alpha1.UpdateIssuerStatusCondition(a.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorAccountRegistrationFailed, s)
		return update.Status, err
	}

	glog.V(4).Info(messageAccountRegistered)
	a.recorder.Event(a.issuer, v1.EventTypeNormal, successAccountRegistered, messageAccountRegistered)
	update := v1alpha1.UpdateIssuerStatusCondition(a.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, successAccountRegistered, messageAccountRegistered)
	update.Status.ACMEStatus().URI = uri

	return update.Status, nil
}
