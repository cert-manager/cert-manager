package acme

import (
	"fmt"

	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
)

const (
	reasonAccountVerified           = "ACME account verified"
	reasonAccountRegistered         = "ACME account registered"
	reasonAccountRegistrationFailed = "ACME account registration failed"

	messageAccountVerified           = "The ACME account was verified with the ACME server"
	messagedAccountRegistered        = "The ACME account was registered with the ACME server"
	messageAccountRegistrationFailed = "Failed to register ACME account with server: %s"
)

func (a *Acme) Setup() (v1alpha1.IssuerStatus, error) {
	err := a.verifyAccount()

	if err == nil {
		update := v1alpha1.UpdateIssuerStatusCondition(a.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionTrue, reasonAccountVerified, reasonAccountRegistered)
		return update.Status, nil
	}

	uri, err := a.registerAccount()

	if err != nil {
		update := v1alpha1.UpdateIssuerStatusCondition(a.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, reasonAccountRegistrationFailed, fmt.Sprintf(messageAccountRegistrationFailed, err.Error()))
		return update.Status, fmt.Errorf("error registering acme account: %s", err.Error())
	}

	update := v1alpha1.UpdateIssuerStatusCondition(a.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, reasonAccountRegistered, messageAccountVerified)
	update.Status.ACMEStatus().URI = uri

	return update.Status, nil
}
