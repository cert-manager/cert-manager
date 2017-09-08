package acme

import (
	"fmt"

	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func (a *Acme) Setup() (v1alpha1.IssuerStatus, error) {
	updateStatus := a.issuer.Status.DeepCopy()

	err := a.verifyAccount()

	if err == nil {
		updateStatus.Ready = true
		return *updateStatus, nil
	}

	uri, err := a.registerAccount()

	if err != nil {
		updateStatus.Ready = false
		return *updateStatus, fmt.Errorf("error registering acme account: %s", err.Error())
	}

	updateStatus.ACMEStatus().URI = uri

	return *updateStatus, nil
}
