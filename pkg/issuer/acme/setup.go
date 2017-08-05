package acme

import (
	"fmt"
	"reflect"
)

func (a *Acme) Setup() (err error) {
	issuerBefore := a.account.issuer.DeepCopy()

	defer func() {
		if !reflect.DeepEqual(issuerBefore, a.account.issuer) {
			if err == nil {
				_, err = a.cmClient.CertmanagerV1alpha1().Issuers(a.account.issuer.Namespace).Update(a.account.issuer)
			}
		}
	}()

	err = a.ensureSetup()

	if err != nil {
		return err
	}

	return nil
}

// ensureSetup will ensure that this issuer is ready to issue certificates.
// it
func (a *Acme) ensureSetup() error {
	err := a.account.verify()

	if err == nil {
		a.account.issuer.Status.Ready = true
		return nil
	}

	a.account.issuer.Status.Ready = false

	err = a.account.register()

	if err != nil {
		// don't write updated state as an actual error occurred
		return fmt.Errorf("error registering acme account: %s", err.Error())
	}

	a.account.issuer.Status.Ready = true

	return nil
}
