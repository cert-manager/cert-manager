/*
Copyright 2018 The Jetstack cert-manager contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package acme

import (
	"context"
	"crypto/rsa"
	"fmt"
	"strings"

	"github.com/golang/glog"
	"k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/pkg/acme"
	"github.com/jetstack/cert-manager/pkg/acme/client"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	acmeapi "github.com/jetstack/cert-manager/third_party/crypto/acme"
)

const (
	errorAccountRegistrationFailed = "ErrRegisterACMEAccount"
	errorAccountVerificationFailed = "ErrVerifyACMEAccount"

	successAccountRegistered = "ACMEAccountRegistered"
	successAccountVerified   = "ACMEAccountVerified"

	messageAccountRegistrationFailed = "Failed to register ACME account: "
	messageAccountVerificationFailed = "Failed to verify ACME account: "
	messageAccountRegistered         = "The ACME account was registered with the ACME server"
	messageAccountVerified           = "The ACME account was verified with the ACME server"
)

// Setup will verify an existing ACME registration, or create one if not
// already registered.
func (a *Acme) Setup(ctx context.Context) error {
	if newURL, ok := acmev1ToV2Mappings[a.issuer.GetSpec().ACME.Server]; ok {
		a.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorInvalidConfig, fmt.Sprintf("Your ACME server URL is set to a v1 endpoint (%s). "+
			"You should update the spec.acme.server field to %q", a.issuer.GetSpec().ACME.Server, newURL))
		// return nil so that Setup only gets called again after the spec is updated
		return nil
	}

	cl, err := a.helper.ClientForIssuer(a.issuer)
	if k8sErrors.IsNotFound(err) || errors.IsInvalidData(err) {
		glog.Infof("%s: generating acme account private key %q", a.issuer.GetObjectMeta().Name, a.issuer.GetSpec().ACME.PrivateKey.Name)
		accountPrivKey, err := a.createAccountPrivateKey(a.issuer.GetSpec().ACME.PrivateKey)
		if err != nil {
			s := messageAccountRegistrationFailed + err.Error()
			a.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorAccountRegistrationFailed, s)
			return fmt.Errorf(s)
		}
		a.issuer.GetStatus().ACMEStatus().URI = ""
		cl, err = acme.ClientWithKey(a.issuer, accountPrivKey)
		if err != nil {
			return err
		}
	} else if err != nil {
		s := messageAccountVerificationFailed + err.Error()
		glog.V(4).Infof("%s: %s", a.issuer.GetObjectMeta().Name, s)
		a.Recorder.Event(a.issuer, v1.EventTypeWarning, errorAccountVerificationFailed, s)
		return err
	}

	// registerAccount will also verify the account exists if it already
	// exists.
	account, err := a.registerAccount(ctx, cl)
	if err != nil {
		s := messageAccountVerificationFailed + err.Error()
		glog.V(4).Infof("%s: %s", a.issuer.GetObjectMeta().Name, s)
		a.Recorder.Event(a.issuer, v1.EventTypeWarning, errorAccountVerificationFailed, s)
		a.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorAccountRegistrationFailed, s)
		return err
	}

	glog.Infof("%s: verified existing registration with ACME server", a.issuer.GetObjectMeta().Name)
	a.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionTrue, successAccountRegistered, messageAccountRegistered)
	a.issuer.GetStatus().ACMEStatus().URI = account.URL

	return nil
}

// registerAccount will register a new ACME account with the server. If an
// account with the clients private key already exists, it will attempt to look
// up and verify the corresponding account, and will return that. If this fails
// due to a not found error it will register a new account with the given key.
func (a *Acme) registerAccount(ctx context.Context, cl client.Interface) (*acmeapi.Account, error) {
	// check if the account already exists
	acc, err := cl.GetAccount(ctx)
	if err == nil {
		return acc, nil
	}
	// return all errors except for 404 errors (which indicate the account
	// is not yet registered)
	acmeErr, ok := err.(*acmeapi.Error)
	if !ok || (acmeErr.StatusCode != 400 && acmeErr.StatusCode != 404) {
		return nil, err
	}

	acc = &acmeapi.Account{
		Contact:     []string{fmt.Sprintf("mailto:%s", strings.ToLower(a.issuer.GetSpec().ACME.Email))},
		TermsAgreed: true,
	}
	acc, err = cl.CreateAccount(ctx, acc)
	if err != nil {
		return nil, err
	}
	// TODO: re-enable this check once this field is set by Pebble
	// if acc.Status != acme.StatusValid {
	// 	return nil, fmt.Errorf("acme account is not valid")
	// }
	return acc, nil
}

func (a *Acme) createAccountPrivateKey(sel v1alpha1.SecretKeySelector) (*rsa.PrivateKey, error) {
	ns := a.Context.ResourceNamespace(a.issuer)
	sel = acme.PrivateKeySelector(sel)
	accountPrivKey, err := pki.GenerateRSAPrivateKey(pki.MinRSAKeySize)
	if err != nil {
		return nil, err
	}

	_, err = a.Client.CoreV1().Secrets(ns).Create(&v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sel.Name,
			Namespace: ns,
		},
		Data: map[string][]byte{
			sel.Key: pki.EncodePKCS1PrivateKey(accountPrivKey),
		},
	})

	if err != nil {
		return nil, err
	}

	return accountPrivKey, err
}
