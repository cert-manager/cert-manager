/*
Copyright 2019 The Jetstack cert-manager contributors.

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
	"net/url"
	"strings"

	"k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"

	"github.com/jetstack/cert-manager/pkg/acme"
	"github.com/jetstack/cert-manager/pkg/acme/client"
	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
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
	// check if user has specified a v1 account URL, and set a status condition if so.
	if newURL, ok := acmev1ToV2Mappings[a.issuer.GetSpec().ACME.Server]; ok {
		apiutil.SetIssuerCondition(a.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, "InvalidConfig",
			fmt.Sprintf("Your ACME server URL is set to a v1 endpoint (%s). "+
				"You should update the spec.acme.server field to %q", a.issuer.GetSpec().ACME.Server, newURL))
		// return nil so that Setup only gets called again after the spec is updated
		return nil
	}

	// if the namespace field is not set, we are working on a ClusterIssuer resource
	// therefore we should check for the ACME private key in the 'cluster resource namespace'.
	ns := a.issuer.GetObjectMeta().Namespace
	if ns == "" {
		ns = a.IssuerOptions.ClusterResourceNamespace
	}

	// attempt to obtain the existing private key from the apiserver.
	// if it does not exist then we generate one
	// if it contains invalid data, warn the user and return without error.
	// if any other error occurs, return it and retry.
	pk, err := a.helper.ReadPrivateKey(a.issuer.GetSpec().ACME.PrivateKey, ns)
	switch {
	case apierrors.IsNotFound(err):
		klog.Infof("%s: generating acme account private key %q", a.issuer.GetObjectMeta().Name, a.issuer.GetSpec().ACME.PrivateKey.Name)
		pk, err = a.createAccountPrivateKey(a.issuer.GetSpec().ACME.PrivateKey, ns)
		if err != nil {
			s := messageAccountRegistrationFailed + err.Error()
			apiutil.SetIssuerCondition(a.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorAccountRegistrationFailed, s)
			return fmt.Errorf(s)
		}
		// We clear the ACME account URI as we have generated a new private key
		a.issuer.GetStatus().ACMEStatus().URI = ""

	case errors.IsInvalidData(err):
		apiutil.SetIssuerCondition(a.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorAccountVerificationFailed, fmt.Sprintf("Account private key is invalid: %v", err))
		return nil

	case err != nil:
		s := messageAccountVerificationFailed + err.Error()
		apiutil.SetIssuerCondition(a.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorAccountVerificationFailed, s)
		return fmt.Errorf(s)

	}

	acme.ClearClientCache()

	cl, err := acme.ClientWithKey(a.issuer, pk)
	if err != nil {
		s := messageAccountVerificationFailed + err.Error()
		klog.Infof("%s: %s", a.issuer.GetObjectMeta().Name, s)
		a.Recorder.Event(a.issuer, v1.EventTypeWarning, errorAccountVerificationFailed, s)
		apiutil.SetIssuerCondition(a.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorAccountVerificationFailed, s)
		return err
	}

	// TODO: perform a complex check to determine whether we need to verify
	// the existing registration with the ACME server.
	// This should take into account the ACME server URL, as well as a checksum
	// of the private key's contents.
	// Alternatively, we could add 'observed generation' fields here, tracking
	// the most recent copy of the Issuer and Secret resource we have checked
	// already.

	rawServerURL := a.issuer.GetSpec().ACME.Server
	parsedServerURL, err := url.Parse(rawServerURL)
	if err != nil {
		r := "InvalidURL"
		s := fmt.Sprintf("Failed to parse existing ACME server URI %q: %v", rawServerURL, err)
		a.Recorder.Eventf(a.issuer, v1.EventTypeWarning, r, s)
		apiutil.SetIssuerCondition(a.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, r, s)
		// absorb errors as retrying will not help resolve this error
		return nil
	}

	rawAccountURL := a.issuer.GetStatus().ACMEStatus().URI
	parsedAccountURL, err := url.Parse(rawAccountURL)
	if err != nil {
		r := "InvalidURL"
		s := fmt.Sprintf("Failed to parse existing ACME account URI %q: %v", rawAccountURL, err)
		a.Recorder.Eventf(a.issuer, v1.EventTypeWarning, r, s)
		apiutil.SetIssuerCondition(a.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, r, s)
		// absorb errors as retrying will not help resolve this error
		return nil
	}

	hasReadyCondition := apiutil.IssuerHasCondition(a.issuer, v1alpha1.IssuerCondition{
		Type:   v1alpha1.IssuerConditionReady,
		Status: v1alpha1.ConditionTrue,
	})

	// If the Host components of the server URL and the account URL match, then
	// we skip re-checking the account status to save excess calls to the
	// ACME api.
	if hasReadyCondition &&
		a.issuer.GetStatus().ACMEStatus().URI != "" &&
		parsedAccountURL.Host == parsedServerURL.Host {
		klog.Infof("Skipping re-verifying ACME account as cached registration " +
			"details look sufficient.")
		return nil
	}

	if parsedAccountURL.Host != parsedServerURL.Host {
		klog.Infof("ACME server URL host and ACME private key registration " +
			"host differ. Re-checking ACME account registration.")
		a.issuer.GetStatus().ACMEStatus().URI = ""
	}

	// registerAccount will also verify the account exists if it already
	// exists.
	account, err := a.registerAccount(ctx, cl)
	if err != nil {
		s := messageAccountVerificationFailed + err.Error()
		klog.Infof("%s: %s", a.issuer.GetObjectMeta().Name, s)
		a.Recorder.Event(a.issuer, v1.EventTypeWarning, errorAccountVerificationFailed, s)
		apiutil.SetIssuerCondition(a.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorAccountRegistrationFailed, s)

		acmeErr, ok := err.(*acmeapi.Error)
		// If this is not an ACME error, we will simply return it and retry later
		if !ok {
			return err
		}

		// If the status code is 400 (BadRequest), we will *not* retry this registration
		// as it implies that something about the request (i.e. email address or private key)
		// is invalid.
		if acmeErr.StatusCode >= 400 && acmeErr.StatusCode < 500 {
			klog.Infof("Skipping retrying account registration as a BadRequest response was returned from the ACME server: %v", acmeErr)
			return nil
		}

		// Otherwise if we receive anything other than a 400, we will retry.
		return err
	}

	klog.Infof("%s: verified existing registration with ACME server", a.issuer.GetObjectMeta().Name)
	apiutil.SetIssuerCondition(a.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionTrue, successAccountRegistered, messageAccountRegistered)
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

// createAccountPrivateKey will generate a new RSA private key, and create it
// as a secret resource in the apiserver.
func (a *Acme) createAccountPrivateKey(sel v1alpha1.SecretKeySelector, ns string) (*rsa.PrivateKey, error) {
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

var acmev1ToV2Mappings = map[string]string{
	"https://acme-v01.api.letsencrypt.org/directory":      "https://acme-v02.api.letsencrypt.org/directory",
	"https://acme-staging.api.letsencrypt.org/directory":  "https://acme-staging-v02.api.letsencrypt.org/directory",
	"https://acme-v01.api.letsencrypt.org/directory/":     "https://acme-v02.api.letsencrypt.org/directory",
	"https://acme-staging.api.letsencrypt.org/directory/": "https://acme-staging-v02.api.letsencrypt.org/directory",
}
