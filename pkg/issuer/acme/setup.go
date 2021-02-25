/*
Copyright 2020 The cert-manager Authors.

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
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	acmeapi "golang.org/x/crypto/acme"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/pkg/acme"
	"github.com/cert-manager/cert-manager/pkg/acme/accounts"
	"github.com/cert-manager/cert-manager/pkg/acme/client"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util/errors"
	"github.com/cert-manager/cert-manager/pkg/util/kube"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

const (
	errorAccountRegistrationFailed = "ErrRegisterACMEAccount"
	errorAccountVerificationFailed = "ErrVerifyACMEAccount"
	errorAccountUpdateFailed       = "ErrUpdateACMEAccount"

	successAccountRegistered = "ACMEAccountRegistered"
	successAccountVerified   = "ACMEAccountVerified"

	messageAccountRegistrationFailed = "Failed to register ACME account: "
	messageAccountVerificationFailed = "Failed to verify ACME account: "
	messageAccountUpdateFailed       = "Failed to update ACME account:"
	messageAccountRegistered         = "The ACME account was registered with the ACME server"
	messageAccountVerified           = "The ACME account was verified with the ACME server"
)

// Setup will verify an existing ACME registration, or create one if not
// already registered.
func (a *Acme) Setup(ctx context.Context) error {
	log := logf.FromContext(ctx)

	// check if user has specified a v1 account URL, and set a status condition if so.
	if newURL, ok := acmev1ToV2Mappings[a.issuer.GetSpec().ACME.Server]; ok {
		apiutil.SetIssuerCondition(a.issuer, v1.IssuerConditionReady, cmmeta.ConditionFalse, "InvalidConfig",
			fmt.Sprintf("Your ACME server URL is set to a v1 endpoint (%s). "+
				"You should update the spec.acme.server field to %q", a.issuer.GetSpec().ACME.Server, newURL))
		// return nil so that Setup only gets called again after the spec is updated
		return nil
	}

	// if the namespace field is not set, we are working on a ClusterIssuer resource
	// therefore we should check for the ACME private key in the 'cluster resource namespace'.
	ns := a.issuer.GetObjectMeta().Namespace
	if ns == "" {
		ns = a.clusterResourceNamespace
	}

	log = logf.WithRelatedResourceName(log, a.issuer.GetSpec().ACME.PrivateKey.Name, ns, "Secret")

	// attempt to obtain the existing private key from the apiserver.
	// if it does not exist then we generate one
	// if it contains invalid data, warn the user and return without error.
	// if any other error occurs, return it and retry.
	privateKeySelector := acme.PrivateKeySelector(a.issuer.GetSpec().ACME.PrivateKey)
	pk, err := kube.SecretTLSKeyRef(ctx, a.secretsLister, ns, privateKeySelector.Name, privateKeySelector.Key)
	switch {
	case !a.issuer.GetSpec().ACME.DisableAccountKeyGeneration && apierrors.IsNotFound(err):
		log.V(logf.InfoLevel).Info("generating acme account private key")
		pk, err = a.createAccountPrivateKey(privateKeySelector, ns)
		if err != nil {
			s := messageAccountRegistrationFailed + err.Error()
			apiutil.SetIssuerCondition(a.issuer, v1.IssuerConditionReady, cmmeta.ConditionFalse, errorAccountRegistrationFailed, s)
			return fmt.Errorf(s)
		}
		// We clear the ACME account URI as we have generated a new private key
		a.issuer.GetStatus().ACMEStatus().URI = ""

	case a.issuer.GetSpec().ACME.DisableAccountKeyGeneration && apierrors.IsNotFound(err):
		wrapErr := fmt.Errorf(messageAccountVerificationFailed+"the ACME issuer config has 'disableAccountKeyGeneration' set to true, but the secret was not found: %w", err)
		apiutil.SetIssuerCondition(a.issuer, v1.IssuerConditionReady, cmmeta.ConditionFalse, errorAccountVerificationFailed, wrapErr.Error())
		return wrapErr

	case errors.IsInvalidData(err):
		apiutil.SetIssuerCondition(a.issuer, v1.IssuerConditionReady, cmmeta.ConditionFalse, errorAccountVerificationFailed, fmt.Sprintf("Account private key is invalid: %v", err))
		return nil

	case err != nil:
		s := messageAccountVerificationFailed + err.Error()
		apiutil.SetIssuerCondition(a.issuer, v1.IssuerConditionReady, cmmeta.ConditionFalse, errorAccountVerificationFailed, s)
		return fmt.Errorf(s)
	}
	rsaPk, ok := pk.(*rsa.PrivateKey)
	if !ok {
		apiutil.SetIssuerCondition(a.issuer, v1.IssuerConditionReady, cmmeta.ConditionFalse, errorAccountVerificationFailed, fmt.Sprintf("ACME private key in %q is not of type RSA", a.issuer.GetSpec().ACME.PrivateKey.Name))
		return nil
	}

	// TODO: don't always clear the client cache.
	//  In future we should intelligently manage items in the account cache
	//  and remove them when the corresponding issuer is updated/deleted.
	a.accountRegistry.RemoveClient(string(a.issuer.GetUID()))
	httpClient := accounts.BuildHTTPClient(a.metrics, a.issuer.GetSpec().ACME.SkipTLSVerify)
	cl := accounts.NewClient(httpClient, *a.issuer.GetSpec().ACME, rsaPk)

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
		a.recorder.Eventf(a.issuer, corev1.EventTypeWarning, r, s)
		apiutil.SetIssuerCondition(a.issuer, v1.IssuerConditionReady, cmmeta.ConditionFalse, r, s)
		// absorb errors as retrying will not help resolve this error
		return nil
	}

	rawAccountURL := a.issuer.GetStatus().ACMEStatus().URI
	parsedAccountURL, err := url.Parse(rawAccountURL)
	if err != nil {
		r := "InvalidURL"
		s := fmt.Sprintf("Failed to parse existing ACME account URI %q: %v", rawAccountURL, err)
		a.recorder.Eventf(a.issuer, corev1.EventTypeWarning, r, s)
		apiutil.SetIssuerCondition(a.issuer, v1.IssuerConditionReady, cmmeta.ConditionFalse, r, s)
		// absorb errors as retrying will not help resolve this error
		return nil
	}

	hasReadyCondition := apiutil.IssuerHasCondition(a.issuer, v1.IssuerCondition{
		Type:   v1.IssuerConditionReady,
		Status: cmmeta.ConditionTrue,
	})

	// If the Host components of the server URL and the account URL match,
	// and the cached email matches the registered email, then
	// we skip re-checking the account status to save excess calls to the
	// ACME api.
	if hasReadyCondition &&
		a.issuer.GetStatus().ACMEStatus().URI != "" &&
		parsedAccountURL.Host == parsedServerURL.Host &&
		a.issuer.GetStatus().ACMEStatus().LastRegisteredEmail == a.issuer.GetSpec().ACME.Email {
		log.V(logf.InfoLevel).Info("skipping re-verifying ACME account as cached registration " +
			"details look sufficient")
		// ensure the cached client in the account registry is up to date
		a.accountRegistry.AddClient(httpClient, string(a.issuer.GetUID()), *a.issuer.GetSpec().ACME, rsaPk)
		return nil
	}

	if parsedAccountURL.Host != parsedServerURL.Host {
		log.V(logf.InfoLevel).Info("ACME server URL host and ACME private key registration " +
			"host differ. Re-checking ACME account registration")
		a.issuer.GetStatus().ACMEStatus().URI = ""
	}

	var eabAccount *acmeapi.ExternalAccountBinding
	if eabObj := a.issuer.GetSpec().ACME.ExternalAccountBinding; eabObj != nil {
		eabKey, err := a.getEABKey(ns)
		switch {
		// Do not re-try if we fail to get the MAC key as it does not exist at the reference.
		case apierrors.IsNotFound(err), errors.IsInvalidData(err):

			log.Error(err, "failed to verify ACME account")
			s := messageAccountRegistrationFailed + err.Error()

			a.recorder.Event(a.issuer, corev1.EventTypeWarning, errorAccountRegistrationFailed, s)
			apiutil.SetIssuerCondition(a.issuer, v1.IssuerConditionReady, cmmeta.ConditionFalse,
				errorAccountRegistrationFailed, fmt.Sprintf("External Account Binding MAC key is invalid: %v", err))

			return nil

		case err != nil:
			s := messageAccountRegistrationFailed + err.Error()
			apiutil.SetIssuerCondition(a.issuer, v1.IssuerConditionReady, cmmeta.ConditionFalse, errorAccountRegistrationFailed, s)
			return fmt.Errorf(s)
		}

		// set the external account binding
		eabAccount = &acmeapi.ExternalAccountBinding{
			KID:          eabObj.KeyID,
			Key:          eabKey,
			KeyAlgorithm: string(eabObj.KeyAlgorithm),
		}
	}

	// registerAccount will also verify the account exists if it already
	// exists.
	account, err := a.registerAccount(ctx, cl, eabAccount)
	if err != nil {
		s := messageAccountVerificationFailed + err.Error()
		log.Error(err, "failed to verify ACME account")
		a.recorder.Event(a.issuer, corev1.EventTypeWarning, errorAccountVerificationFailed, s)
		apiutil.SetIssuerCondition(a.issuer, v1.IssuerConditionReady, cmmeta.ConditionFalse, errorAccountRegistrationFailed, s)

		acmeErr, ok := err.(*acmeapi.Error)
		// If this is not an ACME error, we will simply return it and retry later
		if !ok {
			return err
		}

		// If the status code is 400 (BadRequest), we will *not* retry this registration
		// as it implies that something about the request (i.e. email address or private key)
		// is invalid.
		if acmeErr.StatusCode >= 400 && acmeErr.StatusCode < 500 {
			log.Error(acmeErr, "skipping retrying account registration as a "+
				"BadRequest response was returned from the ACME server")
			return nil
		}

		// Otherwise if we receive anything other than a 400, we will retry.
		return err
	}

	// if we got an account successfully, we must check if the registered
	// email is the same as in the issuer spec
	specEmail := a.issuer.GetSpec().ACME.Email
	account, registeredEmail, err := ensureEmailUpToDate(ctx, cl, account, specEmail)
	if err != nil {
		s := messageAccountUpdateFailed + err.Error()
		log.Error(err, "failed to update ACME account")
		a.recorder.Event(a.issuer, corev1.EventTypeWarning, errorAccountUpdateFailed, s)
		apiutil.SetIssuerCondition(a.issuer, v1.IssuerConditionReady, cmmeta.ConditionFalse, errorAccountUpdateFailed, s)

		acmeErr, ok := err.(*acmeapi.Error)
		// If this is not an ACME error, we will simply return it and retry later
		if !ok {
			return err
		}

		// If the status code is 400 (BadRequest), we will *not* retry this registration
		// as it implies that something about the request (i.e. email address or private key)
		// is invalid.
		if acmeErr.StatusCode >= 400 && acmeErr.StatusCode < 500 {
			log.Error(acmeErr, "skipping updating account email as a "+
				"BadRequest response was returned from the ACME server")
			return nil
		}

		// Otherwise if we receive anything other than a 400, we will retry.
		return err
	}

	log.V(logf.InfoLevel).Info("verified existing registration with ACME server")
	apiutil.SetIssuerCondition(a.issuer, v1.IssuerConditionReady, cmmeta.ConditionTrue, successAccountRegistered, messageAccountRegistered)
	a.issuer.GetStatus().ACMEStatus().URI = account.URI
	a.issuer.GetStatus().ACMEStatus().LastRegisteredEmail = registeredEmail
	// ensure the cached client in the account registry is up to date
	a.accountRegistry.AddClient(httpClient, string(a.issuer.GetUID()), *a.issuer.GetSpec().ACME, rsaPk)

	return nil
}

func ensureEmailUpToDate(ctx context.Context, cl client.Interface, acc *acmeapi.Account, specEmail string) (*acmeapi.Account, string, error) {
	log := logf.FromContext(ctx)

	// if no email was specified, then registeredEmail will remain empty
	registeredEmail := ""
	if len(acc.Contact) > 0 {
		registeredEmail = strings.Replace(acc.Contact[0], "mailto:", "", 1)
	}

	// if they are different, we update the account
	if registeredEmail != specEmail {
		log.V(logf.DebugLevel).Info("updating ACME account email address", "email", specEmail)
		emailurl := []string(nil)
		if specEmail != "" {
			emailurl = []string{fmt.Sprintf("mailto:%s", strings.ToLower(specEmail))}
		}
		acc.Contact = emailurl

		var err error
		acc, err = cl.UpdateReg(ctx, acc)
		if err != nil {
			return nil, "", err
		}

		// update the registeredEmail var so it is updated properly in the status below
		registeredEmail = specEmail
	}

	return acc, registeredEmail, nil
}

// registerAccount will register a new ACME account with the server. If an
// account with the clients private key already exists, it will attempt to look
// up and verify the corresponding account, and will return that. If this fails
// due to a not found error it will register a new account with the given key.
func (a *Acme) registerAccount(ctx context.Context, cl client.Interface, eabAccount *acmeapi.ExternalAccountBinding) (*acmeapi.Account, error) {
	emailurl := []string(nil)
	if a.issuer.GetSpec().ACME.Email != "" {
		emailurl = []string{fmt.Sprintf("mailto:%s", strings.ToLower(a.issuer.GetSpec().ACME.Email))}
	}

	acc := &acmeapi.Account{
		Contact:                emailurl,
		ExternalAccountBinding: eabAccount,
	}

	acc, err := cl.Register(ctx, acc, acmeapi.AcceptTOS)
	// If the account already exists, fetch the Account object and return.
	if err == acmeapi.ErrAccountAlreadyExists {
		return cl.GetReg(ctx, "")
	}
	if err != nil {
		return nil, err
	}
	// TODO: re-enable this check once this field is set by Pebble
	// if acc.Status != acme.StatusValid {
	// 	return nil, fmt.Errorf("acme account is not valid")
	// }

	return acc, nil
}

func (a *Acme) getEABKey(ns string) ([]byte, error) {
	eab := a.issuer.GetSpec().ACME.ExternalAccountBinding.Key
	sec, err := a.secretsClient.Secrets(ns).Get(context.TODO(), eab.Name, metav1.GetOptions{})
	// Surface IsNotFound API error to not cause re-sync
	if apierrors.IsNotFound(err) {
		return nil, err
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get External Account Binding key from secret: %s", err)
	}

	encodedKeyData, ok := sec.Data[eab.Key]
	if !ok {
		return nil, errors.NewInvalidData("failed to find external account binding key data in Secret %q at index %q", eab.Name, eab.Key)
	}

	// decode the base64 encoded secret key data.
	// we include this step to make it easier for end-users to encode secret
	// keys in case the CA provides a key that is not in standard, padded
	// base64 encoding.
	keyData := make([]byte, base64.RawURLEncoding.DecodedLen(len(encodedKeyData)))
	if _, err := base64.RawURLEncoding.Decode(keyData, encodedKeyData); err != nil {
		return nil, errors.NewInvalidData("failed to decode external account binding key data: %v", err)
	}

	return keyData, nil
}

// createAccountPrivateKey will generate a new RSA private key, and create it
// as a secret resource in the apiserver.
func (a *Acme) createAccountPrivateKey(sel cmmeta.SecretKeySelector, ns string) (*rsa.PrivateKey, error) {
	sel = acme.PrivateKeySelector(sel)
	accountPrivKey, err := pki.GenerateRSAPrivateKey(pki.MinRSAKeySize)
	if err != nil {
		return nil, err
	}

	_, err = a.secretsClient.Secrets(ns).Create(context.TODO(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sel.Name,
			Namespace: ns,
		},
		Data: map[string][]byte{
			sel.Key: pki.EncodePKCS1PrivateKey(accountPrivKey),
		},
	}, metav1.CreateOptions{})

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
