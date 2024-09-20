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
	"crypto/sha256"
	"crypto/x509"
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
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

const (
	errorAccountRegistrationFailed = "ErrRegisterACMEAccount"
	errorAccountVerificationFailed = "ErrVerifyACMEAccount"
	errorAccountUpdateFailed       = "ErrUpdateACMEAccount"
	errorInvalidConfig             = "InvalidConfig"
	errorInvalidURL                = "InvalidURL"

	successAccountRegistered = "ACMEAccountRegistered"
	successAccountVerified   = "ACMEAccountVerified"

	messageAccountRegistrationFailed     = "Failed to register ACME account: "
	messageAccountVerificationFailed     = "Failed to verify ACME account: "
	messageAccountUpdateFailed           = "Failed to update ACME account:"
	messageAccountRegistered             = "The ACME account was registered with the ACME server"
	messageAccountVerified               = "The ACME account was verified with the ACME server"
	messageNoSecretKeyGenerationDisabled = "the ACME issuer config has 'disableAccountKeyGeneration' set to true, but the secret was not found: "
	messageInvalidPrivateKey             = "Account private key is invalid: "

	messageTemplateUpdateToV2              = "Your ACME server URL is set to a v1 endpoint (%s). You should update the spec.acme.server field to %q"
	messageTemplateNotRSA                  = "ACME private key in %q is not of type RSA"
	messageTemplateFailedToParseURL        = "Failed to parse existing ACME server URI %q: %v"
	messageTemplateFailedToParseAccountURL = "Failed to parse existing ACME account URI %q: %v"
	messageTemplateFailedToGetEABKey       = "failed to get External Account Binding key from secret: %v"
)

// Setup will verify an existing ACME registration, or create one if not
// already registered.
func (a *Acme) Setup(ctx context.Context) error {
	log := logf.FromContext(ctx)

	// Correct reason and message for issuer's Ready condition must be always set
	// before returning from this function. Status must be set if not false.
	status := cmmeta.ConditionFalse
	var reason, msg string
	defer func() {
		apiutil.SetIssuerCondition(a.issuer,
			a.issuer.GetGeneration(),
			v1.IssuerConditionReady,
			status,
			reason,
			msg)
	}()

	// check if user has specified a v1 account URL, and set a status condition if so.
	if newURL, ok := acmev1ToV2Mappings[a.issuer.GetSpec().ACME.Server]; ok {
		reason = errorInvalidConfig
		msg = fmt.Sprintf(messageTemplateUpdateToV2, a.issuer.GetSpec().ACME.Server, newURL)
		// Return nil, because we do not want to re-queue an Issuer with an invalid spec.
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
	pk, err := a.keyFromSecret(ctx, ns, privateKeySelector.Name, privateKeySelector.Key)
	switch {
	case !a.issuer.GetSpec().ACME.DisableAccountKeyGeneration && apierrors.IsNotFound(err):
		log.V(logf.InfoLevel).Info("generating acme account private key")
		pk, err = a.createAccountPrivateKey(ctx, privateKeySelector, ns)
		if err != nil {
			msg = messageAccountRegistrationFailed + err.Error()
			reason = errorAccountRegistrationFailed
			return fmt.Errorf("%s", msg)
		}
		// We clear the ACME account URI as we have generated a new private key
		a.issuer.GetStatus().ACMEStatus().URI = ""

	case a.issuer.GetSpec().ACME.DisableAccountKeyGeneration && apierrors.IsNotFound(err):
		wrapErr := fmt.Errorf("%s%s%v", messageAccountVerificationFailed,
			messageNoSecretKeyGenerationDisabled,
			err)
		reason = errorAccountVerificationFailed
		msg = wrapErr.Error()
		// TODO: we should not re-queue the Issuer here as a resync will happen
		// when the user adds the Secret or changes Issuer's spec. Should be
		// fixed by https://github.com/cert-manager/cert-manager/issues/4004
		return wrapErr

	case errors.IsInvalidData(err):
		reason = errorAccountVerificationFailed
		msg = fmt.Sprintf("%s%v", messageInvalidPrivateKey, err)
		return nil

	case err != nil:
		reason = errorAccountVerificationFailed
		msg = messageAccountVerificationFailed + err.Error()
		return fmt.Errorf("%s", msg)
	}
	rsaPk, ok := pk.(*rsa.PrivateKey)
	if !ok {
		reason = errorAccountVerificationFailed
		msg = fmt.Sprintf(messageTemplateNotRSA,
			a.issuer.GetSpec().ACME.PrivateKey.Name)
		return nil
	}

	isPKChecksumSame := a.accountRegistry.IsKeyCheckSumCached(a.issuer.GetStatus().ACMEStatus().LastPrivateKeyHash, rsaPk)

	// TODO: don't always clear the client cache.
	//  In future we should intelligently manage items in the account cache
	//  and remove them when the corresponding issuer is updated/deleted.
	// TODO: if we fail earlier, the issuer is considered not ready and we
	// probably don't want other controllers to use its client from the cache.
	// We could therefore move the removing of the client up to the start of
	// this function.
	a.accountRegistry.RemoveClient(string(a.issuer.GetUID()))

	httpClient := accounts.BuildHTTPClientWithCABundle(a.metrics, a.issuer.GetSpec().ACME.SkipTLSVerify, a.issuer.GetSpec().ACME.CABundle)

	cl := a.clientBuilder(httpClient, *a.issuer.GetSpec().ACME, rsaPk, a.userAgent)

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
		reason = errorInvalidURL
		msg = fmt.Sprintf(messageTemplateFailedToParseURL, rawServerURL, err)
		a.recorder.Event(a.issuer, corev1.EventTypeWarning, errorInvalidURL, msg)
		// absorb errors as retrying will not help resolve this error
		return nil
	}

	rawAccountURL := a.issuer.GetStatus().ACMEStatus().URI
	parsedAccountURL, err := url.Parse(rawAccountURL)
	if err != nil {
		reason = errorInvalidURL
		msg = fmt.Sprintf(messageTemplateFailedToParseAccountURL, rawAccountURL, err)
		a.recorder.Event(a.issuer, corev1.EventTypeWarning, errorInvalidURL, msg)
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
		a.issuer.GetStatus().ACMEStatus().LastRegisteredEmail == a.issuer.GetSpec().ACME.Email &&
		isPKChecksumSame {
		log.V(logf.InfoLevel).Info("skipping re-verifying ACME account as cached registration " +
			"details look sufficient")

		// Updating issuer's Ready condition here will ensure that observed
		// generation gets bumped correctly if this re-sync was triggered by a
		// spec change. Last transition time on the condition will not be modified.
		// TODO: perhaps we should retrieve the existing message and reason.
		reason = successAccountRegistered
		msg = messageAccountRegistered
		status = cmmeta.ConditionTrue

		// ensure the cached client in the account registry is up to date
		a.accountRegistry.AddClient(httpClient, string(a.issuer.GetUID()), *a.issuer.GetSpec().ACME, rsaPk, a.userAgent)
		return nil
	}

	if parsedAccountURL.Host != parsedServerURL.Host {
		log.V(logf.InfoLevel).Info("ACME server URL host and ACME private key registration " +
			"host differ. Re-checking ACME account registration")
		a.issuer.GetStatus().ACMEStatus().URI = ""
	}

	var eabAccount *acmeapi.ExternalAccountBinding
	if eabObj := a.issuer.GetSpec().ACME.ExternalAccountBinding; eabObj != nil {
		eabKey, err := a.getEABKey(ctx, ns)
		switch {
		// Do not re-try if we fail to get the MAC key as it does not exist at the reference.
		case apierrors.IsNotFound(err), errors.IsInvalidData(err):
			log.Error(err, "failed to verify ACME account")
			reason = errorAccountRegistrationFailed
			msg = messageAccountRegistrationFailed + err.Error()
			a.recorder.Event(a.issuer, corev1.EventTypeWarning,
				errorAccountRegistrationFailed,
				msg)
			return nil

		case err != nil:
			reason = errorAccountRegistrationFailed
			msg = messageAccountRegistrationFailed + err.Error()
			return fmt.Errorf("%s", msg)
		}

		// set the external account binding
		eabAccount = &acmeapi.ExternalAccountBinding{
			KID: eabObj.KeyID,
			Key: eabKey,
		}
	}

	// register an ACME account or retrieve it if it already exists.
	account, err := a.registerAccount(ctx, cl, eabAccount)
	if err != nil {
		// TODO: this error could be from an account registration or an attempt
		// to retrieve an existing account - perhaps we should log different
		// messages in those two scenarios.
		reason = errorAccountRegistrationFailed
		msg = messageAccountRegistrationFailed + err.Error()
		log.Error(err, "failed to register an ACME account")

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
		reason = errorAccountUpdateFailed
		msg = messageAccountUpdateFailed + err.Error()
		log.Error(err, "failed to update ACME account")
		a.recorder.Event(a.issuer, corev1.EventTypeWarning, errorAccountUpdateFailed, msg)

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
	status = cmmeta.ConditionTrue
	reason = successAccountRegistered
	msg = messageAccountRegistered
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(rsaPk)
	checksum := sha256.Sum256(privateKeyBytes)
	checksumString := base64.StdEncoding.EncodeToString(checksum[:])
	a.issuer.GetStatus().ACMEStatus().URI = account.URI
	a.issuer.GetStatus().ACMEStatus().LastRegisteredEmail = registeredEmail
	a.issuer.GetStatus().ACMEStatus().LastPrivateKeyHash = checksumString
	// ensure the cached client in the account registry is up to date
	a.accountRegistry.AddClient(httpClient, string(a.issuer.GetUID()), *a.issuer.GetSpec().ACME, rsaPk, a.userAgent)

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

	// private key, server URL and HTTP options are stored in the ACME client (cl).
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

func (a *Acme) getEABKey(ctx context.Context, ns string) ([]byte, error) {
	eab := a.issuer.GetSpec().ACME.ExternalAccountBinding.Key
	sec, err := a.secretsClient.Secrets(ns).Get(ctx, eab.Name, metav1.GetOptions{})
	// Surface IsNotFound API error to not cause re-sync
	if apierrors.IsNotFound(err) {
		return nil, err
	}

	if err != nil {
		return nil, fmt.Errorf(messageTemplateFailedToGetEABKey, err)
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
func (a *Acme) createAccountPrivateKey(ctx context.Context, sel cmmeta.SecretKeySelector, ns string) (*rsa.PrivateKey, error) {
	sel = acme.PrivateKeySelector(sel)
	accountPrivKey, err := pki.GenerateRSAPrivateKey(pki.MinRSAKeySize)
	if err != nil {
		return nil, err
	}

	_, err = a.secretsClient.Secrets(ns).Create(ctx, &corev1.Secret{
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

var (
	acmev1Staging = "https://acme-staging.api.letsencrypt.org/directory"
	acmev1Prod    = "https://acme-v01.api.letsencrypt.org/directory"
	acmev2Staging = "https://acme-staging-v02.api.letsencrypt.org/directory"
	acmev2Prod    = "https://acme-v02.api.letsencrypt.org/directory"
)

var acmev1ToV2Mappings = map[string]string{
	acmev1Prod:    acmev2Prod,
	acmev1Staging: acmev2Staging,
	// trailing slashes for v1 URLs
	fmt.Sprintf("%s/", acmev1Prod):    acmev2Prod,
	fmt.Sprintf("%s/", acmev1Staging): acmev2Staging,
}
