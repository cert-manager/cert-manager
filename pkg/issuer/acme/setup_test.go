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
	"crypto"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"testing"
	"time"

	acmeapi "golang.org/x/crypto/acme"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakeclock "k8s.io/utils/clock/testing"

	"github.com/cert-manager/cert-manager/pkg/acme/accounts"
	fakeregistry "github.com/cert-manager/cert-manager/pkg/acme/accounts/test"
	acmecl "github.com/cert-manager/cert-manager/pkg/acme/client"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	controllertest "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/pkg/util/errors"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/coreclients"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func TestAcme_Setup(t *testing.T) {
	var (
		fixedClockStart = time.Now()
		fakeclock       = fakeclock.NewFakeClock(fixedClockStart)
		nowMetaTime     = metav1.NewTime(fakeclock.Now())

		baseIssuer = gen.Issuer("test-issuer",
			gen.SetIssuerACMEURL(acmev2Prod))
		// base issuer's conditions
		readyFalseCondition = gen.IssuerCondition(cmapi.IssuerConditionReady,
			gen.SetIssuerConditionStatus(cmmeta.ConditionFalse),
			gen.SetIssuerConditionLastTransitionTime(&nowMetaTime))
		readyTrueCondition = gen.IssuerCondition(cmapi.IssuerConditionReady,
			gen.SetIssuerConditionStatus(cmmeta.ConditionTrue),
			gen.SetIssuerConditionReason(successAccountRegistered),
			gen.SetIssuerConditionMessage(messageAccountRegistered),
			gen.SetIssuerConditionLastTransitionTime(&nowMetaTime))
		issuerSecretKeyName = "test"

		ecdsaPrivKey = mustGenerateEDCSAKey(t)
		rsaPrivKey   = mustGenerateRSAKey(t)

		notFoundErr    = apierrors.NewNotFound(corev1.Resource("test"), "test")
		invalidDataErr = errors.NewInvalidData("test")
		someErr        = fmt.Errorf("test")
		invalidURL     = "%"
		acmeErr450     = &acmeapi.Error{StatusCode: 450}
		acmeErr500     = &acmeapi.Error{StatusCode: 500}
		//TODO: we should probably mock calls to net/url instead of doing this.
		invalidURLErr = parseURLErr(invalidURL)

		invalidURLMessage        = fmt.Sprintf(messageTemplateFailedToParseURL, invalidURL, invalidURLErr)
		invalidAccountURLMessage = fmt.Sprintf(messageTemplateFailedToParseAccountURL, invalidURL, invalidURLErr)

		someEmail    = "test@test.com"
		someEmailURL = fmt.Sprintf("mailto:%s", someEmail)

		// to be used where we don't care what value is passed
		someString = "test"

		// eabSecret is a mock value for secret with EAB key that user would have created.
		// 'ZEdWemRBbz0K' is 'test' double base64-encoded.
		// cert-manager only accepts double-encoded values, see https://github.com/cert-manager/cert-manager/pull/3877#discussion_r610717791 .
		eabSecret = gen.Secret(someString,
			gen.SetSecretData(map[string][]byte{"key": []byte("ZEdWemRBbz0K")}))

		// 'dGVzdAo=\n' is 'ZEdWemRBbz0K' decoded + a newline.
		// This is the decoded EAB key that we send to the ACME server.
		// TODO: could the newline cause any issues?
		eabKey = "dGVzdAo=\n"
	)

	tests := map[string]struct {
		issuer cmapi.GenericIssuer

		// Private key returned by keyFromSecret stub.
		kfsKey crypto.Signer
		// Error returned by keyFromSecret stub.
		kfsErr error

		// Whether RemoveClient should be called.
		removeClientShouldBeCalled bool

		// Whether AddClient should be called.
		addClientShouldBeCalled bool

		// Error returned by cl.Register
		registerErr error

		// ACME account returned by cl.GetReg
		getRegAcc *acmeapi.Account
		// Error returned by cl.GetReg
		getRegErr error

		// Error return by cl.UpdateRegistration
		updateRegError error

		// Error returned when creating ACME account key.
		acmePrivKeySecretCreateErr error
		// ACME account key created by createAccountPrivateKey.
		acmePrivKey *rsa.PrivateKey

		eabSecret       *corev1.Secret
		eabSecretGetErr error

		// expected ACME account passed to cl.Register
		expectedRegisteredAcc *acmeapi.Account
		// expected issuer conditions after Setup has been called.
		expectedConditions []cmapi.IssuerCondition
		expectedEvents     []string
		wantsErr           bool
	}{
		"LetsEncrypt ACME v1 prod URL specified, return early": {
			issuer: gen.IssuerFrom(baseIssuer,
				gen.SetIssuerACMEURL(acmev1Prod)),
			expectedConditions: []cmapi.IssuerCondition{
				*gen.IssuerConditionFrom(readyFalseCondition,
					gen.SetIssuerConditionReason(errorInvalidConfig),
					gen.SetIssuerConditionMessage(fmt.Sprintf(messageTemplateUpdateToV2, acmev1Prod, acmev2Prod))),
			},
		},
		"LetsEncrypt ACME v1 staging URL with trailing slash specified, return early": {
			issuer: gen.IssuerFrom(baseIssuer,
				gen.SetIssuerACMEURL(fmt.Sprintf("%s/", acmev1Staging))),
			expectedConditions: []cmapi.IssuerCondition{
				*gen.IssuerConditionFrom(readyFalseCondition,
					gen.SetIssuerConditionReason(errorInvalidConfig),
					gen.SetIssuerConditionMessage(fmt.Sprintf(messageTemplateUpdateToV2, fmt.Sprintf("%s/", acmev1Staging), acmev2Staging))),
			},
		},
		"ACME private key secret does not exist, account key generation not disabled, key secret creation fails": {
			issuer: gen.IssuerFrom(baseIssuer,
				gen.SetIssuerACMEPrivKeyRef(issuerSecretKeyName)),
			kfsErr:                     notFoundErr,
			acmePrivKeySecretCreateErr: someErr,
			expectedConditions: []cmapi.IssuerCondition{
				*gen.IssuerConditionFrom(readyFalseCondition,
					gen.SetIssuerConditionReason(errorAccountRegistrationFailed),
					gen.SetIssuerConditionMessage(messageAccountRegistrationFailed+someErr.Error())),
			},
			wantsErr: true,
		},
		"ACME private key secret does not exist, account key generation is disabled": {
			issuer: gen.IssuerFrom(baseIssuer,
				gen.SetIssuerACMEDisableAccountKeyGeneration(true),
			),
			kfsErr: notFoundErr,
			expectedConditions: []cmapi.IssuerCondition{
				*gen.IssuerConditionFrom(readyFalseCondition,
					gen.SetIssuerConditionReason(errorAccountVerificationFailed),
					gen.SetIssuerConditionMessage(messageAccountVerificationFailed+messageNoSecretKeyGenerationDisabled+notFoundErr.Error())),
			},
			wantsErr: true,
		},
		"ACME private key secret does not exist, account key generation is enabled, key creation succeeds": {
			issuer:      gen.IssuerFrom(baseIssuer),
			kfsErr:      notFoundErr,
			acmePrivKey: rsaPrivKey.(*rsa.PrivateKey),
			expectedConditions: []cmapi.IssuerCondition{
				*gen.IssuerConditionFrom(readyTrueCondition)},
			removeClientShouldBeCalled: true,
			addClientShouldBeCalled:    true,
			expectedRegisteredAcc:      &acmeapi.Account{},
		},
		"ACME private key secret exists, but contains invalid private key": {
			issuer: gen.IssuerFrom(baseIssuer),
			kfsErr: invalidDataErr,
			expectedConditions: []cmapi.IssuerCondition{
				*gen.IssuerConditionFrom(readyFalseCondition,
					gen.SetIssuerConditionReason(errorAccountVerificationFailed),
					gen.SetIssuerConditionMessage(fmt.Sprintf("%s%v", messageInvalidPrivateKey, invalidDataErr))),
			},
		},
		"Checking ACME private key secret fails with an unknown error": {
			issuer: gen.IssuerFrom(baseIssuer),
			kfsErr: someErr,
			expectedConditions: []cmapi.IssuerCondition{
				*gen.IssuerConditionFrom(readyFalseCondition,
					gen.SetIssuerConditionReason(errorAccountVerificationFailed),
					gen.SetIssuerConditionMessage(messageAccountVerificationFailed+someErr.Error())),
			},
			wantsErr: true,
		},
		"ACME account's key is not an RSA key": {
			issuer: gen.IssuerFrom(baseIssuer,
				gen.SetIssuerACMEPrivKeyRef(issuerSecretKeyName)),
			kfsKey: ecdsaPrivKey,
			expectedConditions: []cmapi.IssuerCondition{
				*gen.IssuerConditionFrom(readyFalseCondition,
					gen.SetIssuerConditionReason(errorAccountVerificationFailed),
					gen.SetIssuerConditionMessage(fmt.Sprintf(messageTemplateNotRSA, issuerSecretKeyName))),
			},
		},
		"ACME server URL is an invalid URL": {
			issuer: gen.IssuerFrom(baseIssuer,
				gen.SetIssuerACMEURL(invalidURL)),
			kfsKey:                     rsaPrivKey,
			removeClientShouldBeCalled: true,
			expectedConditions: []cmapi.IssuerCondition{
				*gen.IssuerConditionFrom(readyFalseCondition,
					gen.SetIssuerConditionReason(errorInvalidURL),
					gen.SetIssuerConditionMessage(invalidURLMessage)),
			},
			expectedEvents: []string{
				fmt.Sprintf("%s %s %s", corev1.EventTypeWarning, errorInvalidURL, invalidURLMessage)},
		},
		"ACME account URL is an invalid URL": {
			issuer: gen.IssuerFrom(baseIssuer,
				gen.SetIssuerACMEAccountURL(invalidURL)),
			kfsKey:                     rsaPrivKey,
			removeClientShouldBeCalled: true,
			expectedConditions: []cmapi.IssuerCondition{
				*gen.IssuerConditionFrom(readyFalseCondition,
					gen.SetIssuerConditionReason(errorInvalidURL),
					gen.SetIssuerConditionMessage(invalidAccountURLMessage)),
			},
			expectedEvents: []string{
				fmt.Sprintf("%s %s %s", corev1.EventTypeWarning, errorInvalidURL, invalidAccountURLMessage),
			},
		},
		"ACME Issuer is ready, URL and email are matching": {
			issuer: gen.IssuerFrom(baseIssuer,
				gen.SetIssuerACMEAccountURL(acmev2Prod),
				gen.SetIssuerACMEEmail(someEmail),
				gen.SetIssuerACMELastRegisteredEmail(someEmail),
				gen.SetIssuerACMELastPrivateKeyHash(someString),
				gen.AddIssuerCondition(
					*gen.IssuerConditionFrom(readyTrueCondition,
						gen.SetIssuerConditionStatus(cmmeta.ConditionTrue)))),
			expectedConditions: []cmapi.IssuerCondition{
				*gen.IssuerConditionFrom(readyTrueCondition,
					gen.SetIssuerConditionStatus(cmmeta.ConditionTrue),
					gen.SetIssuerConditionMessage(messageAccountRegistered),
					gen.SetIssuerConditionReason(successAccountRegistered)),
			},
			kfsKey:                     rsaPrivKey,
			removeClientShouldBeCalled: true,
			addClientShouldBeCalled:    true,
		},
		"EAB for issuer specified, but the corresponding secret is not found": {
			issuer: gen.IssuerFrom(baseIssuer,
				gen.SetIssuerACMEEAB(someString, someString)),
			kfsKey:                     rsaPrivKey,
			removeClientShouldBeCalled: true,
			eabSecretGetErr:            notFoundErr,
			expectedConditions: []cmapi.IssuerCondition{
				*gen.IssuerConditionFrom(readyFalseCondition,
					gen.SetIssuerConditionReason(errorAccountRegistrationFailed),
					gen.SetIssuerConditionMessage(messageAccountRegistrationFailed+notFoundErr.Error())),
			},
			expectedEvents: []string{
				fmt.Sprintf("%s %s %s", corev1.EventTypeWarning, errorAccountRegistrationFailed, messageAccountRegistrationFailed+notFoundErr.Error()),
			},
		},
		"EAB for issuer specified, attempting to retrieve secret fails with unknown error": {
			issuer: gen.IssuerFrom(baseIssuer,
				gen.SetIssuerACMEEAB(someString, someString)),
			kfsKey:                     rsaPrivKey,
			removeClientShouldBeCalled: true,
			eabSecretGetErr:            someErr,
			expectedConditions: []cmapi.IssuerCondition{
				*gen.IssuerConditionFrom(readyFalseCondition,
					gen.SetIssuerConditionReason(errorAccountRegistrationFailed),
					gen.SetIssuerConditionMessage(messageAccountRegistrationFailed+fmt.Sprintf(messageTemplateFailedToGetEABKey, someErr))),
			},
			wantsErr: true,
		},
		"Attempt to register ACME account returns unknown error": {
			issuer:                     gen.IssuerFrom(baseIssuer),
			kfsKey:                     rsaPrivKey,
			removeClientShouldBeCalled: true,
			registerErr:                someErr,
			expectedRegisteredAcc:      &acmeapi.Account{},
			expectedConditions: []cmapi.IssuerCondition{
				*gen.IssuerConditionFrom(readyFalseCondition,
					gen.SetIssuerConditionReason(errorAccountRegistrationFailed),
					gen.SetIssuerConditionMessage(messageAccountRegistrationFailed+someErr.Error())),
			},
			wantsErr: true,
		},
		"Attempt to register ACME account returns an ACME error in range [400,500)": {
			issuer:                     gen.IssuerFrom(baseIssuer),
			kfsKey:                     rsaPrivKey,
			removeClientShouldBeCalled: true,
			expectedRegisteredAcc:      &acmeapi.Account{},
			registerErr:                acmeErr450,
			expectedConditions: []cmapi.IssuerCondition{
				*gen.IssuerConditionFrom(readyFalseCondition,
					gen.SetIssuerConditionReason(errorAccountRegistrationFailed),
					gen.SetIssuerConditionMessage(messageAccountRegistrationFailed+acmeErr450.Error())),
			},
		},
		"Attempt to register ACME account returns an ACME error outside of range [400,500)": {
			issuer:                     gen.IssuerFrom(baseIssuer),
			kfsKey:                     rsaPrivKey,
			removeClientShouldBeCalled: true,
			expectedRegisteredAcc:      &acmeapi.Account{},
			registerErr:                acmeErr500,
			expectedConditions: []cmapi.IssuerCondition{
				*gen.IssuerConditionFrom(readyFalseCondition,
					gen.SetIssuerConditionReason(errorAccountRegistrationFailed),
					gen.SetIssuerConditionMessage(messageAccountRegistrationFailed+acmeErr500.Error())),
			},
			wantsErr: true,
		},
		"ACME account already exists, attempting to retrieve it fails with unknown error": {
			issuer:                     gen.IssuerFrom(baseIssuer),
			kfsKey:                     rsaPrivKey,
			removeClientShouldBeCalled: true,
			expectedRegisteredAcc:      &acmeapi.Account{},
			registerErr:                acmeapi.ErrAccountAlreadyExists,
			getRegErr:                  someErr,
			expectedConditions: []cmapi.IssuerCondition{
				*gen.IssuerConditionFrom(readyFalseCondition,
					gen.SetIssuerConditionReason(errorAccountRegistrationFailed),
					gen.SetIssuerConditionMessage(messageAccountRegistrationFailed+someErr.Error())),
			},
			wantsErr: true,
		},
		"ACME account with EAB registered successfully": {
			issuer: gen.IssuerFrom(baseIssuer,
				gen.SetIssuerACMEEAB(someString, someString)),
			kfsKey:                     rsaPrivKey,
			removeClientShouldBeCalled: true,
			addClientShouldBeCalled:    true,
			eabSecret:                  eabSecret,
			expectedRegisteredAcc: &acmeapi.Account{ExternalAccountBinding: &acmeapi.ExternalAccountBinding{
				KID: someString,
				Key: []byte(eabKey),
			}},
			expectedConditions: []cmapi.IssuerCondition{
				*gen.IssuerConditionFrom(readyTrueCondition,
					gen.SetIssuerConditionStatus(cmmeta.ConditionTrue),
					gen.SetIssuerConditionReason(successAccountRegistered),
					gen.SetIssuerConditionMessage(messageAccountRegistered)),
			},
		},
		"ACME account with legacy EAB key algorithm set and with an email is registered successfully": {
			issuer: gen.IssuerFrom(baseIssuer,
				gen.SetIssuerACMEEmail(someEmail),
				gen.SetIssuerACMEEABWithKeyAlgorithm(someString, someString, cmacme.HS256)),
			kfsKey:                     rsaPrivKey,
			removeClientShouldBeCalled: true,
			addClientShouldBeCalled:    true,
			eabSecret:                  eabSecret,
			expectedRegisteredAcc: &acmeapi.Account{ExternalAccountBinding: &acmeapi.ExternalAccountBinding{
				KID: someString,
				Key: []byte(eabKey),
			},
				Contact: []string{someEmailURL},
			},
			expectedConditions: []cmapi.IssuerCondition{
				*gen.IssuerConditionFrom(readyTrueCondition,
					gen.SetIssuerConditionStatus(cmmeta.ConditionTrue),
					gen.SetIssuerConditionReason(successAccountRegistered),
					gen.SetIssuerConditionMessage(messageAccountRegistered)),
			},
		},
		"ACME account with legacy EAB key algorithm set, spec email different from registered email and registered successfully": {
			issuer: gen.IssuerFrom(baseIssuer,
				gen.SetIssuerACMEEmail(someEmail),
				gen.SetIssuerACMEEABWithKeyAlgorithm(someString, someString, cmacme.HS256)),
			kfsKey:                     rsaPrivKey,
			removeClientShouldBeCalled: true,
			addClientShouldBeCalled:    true,
			eabSecret:                  eabSecret,
			registerErr:                acmeapi.ErrAccountAlreadyExists,
			getRegAcc: &acmeapi.Account{ExternalAccountBinding: &acmeapi.ExternalAccountBinding{
				KID: someString,
				Key: []byte(eabKey),
			},
				Contact: []string{"some@test.com"},
			},
			expectedRegisteredAcc: &acmeapi.Account{ExternalAccountBinding: &acmeapi.ExternalAccountBinding{
				KID: someString,
				Key: []byte(eabKey),
			},
				Contact: []string{someEmailURL},
			},
			expectedConditions: []cmapi.IssuerCondition{
				*gen.IssuerConditionFrom(readyTrueCondition,
					gen.SetIssuerConditionStatus(cmmeta.ConditionTrue),
					gen.SetIssuerConditionReason(successAccountRegistered),
					gen.SetIssuerConditionMessage(messageAccountRegistered)),
			},
		},
		"ACME account with legacy EAB key algorithm set, spec email different from registered email and registered failed": {
			issuer: gen.IssuerFrom(baseIssuer,
				gen.SetIssuerACMEEmail(someEmail),
				gen.SetIssuerACMEEABWithKeyAlgorithm(someString, someString, cmacme.HS256)),
			kfsKey:                     rsaPrivKey,
			removeClientShouldBeCalled: true,
			eabSecret:                  eabSecret,
			registerErr:                acmeapi.ErrAccountAlreadyExists,
			getRegAcc: &acmeapi.Account{ExternalAccountBinding: &acmeapi.ExternalAccountBinding{
				KID: someString,
				Key: []byte(eabKey),
			},
				Contact: []string{"some@test.com"},
			},
			expectedRegisteredAcc: &acmeapi.Account{ExternalAccountBinding: &acmeapi.ExternalAccountBinding{
				KID: someString,
				Key: []byte(eabKey),
			},
				Contact: []string{someEmailURL},
			},
			updateRegError: someErr,
			wantsErr:       true,
			expectedConditions: []cmapi.IssuerCondition{
				*gen.IssuerConditionFrom(readyTrueCondition,
					gen.SetIssuerConditionStatus(cmmeta.ConditionFalse),
					gen.SetIssuerConditionReason(errorAccountUpdateFailed),
					gen.SetIssuerConditionMessage(fmt.Sprintf("%s%s", messageAccountUpdateFailed, someString))),
			},
			expectedEvents: []string{
				fmt.Sprintf("%s %s %s", corev1.EventTypeWarning, errorAccountUpdateFailed, fmt.Sprintf("%s%s", messageAccountUpdateFailed, someString))},
		},
		"ACME account with legacy EAB key algorithm set, spec email different from registered email and registered failed with non-retryable ACME Error": {
			issuer: gen.IssuerFrom(baseIssuer,
				gen.SetIssuerACMEEmail(someEmail),
				gen.SetIssuerACMEEABWithKeyAlgorithm(someString, someString, cmacme.HS256)),
			kfsKey:                     rsaPrivKey,
			removeClientShouldBeCalled: true,
			eabSecret:                  eabSecret,
			registerErr:                acmeapi.ErrAccountAlreadyExists,
			getRegAcc: &acmeapi.Account{ExternalAccountBinding: &acmeapi.ExternalAccountBinding{
				KID: someString,
				Key: []byte(eabKey),
			},
				Contact: []string{"some@test.com"},
			},
			expectedRegisteredAcc: &acmeapi.Account{ExternalAccountBinding: &acmeapi.ExternalAccountBinding{
				KID: someString,
				Key: []byte(eabKey),
			},
				Contact: []string{someEmailURL},
			},
			updateRegError: acmeErr450,
			wantsErr:       false,
			expectedConditions: []cmapi.IssuerCondition{
				*gen.IssuerConditionFrom(readyTrueCondition,
					gen.SetIssuerConditionStatus(cmmeta.ConditionFalse),
					gen.SetIssuerConditionReason(errorAccountUpdateFailed),
					gen.SetIssuerConditionMessage(fmt.Sprintf("%s%s", messageAccountUpdateFailed, acmeErr450.Error()))),
			},
			expectedEvents: []string{
				fmt.Sprintf("%s %s %s", corev1.EventTypeWarning, errorAccountUpdateFailed, fmt.Sprintf("%s%s", messageAccountUpdateFailed, acmeErr450.Error()))},
		},
		"ACME account with legacy EAB key algorithm set, spec email different from registered email and registered failed with retryable ACME Error": {
			issuer: gen.IssuerFrom(baseIssuer,
				gen.SetIssuerACMEEmail(someEmail),
				gen.SetIssuerACMEEABWithKeyAlgorithm(someString, someString, cmacme.HS256)),
			kfsKey:                     rsaPrivKey,
			removeClientShouldBeCalled: true,
			eabSecret:                  eabSecret,
			registerErr:                acmeapi.ErrAccountAlreadyExists,
			getRegAcc: &acmeapi.Account{ExternalAccountBinding: &acmeapi.ExternalAccountBinding{
				KID: someString,
				Key: []byte(eabKey),
			},
				Contact: []string{"some@test.com"},
			},
			expectedRegisteredAcc: &acmeapi.Account{ExternalAccountBinding: &acmeapi.ExternalAccountBinding{
				KID: someString,
				Key: []byte(eabKey),
			},
				Contact: []string{someEmailURL},
			},
			updateRegError: acmeErr500,
			wantsErr:       true,
			expectedConditions: []cmapi.IssuerCondition{
				*gen.IssuerConditionFrom(readyTrueCondition,
					gen.SetIssuerConditionStatus(cmmeta.ConditionFalse),
					gen.SetIssuerConditionReason(errorAccountUpdateFailed),
					gen.SetIssuerConditionMessage(fmt.Sprintf("%s%s", messageAccountUpdateFailed, acmeErr500.Error()))),
			},
			expectedEvents: []string{
				fmt.Sprintf("%s %s %s", corev1.EventTypeWarning, errorAccountUpdateFailed, fmt.Sprintf("%s%s", messageAccountUpdateFailed, acmeErr500.Error()))},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {

			// Secrets client that will be called from the Setup function to
			// create new secrets and get EAB secret.
			// TODO: this secretsClient fake is really hacky. It relies on the
			// fact that the Setup function currently only uses secretsClient to
			// create account private key secret and to retrieve the EAB secret.
			// We should refactor the Setup function and test this in a better way.
			secretsClient := coreclients.NewFakeSecretsGetterFrom(
				coreclients.NewFakeSecretsGetter(),
				coreclients.SetFakeSecretsGetterCreate(nil,
					test.acmePrivKeySecretCreateErr),
				coreclients.SetFakeSecretsGetterGet(test.eabSecret,
					test.eabSecretGetErr),
			)

			// Set up a mock keyFromSecret.
			kfsWasCalled := false
			kfs := keyFromSecretMockBuilder(&(kfsWasCalled), test.kfsKey, test.kfsErr)

			// Mock ACME accounts registry.
			removeClientWasCalled := false
			addClientWasCalled := false
			ar := &fakeregistry.FakeRegistry{
				RemoveClientFunc: func(string) {
					removeClientWasCalled = true
				},
				AddClientFunc: func(string, cmacme.ACMEIssuer, *rsa.PrivateKey, string) {
					addClientWasCalled = true
				},
				IsKeyCheckSumCachedFunc: func(lastPrivateKeyHash string, privateKey *rsa.PrivateKey) bool {
					return true
				},
			}

			// Mock ACME client.
			var gotAcc *acmeapi.Account
			cl := acmecl.FakeACME{
				FakeRegister: func(_ context.Context, a *acmeapi.Account, _ func(string) bool) (*acmeapi.Account, error) {
					gotAcc = a
					return a, test.registerErr
				},
				FakeGetReg: func(context.Context, string) (*acmeapi.Account, error) {
					return test.getRegAcc, test.getRegErr
				},
				FakeUpdateReg: func(ctx context.Context, a *acmeapi.Account) (*acmeapi.Account, error) {
					return a, test.updateRegError
				},
			}

			// Mock events recorder.
			recorder := new(controllertest.FakeRecorder)
			a := Acme{
				issuer:          test.issuer,
				secretsClient:   secretsClient,
				accountRegistry: ar,
				keyFromSecret:   kfs,
				clientBuilder:   clientBuilderMock(&cl),
				recorder:        recorder,
			}

			// Stub the clock to get consistent last transition times on conditions.
			fakeclock.SetTime(fixedClockStart)
			apiutil.Clock = fakeclock

			// Verify that an error is/is not returned as expected.
			gotErr := a.Setup(context.Background())
			if gotErr == nil && test.wantsErr {
				t.Errorf("Expected error %v, got %v", test.wantsErr, gotErr)
			}

			// Verify that a client was removed from cache if expected.
			if removeClientWasCalled != test.removeClientShouldBeCalled {
				t.Errorf("Expected Acme.accountsRegistry.RemoveClient to be called: %v, was called: %v",
					test.removeClientShouldBeCalled,
					removeClientWasCalled)
			}

			// Verify that a new client was added to cache if expected.
			if addClientWasCalled != test.addClientShouldBeCalled {
				t.Errorf("Expected Acme.accountsRegistry.AddClient to be called: %v, was called: %v",
					test.addClientShouldBeCalled,
					addClientWasCalled)
			}

			// Verify that the expected account value was passed when the
			// account was registered.
			if !reflect.DeepEqual(gotAcc, test.expectedRegisteredAcc) {
				t.Errorf("Expected account value passed to register: %#+v\ngot: %+#v",
					test.expectedRegisteredAcc, gotAcc)
			}

			// Verify issuer's state after Setup was called.
			gotConditions := a.issuer.GetStatus().Conditions
			// Issuer can only have a single condition, so no need to sort the
			// conditions.
			if !reflect.DeepEqual(gotConditions, test.expectedConditions) {
				t.Errorf("Expected issuer's conditions: %#+v\ngot: %#+v",
					test.expectedConditions, gotConditions)
			}

			// Verify that the expected events were recorded.
			if !slices.Equal(test.expectedEvents, recorder.Events) {
				t.Errorf("Expected events:\n%+#v\ngot:%+#v",
					test.expectedEvents,
					recorder.Events)
			}
		})
	}
}

// keyFromSecretMockBuilder returns a mock implementation of keyFromSecretFunc.
func keyFromSecretMockBuilder(wasCalled *bool, key crypto.Signer, err error) keyFromSecretFunc {
	return func(context.Context, string, string, string) (crypto.Signer, error) {
		*wasCalled = true
		return key, err
	}
}

func clientBuilderMock(cl acmecl.Interface) accounts.NewClientFunc {
	return func(*http.Client, cmacme.ACMEIssuer, *rsa.PrivateKey, string) acmecl.Interface {
		return cl
	}
}

func parseURLErr(s string) error {
	_, err := url.Parse(s)
	return err
}

func mustGenerateEDCSAKey(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := pki.GenerateECPrivateKey(256)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustGenerateRSAKey(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := pki.GenerateRSAPrivateKey(pki.MinRSAKeySize)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
