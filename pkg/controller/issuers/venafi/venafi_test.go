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

package venafi

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"

	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/pkg/controller"
	controllertest "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/pkg/internal/venafi"
	internalvenafifake "github.com/jetstack/cert-manager/pkg/internal/venafi/fake"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

func TestSetup(t *testing.T) {
	baseIssuer := gen.Issuer("test-issuer")

	failingClientBuilder := func(string, corelisters.SecretLister,
		cmapi.GenericIssuer) (venafi.Interface, error) {
		return nil, errors.New("this is an error")
	}

	failingPingClient := func(string, corelisters.SecretLister,
		cmapi.GenericIssuer) (venafi.Interface, error) {
		return &internalvenafifake.Venafi{
			PingFn: func() error {
				return errors.New("this is a ping error")
			},
		}, nil
	}

	pingClient := func(string, corelisters.SecretLister,
		cmapi.GenericIssuer) (venafi.Interface, error) {
		return &internalvenafifake.Venafi{
			PingFn: func() error {
				return nil
			},
		}, nil
	}

	tests := map[string]testSetupT{
		"if client builder fails then should error": {
			clientBuilder: failingClientBuilder,
			expectedErr:   true,
			iss:           baseIssuer.DeepCopy(),
			expectedCondition: &cmapi.IssuerCondition{
				Reason:  "ErrorSetup",
				Message: "Failed to setup Venafi issuer: error building client: this is an error",
				Status:  "False",
			},
		},

		"if ping fails then should error": {
			clientBuilder: failingPingClient,
			iss:           baseIssuer.DeepCopy(),
			expectedErr:   true,
			expectedCondition: &cmapi.IssuerCondition{
				Reason:  "ErrorSetup",
				Message: "Failed to setup Venafi issuer: error pinging Venafi API: this is a ping error",
				Status:  "False",
			},
		},

		"if ready then should set condition": {
			clientBuilder: pingClient,
			iss:           baseIssuer.DeepCopy(),
			expectedErr:   false,
			expectedCondition: &cmapi.IssuerCondition{
				Message: "Venafi issuer started",
				Reason:  "Venafi issuer started",
				Status:  "True",
			},
			expectedEvents: []string{
				"Normal Ready Verified issuer with Venafi server",
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.runTest(t, test.iss)
		})
	}
}

type testSetupT struct {
	clientBuilder venafi.VenafiClientBuilder
	iss           cmapi.GenericIssuer

	expectedErr       bool
	expectedEvents    []string
	expectedCondition *cmapi.IssuerCondition
}

func (s *testSetupT) runTest(t *testing.T, iss cmapi.GenericIssuer) {
	rec := &controllertest.FakeRecorder{}

	v := &Venafi{
		issuerOptions: controller.IssuerOptions{
			ClusterResourceNamespace: "test-namespace",
		},
		recorder:      rec,
		clientBuilder: s.clientBuilder,
	}

	err := v.Setup(context.TODO(), iss)
	if err != nil && !s.expectedErr {
		t.Errorf("expected to not get an error, but got: %v", err)
	}
	if err == nil && s.expectedErr {
		t.Errorf("expected to get an error but did not get one")
	}

	if !util.EqualSorted(s.expectedEvents, rec.Events) {
		t.Errorf("got unexpected events, exp='%s' got='%s'",
			s.expectedEvents, rec.Events)
	}

	conditions := s.iss.GetStatus().Conditions
	if s.expectedCondition == nil &&
		len(conditions) > 0 {
		t.Errorf("expected no conditions but got=%+v",
			conditions)
	}

	if s.expectedCondition != nil {
		if len(conditions) != 1 {
			t.Error("expected conditions but got none")
			t.FailNow()
		}

		c := conditions[0]

		if s.expectedCondition.Message != c.Message {
			t.Errorf("unexpected condition message, exp=%s got=%s",
				s.expectedCondition.Message, c.Message)
		}
		if s.expectedCondition.Reason != c.Reason {
			t.Errorf("unexpected condition reason, exp=%s got=%s",
				s.expectedCondition.Reason, c.Reason)
		}
		if s.expectedCondition.Status != c.Status {
			t.Errorf("unexpected condition status, exp=%s got=%s",
				s.expectedCondition.Status, c.Status)
		}
	}
}

func TestImplements(t *testing.T) {
	tests := map[string]struct {
		issuer        cmapi.GenericIssuer
		expImplements bool
	}{
		// Issuer Kind
		"if nil issuer, exp not implements": {
			issuer:        gen.Issuer("test"),
			expImplements: false,
		},
		"if selfsigned issuer, exp not implements": {
			issuer: gen.Issuer("test",
				gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
			),
			expImplements: false,
		},
		"if ca issuer, exp not implements": {
			issuer: gen.Issuer("test",
				gen.SetIssuerCA(cmapi.CAIssuer{}),
			),
			expImplements: false,
		},
		"if vault issuer, exp not implements": {
			issuer: gen.Issuer("test",
				gen.SetIssuerVault(cmapi.VaultIssuer{}),
			),
			expImplements: false,
		},
		"if venafi issuer, exp implements": {
			issuer: gen.Issuer("test",
				gen.SetIssuerVenafi(cmapi.VenafiIssuer{}),
			),
			expImplements: true,
		},
		"if acme issuer, exp not implements": {
			issuer: gen.Issuer("test",
				gen.SetIssuerACME(cmacme.ACMEIssuer{}),
			),
			expImplements: false,
		},

		// ClusterIssuer Kind
		"if nil cluster issuer, exp not implements": {
			issuer:        gen.ClusterIssuer("test"),
			expImplements: false,
		},
		"if selfsigned cluster	issuer, exp not implements": {
			issuer: gen.ClusterIssuer("test",
				gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
			),
			expImplements: false,
		},
		"if ca cluster issuer, exp not implements": {
			issuer: gen.ClusterIssuer("test",
				gen.SetIssuerCA(cmapi.CAIssuer{}),
			),
			expImplements: false,
		},
		"if vault cluster issuer, exp not implements": {
			issuer: gen.ClusterIssuer("test",
				gen.SetIssuerVault(cmapi.VaultIssuer{}),
			),
			expImplements: false,
		},
		"if venafi cluster issuer, exp implements": {
			issuer: gen.ClusterIssuer("test",
				gen.SetIssuerVenafi(cmapi.VenafiIssuer{}),
			),
			expImplements: true,
		},
		"if acme cluster issuer, exp not implements": {
			issuer: gen.ClusterIssuer("test",
				gen.SetIssuerACME(cmacme.ACMEIssuer{}),
			),
			expImplements: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			i := new(Venafi)
			if impl := i.Implements(test.issuer); impl != test.expImplements {
				t.Errorf("unexpected implements, exp=%t got=%t",
					test.expImplements, impl)
			}
		})
	}
}

func TestReferencesSecret(t *testing.T) {
	tests := map[string]struct {
		issuer        cmapi.GenericIssuer
		secret        *corev1.Secret
		expReferences bool
	}{
		// Issuer Kind
		"if issuer not Venafi, ignore": {
			issuer: gen.Issuer("test"),
			secret: gen.Secret("secret",
				gen.SetSecretNamespace(gen.DefaultTestNamespace),
			),
			expReferences: false,
		},
		"if issuer Venafi, but doesn't reference secret, ignore": {
			issuer: gen.Issuer("test",
				gen.SetIssuerVenafi(cmapi.VenafiIssuer{
					TPP: &cmapi.VenafiTPP{
						CredentialsRef: cmmeta.LocalObjectReference{
							Name: "secret-tpp",
						},
					},
					Cloud: &cmapi.VenafiCloud{
						APITokenSecretRef: cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "secret-cloud",
							},
						},
					},
				}),
			),
			secret: gen.Secret("secret",
				gen.SetSecretNamespace(gen.DefaultTestNamespace),
			),
			expReferences: false,
		},
		"if issuer Venafi, references same tpp secret in another namespace, ignore": {
			issuer: gen.Issuer("test",
				gen.SetIssuerVenafi(cmapi.VenafiIssuer{
					TPP: &cmapi.VenafiTPP{
						CredentialsRef: cmmeta.LocalObjectReference{
							Name: "secret-tpp",
						},
					},
					Cloud: &cmapi.VenafiCloud{
						APITokenSecretRef: cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "secret-cloud",
							},
						},
					},
				}),
			),
			secret: gen.Secret("secret-tpp",
				gen.SetSecretNamespace("ns"),
			),
			expReferences: false,
		},
		"if issuer Venafi, references same tpp secret, return true": {
			issuer: gen.Issuer("test",
				gen.SetIssuerVenafi(cmapi.VenafiIssuer{
					TPP: &cmapi.VenafiTPP{
						CredentialsRef: cmmeta.LocalObjectReference{
							Name: "secret-tpp",
						},
					},
					Cloud: &cmapi.VenafiCloud{
						APITokenSecretRef: cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "secret-cloud",
							},
						},
					},
				}),
			),
			secret: gen.Secret("secret-tpp",
				gen.SetSecretNamespace(gen.DefaultTestNamespace),
			),
			expReferences: true,
		},
		"if issuer Venafi, references same cloud secret, return true": {
			issuer: gen.Issuer("test",
				gen.SetIssuerVenafi(cmapi.VenafiIssuer{
					TPP: &cmapi.VenafiTPP{
						CredentialsRef: cmmeta.LocalObjectReference{
							Name: "secret-tpp",
						},
					},
					Cloud: &cmapi.VenafiCloud{
						APITokenSecretRef: cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "secret-cloud",
							},
						},
					},
				}),
			),
			secret: gen.Secret("secret-cloud",
				gen.SetSecretNamespace(gen.DefaultTestNamespace),
			),
			expReferences: true,
		},

		// ClusterIssuer Kind
		"if cluster issuer not Venafi, ignore": {
			issuer: gen.ClusterIssuer("test"),
			secret: gen.Secret("secret",
				gen.SetSecretNamespace("cert-manager"),
			),
			expReferences: false,
		},
		"if cluster issuer Venafi, but doesn't reference secret, ignore": {
			issuer: gen.ClusterIssuer("test",
				gen.SetIssuerVenafi(cmapi.VenafiIssuer{
					TPP: &cmapi.VenafiTPP{
						CredentialsRef: cmmeta.LocalObjectReference{
							Name: "secret-tpp",
						},
					},
					Cloud: &cmapi.VenafiCloud{
						APITokenSecretRef: cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "secret-cloud",
							},
						},
					},
				}),
			),
			secret: gen.Secret("secret",
				gen.SetSecretNamespace("cert-manager"),
			),
			expReferences: false,
		},
		"if cluster issuer Venafi, references same tpp secret in another namespace, ignore": {
			issuer: gen.ClusterIssuer("test",
				gen.SetIssuerVenafi(cmapi.VenafiIssuer{
					TPP: &cmapi.VenafiTPP{
						CredentialsRef: cmmeta.LocalObjectReference{
							Name: "secret-tpp",
						},
					},
					Cloud: &cmapi.VenafiCloud{
						APITokenSecretRef: cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "secret-cloud",
							},
						},
					},
				}),
			),
			secret: gen.Secret("secret-tpp",
				gen.SetSecretNamespace(gen.DefaultTestNamespace),
			),
			expReferences: false,
		},
		"if cluster issuer Venafi, references same tpp secret, return true": {
			issuer: gen.ClusterIssuer("test",
				gen.SetIssuerVenafi(cmapi.VenafiIssuer{
					TPP: &cmapi.VenafiTPP{
						CredentialsRef: cmmeta.LocalObjectReference{
							Name: "secret-tpp",
						},
					},
					Cloud: &cmapi.VenafiCloud{
						APITokenSecretRef: cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "secret-cloud",
							},
						},
					},
				}),
			),
			secret: gen.Secret("secret-tpp",
				gen.SetSecretNamespace("cert-manager"),
			),
			expReferences: true,
		},
		"if cluster issuer Venafi, references same cloud secret, return true": {
			issuer: gen.ClusterIssuer("test",
				gen.SetIssuerVenafi(cmapi.VenafiIssuer{
					TPP: &cmapi.VenafiTPP{
						CredentialsRef: cmmeta.LocalObjectReference{
							Name: "secret-tpp",
						},
					},
					Cloud: &cmapi.VenafiCloud{
						APITokenSecretRef: cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "secret-cloud",
							},
						},
					},
				}),
			),
			secret: gen.Secret("secret-cloud",
				gen.SetSecretNamespace("cert-manager"),
			),
			expReferences: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			i := new(Venafi)
			i.issuerOptions.ClusterResourceNamespace = "cert-manager"
			if refs := i.ReferencesSecret(test.issuer, test.secret); refs != test.expReferences {
				t.Errorf("unexpected references, exp=%t got=%t",
					test.expReferences, refs)
			}
		})
	}
}
