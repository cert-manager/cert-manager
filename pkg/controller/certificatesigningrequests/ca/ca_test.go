/*
Copyright 2021 The cert-manager Authors.

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

package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authzv1 "k8s.io/api/authorization/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientcorev1 "k8s.io/client-go/listers/core/v1"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	"github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/cmrand"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/util"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"
	testlisters "github.com/cert-manager/cert-manager/test/unit/listers"
)

var (
	fixedClockStart = time.Now()
	fixedClock      = fakeclock.NewFakeClock(fixedClockStart)
)

func generateCSR(t *testing.T, secretKey crypto.Signer) []byte {
	csr, err := gen.CSRWithSigner(secretKey,
		gen.SetCSRCommonName("test"),
	)
	if err != nil {
		t.Fatal(err)
	}

	return csr
}

func generateSelfSignedCACert(t *testing.T, key crypto.Signer, name string) (*x509.Certificate, []byte) {
	tmpl := &x509.Certificate{
		Version:               3,
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(0),
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Minute),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		PublicKey: key.Public(),
		IsCA:      true,
	}

	pem, cert, err := pki.SignCertificate(tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	return cert, pem
}

func TestSign(t *testing.T) {
	metaFixedClockStart := metav1.NewTime(fixedClockStart)
	util.Clock = fixedClock

	baseIssuer := gen.Issuer("test-issuer",
		gen.SetIssuerCA(cmapi.CAIssuer{SecretName: "root-ca-secret"}),
		gen.AddIssuerCondition(cmapi.IssuerCondition{
			Type:   cmapi.IssuerConditionReady,
			Status: cmmeta.ConditionTrue,
		}),
	)

	rootPK, err := pki.GenerateECPrivateKey(256)
	if err != nil {
		t.Fatal(err)
	}
	rootPKPEM, err := pki.EncodeECPrivateKey(rootPK)
	if err != nil {
		t.Fatal(err)
	}

	testpk, err := pki.GenerateECPrivateKey(256)
	if err != nil {
		t.Fatal(err)
	}
	testCSR := generateCSR(t, testpk)

	baseCSRNotApproved := gen.CertificateSigningRequest("test-cr",
		gen.SetCertificateSigningRequestIsCA(true),
		gen.SetCertificateSigningRequestRequest(testCSR),
		gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/"+gen.DefaultTestNamespace+"."+baseIssuer.Name),
		gen.SetCertificateSigningRequestDuration("1440h"),
		gen.SetCertificateSigningRequestUsername("user-1"),
		gen.SetCertificateSigningRequestGroups([]string{"group-1", "group-2"}),
		gen.SetCertificateSigningRequestUID("uid-1"),
		gen.SetCertificateSigningRequestExtra(map[string]certificatesv1.ExtraValue{
			"extra": []string{"1", "2"},
		}),
	)
	baseCSRDenied := gen.CertificateSigningRequestFrom(baseCSRNotApproved,
		gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
			Type:               certificatesv1.CertificateDenied,
			Status:             corev1.ConditionTrue,
			Reason:             "Foo",
			Message:            "Certificate request has been denied by cert-manager.io",
			LastTransitionTime: metaFixedClockStart,
		}),
	)
	baseCSR := gen.CertificateSigningRequestFrom(baseCSRNotApproved,
		gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
			Type:               certificatesv1.CertificateApproved,
			Status:             corev1.ConditionTrue,
			Reason:             "cert-manager.io",
			Message:            "Certificate request has been approved by cert-manager.io",
			LastTransitionTime: metaFixedClockStart,
		}),
	)

	// generate a self signed root ca valid for 60d
	rootCert, rootCertPEM := generateSelfSignedCACert(t, rootPK, "root")
	ecCASecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "root-ca-secret",
			Namespace: gen.DefaultTestNamespace,
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: rootPKPEM,
			corev1.TLSCertKey:       rootCertPEM,
		},
	}

	badDataSecret := ecCASecret.DeepCopy()
	badDataSecret.Data[corev1.TLSPrivateKeyKey] = []byte("bad key")

	template, err := pki.CertificateTemplateFromCertificateSigningRequest(baseCSR)
	if err != nil {
		t.Fatal(err)
	}
	certBundle, err := pki.SignCSRTemplate([]*x509.Certificate{rootCert}, rootPK, template)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]testT{
		"a CertificateSigningRequest without an approved condition should fire event": {
			csr: baseCSRNotApproved.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{baseCSRNotApproved.DeepCopy()},
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Normal WaitingApproval Waiting for the Approved condition before issuing",
				},
			},
		},
		"a CertificateSigningRequest with a denied condition should do nothing": {
			csr: baseCSRDenied.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{baseCSRDenied.DeepCopy()},
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents:     []string{},
				ExpectedActions:    nil,
			},
		},
		"an approved CSR with missing CA key pair should send event and wait for a re-sync": {
			csr: baseCSR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{baseCSR.DeepCopy()},
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					`Warning SecretMissing Referenced secret default-unit-test-ns/root-ca-secret not found`,
				},

				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						authzv1.SchemeGroupVersion.WithResource("subjectaccessreviews"),
						"",
						&authzv1.SubjectAccessReview{
							Spec: authzv1.SubjectAccessReviewSpec{
								User:   "user-1",
								Groups: []string{"group-1", "group-2"},
								Extra: map[string]authzv1.ExtraValue{
									"extra": []string{"1", "2"},
								},
								UID: "uid-1",

								ResourceAttributes: &authzv1.ResourceAttributes{
									Group:     certmanager.GroupName,
									Resource:  "signers",
									Verb:      "reference",
									Namespace: baseIssuer.Namespace,
									Name:      baseIssuer.Name,
									Version:   "*",
								},
							},
						},
					)),
				},
			},
		},
		"an approved CSR but secret with invalid data should send event and wait for re-sync": {
			csr: baseCSR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{badDataSecret, baseCSR.DeepCopy()},
				CertManagerObjects: []runtime.Object{gen.IssuerFrom(baseIssuer.DeepCopy(),
					gen.SetIssuerCA(cmapi.CAIssuer{SecretName: badDataSecret.Name}),
				),
				},
				ExpectedEvents: []string{
					"Warning SecretInvalidData Failed to parse signing CA keypair from secret default-unit-test-ns/root-ca-secret: error decoding private key PEM block",
				},

				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						authzv1.SchemeGroupVersion.WithResource("subjectaccessreviews"),
						"",
						&authzv1.SubjectAccessReview{
							Spec: authzv1.SubjectAccessReviewSpec{
								User:   "user-1",
								Groups: []string{"group-1", "group-2"},
								Extra: map[string]authzv1.ExtraValue{
									"extra": []string{"1", "2"},
								},
								UID: "uid-1",

								ResourceAttributes: &authzv1.ResourceAttributes{
									Group:     certmanager.GroupName,
									Resource:  "signers",
									Verb:      "reference",
									Namespace: baseIssuer.Namespace,
									Name:      baseIssuer.Name,
									Version:   "*",
								},
							},
						},
					)),
				},
			},
		},
		"an approved CSR that transiently fails a secret lookup should backoff error to retry": {
			csr: baseCSR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{ecCASecret, baseCSR.DeepCopy()},
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					`Warning SecretGetError Failed to get certificate key pair from secret default-unit-test-ns/root-ca-secret: this is a network error`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						authzv1.SchemeGroupVersion.WithResource("subjectaccessreviews"),
						"",
						&authzv1.SubjectAccessReview{
							Spec: authzv1.SubjectAccessReviewSpec{
								User:   "user-1",
								Groups: []string{"group-1", "group-2"},
								Extra: map[string]authzv1.ExtraValue{
									"extra": []string{"1", "2"},
								},
								UID: "uid-1",

								ResourceAttributes: &authzv1.ResourceAttributes{
									Group:     certmanager.GroupName,
									Resource:  "signers",
									Verb:      "reference",
									Namespace: baseIssuer.Namespace,
									Name:      baseIssuer.Name,
									Version:   "*",
								},
							},
						},
					)),
				},
			},
			fakeLister: &testlisters.FakeSecretLister{
				SecretsFn: func(namespace string) clientcorev1.SecretNamespaceLister {
					return &testlisters.FakeSecretNamespaceLister{
						GetFn: func(name string) (ret *corev1.Secret, err error) {
							return nil, errors.New("this is a network error")
						},
					}
				},
			},
			expectedErr: true,
		},
		"an approved CSR should exit nil and send event if referenced issuer is not ready": {
			csr: baseCSR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{ecCASecret, baseCSR.DeepCopy()},
				CertManagerObjects: []runtime.Object{gen.Issuer(baseIssuer.DeepCopy().Name,
					gen.SetIssuerCA(cmapi.CAIssuer{}),
				)},
				ExpectedEvents: []string{
					"Warning IssuerNotReady Referenced Issuer default-unit-test-ns/test-issuer does not have a Ready status condition",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						authzv1.SchemeGroupVersion.WithResource("subjectaccessreviews"),
						"",
						&authzv1.SubjectAccessReview{
							Spec: authzv1.SubjectAccessReviewSpec{
								User:   "user-1",
								Groups: []string{"group-1", "group-2"},
								Extra: map[string]authzv1.ExtraValue{
									"extra": []string{"1", "2"},
								},
								UID: "uid-1",

								ResourceAttributes: &authzv1.ResourceAttributes{
									Group:     certmanager.GroupName,
									Resource:  "signers",
									Verb:      "reference",
									Namespace: baseIssuer.Namespace,
									Name:      baseIssuer.Name,
									Version:   "*",
								},
							},
						},
					)),
				},
			},
		},
		"a secret that fails to sign due to failing to generate the certificate template should set condition to failed": {
			csr: baseCSR.DeepCopy(),
			templateGenerator: func(*certificatesv1.CertificateSigningRequest) (*x509.Certificate, error) {
				return nil, errors.New("this is a template generate error")
			},
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{ecCASecret, baseCSR.DeepCopy()},
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Warning SigningError Error generating certificate template: this is a template generate error",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						authzv1.SchemeGroupVersion.WithResource("subjectaccessreviews"),
						"",
						&authzv1.SubjectAccessReview{
							Spec: authzv1.SubjectAccessReviewSpec{
								User:   "user-1",
								Groups: []string{"group-1", "group-2"},
								Extra: map[string]authzv1.ExtraValue{
									"extra": []string{"1", "2"},
								},
								UID: "uid-1",

								ResourceAttributes: &authzv1.ResourceAttributes{
									Group:     certmanager.GroupName,
									Resource:  "signers",
									Verb:      "reference",
									Namespace: baseIssuer.Namespace,
									Name:      baseIssuer.Name,
									Version:   "*",
								},
							},
						},
					)),
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						certificatesv1.SchemeGroupVersion.WithResource("certificatesigningrequests"),
						"status",
						"",
						gen.CertificateSigningRequestFrom(baseCSR.DeepCopy(),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:               certificatesv1.CertificateFailed,
								Status:             corev1.ConditionTrue,
								Reason:             "SigningError",
								Message:            "Error generating certificate template: this is a template generate error",
								LastTransitionTime: metaFixedClockStart,
								LastUpdateTime:     metaFixedClockStart,
							}),
						),
					)),
				},
			},
			expectedErr: false,
		},
		"if signing fails then the CertificateSigningRequest should be updated as Failed": {
			csr: baseCSR.DeepCopy(),
			signingFn: func(_ []*x509.Certificate, _ crypto.Signer, _ *x509.Certificate) (pki.PEMBundle, error) {
				return pki.PEMBundle{}, errors.New("this is a signing error")
			},
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{ecCASecret, baseCSR.DeepCopy()},
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Warning SigningError Error signing certificate: this is a signing error",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						authzv1.SchemeGroupVersion.WithResource("subjectaccessreviews"),
						"",
						&authzv1.SubjectAccessReview{
							Spec: authzv1.SubjectAccessReviewSpec{
								User:   "user-1",
								Groups: []string{"group-1", "group-2"},
								Extra: map[string]authzv1.ExtraValue{
									"extra": []string{"1", "2"},
								},
								UID: "uid-1",

								ResourceAttributes: &authzv1.ResourceAttributes{
									Group:     certmanager.GroupName,
									Resource:  "signers",
									Verb:      "reference",
									Namespace: baseIssuer.Namespace,
									Name:      baseIssuer.Name,
									Version:   "*",
								},
							},
						},
					)),
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						certificatesv1.SchemeGroupVersion.WithResource("certificatesigningrequests"),
						"status",
						"",
						gen.CertificateSigningRequestFrom(baseCSR.DeepCopy(),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:               certificatesv1.CertificateFailed,
								Status:             corev1.ConditionTrue,
								Reason:             "SigningError",
								Message:            "Error signing certificate: this is a signing error",
								LastTransitionTime: metaFixedClockStart,
								LastUpdateTime:     metaFixedClockStart,
							}),
						),
					)),
				},
			},
			expectedErr: false,
		},
		"a successful signing should update CertificateSigningRequest Certificate and CA annotation": {
			csr: baseCSR.DeepCopy(),
			templateGenerator: func(csr *certificatesv1.CertificateSigningRequest) (*x509.Certificate, error) {
				// Pass the given CSR to a "real" template generator to ensure that it
				// doesn't err. Return the pre-generated template.
				_, err := pki.CertificateTemplateFromCertificateSigningRequest(csr)
				if err != nil {
					return nil, err
				}

				return template, nil
			},
			signingFn: func(_ []*x509.Certificate, _ crypto.Signer, _ *x509.Certificate) (pki.PEMBundle, error) {
				return pki.PEMBundle{CAPEM: certBundle.CAPEM, ChainPEM: certBundle.ChainPEM}, nil
			},
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{ecCASecret, baseCSR.DeepCopy()},
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Normal CertificateIssued Certificate fetched from issuer successfully",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						authzv1.SchemeGroupVersion.WithResource("subjectaccessreviews"),
						"",
						&authzv1.SubjectAccessReview{
							Spec: authzv1.SubjectAccessReviewSpec{
								User:   "user-1",
								Groups: []string{"group-1", "group-2"},
								Extra: map[string]authzv1.ExtraValue{
									"extra": []string{"1", "2"},
								},
								UID: "uid-1",

								ResourceAttributes: &authzv1.ResourceAttributes{
									Group:     certmanager.GroupName,
									Resource:  "signers",
									Verb:      "reference",
									Namespace: baseIssuer.Namespace,
									Name:      baseIssuer.Name,
									Version:   "*",
								},
							},
						},
					)),
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						certificatesv1.SchemeGroupVersion.WithResource("certificatesigningrequests"),
						"status",
						"",
						gen.CertificateSigningRequestFrom(baseCSR,
							gen.SetCertificateSigningRequestCertificate(certBundle.ChainPEM),
						),
					)),
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixedClock.SetTime(fixedClockStart)
			test.builder.Clock = fixedClock
			runTest(t, test)
		})
	}
}

type testT struct {
	builder           *testpkg.Builder
	csr               *certificatesv1.CertificateSigningRequest
	templateGenerator templateGenerator
	signingFn         signingFn

	expectedErr bool

	fakeLister *testlisters.FakeSecretLister
}

func runTest(t *testing.T, test testT) {
	test.builder.T = t
	test.builder.Init()

	// Always return true for SubjectAccessReviews in tests
	test.builder.FakeKubeClient().PrependReactor("create", "*", func(action coretesting.Action) (bool, runtime.Object, error) {
		if action.GetResource() != authzv1.SchemeGroupVersion.WithResource("subjectaccessreviews") {
			return false, nil, nil
		}
		return true, &authzv1.SubjectAccessReview{
			Status: authzv1.SubjectAccessReviewStatus{
				Allowed: true,
			},
		}, nil
	})

	defer test.builder.Stop()

	ca := NewCA(test.builder.Context).(*CA)

	if test.fakeLister != nil {
		ca.secretsLister = test.fakeLister
	}

	if test.templateGenerator != nil {
		ca.templateGenerator = test.templateGenerator
	}
	if test.signingFn != nil {
		ca.signingFn = test.signingFn
	}

	controller := certificatesigningrequests.New(
		apiutil.IssuerCA,
		func(*controller.Context) certificatesigningrequests.Signer { return ca },
	)
	if _, _, err := controller.Register(test.builder.Context); err != nil {
		t.Fatal(err)
	}
	test.builder.Start()

	err := controller.ProcessItem(context.Background(), types.NamespacedName{
		Name: test.csr.Name,
	})
	if err != nil && !test.expectedErr {
		t.Errorf("expected to not get an error, but got: %v", err)
	}
	if err == nil && test.expectedErr {
		t.Errorf("expected to get an error but did not get one")
	}

	test.builder.CheckAndFinish(err)
}

func TestCA_Sign(t *testing.T) {
	rootPK, err := pki.GenerateECPrivateKey(256)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, _ := generateSelfSignedCACert(t, rootPK, "root")

	// Build test CSR
	testpk, err := pki.GenerateECPrivateKey(256)
	if err != nil {
		t.Fatal(err)
	}
	testCSR := generateCSR(t, testpk)

	tests := map[string]struct {
		givenCASecret    *corev1.Secret
		givenCAIssuer    cmapi.GenericIssuer
		givenCSR         *certificatesv1.CertificateSigningRequest
		assertSignedCert func(t *testing.T, got *x509.Certificate)
	}{
		"when the CertificateSigningRequest has the duration field set, it should appear as notAfter on the signed ca": {
			givenCASecret: gen.SecretFrom(gen.Secret("secret-1"), gen.SetSecretNamespace("default"), gen.SetSecretData(secretDataFor(t, rootPK, rootCert))),
			givenCAIssuer: gen.Issuer("issuer-1", gen.SetIssuerCA(cmapi.CAIssuer{
				SecretName: "secret-1",
			})),
			givenCSR: gen.CertificateSigningRequest("csr-1",
				gen.SetCertificateSigningRequestRequest(testCSR),
				gen.SetCertificateSigningRequestSignerName("issers.cert-manager.io/"+gen.DefaultTestNamespace+".issuer-1"),
				gen.SetCertificateSigningRequestDuration("30m"),
			),
			assertSignedCert: func(t *testing.T, got *x509.Certificate) {
				// Although there is less than 1µs between the time.Now
				// call made by the certificate template func (in the "pki"
				// package) and the time.Now below, rounding or truncating
				// will always end up with a flaky test. This is due to the
				// rounding made to the notAfter value when serializing the
				// certificate to ASN.1 [1].
				//
				//  [1]: https://tools.ietf.org/html/rfc5280#section-4.1.2.5.1
				//
				// So instead of using a truncation or rounding in order to
				// check the time, we use a delta of 2 seconds. One entire
				// second is totally overkill since, as detailed above, the
				// delay is probably less than a microsecond. But that will
				// do for now!
				//
				// Note that we do have a plan to fix this. We want to be
				// injecting a time (instead of time.Now) to the template
				// functions. This work is being tracked in this issue:
				// https://github.com/cert-manager/cert-manager/issues/3738
				expectNotAfter := time.Now().UTC().Add(30 * time.Minute)
				deltaSec := math.Abs(expectNotAfter.Sub(got.NotAfter).Seconds())
				assert.LessOrEqualf(t, deltaSec, 2., "expected a time delta lower than 2 second. Time expected='%s', got='%s'", expectNotAfter.String(), got.NotAfter.String())
			},
		},
		"when the CertificateSigningRequest has the expiration seconds field set, it should appear as notAfter on the signed ca": {
			givenCASecret: gen.SecretFrom(gen.Secret("secret-1"), gen.SetSecretNamespace("default"), gen.SetSecretData(secretDataFor(t, rootPK, rootCert))),
			givenCAIssuer: gen.Issuer("issuer-1", gen.SetIssuerCA(cmapi.CAIssuer{
				SecretName: "secret-1",
			})),
			givenCSR: gen.CertificateSigningRequest("csr-1",
				gen.SetCertificateSigningRequestRequest(testCSR),
				gen.SetCertificateSigningRequestSignerName("issers.cert-manager.io/"+gen.DefaultTestNamespace+".issuer-1"),
				gen.SetCertificateSigningRequestExpirationSeconds(654),
			),
			assertSignedCert: func(t *testing.T, got *x509.Certificate) {
				// Although there is less than 1µs between the time.Now
				// call made by the certificate template func (in the "pki"
				// package) and the time.Now below, rounding or truncating
				// will always end up with a flaky test. This is due to the
				// rounding made to the notAfter value when serializing the
				// certificate to ASN.1 [1].
				//
				//  [1]: https://tools.ietf.org/html/rfc5280#section-4.1.2.5.1
				//
				// So instead of using a truncation or rounding in order to
				// check the time, we use a delta of 2 seconds. One entire
				// second is totally overkill since, as detailed above, the
				// delay is probably less than a microsecond. But that will
				// do for now!
				//
				// Note that we do have a plan to fix this. We want to be
				// injecting a time (instead of time.Now) to the template
				// functions. This work is being tracked in this issue:
				// https://github.com/cert-manager/cert-manager/issues/3738
				expectNotAfter := time.Now().UTC().Add(654 * time.Second)
				deltaSec := math.Abs(expectNotAfter.Sub(got.NotAfter).Seconds())
				assert.LessOrEqualf(t, deltaSec, 2., "expected a time delta lower than 2 second. Time expected='%s', got='%s'", expectNotAfter.String(), got.NotAfter.String())
			},
		},
		"when the CertificateSigningRequest has the isCA field set, it should appear on the signed ca": {
			givenCASecret: gen.SecretFrom(gen.Secret("secret-1"), gen.SetSecretNamespace("default"), gen.SetSecretData(secretDataFor(t, rootPK, rootCert))),
			givenCAIssuer: gen.Issuer("issuer-1", gen.SetIssuerCA(cmapi.CAIssuer{
				SecretName: "secret-1",
			})),
			givenCSR: gen.CertificateSigningRequest("csr-1",
				gen.SetCertificateSigningRequestRequest(testCSR),
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/"+gen.DefaultTestNamespace+".issuer-1"),
				gen.SetCertificateSigningRequestIsCA(true),
			),
			assertSignedCert: func(t *testing.T, got *x509.Certificate) {
				assert.Equal(t, true, got.IsCA)
			},
		},
		"when the Issuer has ocspServers set, it should appear on the signed ca": {
			givenCASecret: gen.SecretFrom(gen.Secret("secret-1"), gen.SetSecretNamespace("default"), gen.SetSecretData(secretDataFor(t, rootPK, rootCert))),
			givenCAIssuer: gen.Issuer("issuer-1", gen.SetIssuerCA(cmapi.CAIssuer{
				SecretName:  "secret-1",
				OCSPServers: []string{"http://ocsp-v3.example.org"},
			})),
			givenCSR: gen.CertificateSigningRequest("cr-1",
				gen.SetCertificateSigningRequestRequest(testCSR),
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/"+gen.DefaultTestNamespace+".issuer-1"),
			),
			assertSignedCert: func(t *testing.T, got *x509.Certificate) {
				assert.Equal(t, []string{"http://ocsp-v3.example.org"}, got.OCSPServer)
			},
		},
		"when the Issuer has issuingCertificateURLs set, it should appear on the signed ca": {
			givenCASecret: gen.SecretFrom(gen.Secret("secret-1"), gen.SetSecretNamespace("default"), gen.SetSecretData(secretDataFor(t, rootPK, rootCert))),
			givenCAIssuer: gen.Issuer("issuer-1", gen.SetIssuerCA(cmapi.CAIssuer{
				SecretName:             "secret-1",
				IssuingCertificateURLs: []string{"http://ca.example.com/ca.crt"},
			})),
			givenCSR: gen.CertificateSigningRequest("cr-1",
				gen.SetCertificateSigningRequestRequest(testCSR),
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/"+gen.DefaultTestNamespace+".issuer-1"),
			),
			assertSignedCert: func(t *testing.T, got *x509.Certificate) {
				assert.Equal(t, []string{"http://ca.example.com/ca.crt"}, got.IssuingCertificateURL)
			},
		},
		"when the Issuer has crlDistributionPoints set, it should appear on the signed ca ": {
			givenCASecret: gen.SecretFrom(gen.Secret("secret-1"), gen.SetSecretNamespace("default"), gen.SetSecretData(secretDataFor(t, rootPK, rootCert))),
			givenCAIssuer: gen.Issuer("issuer-1", gen.SetIssuerCA(cmapi.CAIssuer{
				SecretName:            "secret-1",
				CRLDistributionPoints: []string{"http://www.example.com/crl/test.crl"},
			})),
			givenCSR: gen.CertificateSigningRequest("cr-1",
				gen.SetCertificateSigningRequestIsCA(true),
				gen.SetCertificateSigningRequestRequest(testCSR),
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/"+gen.DefaultTestNamespace+".issuer-1"),
			),
			assertSignedCert: func(t *testing.T, gotCA *x509.Certificate) {
				assert.Equal(t, []string{"http://www.example.com/crl/test.crl"}, gotCA.CRLDistributionPoints)
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			builder := &testpkg.Builder{
				KubeObjects:        []runtime.Object{test.givenCSR, test.givenCASecret},
				CertManagerObjects: []runtime.Object{test.givenCAIssuer},
			}
			builder.T = t
			builder.Init()
			defer builder.Stop()
			builder.Start()

			c := &CA{
				issuerOptions: controller.IssuerOptions{
					ClusterResourceNamespace:        "",
					ClusterIssuerAmbientCredentials: false,
					IssuerAmbientCredentials:        false,
				},
				certClient: builder.Client.CertificatesV1().CertificateSigningRequests(),
				recorder:   new(testpkg.FakeRecorder),
				secretsLister: testlisters.FakeSecretListerFrom(testlisters.NewFakeSecretLister(),
					testlisters.SetFakeSecretNamespaceListerGet(test.givenCASecret, nil),
				),
				templateGenerator: pki.CertificateTemplateFromCertificateSigningRequest,
				signingFn:         pki.SignCSRTemplate,
			}

			gotErr := c.Sign(context.Background(), test.givenCSR, test.givenCAIssuer)
			require.NoError(t, gotErr)
			builder.Sync()

			csr, err := builder.Client.CertificatesV1().CertificateSigningRequests().Get(context.TODO(), test.givenCSR.Name, metav1.GetOptions{})
			require.NoError(t, err)

			require.NotEmpty(t, csr.Status.Certificate)
			gotCert, err := pki.DecodeX509CertificateBytes(csr.Status.Certificate)
			require.NoError(t, err)

			test.assertSignedCert(t, gotCert)
		})
	}
}

// Returns a map that is meant to be used for creating a certificate Secret
// that contains the fields "tls.crt" and "tls.key".
func secretDataFor(t *testing.T, caKey *ecdsa.PrivateKey, caCrt *x509.Certificate) (secretData map[string][]byte) {
	rootCADER, err := x509.CreateCertificate(cmrand.Reader, caCrt, caCrt, caKey.Public(), caKey)
	require.NoError(t, err)
	caCrt, err = x509.ParseCertificate(rootCADER)
	require.NoError(t, err)
	caKeyPEM, err := pki.EncodeECPrivateKey(caKey)
	require.NoError(t, err)
	caCrtPEM, err := pki.EncodeX509(caCrt)
	require.NoError(t, err)

	return map[string][]byte{
		"tls.key": caKeyPEM,
		"tls.crt": caCrtPEM,
	}
}
