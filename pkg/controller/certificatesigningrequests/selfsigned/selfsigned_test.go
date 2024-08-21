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

package selfsigned

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"math"
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
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	"github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
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

type cryptoBundle struct {
	csrPEM []byte
	key    crypto.Signer
	keyPEM []byte
	secret *corev1.Secret
}

func mustCryptoBundle(t *testing.T) cryptoBundle {
	key, err := pki.GenerateECPrivateKey(256)
	if err != nil {
		t.Fatal(err)
	}

	csrPEM, err := gen.CSRWithSigner(key, gen.SetCSRCommonName("test"))
	if err != nil {
		t.Fatal(err)
	}

	keyPEM, err := pki.EncodePKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default-unit-test-ns",
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}

	return cryptoBundle{
		csrPEM: csrPEM,
		key:    key,
		keyPEM: keyPEM,
		secret: secret,
	}
}

func TestProcessItem(t *testing.T) {
	metaFixedClockStart := metav1.NewTime(fixedClockStart)
	util.Clock = fixedClock

	baseIssuer := gen.Issuer("test-issuer",
		gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
		gen.AddIssuerCondition(cmapi.IssuerCondition{
			Type:   cmapi.IssuerConditionReady,
			Status: cmmeta.ConditionTrue,
		}),
	)

	csrBundle := mustCryptoBundle(t)
	baseCSR := gen.CertificateSigningRequest("test-cr",
		gen.SetCertificateSigningRequestRequest(csrBundle.csrPEM),
		gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/default-unit-test-ns."+baseIssuer.Name),
		gen.SetCertificateSigningRequestDuration("1440h"),
		gen.SetCertificateSigningRequestUsername("user-1"),
		gen.SetCertificateSigningRequestGroups([]string{"group-1", "group-2"}),
		gen.SetCertificateSigningRequestUID("uid-1"),
		gen.SetCertificateSigningRequestExtra(map[string]certificatesv1.ExtraValue{
			"extra": []string{"1", "2"},
		}),
	)

	tests := map[string]struct {
		builder     *testpkg.Builder
		csr         *certificatesv1.CertificateSigningRequest
		signingFn   signingFn
		fakeLister  *testlisters.FakeSecretLister
		expectedErr bool
	}{
		"a CertificateSigningRequest without an approved condition should fire an event": {
			csr: gen.CertificateSigningRequestFrom(baseCSR),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Normal WaitingApproval Waiting for the Approved condition before issuing",
				},
			},
		},
		"a CertificateSigningRequest with a denied condition should do nothing": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateDenied,
					Status: corev1.ConditionTrue,
				}),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents:     []string{},
				ExpectedActions:    nil,
			},
		},
		"an approved CSR without a private key reference should be marked as failed": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					`Warning MissingAnnotation Missing private key reference annotation: "experimental.cert-manager.io/private-key-secret-name"`,
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
								Type:   certificatesv1.CertificateApproved,
								Status: corev1.ConditionTrue,
							}),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:               certificatesv1.CertificateFailed,
								Status:             corev1.ConditionTrue,
								Reason:             "MissingAnnotation",
								Message:            `Missing private key reference annotation: "experimental.cert-manager.io/private-key-secret-name"`,
								LastTransitionTime: metaFixedClockStart,
								LastUpdateTime:     metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"an approved CSR but the private key references a Secret that does not exist should fire an event and return error": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
				gen.AddCertificateSigningRequestAnnotations(map[string]string{
					"experimental.cert-manager.io/private-key-secret-name": "test-secret",
				}),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					`Warning SecretNotFound Referenced Secret default-unit-test-ns/test-secret not found`,
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
			expectedErr: false,
		},
		"an approved CSR but the private key references a Secret that contains bad data should fire warning event.": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
				gen.AddCertificateSigningRequestAnnotations(map[string]string{
					"experimental.cert-manager.io/private-key-secret-name": "test-secret",
				}),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-secret",
							Namespace: "default-unit-test-ns",
						},
						Data: map[string][]byte{
							"tls.key": []byte("garbage data"),
						},
					},
				},
				ExpectedEvents: []string{
					`Warning ErrorParsingKey Failed to parse signing key from secret default-unit-test-ns/test-secret: error decoding private key PEM block`,
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
		"an approved CSR which contains a garbage request PEM should be marked as failed": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
				gen.AddCertificateSigningRequestAnnotations(map[string]string{
					"experimental.cert-manager.io/private-key-secret-name": "test-secret",
				}),
				gen.SetCertificateSigningRequestRequest([]byte("garbage data")),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				KubeObjects:        []runtime.Object{csrBundle.secret},
				ExpectedEvents: []string{
					"Warning ErrorGenerating Error generating certificate template: error decoding certificate request PEM block",
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
							gen.AddCertificateSigningRequestAnnotations(map[string]string{
								"experimental.cert-manager.io/private-key-secret-name": "test-secret",
							}),
							gen.SetCertificateSigningRequestRequest([]byte("garbage data")),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:   certificatesv1.CertificateApproved,
								Status: corev1.ConditionTrue,
							}),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:               certificatesv1.CertificateFailed,
								Status:             corev1.ConditionTrue,
								Reason:             "ErrorGenerating",
								Message:            "Error generating certificate template: error decoding certificate request PEM block",
								LastTransitionTime: metaFixedClockStart,
								LastUpdateTime:     metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"an approved CSR which references a Secret containing a private key that does not match the request PEM should be marked as failed": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
				gen.AddCertificateSigningRequestAnnotations(map[string]string{
					"experimental.cert-manager.io/private-key-secret-name": "test-secret",
				}),
				gen.SetCertificateSigningRequestRequest(csrBundle.csrPEM),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				KubeObjects:        []runtime.Object{mustCryptoBundle(t).secret},
				ExpectedEvents: []string{
					"Warning ErrorKeyMatch Referenced private key in Secret does not match that in the request",
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
							gen.AddCertificateSigningRequestAnnotations(map[string]string{
								"experimental.cert-manager.io/private-key-secret-name": "test-secret",
							}),
							gen.SetCertificateSigningRequestRequest(csrBundle.csrPEM),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:   certificatesv1.CertificateApproved,
								Status: corev1.ConditionTrue,
							}),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:               certificatesv1.CertificateFailed,
								Status:             corev1.ConditionTrue,
								Reason:             "ErrorKeyMatch",
								Message:            "Referenced private key in Secret does not match that in the request",
								LastTransitionTime: metaFixedClockStart,
								LastUpdateTime:     metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"an approved CSR which failed to sign the request should be marked as failed": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
				gen.AddCertificateSigningRequestAnnotations(map[string]string{
					"experimental.cert-manager.io/private-key-secret-name": "test-secret",
				}),
				gen.SetCertificateSigningRequestRequest(csrBundle.csrPEM),
			),
			signingFn: func(*x509.Certificate, *x509.Certificate, crypto.PublicKey, interface{}) ([]byte, *x509.Certificate, error) {
				return nil, nil, errors.New("this is a signing error")
			},

			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				KubeObjects:        []runtime.Object{csrBundle.secret},
				ExpectedEvents: []string{
					"Warning ErrorSigning Error signing certificate: this is a signing error",
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
							gen.AddCertificateSigningRequestAnnotations(map[string]string{
								"experimental.cert-manager.io/private-key-secret-name": "test-secret",
							}),
							gen.SetCertificateSigningRequestRequest(csrBundle.csrPEM),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:   certificatesv1.CertificateApproved,
								Status: corev1.ConditionTrue,
							}),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:               certificatesv1.CertificateFailed,
								Status:             corev1.ConditionTrue,
								Reason:             "ErrorSigning",
								Message:            "Error signing certificate: this is a signing error",
								LastTransitionTime: metaFixedClockStart,
								LastUpdateTime:     metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"an approved CSR successfully signs the request should update the CSR with the signed certificate": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
				gen.AddCertificateSigningRequestAnnotations(map[string]string{
					"experimental.cert-manager.io/private-key-secret-name": "test-secret",
				}),
				gen.SetCertificateSigningRequestRequest(csrBundle.csrPEM),
			),
			signingFn: func(*x509.Certificate, *x509.Certificate, crypto.PublicKey, interface{}) ([]byte, *x509.Certificate, error) {
				return []byte("signed-cert"), nil, nil
			},

			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				KubeObjects:        []runtime.Object{csrBundle.secret},
				ExpectedEvents: []string{
					"Normal CertificateIssued Certificate self signed successfully",
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
							gen.AddCertificateSigningRequestAnnotations(map[string]string{
								"experimental.cert-manager.io/private-key-secret-name": "test-secret",
							}),
							gen.SetCertificateSigningRequestRequest(csrBundle.csrPEM),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:   certificatesv1.CertificateApproved,
								Status: corev1.ConditionTrue,
							}),
							gen.SetCertificateSigningRequestCertificate([]byte("signed-cert")),
						),
					)),
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if test.csr != nil {
				test.builder.KubeObjects = append(test.builder.KubeObjects, test.csr)
			}

			fixedClock.SetTime(fixedClockStart)
			test.builder.Clock = fixedClock
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

			selfsigned := NewSelfSigned(test.builder.Context).(*SelfSigned)

			if test.fakeLister != nil {
				selfsigned.secretsLister = test.fakeLister
			}

			if test.signingFn != nil {
				selfsigned.signingFn = test.signingFn
			}

			controller := certificatesigningrequests.New(
				apiutil.IssuerSelfSigned,
				func(*controller.Context) certificatesigningrequests.Signer { return selfsigned },
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
		})
	}
}

func TestSign(t *testing.T) {
	csrBundle := mustCryptoBundle(t)
	baseIssuer := gen.Issuer("issuer-1",
		gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
	)

	tests := map[string]struct {
		csr              *certificatesv1.CertificateSigningRequest
		issuer           *cmapi.Issuer
		assertSignedCert func(t *testing.T, got *x509.Certificate)
	}{
		"when the CertificateSigningRequest has the duration field set, it should appear as notAfter on the signed certificate": {
			csr: gen.CertificateSigningRequest("csr-1",
				gen.AddCertificateSigningRequestAnnotations(map[string]string{
					"experimental.cert-manager.io/private-key-secret-name": "test-secret",
				}),
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/default-unit-test-ns.issuer-1"),
				gen.SetCertificateSigningRequestDuration("30m"),
				gen.SetCertificateSigningRequestRequest(csrBundle.csrPEM),
			),
			issuer: baseIssuer,
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
		"when the CertificateSigningRequest has the expiration seconds field set, it should appear as notAfter on the signed certificate": {
			csr: gen.CertificateSigningRequest("csr-1",
				gen.AddCertificateSigningRequestAnnotations(map[string]string{
					"experimental.cert-manager.io/private-key-secret-name": "test-secret",
				}),
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/default-unit-test-ns.issuer-1"),
				gen.SetCertificateSigningRequestExpirationSeconds(444),
				gen.SetCertificateSigningRequestRequest(csrBundle.csrPEM),
			),
			issuer: baseIssuer,
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
				expectNotAfter := time.Now().UTC().Add(444 * time.Second)
				deltaSec := math.Abs(expectNotAfter.Sub(got.NotAfter).Seconds())
				assert.LessOrEqualf(t, deltaSec, 2., "expected a time delta lower than 2 second. Time expected='%s', got='%s'", expectNotAfter.String(), got.NotAfter.String())
			},
		},
		"when the CertificateSigningRequest has the isCA field set, it should appear on the signed certificate": {
			csr: gen.CertificateSigningRequest("csr-1",
				gen.AddCertificateSigningRequestAnnotations(map[string]string{
					"experimental.cert-manager.io/private-key-secret-name": "test-secret",
				}),
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/default-unit-test-ns.issuer-1"),
				gen.SetCertificateSigningRequestRequest(csrBundle.csrPEM),
				gen.SetCertificateSigningRequestIsCA(true),
			),
			issuer: baseIssuer,
			assertSignedCert: func(t *testing.T, got *x509.Certificate) {
				assert.Equal(t, true, got.IsCA)
			},
		},
		"when the Issuer has crlDistributionPoints set, it should appear on the signed ca ": {
			csr: gen.CertificateSigningRequest("cr-1",
				gen.AddCertificateSigningRequestAnnotations(map[string]string{
					"experimental.cert-manager.io/private-key-secret-name": "test-secret",
				}),
				gen.SetCertificateSigningRequestRequest(csrBundle.csrPEM),
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/default-unit-test-ns.issuer-1"),
			),
			issuer: gen.IssuerFrom(baseIssuer,
				gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{
					CRLDistributionPoints: []string{"http://www.example.com/crl/test.crl"},
				}),
			),
			assertSignedCert: func(t *testing.T, gotCA *x509.Certificate) {
				assert.Equal(t, []string{"http://www.example.com/crl/test.crl"}, gotCA.CRLDistributionPoints)
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			builder := &testpkg.Builder{
				KubeObjects:        []runtime.Object{test.csr, csrBundle.secret},
				CertManagerObjects: []runtime.Object{test.issuer},
			}
			builder.T = t
			builder.Init()
			defer builder.Stop()
			builder.Start()

			selfsigned := &SelfSigned{
				certClient: builder.Client.CertificatesV1().CertificateSigningRequests(),
				recorder:   new(testpkg.FakeRecorder),
				secretsLister: testlisters.FakeSecretListerFrom(testlisters.NewFakeSecretLister(),
					testlisters.SetFakeSecretNamespaceListerGet(csrBundle.secret, nil),
				),
				signingFn: pki.SignCertificate,
			}

			gotErr := selfsigned.Sign(context.Background(), test.csr, test.issuer)
			require.NoError(t, gotErr)
			builder.Sync()

			csr, err := builder.Client.CertificatesV1().CertificateSigningRequests().Get(context.TODO(), test.csr.Name, metav1.GetOptions{})
			require.NoError(t, err)

			require.NotEmpty(t, csr.Status.Certificate)
			gotCert, err := pki.DecodeX509CertificateBytes(csr.Status.Certificate)
			require.NoError(t, err)

			test.assertSignedCert(t, gotCert)
		})
	}
}
