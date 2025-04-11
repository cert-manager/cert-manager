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

package issuing

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/issuing/internal"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	testcrypto "github.com/cert-manager/cert-manager/test/unit/crypto"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

var (
	fixedClockStart = time.Now()
	fixedClock      = fakeclock.NewFakeClock(fixedClockStart)
)

func testLocalTemporarySignerFn(b []byte) localTemporarySignerFn {
	return func(crt *cmapi.Certificate, pk []byte) ([]byte, error) {
		return b, nil
	}
}

func TestIssuingController(t *testing.T) {
	type testT struct {
		builder *testpkg.Builder

		certificate             *cmapi.Certificate
		expSecretUpdateDataCall *internal.SecretData

		expectedErr bool
	}

	nextPrivateKeySecretName := "next-private-key"

	baseCert := gen.Certificate("test",
		gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "ca-issuer", Kind: "Issuer", Group: "foo.io"}),
		gen.SetCertificateGeneration(3),
		gen.SetCertificateSecretName("output"),
		gen.SetCertificateRenewBefore(&metav1.Duration{Duration: time.Hour * 36}),
		gen.SetCertificateDNSNames("example.com"),
		gen.SetCertificateRevision(1),
		gen.SetCertificateNextPrivateKeySecretName(nextPrivateKeySecretName),
	)
	exampleBundle := testcrypto.MustCreateCryptoBundle(t, baseCert.DeepCopy(), fixedClock)

	exampleBundleAlt := testcrypto.MustCreateCryptoBundle(t, baseCert.DeepCopy(), fixedClock)
	metaFixedClockStart := metav1.NewTime(fixedClockStart)

	issuingCert := gen.CertificateFrom(baseCert.DeepCopy(),
		gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
			Type:               cmapi.CertificateConditionIssuing,
			Status:             cmmeta.ConditionTrue,
			ObservedGeneration: 3,
			LastTransitionTime: &metaFixedClockStart,
		}),
	)

	tests := map[string]testT{
		"if certificate is not in Issuing state, then do nothing": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					baseCert.DeepCopy(),
				},
				KubeObjects:     []runtime.Object{},
				ExpectedActions: []testpkg.Action{},
			},
			expectedErr: false,
		},

		"if certificate is an Issuing state but is set to False, then do nothing": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(baseCert.DeepCopy(),
						gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionFalse,
						}),
					),
				},
				KubeObjects:     []runtime.Object{},
				ExpectedActions: []testpkg.Action{},
			},
			expectedErr: false,
		},

		"if certificate is in Issuing state, but no NextPrivateKeySecretName, do nothing": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert.DeepCopy(),
						gen.SetCertificateNextPrivateKeySecretName(""),
					),
				},
				KubeObjects:     []runtime.Object{},
				ExpectedActions: []testpkg.Action{},
			},
			expectedErr: false,
		},

		"if certificate is in Issuing state, but no CertificateRequests, do nothing": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					issuingCert.DeepCopy(),
				},
				KubeObjects:     []runtime.Object{},
				ExpectedActions: []testpkg.Action{},
			},
			expectedErr: false,
		},

		"if certificate is in Issuing state, but two CertificateRequests, do nothing": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					issuingCert.DeepCopy(),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequestReady,
						gen.SetCertificateRequestName(fmt.Sprintf("%s-2", exampleBundle.CertificateRequestReady.Name)),
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
					),
				},
				KubeObjects:     []runtime.Object{},
				ExpectedActions: []testpkg.Action{},
			},
			expectedErr: false,
		},

		"if certificate is in Issuing state, one CertificateRequest, but not in final state, do nothing": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					issuingCert.DeepCopy(),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequestReady,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
						gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionReady,
							Status: cmmeta.ConditionFalse,
							Reason: cmapi.CertificateRequestReasonPending,
						}),
					)},
				KubeObjects:     []runtime.Object{},
				ExpectedActions: []testpkg.Action{},
			},
			expectedErr: false,
		},

		"if certificate is in Issuing state, one CertificateRequest, but has failed and does not match the certificate spec, do nothing": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					issuingCert.DeepCopy(),
					gen.CertificateRequestFrom(
						testcrypto.MustCreateCryptoBundle(t,
							gen.CertificateFrom(issuingCert,
								gen.SetCertificateDNSNames("foo.com"), // Mismatch since the cert has "example.com"
							), fixedClock,
						).CertificateRequest,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}), gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:    cmapi.CertificateRequestConditionReady,
							Status:  cmmeta.ConditionFalse,
							Reason:  cmapi.CertificateRequestReasonFailed,
							Message: "The certificate request failed because of reasons",
						}),
					),
				},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      nextPrivateKeySecretName,
							Namespace: exampleBundle.Certificate.Namespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.PrivateKeyBytes,
						},
					},
				},
				ExpectedActions: []testpkg.Action{},
			},
			expectedErr: false,
		},
		"if certificate is in Issuing state, one CertificateRequest that has failed during previous issuance, do nothing": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequestFailed,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
						gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:    cmapi.CertificateRequestConditionReady,
							Status:  cmmeta.ConditionFalse,
							Reason:  cmapi.CertificateRequestReasonFailed,
							Message: "The certificate request failed because of reasons",
						}),
						gen.SetCertificateRequestFailureTime(metav1.Time{Time: metaFixedClockStart.Time.Add(time.Hour * -1)}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      nextPrivateKeySecretName,
							Namespace: exampleBundle.Certificate.Namespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.PrivateKeyBytes,
						},
					},
				},
				ExpectedActions: []testpkg.Action{},
			},
			expectedErr: false,
		},
		"if certificate is in Issuing state, one CertificateRequest, and has failed for the first time during this series of attempts, set failed state with one issuance attempt and log event": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequestFailed,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
						gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:    cmapi.CertificateRequestConditionReady,
							Status:  cmmeta.ConditionFalse,
							Reason:  cmapi.CertificateRequestReasonFailed,
							Message: "The certificate request failed because of reasons",
						}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      nextPrivateKeySecretName,
							Namespace: exampleBundle.Certificate.Namespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.PrivateKeyBytes,
						},
					},
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						"status",
						exampleBundle.Certificate.Namespace,
						gen.CertificateFrom(exampleBundle.Certificate,
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionIssuing,
								Status:             cmmeta.ConditionFalse,
								Reason:             "Failed",
								Message:            "The certificate request has failed to complete and will be retried: The certificate request failed because of reasons",
								LastTransitionTime: &metaFixedClockStart,
								ObservedGeneration: 3,
							}),
							gen.SetCertificateLastFailureTime(metaFixedClockStart),
							gen.SetCertificateIssuanceAttempts(ptr.To(1)),
						),
					)),
				},
				ExpectedEvents: []string{
					"Warning Failed The certificate request has failed to complete and will be retried: The certificate request failed because of reasons",
				},
			},
			expectedErr: false,
		},
		"if certificate is in Issuing state, one CertificateRequest, and has failed for the fifth time during this series of attempts, set failed state with five issuance attempts and log event": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert, gen.SetCertificateIssuanceAttempts(ptr.To(4))),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequestFailed,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
						gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:    cmapi.CertificateRequestConditionReady,
							Status:  cmmeta.ConditionFalse,
							Reason:  cmapi.CertificateRequestReasonFailed,
							Message: "The certificate request failed because of reasons",
						}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      nextPrivateKeySecretName,
							Namespace: exampleBundle.Certificate.Namespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.PrivateKeyBytes,
						},
					},
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						"status",
						exampleBundle.Certificate.Namespace,
						gen.CertificateFrom(exampleBundle.Certificate,
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionIssuing,
								Status:             cmmeta.ConditionFalse,
								Reason:             "Failed",
								Message:            "The certificate request has failed to complete and will be retried: The certificate request failed because of reasons",
								LastTransitionTime: &metaFixedClockStart,
								ObservedGeneration: 3,
							}),
							gen.SetCertificateLastFailureTime(metaFixedClockStart),
							gen.SetCertificateIssuanceAttempts(ptr.To(5)),
						),
					)),
				},
				ExpectedEvents: []string{
					"Warning Failed The certificate request has failed to complete and will be retried: The certificate request failed because of reasons",
				},
			},
			expectedErr: false,
		},
		"if certificate is in Issuing state, one CertificateRequest, but has failed, but the private key does not exist, do nothing": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequestFailed,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
						gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:    cmapi.CertificateRequestConditionReady,
							Status:  cmmeta.ConditionFalse,
							Reason:  cmapi.CertificateRequestReasonFailed,
							Message: "The certificate request failed because of reasons",
						}),
					)},
				KubeObjects:     []runtime.Object{},
				ExpectedActions: []testpkg.Action{},
				ExpectedEvents:  []string{},
			},
			expectedErr: false,
		},
		"if certificate is in Issuing state, one CertificateRequest, and is ready, but the Secret storing the private key does not exist, do nothing": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequestReady,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
					)},
				KubeObjects:     []runtime.Object{},
				ExpectedActions: []testpkg.Action{},
				ExpectedEvents:  []string{},
			},
			expectedErr: false,
		},
		"if certificate is in Issuing state, one CertificateRequest, and is ready, but the private key stored in the Secret cannot be parsed, do nothing": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequestReady,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      nextPrivateKeySecretName,
							Namespace: exampleBundle.Certificate.Namespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: []byte("bad key"),
						},
					},
				},
				ExpectedActions: []testpkg.Action{},
				ExpectedEvents:  []string{},
			},
			expectedErr: false,
		},
		"if certificate is in Issuing state, one CertificateRequest, and is ready, but the private key stored in the Secret does not match that creating the CSR, do nothing": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequestReady,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      nextPrivateKeySecretName,
							Namespace: exampleBundle.Certificate.Namespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundleAlt.PrivateKeyBytes,
						},
					},
				},
				ExpectedActions: []testpkg.Action{},
				ExpectedEvents:  []string{},
			},
			expectedErr: false,
		},
		"if certificate is in Issuing state, one CertificateRequest, and is ready, but the CertificateRequest contains a violation, do nothing": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequestReady,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
						gen.SetCertificateRequestKeyUsages(cmapi.UsageCRLSign),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      nextPrivateKeySecretName,
							Namespace: exampleBundle.Certificate.Namespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.PrivateKeyBytes,
						},
					},
				},
				ExpectedActions: []testpkg.Action{},
				ExpectedEvents:  []string{},
			},
			expectedErr: false,
		},

		"if certificate is in Issuing state, one CertificateRequests, and is ready, store the signed certificate, ca, and private key to a new secret, and log an event": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequestReady,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      nextPrivateKeySecretName,
							Namespace: exampleBundle.Certificate.Namespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.PrivateKeyBytes,
						},
					},
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						"status",
						exampleBundle.Certificate.Namespace,
						gen.CertificateFrom(exampleBundle.Certificate,
							gen.SetCertificateRevision(2),
						),
					)),
				},
				ExpectedEvents: []string{
					"Normal Issuing The certificate has been successfully issued",
				},
			},
			expSecretUpdateDataCall: &internal.SecretData{
				Certificate:     exampleBundle.CertificateRequestReady.Status.Certificate,
				PrivateKey:      exampleBundle.PrivateKeyBytes,
				CA:              nil,
				CertificateName: "test",
				IssuerName:      "ca-issuer",
				IssuerKind:      "Issuer",
				IssuerGroup:     "foo.io",
			},
			expectedErr: false,
		},

		"if certificate is in Issuing state, one CertificateRequests, and is ready, store the signed certificate, ca, and private key to an existing secret, and log an event": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequestReady,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      nextPrivateKeySecretName,
							Namespace: exampleBundle.Certificate.Namespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.PrivateKeyBytes,
						},
					},
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: exampleBundle.Certificate.Namespace,
							Name:      "output",
							Annotations: map[string]string{
								"my-custom": "annotation",
							},
							Labels: map[string]string{},
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						"status",
						exampleBundle.Certificate.Namespace,
						gen.CertificateFrom(exampleBundle.Certificate,
							gen.SetCertificateRevision(2),
						),
					)),
				},
				ExpectedEvents: []string{
					"Normal Issuing The certificate has been successfully issued",
				},
			},
			expSecretUpdateDataCall: &internal.SecretData{
				Certificate:     exampleBundle.CertificateRequestReady.Status.Certificate,
				PrivateKey:      exampleBundle.PrivateKeyBytes,
				CA:              nil,
				CertificateName: "test",
				IssuerName:      "ca-issuer",
				IssuerKind:      "Issuer",
				IssuerGroup:     "foo.io",
			},
			expectedErr: false,
		},
		"if certificate is in Issuing state, one ready CertificateRequest and has last failure time set from previous issuance, set the Issuing condition to true, remove last failure time and store the signed certificate, ca, and private key to an existing secret, and log an event": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert, gen.SetCertificateLastFailureTime(metaFixedClockStart)),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequestReady,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      nextPrivateKeySecretName,
							Namespace: exampleBundle.Certificate.Namespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.PrivateKeyBytes,
						},
					},
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: exampleBundle.Certificate.Namespace,
							Name:      "output",
							Annotations: map[string]string{
								"my-custom": "annotation",
							},
							Labels: map[string]string{},
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						"status",
						exampleBundle.Certificate.Namespace,
						gen.CertificateFrom(exampleBundle.Certificate,
							gen.SetCertificateRevision(2),
						),
					)),
				},
				ExpectedEvents: []string{
					"Normal Issuing The certificate has been successfully issued",
				},
			},
			expSecretUpdateDataCall: &internal.SecretData{
				Certificate:     exampleBundle.CertificateRequestReady.Status.Certificate,
				PrivateKey:      exampleBundle.PrivateKeyBytes,
				CA:              nil,
				CertificateName: "test",
				IssuerName:      "ca-issuer",
				IssuerKind:      "Issuer",
				IssuerGroup:     "foo.io",
			},
			expectedErr: false,
		},
		"if certificate is in Issuing state, one ready CertificateRequest and has last failure time and issuance attempts set from a previous issuance, set the Issuing condition to true, remove last failure time and issuance attempts and store the signed certificate, ca, and private key to an existing secret, and log an event": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert, gen.SetCertificateLastFailureTime(metaFixedClockStart),
						gen.SetCertificateIssuanceAttempts(ptr.To(4))),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequestReady,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      nextPrivateKeySecretName,
							Namespace: exampleBundle.Certificate.Namespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.PrivateKeyBytes,
						},
					},
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: exampleBundle.Certificate.Namespace,
							Name:      "output",
							Annotations: map[string]string{
								"my-custom": "annotation",
							},
							Labels: map[string]string{},
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						"status",
						exampleBundle.Certificate.Namespace,
						gen.CertificateFrom(exampleBundle.Certificate,
							gen.SetCertificateRevision(2),
						),
					)),
				},
				ExpectedEvents: []string{
					"Normal Issuing The certificate has been successfully issued",
				},
			},
			expSecretUpdateDataCall: &internal.SecretData{
				Certificate:     exampleBundle.CertificateRequestReady.Status.Certificate,
				PrivateKey:      exampleBundle.PrivateKeyBytes,
				CA:              nil,
				CertificateName: "test",
				IssuerName:      "ca-issuer",
				IssuerKind:      "Issuer",
				IssuerGroup:     "foo.io",
			},
			expectedErr: false,
		},

		"if certificate is in Issuing state with temp annotation, one CertificateRequest Pending, no target Secret, create target secret with temporary certificate": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert,
						gen.AddCertificateAnnotations(map[string]string{
							cmapi.IssueTemporaryCertificateAnnotation: "true",
						}),
					),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequestPending,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      nextPrivateKeySecretName,
							Namespace: exampleBundle.Certificate.Namespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.PrivateKeyBytes,
						},
					},
				},
				ExpectedEvents: []string{
					"Normal Issuing Issued temporary certificate",
				},
			},
			expSecretUpdateDataCall: &internal.SecretData{
				Certificate:     exampleBundle.LocalTemporaryCertificateBytes,
				PrivateKey:      exampleBundle.PrivateKeyBytes,
				CA:              nil,
				CertificateName: "test",
			},
			expectedErr: false,
		},

		"if certificate is in Issuing state with temp annotation, one CertificateRequest Pending, a target Secret but with no data, issue temporary certificate to that Secret": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert,
						gen.AddCertificateAnnotations(map[string]string{
							cmapi.IssueTemporaryCertificateAnnotation: "true",
						}),
					),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequestPending,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      nextPrivateKeySecretName,
							Namespace: exampleBundle.Certificate.Namespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.PrivateKeyBytes,
						},
					},
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      exampleBundle.Certificate.Spec.SecretName,
							Namespace: exampleBundle.Certificate.Namespace,
							Annotations: map[string]string{
								"my-custom": "annotation",
							},
						},
						Data: nil,
						Type: corev1.SecretTypeTLS,
					},
				},
				ExpectedEvents: []string{
					"Normal Issuing Issued temporary certificate",
				},
			},
			expSecretUpdateDataCall: &internal.SecretData{
				Certificate:     exampleBundle.LocalTemporaryCertificateBytes,
				PrivateKey:      exampleBundle.PrivateKeyBytes,
				CA:              nil,
				CertificateName: "test",
			},
			expectedErr: false,
		},

		"if certificate is in Issuing state with temp annotation, one CertificateRequest Pending, a target Secret but with a cert/key that is not the NextPrivateKey, do nothing": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert,
						gen.AddCertificateAnnotations(map[string]string{
							cmapi.IssueTemporaryCertificateAnnotation: "true",
						}),
					),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequestPending,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      nextPrivateKeySecretName,
							Namespace: exampleBundle.Certificate.Namespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.PrivateKeyBytes,
						},
					},
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      exampleBundle.Certificate.Spec.SecretName,
							Namespace: exampleBundle.Certificate.Namespace,
							Annotations: map[string]string{
								"my-custom": "annotation",
							},
							Labels: map[string]string{},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       exampleBundleAlt.CertBytes,
							corev1.TLSPrivateKeyKey: exampleBundleAlt.PrivateKeyBytes,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				ExpectedActions: []testpkg.Action{},
				ExpectedEvents:  []string{},
			},
			expectedErr: false,
		},

		"if certificate is in Issuing state with temp annotation, one CertificateRequest Pending, a target Secret with a cert/key that are garbage, issue temporary certificate": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert,
						gen.AddCertificateAnnotations(map[string]string{
							cmapi.IssueTemporaryCertificateAnnotation: "true",
						}),
					),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequestPending,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      nextPrivateKeySecretName,
							Namespace: exampleBundle.Certificate.Namespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.PrivateKeyBytes,
						},
					},
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      exampleBundle.Certificate.Spec.SecretName,
							Namespace: exampleBundle.Certificate.Namespace,
							Annotations: map[string]string{
								"my-custom": "annotation",
							},
							Labels: map[string]string{},
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: []byte("abc"),
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				ExpectedEvents: []string{
					"Normal Issuing Issued temporary certificate",
				},
			},
			expSecretUpdateDataCall: &internal.SecretData{
				Certificate:     exampleBundle.LocalTemporaryCertificateBytes,
				PrivateKey:      exampleBundle.PrivateKeyBytes,
				CA:              nil,
				CertificateName: "test",
			},
			expectedErr: false,
		},

		"if certificate is in Issuing state with temp annotation, one CertificateRequest Pending, a target Secret with a cert/key with a matching key, do not issue temporary certificate": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert,
						gen.AddCertificateAnnotations(map[string]string{
							cmapi.IssueTemporaryCertificateAnnotation: "true",
						}),
					),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequestPending,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      nextPrivateKeySecretName,
							Namespace: exampleBundle.Certificate.Namespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.PrivateKeyBytes,
						},
					},
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      exampleBundle.Certificate.Spec.SecretName,
							Namespace: exampleBundle.Certificate.Namespace,
							Annotations: map[string]string{
								"my-custom": "annotation",
							},
							Labels: map[string]string{},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       exampleBundle.LocalTemporaryCertificateBytes, // Cert not valid but still matches private key
							corev1.TLSPrivateKeyKey: exampleBundle.PrivateKeyBytes,
						},
						Type: corev1.SecretTypeTLS,
					},
				},
				ExpectedActions: []testpkg.Action{},
				ExpectedEvents:  []string{},
			},
			expectedErr: false,
		},
		"if certificate is in Issuing state with temp annotation, one CertificateRequest Ready, a target Secret does not exist, issue Certificate from CertificateRequest": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert,
						gen.AddCertificateAnnotations(map[string]string{
							cmapi.IssueTemporaryCertificateAnnotation: "true",
						}),
					),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequestReady,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      nextPrivateKeySecretName,
							Namespace: exampleBundle.Certificate.Namespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.PrivateKeyBytes,
						},
					},
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						"status",
						exampleBundle.Certificate.Namespace,
						gen.CertificateFrom(exampleBundle.Certificate,
							gen.AddCertificateAnnotations(map[string]string{
								cmapi.IssueTemporaryCertificateAnnotation: "true",
							}),
							gen.SetCertificateRevision(2),
						),
					)),
				},
				ExpectedEvents: []string{
					"Normal Issuing The certificate has been successfully issued",
				},
			},
			expSecretUpdateDataCall: &internal.SecretData{
				Certificate:     exampleBundle.CertificateRequestReady.Status.Certificate,
				PrivateKey:      exampleBundle.PrivateKeyBytes,
				CA:              nil,
				CertificateName: "test",
				IssuerName:      "ca-issuer",
				IssuerKind:      "Issuer",
				IssuerGroup:     "foo.io",
			},
			expectedErr: false,
		},
		"if certificate is in Issuing state with temp annotation, one CertificateRequest Failed, a target Secret does not exist, mark the Certificate as failed": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert,
						gen.AddCertificateAnnotations(map[string]string{
							cmapi.IssueTemporaryCertificateAnnotation: "true",
						}),
					),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequestFailed,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
						gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:    cmapi.CertificateRequestConditionReady,
							Status:  cmmeta.ConditionFalse,
							Reason:  cmapi.CertificateRequestReasonFailed,
							Message: "The certificate request failed because of reasons",
						}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      nextPrivateKeySecretName,
							Namespace: exampleBundle.Certificate.Namespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.PrivateKeyBytes,
						},
					},
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						"status",
						exampleBundle.Certificate.Namespace,
						gen.CertificateFrom(exampleBundle.Certificate,
							gen.AddCertificateAnnotations(map[string]string{
								cmapi.IssueTemporaryCertificateAnnotation: "true",
							}),
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionIssuing,
								Status:             cmmeta.ConditionFalse,
								Reason:             "Failed",
								Message:            "The certificate request has failed to complete and will be retried: The certificate request failed because of reasons",
								LastTransitionTime: &metaFixedClockStart,
								ObservedGeneration: 3,
							}),
							gen.SetCertificateLastFailureTime(metaFixedClockStart),
							gen.SetCertificateIssuanceAttempts(ptr.To(1)),
						),
					)),
				},
				ExpectedEvents: []string{
					"Warning Failed The certificate request has failed to complete and will be retried: The certificate request failed because of reasons",
				},
			},
			expectedErr: false,
		},
		"if certificate is in Issuing state, one CertificateRequest without Ready condition, but with Denied condition, report denial and set last failed time and issuance attempts": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequest,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
						gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:    cmapi.CertificateRequestConditionDenied,
							Status:  cmmeta.ConditionTrue,
							Reason:  "DeniedReason",
							Message: "The certificate request has been denied",
						}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      nextPrivateKeySecretName,
							Namespace: exampleBundle.Certificate.Namespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.PrivateKeyBytes,
						},
					},
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						"status",
						exampleBundle.Certificate.Namespace,
						gen.CertificateFrom(exampleBundle.Certificate,
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionIssuing,
								Status:             cmmeta.ConditionFalse,
								Reason:             "DeniedReason",
								Message:            "The certificate request has failed to complete and will be retried: The certificate request has been denied",
								LastTransitionTime: &metaFixedClockStart,
								ObservedGeneration: 3,
							}),
							gen.SetCertificateLastFailureTime(metaFixedClockStart),
							gen.SetCertificateIssuanceAttempts(ptr.To(1)),
						),
					)),
				},
				ExpectedEvents: []string{
					"Warning DeniedReason The certificate request has failed to complete and will be retried: The certificate request has been denied",
				},
			},
			expectedErr: false,
		},
		"if certificate is in Issuing state, one CertificateRequest with a pending Ready condition and a Denied condition, report denial and set last failed time and issuance attempts": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequest,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
						gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:    cmapi.CertificateRequestConditionDenied,
							Status:  cmmeta.ConditionTrue,
							Reason:  "DeniedReason",
							Message: "The certificate request has been denied",
						}),
						gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:    cmapi.CertificateRequestConditionReady,
							Status:  cmmeta.ConditionFalse,
							Reason:  "Pending",
							Message: "The certificate request is pending",
						}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      nextPrivateKeySecretName,
							Namespace: exampleBundle.Certificate.Namespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.PrivateKeyBytes,
						},
					},
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						"status",
						exampleBundle.Certificate.Namespace,
						gen.CertificateFrom(exampleBundle.Certificate,
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionIssuing,
								Status:             cmmeta.ConditionFalse,
								Reason:             "DeniedReason",
								Message:            "The certificate request has failed to complete and will be retried: The certificate request has been denied",
								LastTransitionTime: &metaFixedClockStart,
								ObservedGeneration: 3,
							}),
							gen.SetCertificateLastFailureTime(metaFixedClockStart),
							gen.SetCertificateIssuanceAttempts(ptr.To(1)),
						),
					)),
				},
				ExpectedEvents: []string{
					"Warning DeniedReason The certificate request has failed to complete and will be retried: The certificate request has been denied",
				},
			},
			expectedErr: false,
		},
		"if certificate is in Issuing state, one CertificateRequest that has been issued, but also has a Denied condition, report denial and set last failed time and issuance attempts": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequest,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
						gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:    cmapi.CertificateRequestConditionDenied,
							Status:  cmmeta.ConditionTrue,
							Reason:  "DeniedReason",
							Message: "The certificate request has been denied",
						}),
						gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:    cmapi.CertificateRequestConditionReady,
							Status:  cmmeta.ConditionTrue,
							Reason:  "Issued",
							Message: "The certificate request has been issued",
						}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      nextPrivateKeySecretName,
							Namespace: exampleBundle.Certificate.Namespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.PrivateKeyBytes,
						},
					},
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						"status",
						exampleBundle.Certificate.Namespace,
						gen.CertificateFrom(exampleBundle.Certificate,
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionIssuing,
								Status:             cmmeta.ConditionFalse,
								Reason:             "DeniedReason",
								Message:            "The certificate request has failed to complete and will be retried: The certificate request has been denied",
								LastTransitionTime: &metaFixedClockStart,
								ObservedGeneration: 3,
							}),
							gen.SetCertificateLastFailureTime(metaFixedClockStart),
							gen.SetCertificateIssuanceAttempts(ptr.To(1)),
						),
					)),
				},
				ExpectedEvents: []string{
					"Warning DeniedReason The certificate request has failed to complete and will be retried: The certificate request has been denied",
				},
			},
			expectedErr: false,
		},
		"if certificate is in Issuing state, one CertificateRequest that has no ready condition and has been marked as invalid, report error and set last failed time and issuance attempts": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequest,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
						gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:    cmapi.CertificateRequestConditionInvalidRequest,
							Status:  cmmeta.ConditionTrue,
							Reason:  "InvalidRequest",
							Message: "The certificate request is invalid",
						}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      nextPrivateKeySecretName,
							Namespace: exampleBundle.Certificate.Namespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.PrivateKeyBytes,
						},
					},
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						"status",
						exampleBundle.Certificate.Namespace,
						gen.CertificateFrom(exampleBundle.Certificate,
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionIssuing,
								Status:             cmmeta.ConditionFalse,
								Reason:             "InvalidRequest",
								Message:            "The certificate request has failed to complete and will be retried: The certificate request is invalid",
								LastTransitionTime: &metaFixedClockStart,
								ObservedGeneration: 3,
							}),
							gen.SetCertificateLastFailureTime(metaFixedClockStart),
							gen.SetCertificateIssuanceAttempts(ptr.To(1)),
						),
					)),
				},
				ExpectedEvents: []string{
					"Warning InvalidRequest The certificate request has failed to complete and will be retried: The certificate request is invalid",
				},
			},
			expectedErr: false,
		},
		"if certificate is in Issuing state, one CertificateRequest that has a pending ready condition and has been marked as invalid, report error and set last failed time and issuance attempts": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequest,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
						gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:    cmapi.CertificateRequestConditionInvalidRequest,
							Status:  cmmeta.ConditionTrue,
							Reason:  "InvalidRequest",
							Message: "The certificate request is invalid",
						}),
						gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:    cmapi.CertificateRequestConditionReady,
							Status:  cmmeta.ConditionFalse,
							Reason:  "Pending",
							Message: "The certificate request is being issued",
						}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      nextPrivateKeySecretName,
							Namespace: exampleBundle.Certificate.Namespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.PrivateKeyBytes,
						},
					},
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						"status",
						exampleBundle.Certificate.Namespace,
						gen.CertificateFrom(exampleBundle.Certificate,
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionIssuing,
								Status:             cmmeta.ConditionFalse,
								Reason:             "InvalidRequest",
								Message:            "The certificate request has failed to complete and will be retried: The certificate request is invalid",
								LastTransitionTime: &metaFixedClockStart,
								ObservedGeneration: 3,
							}),
							gen.SetCertificateLastFailureTime(metaFixedClockStart),
							gen.SetCertificateIssuanceAttempts(ptr.To(1)),
						),
					)),
				},
				ExpectedEvents: []string{
					"Warning InvalidRequest The certificate request has failed to complete and will be retried: The certificate request is invalid",
				},
			},
			expectedErr: false,
		},
		"if certificate is in Issuing state, one CertificateRequest that has been issued, but has also been marked as invalid, report error and set last failed time and issuance attempts": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequest,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
						gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:    cmapi.CertificateRequestConditionInvalidRequest,
							Status:  cmmeta.ConditionTrue,
							Reason:  "InvalidRequest",
							Message: "The certificate request is invalid",
						}),
						gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:    cmapi.CertificateRequestConditionReady,
							Status:  cmmeta.ConditionTrue,
							Reason:  "Issued",
							Message: "The certificate request has been issued",
						}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      nextPrivateKeySecretName,
							Namespace: exampleBundle.Certificate.Namespace,
						},
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.PrivateKeyBytes,
						},
					},
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						"status",
						exampleBundle.Certificate.Namespace,
						gen.CertificateFrom(exampleBundle.Certificate,
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionIssuing,
								Status:             cmmeta.ConditionFalse,
								Reason:             "InvalidRequest",
								Message:            "The certificate request has failed to complete and will be retried: The certificate request is invalid",
								LastTransitionTime: &metaFixedClockStart,
								ObservedGeneration: 3,
							}),
							gen.SetCertificateLastFailureTime(metaFixedClockStart),
							gen.SetCertificateIssuanceAttempts(ptr.To(1)),
						),
					)),
				},
				ExpectedEvents: []string{
					"Warning InvalidRequest The certificate request has failed to complete and will be retried: The certificate request is invalid",
				},
			},
			expectedErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixedClock.SetTime(fixedClockStart)
			test.builder.Clock = fixedClock
			test.builder.T = t
			test.builder.InitWithRESTConfig()
			defer test.builder.Stop()

			w := controllerWrapper{}
			_, _, err := w.Register(test.builder.Context)
			require.NoError(t, err)
			w.controller.localTemporarySigner = testLocalTemporarySignerFn(exampleBundle.LocalTemporaryCertificateBytes)

			var secretsUpdateDataCalled bool
			w.controller.secretsUpdateData = func(_ context.Context, _ *cmapi.Certificate, secretData internal.SecretData) error {
				secretsUpdateDataCalled = true
				assert.Equal(t, *test.expSecretUpdateDataCall, secretData, "expected secretData: %#+v, got %#+v", *test.expSecretUpdateDataCall, secretData)
				return nil
			}
			t.Cleanup(func() {
				wantsSecretUpdateDataCall := test.expSecretUpdateDataCall != nil
				assert.Equal(t, test.expSecretUpdateDataCall != nil, secretsUpdateDataCalled, "expected secretUpdateData func to be called: %t was called: %t", wantsSecretUpdateDataCall, secretsUpdateDataCalled)
			})

			test.builder.Start()

			err = w.controller.ProcessItem(context.Background(), types.NamespacedName{
				Namespace: test.certificate.Namespace,
				Name:      test.certificate.Name,
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
