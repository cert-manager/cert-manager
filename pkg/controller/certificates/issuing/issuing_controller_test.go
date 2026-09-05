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
	"encoding/json"
	"errors"
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
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	fakeclock "k8s.io/utils/clock/testing"

	"github.com/cert-manager/cert-manager/internal/controller/feature"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/issuing/internal"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
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

const nextPrivateKeySecretName = "next-private-key"

// nextPrivateKeySecretMeta builds the ObjectMeta that the keymanager
// controller gives to a next private key Secret: the next-private-key label,
// and a controller owner reference back to the Certificate. The issuing
// controller only consumes Secrets carrying both, so fixtures must set them.
func nextPrivateKeySecretMeta(crt *cmapi.Certificate) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Namespace: crt.Namespace,
		Name:      nextPrivateKeySecretName,
		Labels: map[string]string{
			cmapi.IsNextPrivateKeySecretLabelKey: "true",
		},
		OwnerReferences: []metav1.OwnerReference{
			*metav1.NewControllerRef(crt, cmapi.SchemeGroupVersion.WithKind("Certificate")),
		},
	}
}

func TestIssuingController(t *testing.T) {
	type testT struct {
		builder *testpkg.Builder

		certificate             *cmapi.Certificate
		expSecretUpdateDataCall *internal.SecretData

		// localTemporarySigner, if set, overrides the signer that the runner
		// otherwise wires up to return a valid temporary certificate.
		localTemporarySigner localTemporarySignerFn

		expectedErr bool
	}

	baseCert := gen.Certificate("test",
		gen.SetCertificateIssuer(cmmeta.IssuerReference{Name: "ca-issuer", Kind: "Issuer", Group: "foo.io"}),
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

		"if certificate is in Issuing state but NextPrivateKeySecretName names a Secret it does not own, do nothing": {
			// A principal with access only to the certificates/status
			// subresource must not be able to make the controller read an
			// unrelated Secret and copy its private key into spec.secretName.
			//
			// Everything else here matches the successful issuance case below,
			// so the only reason nothing happens is that the Secret named by
			// status.nextPrivateKeySecretName carries neither the
			// cert-manager.io/next-private-key label nor a controller owner
			// reference back to this Certificate.
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					issuingCert.DeepCopy(),
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
				ExpectedActions: []testpkg.Action{},
				ExpectedEvents:  []string{},
			},
			// No expSecretUpdateDataCall: the private key must not be copied
			// into spec.secretName.
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
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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
							gen.SetCertificateIssuanceAttempts(new(1)),
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
					gen.CertificateFrom(issuingCert, gen.SetCertificateIssuanceAttempts(new(4))),
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
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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
							gen.SetCertificateIssuanceAttempts(new(5)),
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
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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
		"if certificate is in Issuing state, one CertificateRequest that failed, but the private key stored in the Secret does not match that creating the CSR, do nothing": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequestFailed,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
						// After the Issuing transition, so this is not the earlier
						// "failed during a previous issuance" case.
						gen.SetCertificateRequestFailureTime(metav1.Time{Time: metaFixedClockStart.Time.Add(time.Second)}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
						Data: map[string][]byte{
							// Replaced after this request's CSR was built.
							corev1.TLSPrivateKeyKey: exampleBundleAlt.PrivateKeyBytes,
						},
					},
				},
				ExpectedActions: []testpkg.Action{},
				ExpectedEvents:  []string{},
			},
			expectedErr: false,
		},
		"if certificate is in Issuing state, one CertificateRequest that was denied, but the private key stored in the Secret does not match that creating the CSR, do nothing": {
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
							Reason:  "Denied",
							Message: "denied by policy",
						}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
						Data: map[string][]byte{
							// Replaced after this request's CSR was built.
							corev1.TLSPrivateKeyKey: exampleBundleAlt.PrivateKeyBytes,
						},
					},
				},
				ExpectedActions: []testpkg.Action{},
				ExpectedEvents:  []string{},
			},
			expectedErr: false,
		},
		"if certificate is in Issuing state, one CertificateRequest with a failure time but no Ready condition, emit a Stalled event": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequest,
						// Explicit, so the case keeps covering the missing condition.
						func(cr *cmapi.CertificateRequest) { cr.Status.Conditions = nil },
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
						// After the Issuing transition, so this is the "stalled
						// during the current attempt" case, not the earlier
						// "failed during a previous issuance" case handled above.
						gen.SetCertificateRequestFailureTime(metav1.Time{Time: metaFixedClockStart.Time.Add(time.Second)}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.PrivateKeyBytes,
						},
					},
				},
				ExpectedActions: []testpkg.Action{},
				ExpectedEvents: []string{
					fmt.Sprintf("Warning Stalled CertificateRequest %q has a failureTime set but no Ready condition; issuance is stalled. Delete the CertificateRequest to retry.", exampleBundle.CertificateRequest.Name),
				},
			},
			expectedErr: false,
		},
		"if certificate is in Issuing state, one CertificateRequest with no failure time and no Ready condition, do nothing": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequest,
						// Explicit, so the case keeps covering the missing condition.
						func(cr *cmapi.CertificateRequest) { cr.Status.Conditions = nil },
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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
						gen.SetCertificateIssuanceAttempts(new(4))),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequestReady,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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

		// Issuing a temporary certificate can fail on a Certificate that the
		// webhook accepts, e.g. an unsupported spec.privateKey.encoding, and
		// then fails identically on every reconcile.
		"if certificate is in Issuing state with temp annotation and the temporary certificate cannot be issued, record a Warning event": {
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
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
						Data: map[string][]byte{
							corev1.TLSPrivateKeyKey: exampleBundle.PrivateKeyBytes,
						},
					},
				},
				ExpectedEvents: []string{
					"Warning TemporaryCertificateFailed Failed to issue temporary certificate: this is a signing error",
				},
			},
			localTemporarySigner: func(_ *cmapi.Certificate, _ []byte) ([]byte, error) {
				return nil, errors.New("this is a signing error")
			},
			expectedErr: true,
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
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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
							gen.SetCertificateIssuanceAttempts(new(1)),
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
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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
							gen.SetCertificateIssuanceAttempts(new(1)),
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
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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
							gen.SetCertificateIssuanceAttempts(new(1)),
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
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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
							gen.SetCertificateIssuanceAttempts(new(1)),
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
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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
							gen.SetCertificateIssuanceAttempts(new(1)),
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
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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
							gen.SetCertificateIssuanceAttempts(new(1)),
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
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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
							gen.SetCertificateIssuanceAttempts(new(1)),
						),
					)),
				},
				ExpectedEvents: []string{
					"Warning InvalidRequest The certificate request has failed to complete and will be retried: The certificate request is invalid",
				},
			},
			expectedErr: false,
		},
		"if certificate is in Issuing state, CertificateRequest is ready but returns certificate with mismatched public key, fail issuance with backoff": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequestReady,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
						gen.SetCertificateRequestCertificate(exampleBundleAlt.CertBytes),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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
								Reason:             "InvalidCertificate",
								Message:            "The certificate request has failed to complete and will be retried: Issuer returned a certificate with a public key that does not match the CSR. This usually indicates a misconfigured issuer.",
								LastTransitionTime: &metaFixedClockStart,
								ObservedGeneration: 3,
							}),
							gen.SetCertificateLastFailureTime(metaFixedClockStart),
							gen.SetCertificateIssuanceAttempts(new(1)),
						),
					)),
				},
				ExpectedEvents: []string{
					"Warning InvalidCertificate The certificate request has failed to complete and will be retried: Issuer returned a certificate with a public key that does not match the CSR. This usually indicates a misconfigured issuer.",
				},
			},
			expectedErr: false,
		},
		"if certificate is in Issuing state, CertificateRequest is ready but returns already expired certificate, fail issuance with backoff": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequestReady,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2", // Current Certificate revision=1
						}),
						gen.SetCertificateRequestCertificate(
							testcrypto.MustCreateCertWithNotBeforeAfter(t, exampleBundle.PrivateKeyBytes, exampleBundle.Certificate,
								fixedClockStart.Add(-2*time.Hour), fixedClockStart.Add(-1*time.Hour)),
						),
					)},
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: nextPrivateKeySecretMeta(exampleBundle.Certificate),
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
								Reason:             "InvalidCertificate",
								Message:            "The certificate request has failed to complete and will be retried: Issuer returned an already expired certificate (notAfter: " + fixedClockStart.Add(-1*time.Hour).UTC().Format(time.RFC3339) + "). This usually indicates an expired CA certificate in the issuer.",
								LastTransitionTime: &metaFixedClockStart,
								ObservedGeneration: 3,
							}),
							gen.SetCertificateLastFailureTime(metaFixedClockStart),
							gen.SetCertificateIssuanceAttempts(new(1)),
						),
					)),
				},
				ExpectedEvents: []string{
					"Warning InvalidCertificate The certificate request has failed to complete and will be retried: Issuer returned an already expired certificate (notAfter: " + fixedClockStart.Add(-1*time.Hour).UTC().Format(time.RFC3339) + "). This usually indicates an expired CA certificate in the issuer.",
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
			if test.localTemporarySigner != nil {
				w.controller.localTemporarySigner = test.localTemporarySigner
			}

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

			err = w.controller.ProcessItem(t.Context(), types.NamespacedName{
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

// TestIssuingController_ServerSideApplyFailedIssuanceAttempts checks ApplyStatus
// includes failedIssuanceAttempts on failure and omits it on success.
func TestIssuingController_ServerSideApplyFailedIssuanceAttempts(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, feature.ServerSideApply, true)

	fixture := failedIssuanceFixture(t)
	exampleBundle := fixture.bundle
	issuingCert := fixture.issuingCert
	nextPrivateKeySecret := fixture.nextPrivateKeySecret
	metaFixedClockStart := metav1.NewTime(fixedClockStart)

	type testT struct {
		builder                 *testpkg.Builder
		certificate             *cmapi.Certificate
		expSecretUpdateDataCall *internal.SecretData
		expApplyStatusPatch     []byte
	}

	tests := map[string]testT{
		"failure ApplyStatus includes failedIssuanceAttempts": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert),
					fixture.failedRequest,
				},
				KubeObjects: []runtime.Object{nextPrivateKeySecret},
				ExpectedEvents: []string{
					"Warning Failed The certificate request has failed to complete and will be retried: The certificate request failed because of reasons",
				},
			},
			expApplyStatusPatch: mustSerializeApplyStatus(t, exampleBundle.Certificate, cmapi.CertificateStatus{
				Conditions: []cmapi.CertificateCondition{{
					Type:               cmapi.CertificateConditionIssuing,
					Status:             cmmeta.ConditionFalse,
					LastTransitionTime: &metaFixedClockStart,
					Reason:             "Failed",
					Message:            "The certificate request has failed to complete and will be retried: The certificate request failed because of reasons",
					ObservedGeneration: 3,
				}},
				LastFailureTime:        &metaFixedClockStart,
				Revision:               new(1),
				FailedIssuanceAttempts: new(1),
			}),
		},
		"success ApplyStatus omits failedIssuanceAttempts and lastFailureTime": {
			certificate: exampleBundle.Certificate,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.CertificateFrom(issuingCert,
						gen.SetCertificateLastFailureTime(metaFixedClockStart),
						gen.SetCertificateIssuanceAttempts(new(4)),
					),
					gen.CertificateRequestFrom(exampleBundle.CertificateRequestReady,
						gen.AddCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestRevisionAnnotationKey: "2",
						}),
					),
				},
				KubeObjects: []runtime.Object{
					nextPrivateKeySecret,
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
			expApplyStatusPatch: mustSerializeApplyStatus(t, exampleBundle.Certificate, cmapi.CertificateStatus{
				Conditions: []cmapi.CertificateCondition{{
					Type:               cmapi.CertificateConditionIssuing,
					Status:             cmmeta.ConditionFalse,
					LastTransitionTime: &metaFixedClockStart,
					Reason:             "Issued",
					Message:            "The certificate has been successfully issued",
					ObservedGeneration: 3,
				}},
				Revision: new(2),
			}),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixedClock.SetTime(fixedClockStart)
			test.builder.Clock = fixedClock
			test.builder.T = t

			test.builder.ExpectedActions = []testpkg.Action{
				testpkg.NewAction(coretesting.NewPatchSubresourceActionWithOptions(
					cmapi.SchemeGroupVersion.WithResource("certificates"),
					exampleBundle.Certificate.Namespace,
					exampleBundle.Certificate.Name,
					types.ApplyPatchType,
					test.expApplyStatusPatch,
					metav1.PatchOptions{Force: new(true), FieldManager: testpkg.FieldManager},
					"status",
				)),
			}

			test.builder.InitWithRESTConfig()
			defer test.builder.Stop()

			w := controllerWrapper{}
			_, _, err := w.Register(test.builder.Context)
			require.NoError(t, err)
			w.controller.localTemporarySigner = testLocalTemporarySignerFn(exampleBundle.LocalTemporaryCertificateBytes)

			var secretsUpdateDataCalled bool
			w.controller.secretsUpdateData = func(_ context.Context, _ *cmapi.Certificate, secretData internal.SecretData) error {
				secretsUpdateDataCalled = true
				assert.Equal(t, *test.expSecretUpdateDataCall, secretData)
				return nil
			}
			t.Cleanup(func() {
				wantsSecretUpdateDataCall := test.expSecretUpdateDataCall != nil
				assert.Equal(t, wantsSecretUpdateDataCall, secretsUpdateDataCalled)
			})

			test.builder.Start()

			err = w.controller.ProcessItem(t.Context(), types.NamespacedName{
				Namespace: test.certificate.Namespace,
				Name:      test.certificate.Name,
			})
			require.NoError(t, err)
			test.builder.CheckAndFinish(err)
		})
	}
}

// TestIssuingController_FailIssuanceDoesNotMutateInformerCache checks that a
// failed issuance is not recorded on the Certificate in the shared informer
// cache. The gate is pinned both ways because the status write is an update or
// a patch depending on it, which changes the client verb the reactor matches.
func TestIssuingController_FailIssuanceDoesNotMutateInformerCache(t *testing.T) {
	tests := map[string]struct {
		serverSideApply bool
		failedVerb      string
	}{
		"UpdateStatus, ServerSideApply disabled": {serverSideApply: false, failedVerb: "update"},
		"ApplyStatus, ServerSideApply enabled":   {serverSideApply: true, failedVerb: "patch"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, feature.ServerSideApply, test.serverSideApply)

			fixture := failedIssuanceFixture(t)

			fixedClock.SetTime(fixedClockStart)
			b := &testpkg.Builder{
				T:                  t,
				Clock:              fixedClock,
				CertManagerObjects: []runtime.Object{fixture.issuingCert, fixture.failedRequest},
				KubeObjects:        []runtime.Object{fixture.nextPrivateKeySecret},
			}
			b.InitWithRESTConfig()
			defer b.Stop()

			w := controllerWrapper{}
			_, _, err := w.Register(b.Context)
			require.NoError(t, err)
			w.controller.localTemporarySigner = testLocalTemporarySignerFn(fixture.bundle.LocalTemporaryCertificateBytes)

			// Fail the status write, so the failure never reaches the API
			// server and the cache is the only place it could have landed.
			var failedWriteCalled bool
			b.FakeCMClient().PrependReactor(test.failedVerb, "certificates", func(coretesting.Action) (bool, runtime.Object, error) {
				failedWriteCalled = true
				return true, nil, errors.New("simulated status write failure")
			})

			b.Start()

			err = w.controller.ProcessItem(t.Context(), types.NamespacedName{
				Namespace: fixture.bundle.Certificate.Namespace,
				Name:      fixture.bundle.Certificate.Name,
			})
			require.Error(t, err)
			require.True(t, failedWriteCalled, "the reactor must match the verb the status write actually uses")

			cached, err := b.SharedInformerFactory.Certmanager().V1().Certificates().
				Lister().Certificates(fixture.bundle.Certificate.Namespace).Get(fixture.bundle.Certificate.Name)
			require.NoError(t, err)
			assert.Nil(t, cached.Status.FailedIssuanceAttempts, "failed issuance attempts must not be written to the informer cache")
			assert.Nil(t, cached.Status.LastFailureTime, "last failure time must not be written to the informer cache")
		})
	}
}

// failedIssuanceObjects is the set of objects a failed-issuance test needs: a
// Certificate mid-issuance at revision 1, the failed CertificateRequest for
// revision 2, and the Secret holding the next private key.
type failedIssuanceObjects struct {
	bundle               testcrypto.CryptoBundle
	issuingCert          *cmapi.Certificate
	failedRequest        *cmapi.CertificateRequest
	nextPrivateKeySecret *corev1.Secret
}

func failedIssuanceFixture(t *testing.T) failedIssuanceObjects {
	t.Helper()

	baseCert := gen.Certificate("test",
		gen.SetCertificateIssuer(cmmeta.IssuerReference{Name: "ca-issuer", Kind: "Issuer", Group: "foo.io"}),
		gen.SetCertificateGeneration(3),
		gen.SetCertificateSecretName("output"),
		gen.SetCertificateRenewBefore(&metav1.Duration{Duration: time.Hour * 36}),
		gen.SetCertificateDNSNames("example.com"),
		gen.SetCertificateRevision(1),
		gen.SetCertificateNextPrivateKeySecretName(nextPrivateKeySecretName),
	)
	bundle := testcrypto.MustCreateCryptoBundle(t, baseCert.DeepCopy(), fixedClock)
	metaFixedClockStart := metav1.NewTime(fixedClockStart)

	return failedIssuanceObjects{
		bundle: bundle,
		issuingCert: gen.CertificateFrom(baseCert.DeepCopy(),
			gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
				Type:               cmapi.CertificateConditionIssuing,
				Status:             cmmeta.ConditionTrue,
				ObservedGeneration: 3,
				LastTransitionTime: &metaFixedClockStart,
			}),
		),
		failedRequest: gen.CertificateRequestFrom(bundle.CertificateRequestFailed,
			gen.AddCertificateRequestAnnotations(map[string]string{
				cmapi.CertificateRequestRevisionAnnotationKey: "2",
			}),
			gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
				Type:    cmapi.CertificateRequestConditionReady,
				Status:  cmmeta.ConditionFalse,
				Reason:  cmapi.CertificateRequestReasonFailed,
				Message: "The certificate request failed because of reasons",
			}),
		),
		nextPrivateKeySecret: &corev1.Secret{
			ObjectMeta: nextPrivateKeySecretMeta(bundle.Certificate),
			Data: map[string][]byte{
				corev1.TLSPrivateKeyKey: bundle.PrivateKeyBytes,
			},
		},
	}
}

// mustSerializeApplyStatus renders the bytes internalcertificates.ApplyStatus sends.
func mustSerializeApplyStatus(t *testing.T, crt *cmapi.Certificate, status cmapi.CertificateStatus) []byte {
	t.Helper()
	data, err := json.Marshal(&cmapi.Certificate{
		TypeMeta:   metav1.TypeMeta{Kind: cmapi.CertificateKind, APIVersion: cmapi.SchemeGroupVersion.Identifier()},
		ObjectMeta: metav1.ObjectMeta{Namespace: crt.Namespace, Name: crt.Name},
		Status:     status,
	})
	require.NoError(t, err)
	return data
}
