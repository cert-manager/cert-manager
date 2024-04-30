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

package venafi

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/go-logr/logr"
	authzv1 "k8s.io/api/authorization/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	"github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/util"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	venaficlient "github.com/cert-manager/cert-manager/pkg/issuer/venafi/client"
	venafiapi "github.com/cert-manager/cert-manager/pkg/issuer/venafi/client/api"
	fakevenaficlient "github.com/cert-manager/cert-manager/pkg/issuer/venafi/client/fake"
	"github.com/cert-manager/cert-manager/pkg/metrics"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

var (
	fixedClockStart = time.Now()
	fixedClock      = fakeclock.NewFakeClock(fixedClockStart)
)

func TestProcessItem(t *testing.T) {
	metaFixedClockStart := metav1.NewTime(fixedClockStart)
	util.Clock = fixedClock

	rootCSRPEM, rootPK, err := gen.CSR(x509.RSA,
		gen.SetCSRCommonName("root"),
	)
	if err != nil {
		t.Fatal(err)
	}

	rootTmpl, err := pki.CertificateTemplateFromCSRPEM(
		rootCSRPEM,
		pki.CertificateTemplateOverrideDuration(time.Hour),
		pki.CertificateTemplateValidateAndOverrideBasicConstraints(true, nil),
		pki.CertificateTemplateValidateAndOverrideKeyUsages(0, nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, rootCert, err := pki.SignCertificate(rootTmpl, rootTmpl, rootPK.Public(), rootPK)
	if err != nil {
		t.Fatal(err)
	}

	leafCSRPEM, leafPK, err := gen.CSR(x509.RSA,
		gen.SetCSRCommonName("leaf"),
	)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl, err := pki.CertificateTemplateFromCSRPEM(
		leafCSRPEM,
		pki.CertificateTemplateOverrideDuration(time.Hour),
		pki.CertificateTemplateValidateAndOverrideBasicConstraints(false, nil),
		pki.CertificateTemplateValidateAndOverrideKeyUsages(0, nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, leafCert, err := pki.SignCertificate(leafTmpl, rootCert, leafPK.Public(), rootPK)
	if err != nil {
		t.Fatal(err)
	}
	certBundle, err := pki.ParseSingleCertificateChain([]*x509.Certificate{leafCert, rootCert})
	if err != nil {
		t.Fatal(err)
	}

	baseIssuer := gen.Issuer("test-issuer",
		gen.SetIssuerVenafi(cmapi.VenafiIssuer{
			Cloud: &cmapi.VenafiCloud{},
		}),
		gen.AddIssuerCondition(cmapi.IssuerCondition{
			Type:   cmapi.IssuerConditionReady,
			Status: cmmeta.ConditionTrue,
		}),
	)

	baseCSR := gen.CertificateSigningRequest("test-cr",
		gen.SetCertificateSigningRequestRequest(leafCSRPEM),
		gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/default-unit-test-ns.test-issuer"),
		gen.SetCertificateSigningRequestDuration("1440h"),
		gen.SetCertificateSigningRequestUsername("user-1"),
		gen.SetCertificateSigningRequestGroups([]string{"group-1", "group-2"}),
		gen.SetCertificateSigningRequestUID("uid-1"),
		gen.SetCertificateSigningRequestExtra(map[string]certificatesv1.ExtraValue{
			"extra": []string{"1", "2"},
		}),
	)

	tests := map[string]struct {
		builder       *testpkg.Builder
		csr           *certificatesv1.CertificateSigningRequest
		clientBuilder venaficlient.VenafiClientBuilder
		expectedErr   bool
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
		"an approved CSR where the venafi client builder returns a not found error should fire event and do nothing": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			clientBuilder: func(_ string, _ internalinformers.SecretLister, _ cmapi.GenericIssuer, _ *metrics.Metrics, _ logr.Logger, _ string) (venaficlient.Interface, error) {
				return nil, apierrors.NewNotFound(schema.GroupResource{}, "test-secret")
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Warning SecretNotFound Required secret resource not found",
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
		"an approved CSR where the venafi client builder returns a generic error should mark as Failed": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			clientBuilder: func(_ string, _ internalinformers.SecretLister, _ cmapi.GenericIssuer, _ *metrics.Metrics, _ logr.Logger, _ string) (venaficlient.Interface, error) {
				return nil, errors.New("generic error")
			},
			expectedErr: true,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Warning ErrorVenafiInit Failed to initialise venafi client for signing: generic error",
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
		"an approved CSR where the custom fields annotations contain garbage data should mark as Failed": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.AddCertificateSigningRequestAnnotations(map[string]string{
					"venafi.experimental.cert-manager.io/custom-fields": "garbage-data",
				}),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			clientBuilder: func(_ string, _ internalinformers.SecretLister, _ cmapi.GenericIssuer, _ *metrics.Metrics, _ logr.Logger, _ string) (venaficlient.Interface, error) {
				return &fakevenaficlient.Venafi{}, nil
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					`Warning ErrorCustomFields Failed to parse "venafi.experimental.cert-manager.io/custom-fields" annotation: invalid character 'g' looking for beginning of value`,
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
								"venafi.experimental.cert-manager.io/custom-fields": "garbage-data",
							}),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:   certificatesv1.CertificateApproved,
								Status: corev1.ConditionTrue,
							}),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:               certificatesv1.CertificateFailed,
								Status:             corev1.ConditionTrue,
								Reason:             "ErrorCustomFields",
								Message:            `Failed to parse "venafi.experimental.cert-manager.io/custom-fields" annotation: invalid character 'g' looking for beginning of value`,
								LastTransitionTime: metaFixedClockStart,
								LastUpdateTime:     metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"an approved CSR where the requested duration annotations contains garbage data should mark as Failed": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.AddCertificateSigningRequestAnnotations(map[string]string{
					"venafi.experimental.cert-manager.io/custom-fields": `[ {"name": "field-name", "value": "vield value"}]`,
				}),
				gen.SetCertificateSigningRequestDuration("garbage-duration"),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			clientBuilder: func(_ string, _ internalinformers.SecretLister, _ cmapi.GenericIssuer, _ *metrics.Metrics, _ logr.Logger, _ string) (venaficlient.Interface, error) {
				return &fakevenaficlient.Venafi{}, nil
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					`Warning ErrorParseDuration Failed to parse requested duration: failed to parse requested duration on annotation "experimental.cert-manager.io/request-duration": time: invalid duration "garbage-duration"`,
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
							gen.SetCertificateSigningRequestDuration("garbage-duration"),
							gen.AddCertificateSigningRequestAnnotations(map[string]string{
								"venafi.experimental.cert-manager.io/custom-fields": `[ {"name": "field-name", "value": "vield value"}]`,
							}),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:   certificatesv1.CertificateApproved,
								Status: corev1.ConditionTrue,
							}),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:               certificatesv1.CertificateFailed,
								Status:             corev1.ConditionTrue,
								Reason:             "ErrorParseDuration",
								Message:            `Failed to parse requested duration: failed to parse requested duration on annotation "experimental.cert-manager.io/request-duration": time: invalid duration "garbage-duration"`,
								LastTransitionTime: metaFixedClockStart,
								LastUpdateTime:     metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"an approved CSR which does not yet have a pickup ID, but the client responds with fields type error, should mark as Failed": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.AddCertificateSigningRequestAnnotations(map[string]string{
					"venafi.experimental.cert-manager.io/custom-fields": `[ {"name": "field-name", "value": "vield value"}]`,
				}),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			clientBuilder: func(_ string, _ internalinformers.SecretLister, _ cmapi.GenericIssuer, _ *metrics.Metrics, _ logr.Logger, _ string) (venaficlient.Interface, error) {
				return &fakevenaficlient.Venafi{
					RequestCertificateFn: func(_ []byte, _ []venafiapi.CustomField) (string, error) {
						return "", venaficlient.ErrCustomFieldsType{Type: "test-type"}
					},
				}, nil
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					`Warning ErrorCustomFields certificate request contains an invalid Venafi custom fields type: "test-type"`,
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
								"venafi.experimental.cert-manager.io/custom-fields": `[ {"name": "field-name", "value": "vield value"}]`,
							}),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:   certificatesv1.CertificateApproved,
								Status: corev1.ConditionTrue,
							}),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:               certificatesv1.CertificateFailed,
								Status:             corev1.ConditionTrue,
								Reason:             "ErrorCustomFields",
								Message:            `certificate request contains an invalid Venafi custom fields type: "test-type"`,
								LastTransitionTime: metaFixedClockStart,
								LastUpdateTime:     metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"an approved CSR which does not yet have a pickup ID, but the client responds a generic error, should mark as Failed": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.AddCertificateSigningRequestAnnotations(map[string]string{
					"venafi.experimental.cert-manager.io/custom-fields": `[ {"name": "field-name", "value": "vield value"}]`,
				}),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			clientBuilder: func(_ string, _ internalinformers.SecretLister, _ cmapi.GenericIssuer, _ *metrics.Metrics, _ logr.Logger, _ string) (venaficlient.Interface, error) {
				return &fakevenaficlient.Venafi{
					RequestCertificateFn: func(_ []byte, _ []venafiapi.CustomField) (string, error) {
						return "", errors.New("generic error")
					},
				}, nil
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Warning ErrorRequest Failed to request venafi certificate: generic error",
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
								"venafi.experimental.cert-manager.io/custom-fields": `[ {"name": "field-name", "value": "vield value"}]`,
							}),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:   certificatesv1.CertificateApproved,
								Status: corev1.ConditionTrue,
							}),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:               certificatesv1.CertificateFailed,
								Status:             corev1.ConditionTrue,
								Reason:             "ErrorRequest",
								Message:            "Failed to request venafi certificate: generic error",
								LastTransitionTime: metaFixedClockStart,
								LastUpdateTime:     metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"an approved CSR which does not yet have a pickup ID, should update the annotation with one and return": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.AddCertificateSigningRequestAnnotations(map[string]string{
					"venafi.experimental.cert-manager.io/custom-fields": `[ {"name": "field-name", "value": "vield value"}]`,
				}),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			clientBuilder: func(_ string, _ internalinformers.SecretLister, _ cmapi.GenericIssuer, _ *metrics.Metrics, _ logr.Logger, _ string) (venaficlient.Interface, error) {
				return &fakevenaficlient.Venafi{
					RequestCertificateFn: func(_ []byte, _ []venafiapi.CustomField) (string, error) {
						return "test-pickup-id", nil
					},
				}, nil
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents:     []string{},
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
					testpkg.NewAction(coretesting.NewUpdateAction(
						certificatesv1.SchemeGroupVersion.WithResource("certificatesigningrequests"),
						"",
						gen.CertificateSigningRequestFrom(baseCSR.DeepCopy(),
							gen.AddCertificateSigningRequestAnnotations(map[string]string{
								"venafi.experimental.cert-manager.io/custom-fields": `[ {"name": "field-name", "value": "vield value"}]`,
								"venafi.experimental.cert-manager.io/pickup-id":     "test-pickup-id",
							}),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:   certificatesv1.CertificateApproved,
								Status: corev1.ConditionTrue,
							}),
						),
					)),
				},
			},
		},
		"an approved CSR which has a pickup ID, retrieve certificate returns a pending error, fire event and return error": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.AddCertificateSigningRequestAnnotations(map[string]string{
					"venafi.experimental.cert-manager.io/custom-fields": `[ {"name": "field-name", "value": "vield value"}]`,
					"venafi.experimental.cert-manager.io/pickup-id":     "test-pickup-id",
				}),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			clientBuilder: func(_ string, _ internalinformers.SecretLister, _ cmapi.GenericIssuer, _ *metrics.Metrics, _ logr.Logger, _ string) (venaficlient.Interface, error) {
				return &fakevenaficlient.Venafi{
					RetrieveCertificateFn: func(_ string, _ []byte, _ []venafiapi.CustomField) ([]byte, error) {
						return nil, endpoint.ErrCertificatePending{}
					},
				}, nil
			},
			expectedErr: true,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Normal IssuancePending Venafi certificate still in a pending state, waiting",
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
		"an approved CSR which has a pickup ID, retrieve certificate returns a timeout error, fire event and return error": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.AddCertificateSigningRequestAnnotations(map[string]string{
					"venafi.experimental.cert-manager.io/custom-fields": `[ {"name": "field-name", "value": "vield value"}]`,
					"venafi.experimental.cert-manager.io/pickup-id":     "test-pickup-id",
				}),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			clientBuilder: func(_ string, _ internalinformers.SecretLister, _ cmapi.GenericIssuer, _ *metrics.Metrics, _ logr.Logger, _ string) (venaficlient.Interface, error) {
				return &fakevenaficlient.Venafi{
					RetrieveCertificateFn: func(_ string, _ []byte, _ []venafiapi.CustomField) ([]byte, error) {
						return nil, endpoint.ErrRetrieveCertificateTimeout{}
					},
				}, nil
			},
			expectedErr: true,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Warning RetrieveCertificateTimeout Venafi retrieve certificate timeout, retrying",
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
		"an approved CSR which has a pickup ID, retrieve certificate returns a generic error, fire event and return error": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.AddCertificateSigningRequestAnnotations(map[string]string{
					"venafi.experimental.cert-manager.io/custom-fields": `[ {"name": "field-name", "value": "vield value"}]`,
					"venafi.experimental.cert-manager.io/pickup-id":     "test-pickup-id",
				}),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			clientBuilder: func(_ string, _ internalinformers.SecretLister, _ cmapi.GenericIssuer, _ *metrics.Metrics, _ logr.Logger, _ string) (venaficlient.Interface, error) {
				return &fakevenaficlient.Venafi{
					RetrieveCertificateFn: func(_ string, _ []byte, _ []venafiapi.CustomField) ([]byte, error) {
						return nil, errors.New("generic error")
					},
				}, nil
			},
			expectedErr: true,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Warning ErrorRetrieve Failed to obtain venafi certificate: generic error",
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
		"an approved CSR which has a pickup ID, retrieve certificate returns garbage certificates, should mark as Failed": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.AddCertificateSigningRequestAnnotations(map[string]string{
					"venafi.experimental.cert-manager.io/custom-fields": `[ {"name": "field-name", "value": "vield value"}]`,
					"venafi.experimental.cert-manager.io/pickup-id":     "test-pickup-id",
				}),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			clientBuilder: func(_ string, _ internalinformers.SecretLister, _ cmapi.GenericIssuer, _ *metrics.Metrics, _ logr.Logger, _ string) (venaficlient.Interface, error) {
				return &fakevenaficlient.Venafi{
					RetrieveCertificateFn: func(_ string, _ []byte, _ []venafiapi.CustomField) ([]byte, error) {
						return []byte("garbage"), nil
					},
				}, nil
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Warning ErrorParse Failed to parse returned certificate bundle: error decoding certificate PEM block",
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
								"venafi.experimental.cert-manager.io/custom-fields": `[ {"name": "field-name", "value": "vield value"}]`,
								"venafi.experimental.cert-manager.io/pickup-id":     "test-pickup-id",
							}),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:   certificatesv1.CertificateApproved,
								Status: corev1.ConditionTrue,
							}),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:               certificatesv1.CertificateFailed,
								Status:             corev1.ConditionTrue,
								Reason:             "ErrorParse",
								Message:            "Failed to parse returned certificate bundle: error decoding certificate PEM block",
								LastTransitionTime: metaFixedClockStart,
								LastUpdateTime:     metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"an approved CSR which has a pickup ID, retrieve certificate returns a CA and certificate should update with certificate": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.AddCertificateSigningRequestAnnotations(map[string]string{
					"venafi.experimental.cert-manager.io/custom-fields": `[ {"name": "field-name", "value": "vield value"}]`,
					"venafi.experimental.cert-manager.io/pickup-id":     "test-pickup-id",
				}),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			clientBuilder: func(_ string, _ internalinformers.SecretLister, _ cmapi.GenericIssuer, _ *metrics.Metrics, _ logr.Logger, _ string) (venaficlient.Interface, error) {
				return &fakevenaficlient.Venafi{
					RetrieveCertificateFn: func(_ string, _ []byte, _ []venafiapi.CustomField) ([]byte, error) {
						return []byte(fmt.Sprintf("%s%s", certBundle.ChainPEM, certBundle.CAPEM)), nil
					},
				}, nil
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Normal CertificateIssued Certificate fetched from venafi issuer successfully",
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
								"venafi.experimental.cert-manager.io/custom-fields": `[ {"name": "field-name", "value": "vield value"}]`,
								"venafi.experimental.cert-manager.io/pickup-id":     "test-pickup-id",
							}),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:   certificatesv1.CertificateApproved,
								Status: corev1.ConditionTrue,
							}),
							gen.SetCertificateSigningRequestCertificate(certBundle.ChainPEM),
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
			test.builder.InitWithRESTConfig()

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

			venafi := NewVenafi(test.builder.Context).(*Venafi)
			venafi.clientBuilder = test.clientBuilder

			controller := certificatesigningrequests.New(
				apiutil.IssuerVenafi,
				func(*controllerpkg.Context) certificatesigningrequests.Signer { return venafi },
			)
			controller.Register(test.builder.Context)
			test.builder.Start()

			err := controller.ProcessItem(context.Background(), test.csr.Name)
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
