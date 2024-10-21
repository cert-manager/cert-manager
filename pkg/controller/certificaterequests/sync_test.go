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

package certificaterequests

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	"github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/cmrand"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificaterequests/fake"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/pkg/issuer"
	issuerfake "github.com/cert-manager/cert-manager/pkg/issuer/fake"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"

	_ "github.com/cert-manager/cert-manager/pkg/issuer/selfsigned"
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

func generateSelfSignedCert(t *testing.T, cr *cmapi.CertificateRequest, key crypto.Signer, notBefore, notAfter time.Time) []byte {
	t.Helper()
	template, err := pki.CertificateTemplateFromCertificateRequest(cr)
	if err != nil {
		t.Errorf("failed to generate cert template from CSR: %v", err)
		t.FailNow()
	}

	template.NotAfter = notAfter
	template.NotBefore = notBefore

	derBytes, err := x509.CreateCertificate(cmrand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Errorf("error signing cert: %v", err)
		t.FailNow()
	}

	pemByteBuffer := bytes.NewBuffer([]byte{})
	err = pem.Encode(pemByteBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		t.Errorf("failed to encode cert: %v", err)
		t.FailNow()
	}

	return pemByteBuffer.Bytes()
}

func TestSync(t *testing.T) {
	nowMetaTime := metav1.NewTime(fixedClockStart)

	skRSA, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	skEC, err := pki.GenerateECPrivateKey(256)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	csrRSAPEM := generateCSR(t, skRSA)
	csrECPEM := generateCSR(t, skEC)

	baseIssuer := gen.Issuer("test-issuer",
		gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
		gen.AddIssuerCondition(cmapi.IssuerCondition{
			Type:   cmapi.IssuerConditionReady,
			Status: cmmeta.ConditionTrue,
		}),
	)

	baseCRNotApproved := gen.CertificateRequest("test-cr",
		gen.SetCertificateRequestIsCA(false),
		gen.SetCertificateRequestCSR(csrRSAPEM),
		gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
			Kind: baseIssuer.Kind,
			Name: baseIssuer.Name,
		}),
	)

	baseCR := gen.CertificateRequestFrom(baseCRNotApproved,
		gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
			Type:               cmapi.CertificateRequestConditionApproved,
			Status:             cmmeta.ConditionTrue,
			Reason:             "cert-manager.io",
			Message:            "Certificate request has been approved by cert-manager.io",
			LastTransitionTime: &nowMetaTime,
		}),
	)
	baseCRNotApprovedEC := gen.CertificateRequest("test-cr",
		gen.SetCertificateRequestIsCA(false),
		gen.SetCertificateRequestCSR(csrECPEM),
		gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
			Kind: baseIssuer.Kind,
			Name: baseIssuer.Name,
		}),
	)

	baseCREC := gen.CertificateRequestFrom(baseCRNotApprovedEC,
		gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
			Type:               cmapi.CertificateRequestConditionApproved,
			Status:             cmmeta.ConditionTrue,
			Reason:             "cert-manager.io",
			Message:            "Certificate request has been approved by cert-manager.io",
			LastTransitionTime: &nowMetaTime,
		}),
	)

	certRSAPEM := generateSelfSignedCert(t, baseCR, skRSA, fixedClockStart, fixedClockStart.Add(time.Hour*12))
	certRSAPEMExpired := generateSelfSignedCert(t, baseCR, skRSA, fixedClockStart.Add(-time.Hour*13), fixedClockStart.Add(-time.Hour*12))

	certECPEM := generateSelfSignedCert(t, baseCREC, skEC, fixedClockStart, fixedClockStart.Add(time.Hour*12))
	certECPEMExpired := generateSelfSignedCert(t, baseCREC, skEC, fixedClockStart.Add(-time.Hour*13), fixedClockStart.Add(-time.Hour*12))

	tests := map[string]testT{
		"should return nil (no action) if group name if not 'cert-manager.io' or ''": {
			certificateRequest: gen.CertificateRequestFrom(baseCR,
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Group: "not-cert-manager.io",
				}),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer, baseCR},
				ExpectedEvents:     []string{},
				ExpectedActions:    []testpkg.Action{},
			},
		},
		"should return nil (no action) if certificate request is not approved": {
			certificateRequest: gen.CertificateRequestFrom(baseCRNotApproved),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer, baseCR},
				ExpectedEvents: []string{
					"Normal WaitingForApproval Not signing CertificateRequest until it is Approved",
				},
				ExpectedActions: []testpkg.Action{},
			},
		},
		"should update Ready condition with 'Denied' if certificate request is denied": {
			certificateRequest: gen.CertificateRequestFrom(baseCRNotApproved,
				gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type:               cmapi.CertificateRequestConditionDenied,
					Status:             cmmeta.ConditionTrue,
					Reason:             "Foo",
					Message:            "Certificate request has been denied by cert-manager.io",
					LastTransitionTime: &nowMetaTime,
				}),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer, baseCR},
				ExpectedEvents:     []string{},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCRNotApproved,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionDenied,
								Status:             cmmeta.ConditionTrue,
								Reason:             "Foo",
								Message:            "Certificate request has been denied by cert-manager.io",
								LastTransitionTime: &nowMetaTime,
							}),
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             "Denied",
								Message:            "The CertificateRequest was denied by an approval controller",
								LastTransitionTime: &nowMetaTime,
							}),
							gen.SetCertificateRequestFailureTime(nowMetaTime),
						),
					)),
				},
			},
		},
		"should overwrite Ready condition with Denied if certificate request is denied": {
			certificateRequest: gen.CertificateRequestFrom(baseCRNotApproved,
				gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type:               cmapi.CertificateRequestConditionDenied,
					Status:             cmmeta.ConditionTrue,
					Reason:             "Foo",
					Message:            "Certificate request has been denied by cert-manager.io",
					LastTransitionTime: &nowMetaTime,
				}),
				gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type:               cmapi.CertificateRequestConditionReady,
					Status:             cmmeta.ConditionFalse,
					Reason:             "Failed",
					Message:            "Request has failed",
					LastTransitionTime: &nowMetaTime,
				}),
				gen.SetCertificateRequestFailureTime(nowMetaTime),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer, baseCR},
				ExpectedEvents:     []string{},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCRNotApproved,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionDenied,
								Status:             cmmeta.ConditionTrue,
								Reason:             "Foo",
								Message:            "Certificate request has been denied by cert-manager.io",
								LastTransitionTime: &nowMetaTime,
							}),
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             "Denied",
								Message:            "The CertificateRequest was denied by an approval controller",
								LastTransitionTime: &nowMetaTime,
							}),
							gen.SetCertificateRequestFailureTime(nowMetaTime),
						),
					)),
				},
			},
		},
		"should do nothing if request has a Denied condition and already has a False Ready condition": {
			certificateRequest: gen.CertificateRequestFrom(baseCRNotApproved,
				gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type:               cmapi.CertificateRequestConditionDenied,
					Status:             cmmeta.ConditionTrue,
					Reason:             "Foo",
					Message:            "Certificate request has been denied by cert-manager.io",
					LastTransitionTime: &nowMetaTime,
				}),
				gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type:               cmapi.CertificateRequestConditionReady,
					Status:             cmmeta.ConditionFalse,
					Reason:             "Denied",
					Message:            "The CertificateRequest was denied by an approval controller",
					LastTransitionTime: &nowMetaTime,
				}),
				gen.SetCertificateRequestFailureTime(nowMetaTime),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer,
					gen.CertificateRequestFrom(baseCRNotApproved,
						gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:               cmapi.CertificateRequestConditionDenied,
							Status:             cmmeta.ConditionTrue,
							Reason:             "Foo",
							Message:            "Certificate request has been denied by cert-manager.io",
							LastTransitionTime: &nowMetaTime,
						}),
						gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:               cmapi.CertificateRequestConditionReady,
							Status:             cmmeta.ConditionFalse,
							Reason:             "Denied",
							Message:            "The CertificateRequest was denied by an approval controller",
							LastTransitionTime: &nowMetaTime,
						}),
						gen.SetCertificateRequestFailureTime(nowMetaTime),
					),
				},
				ExpectedEvents:  []string{},
				ExpectedActions: []testpkg.Action{},
			},
		},
		"should set Ready condition reason to Denied if certificate request is denied and has a Pending reason for the Ready condition": {
			certificateRequest: gen.CertificateRequestFrom(baseCRNotApproved,
				gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type:               cmapi.CertificateRequestConditionDenied,
					Status:             cmmeta.ConditionTrue,
					Reason:             "Foo",
					Message:            "Certificate request has been denied by cert-manager.io",
					LastTransitionTime: &nowMetaTime,
				}),
				gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type:               cmapi.CertificateRequestConditionReady,
					Status:             cmmeta.ConditionFalse,
					Reason:             "Pending",
					Message:            "Certificate request is pending",
					LastTransitionTime: &nowMetaTime,
				}),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer, baseCR},
				ExpectedEvents:     []string{},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCRNotApproved,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionDenied,
								Status:             cmmeta.ConditionTrue,
								Reason:             "Foo",
								Message:            "Certificate request has been denied by cert-manager.io",
								LastTransitionTime: &nowMetaTime,
							}),
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             "Denied",
								Message:            "The CertificateRequest was denied by an approval controller",
								LastTransitionTime: &nowMetaTime,
							}),
							gen.SetCertificateRequestFailureTime(nowMetaTime),
						),
					)),
				},
			},
		},
		"should return nil (no action) if certificate request approved is set to false": {
			certificateRequest: gen.CertificateRequestFrom(baseCRNotApproved,
				gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type:               cmapi.CertificateRequestConditionApproved,
					Status:             cmmeta.ConditionFalse,
					Reason:             "cert-manager.io",
					Message:            "Certificate request has not been approved",
					LastTransitionTime: &nowMetaTime,
				}),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer, baseCR},
				ExpectedEvents: []string{
					"Normal WaitingForApproval Not signing CertificateRequest until it is Approved",
				},
				ExpectedActions: []testpkg.Action{},
			},
		},
		"should return nil (no action) if certificate request invalidrequest is set to true": {
			certificateRequest: gen.CertificateRequestFrom(baseCRNotApproved,
				gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type:               cmapi.CertificateRequestConditionInvalidRequest,
					Status:             cmmeta.ConditionTrue,
					Reason:             "InvalidRequest",
					Message:            "Certificate request is invalid",
					LastTransitionTime: &nowMetaTime,
				}),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer, baseCR},
				ExpectedActions:    []testpkg.Action{},
			},
		},
		"should return nil (no action) if certificate request is ready and reason Issued": {
			certificateRequest: gen.CertificateRequestFrom(baseCR,
				gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type:               cmapi.CertificateRequestConditionReady,
					Status:             cmmeta.ConditionTrue,
					Reason:             "Issued",
					Message:            "Certificate issued",
					LastTransitionTime: &nowMetaTime,
				}),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer, baseCR},
				ExpectedEvents:     []string{},
				ExpectedActions:    []testpkg.Action{},
			},
		},
		"should return nil (no action) if certificate request is not ready and reason Failed": {
			certificateRequest: gen.CertificateRequestFrom(baseCR,
				gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type:               cmapi.CertificateRequestConditionReady,
					Status:             cmmeta.ConditionFalse,
					Reason:             "Failed",
					Message:            "Certificate failed",
					LastTransitionTime: &nowMetaTime,
				}),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer, baseCR},
				ExpectedEvents:     []string{},
				ExpectedActions:    []testpkg.Action{},
			},
		},
		"should report pending if issuer not found": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseCR},
				ExpectedEvents: []string{
					`Normal IssuerNotFound Referenced "Issuer" not found: issuer.cert-manager.io "test-issuer" not found`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             "Pending",
								Message:            `Referenced "Issuer" not found: issuer.cert-manager.io "test-issuer" not found`,
								LastTransitionTime: &nowMetaTime,
							}),
						),
					)),
				},
			},
		},
		"should return error to try again if there was an error getting issuer wasn't a not found error": {
			certificateRequest: baseCR.DeepCopy(),
			helper: &issuerfake.Helper{
				GetGenericIssuerFunc: func(cmmeta.ObjectReference, string) (cmapi.GenericIssuer, error) {
					return nil, errors.New("this is a network error")
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseCR},
				ExpectedEvents:     []string{},
				ExpectedActions:    []testpkg.Action{},
			},
			expectedErr: true,
		},
		"report pending if we cannot determine the issuer type (probably not set)": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseCR,
					// no type set
					gen.Issuer(baseIssuer.Name),
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             "Pending",
								Message:            "Missing issuer type: no issuer specified for Issuer 'default-unit-test-ns/test-issuer'",
								LastTransitionTime: &nowMetaTime,
							}),
						),
					)),
				},
				ExpectedEvents: []string{
					"Normal IssuerTypeMissing Missing issuer type: no issuer specified for Issuer 'default-unit-test-ns/test-issuer'",
				},
			},
		},
		"should exit nil and set status pending if referenced issuer is not ready": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseCR,
					gen.Issuer(baseIssuer.Name,
						gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
					),
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             "Pending",
								Message:            "Referenced issuer does not have a Ready status condition",
								LastTransitionTime: &nowMetaTime,
							}),
						),
					)),
				},
				ExpectedEvents: []string{
					"Normal IssuerNotReady Referenced issuer does not have a Ready status condition",
				},
			},
		},
		"exit nil and no action if the issuer type does not match ours (its not meant for us)": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseCR,
					gen.Issuer(baseIssuer.Name,
						gen.AddIssuerCondition(cmapi.IssuerCondition{
							Type:   cmapi.IssuerConditionReady,
							Status: cmmeta.ConditionTrue,
						}),
						gen.SetIssuerCA(cmapi.CAIssuer{}),
					),
				},
				ExpectedActions: []testpkg.Action{},
				ExpectedEvents:  []string{},
			},
		},
		"if the Certificate is already set in the status then return nil and no-op, regardless of condition": {
			certificateRequest: gen.CertificateRequestFrom(baseCR,
				gen.SetCertificateRequestCertificate([]byte("a cert")),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseCR, baseIssuer},
				ExpectedEvents:     []string{},
				ExpectedActions:    []testpkg.Action{},
			},
		},
		"if calling sign errors, we should not update condition and return error to retry": {
			certificateRequest: gen.CertificateRequestFrom(baseCR),
			issuerImpl: &fake.Issuer{
				FakeSign: func(context.Context, *cmapi.CertificateRequest, cmapi.GenericIssuer) (*issuer.IssueResponse, error) {
					return nil, errors.New("sign call returns error")
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseCR, baseIssuer},
				ExpectedEvents:     []string{},
				ExpectedActions:    []testpkg.Action{},
			},
			expectedErr: true,
		},
		"if calling sign returns nil, nil then we should return nil with no-op since the underlying issuer has probably set the condition to failed": {
			certificateRequest: gen.CertificateRequestFrom(baseCR),
			issuerImpl: &fake.Issuer{
				FakeSign: func(context.Context, *cmapi.CertificateRequest, cmapi.GenericIssuer) (*issuer.IssueResponse, error) {
					return nil, nil
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseCR, baseIssuer},
				ExpectedEvents:     []string{},
				ExpectedActions:    []testpkg.Action{},
			},
			expectedErr: false,
		},
		"if calling sign returns a response but the certificate is badly formed then we fail": {
			certificateRequest: baseCR.DeepCopy(),
			issuerImpl: &fake.Issuer{
				FakeSign: func(context.Context, *cmapi.CertificateRequest, cmapi.GenericIssuer) (*issuer.IssueResponse, error) {
					return &issuer.IssueResponse{
						Certificate: []byte("a bad certificate"),
					}, nil
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer,
					gen.CertificateRequestFrom(baseCR,
						gen.SetCertificateRequestCertificate([]byte("a bad certificate")),
					)},
				ExpectedEvents: []string{
					"Warning DecodeError Failed to decode returned certificate: error decoding certificate PEM block",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestCertificate([]byte("a bad certificate")),
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             "Failed",
								Message:            "Failed to decode returned certificate: error decoding certificate PEM block",
								LastTransitionTime: &nowMetaTime,
							}),
							gen.SetCertificateRequestFailureTime(nowMetaTime),
						),
					)),
				},
			},
		},
		"if calling sign returns a response with a valid RSA signed certificate then set condition Ready": {
			certificateRequest: baseCR.DeepCopy(),
			issuerImpl: &fake.Issuer{
				FakeSign: func(context.Context, *cmapi.CertificateRequest, cmapi.GenericIssuer) (*issuer.IssueResponse, error) {
					return &issuer.IssueResponse{
						Certificate: certRSAPEM,
					}, nil
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer, baseCR.DeepCopy()},
				ExpectedEvents: []string{
					"Normal CertificateIssued Certificate fetched from issuer successfully",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestCertificate(certRSAPEM),
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionTrue,
								Reason:             "Issued",
								Message:            "Certificate fetched from issuer successfully",
								LastTransitionTime: &nowMetaTime,
							}),
						),
					)),
				},
			},
		},
		"if calling sign returns a response with an expired RSA certificate then set condition Ready": {
			certificateRequest: baseCR.DeepCopy(),
			issuerImpl: &fake.Issuer{
				FakeSign: func(context.Context, *cmapi.CertificateRequest, cmapi.GenericIssuer) (*issuer.IssueResponse, error) {
					return &issuer.IssueResponse{
						Certificate: certRSAPEMExpired,
					}, nil
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer, baseCR.DeepCopy()},
				ExpectedEvents: []string{
					"Normal CertificateIssued Certificate fetched from issuer successfully",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestCertificate(certRSAPEMExpired),
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionTrue,
								Reason:             "Issued",
								Message:            "Certificate fetched from issuer successfully",
								LastTransitionTime: &nowMetaTime,
							}),
						),
					)),
				},
			},
		},
		"if calling sign returns a response with a valid EC signed certificate then set condition Ready": {
			certificateRequest: baseCR.DeepCopy(),
			issuerImpl: &fake.Issuer{
				FakeSign: func(context.Context, *cmapi.CertificateRequest, cmapi.GenericIssuer) (*issuer.IssueResponse, error) {
					return &issuer.IssueResponse{
						Certificate: certECPEM,
					}, nil
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer, baseCR.DeepCopy()},
				ExpectedEvents: []string{
					"Normal CertificateIssued Certificate fetched from issuer successfully",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestCertificate(certECPEM),
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionTrue,
								Reason:             "Issued",
								Message:            "Certificate fetched from issuer successfully",
								LastTransitionTime: &nowMetaTime,
							}),
						),
					)),
				},
			},
		},
		"if calling sign returns a response with an expired EC certificate then set condition Ready": {
			certificateRequest: baseCR.DeepCopy(),
			issuerImpl: &fake.Issuer{
				FakeSign: func(context.Context, *cmapi.CertificateRequest, cmapi.GenericIssuer) (*issuer.IssueResponse, error) {
					return &issuer.IssueResponse{
						Certificate: certECPEMExpired,
					}, nil
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer, baseCR.DeepCopy()},
				ExpectedEvents: []string{
					"Normal CertificateIssued Certificate fetched from issuer successfully",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestCertificate(certECPEMExpired),
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionTrue,
								Reason:             "Issued",
								Message:            "Certificate fetched from issuer successfully",
								LastTransitionTime: &nowMetaTime,
							}),
						),
					)),
				},
			},
		},
	}

	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			fixedClock.SetTime(fixedClockStart)
			runTest(t, test)
		})
	}
}

type testT struct {
	builder            *testpkg.Builder
	issuerImpl         Issuer
	certificateRequest *cmapi.CertificateRequest
	helper             *issuerfake.Helper
	expectedErr        bool
}

func runTest(t *testing.T, test testT) {
	test.builder.T = t
	test.builder.Clock = fixedClock
	test.builder.Init()

	defer test.builder.Stop()

	if test.issuerImpl == nil {
		test.issuerImpl = &fake.Issuer{
			FakeSign: func(context.Context, *cmapi.CertificateRequest, cmapi.GenericIssuer) (*issuer.IssueResponse, error) {
				return nil, errors.New("unexpected sign call")
			},
		}
	}

	c := New(util.IssuerSelfSigned, func(*controller.Context) Issuer { return test.issuerImpl })
	if _, _, err := c.Register(test.builder.Context); err != nil {
		t.Fatal(err)
	}

	if test.helper != nil {
		c.helper = test.helper
	}

	test.builder.Start()

	err := c.Sync(context.Background(), test.certificateRequest)
	if err != nil && !test.expectedErr {
		t.Errorf("expected to not get an error, but got: %v", err)
	}
	if err == nil && test.expectedErr {
		t.Errorf("expected to get an error but did not get one")
	}
	test.builder.CheckAndFinish(err)
}
