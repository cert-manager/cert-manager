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

package validation

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"reflect"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	cminternal "github.com/cert-manager/cert-manager/internal/apis/certmanager"
	cminternalmeta "github.com/cert-manager/cert-manager/internal/apis/meta"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func TestValidateCertificateRequestUpdate(t *testing.T) {
	fldPathConditions := field.NewPath("status", "conditions")

	baseRequest := mustGenerateCSR(t, gen.Certificate("test", gen.SetCertificateDNSNames("example.com")))

	baseCR := &cminternal.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"abc":                      "123",
				"cert-manager.io/foo":      "abc",
				"acme.cert-manager.io/bar": "123",
			},
		},
		Spec: cminternal.CertificateRequestSpec{
			Request:   baseRequest,
			IssuerRef: validIssuerRef,
			Usages:    nil,
			UID:       "abc",
			Username:  "user-1",
			Groups:    []string{"group-1", "group-2"},
			Extra: map[string][]string{
				"1": {"abc", "efg"},
				"2": {"efg", "abc"},
			},
		},
	}
	someAdmissionRequest := &admissionv1.AdmissionRequest{
		RequestKind: &metav1.GroupVersionKind{
			Group:   "test",
			Kind:    "test",
			Version: "test",
		},
	}

	tests := map[string]struct {
		oldCR, newCR *cminternal.CertificateRequest
		a            *admissionv1.AdmissionRequest
		wantE        field.ErrorList
		wantW        []string
	}{
		"if CertificateRequest spec and cert-manager.io annotations change, error": {
			oldCR: baseCR.DeepCopy(),
			newCR: &cminternal.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"acme.cert-manager.io/bar": "123",
						"123":                      "abc",
					},
				},
				Spec: cminternal.CertificateRequestSpec{
					Request: mustGenerateCSR(t, gen.Certificate("test", gen.SetCertificateDNSNames("example.com"))),
				},
			},
			a: someAdmissionRequest,
			wantE: []*field.Error{
				field.Forbidden(field.NewPath("metadata", "annotations", "cert-manager.io/foo"), "cannot change cert-manager annotation after creation"),
				field.Forbidden(field.NewPath("spec"), "cannot change spec after creation"),
			},
		},
		"if CertificateRequest spec and acme.cert-manager.io annotations change, error": {
			oldCR: baseCR.DeepCopy(),
			newCR: &cminternal.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"cert-manager.io/foo": "abc",
						"123":                 "abc",
					},
				},
				Spec: cminternal.CertificateRequestSpec{
					Request: mustGenerateCSR(t, gen.Certificate("test", gen.SetCertificateDNSNames("example.com"))),
				},
			},
			a: someAdmissionRequest,
			wantE: []*field.Error{
				field.Forbidden(field.NewPath("metadata", "annotations", "acme.cert-manager.io/bar"), "cannot change cert-manager annotation after creation"),
				field.Forbidden(field.NewPath("spec"), "cannot change spec after creation"),
			},
		},
		"if CertificateRequest spec and annotations do not change, don't error": {
			oldCR: baseCR.DeepCopy(),
			newCR: baseCR.DeepCopy(),
			a:     someAdmissionRequest,
			wantE: nil,
		},
		"CertificateRequest with single Approved=true condition that doesn't change, shouldn't error": {
			oldCR: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   baseRequest,
					IssuerRef: validIssuerRef,
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{
						{
							Type:   cminternal.CertificateRequestConditionApproved,
							Status: cminternalmeta.ConditionTrue,
						},
					},
				},
			},
			newCR: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   baseRequest,
					IssuerRef: validIssuerRef,
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{
						{
							Type:   cminternal.CertificateRequestConditionApproved,
							Status: cminternalmeta.ConditionTrue,
						},
					},
				},
			},
			a:     someAdmissionRequest,
			wantE: nil,
		},
		"CertificateRequest with single Denied=true condition that doesn't change, shouldn't error": {
			oldCR: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   baseRequest,
					IssuerRef: validIssuerRef,
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{
						{
							Type:   cminternal.CertificateRequestConditionDenied,
							Status: cminternalmeta.ConditionTrue,
						},
					},
				},
			},
			newCR: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   baseRequest,
					IssuerRef: validIssuerRef,
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{
						{
							Type:   cminternal.CertificateRequestConditionDenied,
							Status: cminternalmeta.ConditionTrue,
						},
					},
				},
			},
			a:     someAdmissionRequest,
			wantE: nil,
		},
		"CertificateRequest with single Approved=false condition that changes, should error": {
			oldCR: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   baseRequest,
					IssuerRef: validIssuerRef,
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{
						{
							Type:   cminternal.CertificateRequestConditionApproved,
							Status: cminternalmeta.ConditionFalse,
							Reason: "Foo",
						},
					},
				},
			},
			newCR: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   baseRequest,
					IssuerRef: validIssuerRef,
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{
						{
							Type:   cminternal.CertificateRequestConditionApproved,
							Status: cminternalmeta.ConditionTrue,
							Reason: "cert-manager.io",
						},
					},
				},
			},
			a: someAdmissionRequest,
			wantE: []*field.Error{
				field.Forbidden(fldPathConditions, "'Approved' condition may not be modified once set"),
			},
		},
		"CertificateRequest with single Denied=false condition that changes, should error": {
			oldCR: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   baseRequest,
					IssuerRef: validIssuerRef,
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{
						{
							Type:   cminternal.CertificateRequestConditionDenied,
							Status: cminternalmeta.ConditionTrue,
							Reason: "Foo",
						},
					},
				},
			},
			newCR: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   baseRequest,
					IssuerRef: validIssuerRef,
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{
						{
							Type:   cminternal.CertificateRequestConditionDenied,
							Status: cminternalmeta.ConditionFalse,
							Reason: "test",
						},
					},
				},
			},
			a: someAdmissionRequest,
			wantE: []*field.Error{
				field.Forbidden(fldPathConditions, "'Denied' condition may not be modified once set"),
				field.Invalid(fldPathConditions.Child("Denied"), nil, `"Denied" condition may only be set to True`),
			},
		},
		"CertificateRequest with single Denied=true condition that changes to Approve=true, should error": {
			oldCR: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   baseRequest,
					IssuerRef: validIssuerRef,
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{
						{
							Type:   cminternal.CertificateRequestConditionDenied,
							Status: cminternalmeta.ConditionTrue,
							Reason: "Foo",
						},
					},
				},
			},
			newCR: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   baseRequest,
					IssuerRef: validIssuerRef,
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{
						{
							Type:   cminternal.CertificateRequestConditionApproved,
							Status: cminternalmeta.ConditionTrue,
							Reason: "cert-manager.io",
						},
					},
				},
			},
			a: someAdmissionRequest,
			wantE: []*field.Error{
				field.Forbidden(fldPathConditions, "'Denied' condition may not be modified once set"),
			},
		},
		"CertificateRequest with single Approved=true condition that changes to Denied=true, should error": {
			oldCR: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   baseRequest,
					IssuerRef: validIssuerRef,
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{
						{
							Type:   cminternal.CertificateRequestConditionApproved,
							Status: cminternalmeta.ConditionTrue,
							Reason: "cert-manager.io",
						},
					},
				},
			},
			newCR: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   baseRequest,
					IssuerRef: validIssuerRef,
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{
						{
							Type:   cminternal.CertificateRequestConditionDenied,
							Status: cminternalmeta.ConditionTrue,
							Reason: "Foo",
						},
					},
				},
			},
			a: someAdmissionRequest,
			wantE: []*field.Error{
				field.Forbidden(fldPathConditions, "'Approved' condition may not be modified once set"),
			},
		},
		"CertificateRequest with no condition that changes to Approve=true, shouldn't error": {
			oldCR: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   baseRequest,
					IssuerRef: validIssuerRef,
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{},
				},
			},
			newCR: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   baseRequest,
					IssuerRef: validIssuerRef,
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{
						{
							Type:   cminternal.CertificateRequestConditionApproved,
							Status: cminternalmeta.ConditionTrue,
							Reason: "cert-manager.io",
						},
					},
				},
			},
			a:     someAdmissionRequest,
			wantE: nil,
		},
		"CertificateRequest with no condition that changes to Denied=true, shouldn't error": {
			oldCR: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   baseRequest,
					IssuerRef: validIssuerRef,
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{},
				},
			},
			newCR: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   baseRequest,
					IssuerRef: validIssuerRef,
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{
						{
							Type:   cminternal.CertificateRequestConditionDenied,
							Status: cminternalmeta.ConditionTrue,
							Reason: "Foo",
						},
					},
				},
			},
			a:     someAdmissionRequest,
			wantE: nil,
		},
		"CertificateRequest with single Approved=true condition that is removed, should error": {
			oldCR: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   baseRequest,
					IssuerRef: validIssuerRef,
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{
						{
							Type:   cminternal.CertificateRequestConditionApproved,
							Status: cminternalmeta.ConditionTrue,
						},
					},
				},
			},
			newCR: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   baseRequest,
					IssuerRef: validIssuerRef,
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{},
				},
			},
			a: someAdmissionRequest,
			wantE: []*field.Error{
				field.Forbidden(fldPathConditions, "'Approved' condition may not be modified once set"),
			},
		},
		"CertificateRequest with single Denied=true condition that is removed, should error": {
			oldCR: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   baseRequest,
					IssuerRef: validIssuerRef,
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{
						{
							Type:   cminternal.CertificateRequestConditionDenied,
							Status: cminternalmeta.ConditionTrue,
						},
					},
				},
			},
			newCR: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   baseRequest,
					IssuerRef: validIssuerRef,
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{},
				},
			},
			a: someAdmissionRequest,
			wantE: []*field.Error{
				field.Forbidden(fldPathConditions, "'Denied' condition may not be modified once set"),
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gotE, gotW := ValidateUpdateCertificateRequest(test.a, test.oldCR, test.newCR)
			for i := range gotE {
				if gotE[i].Type != field.ErrorTypeForbidden {
					// filter out the value so it does not print the full CSR in tests
					gotE[i].BadValue = nil
				}
			}

			if !reflect.DeepEqual(gotE, test.wantE) {
				t.Errorf("errors from ValidateUpdateCertificateRequest() = %v, want %v", gotE, test.wantE)
			}
			if !reflect.DeepEqual(gotW, test.wantW) {
				t.Errorf("warnings from ValidateUpdateCertificateRequest() = %#+v, want %#+v", gotW, test.wantW)
			}
		})
	}
}

func TestValidateCertificateRequest(t *testing.T) {
	fldPath := field.NewPath("spec")
	fldPathConditions := field.NewPath("status", "conditions")

	tests := map[string]struct {
		cr    *cminternal.CertificateRequest
		a     *admissionv1.AdmissionRequest
		wantE field.ErrorList
		wantW []string
	}{
		"Test csr with no usages": {
			cr: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   mustGenerateCSR(t, gen.Certificate("test", gen.SetCertificateDNSNames("example.com"))),
					IssuerRef: validIssuerRef,
					Usages:    nil,
				},
			},
			a:     someAdmissionRequest,
			wantE: []*field.Error{},
		},
		"Test csr with double signature usages": {
			cr: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   mustGenerateCSR(t, gen.Certificate("test", gen.SetCertificateDNSNames("example.com"), gen.SetCertificateKeyUsages(cmapi.UsageSigning, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment))),
					IssuerRef: validIssuerRef,
					Usages:    []cminternal.KeyUsage{cminternal.UsageSigning, cminternal.UsageKeyEncipherment},
				},
			},
			a:     someAdmissionRequest,
			wantE: []*field.Error{},
		},
		"Test csr with double extended usages": {
			cr: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   mustGenerateCSR(t, gen.Certificate("test", gen.SetCertificateDNSNames("example.com"), gen.SetCertificateKeyUsages(cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageServerAuth, cmapi.UsageClientAuth))),
					IssuerRef: validIssuerRef,
					Usages:    []cminternal.KeyUsage{cminternal.UsageSigning, cminternal.UsageKeyEncipherment, cminternal.UsageServerAuth, cminternal.UsageClientAuth},
				},
			},
			a:     someAdmissionRequest,
			wantE: []*field.Error{},
		},
		"Test csr with reordered usages": {
			cr: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   mustGenerateCSR(t, gen.Certificate("test", gen.SetCertificateDNSNames("example.com"), gen.SetCertificateKeyUsages(cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageServerAuth, cmapi.UsageClientAuth))),
					IssuerRef: validIssuerRef,
					Usages:    []cminternal.KeyUsage{cminternal.UsageServerAuth, cminternal.UsageClientAuth, cminternal.UsageKeyEncipherment, cminternal.UsageDigitalSignature},
				},
			},
			a:     someAdmissionRequest,
			wantE: []*field.Error{},
		},
		"Test csr that is CA with usages set": {
			cr: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   mustGenerateCSR(t, gen.Certificate("test", gen.SetCertificateDNSNames("example.com"), gen.SetCertificateKeyUsages(cmapi.UsageAny, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageCertSign), gen.SetCertificateIsCA(true))),
					IssuerRef: validIssuerRef,
					IsCA:      true,
					Usages:    []cminternal.KeyUsage{cminternal.UsageAny, cminternal.UsageDigitalSignature, cminternal.UsageKeyEncipherment, cminternal.UsageCertSign},
				},
			},
			a:     someAdmissionRequest,
			wantE: []*field.Error{},
		},
		"Test csr that is CA but no cert sign in usages": {
			cr: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   mustGenerateCSR(t, gen.Certificate("test", gen.SetCertificateDNSNames("example.com"), gen.SetCertificateKeyUsages(cmapi.UsageAny, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageClientAuth, cmapi.UsageServerAuth), gen.SetCertificateIsCA(true))),
					IssuerRef: validIssuerRef,
					IsCA:      true,
					Usages:    []cminternal.KeyUsage{cminternal.UsageAny, cminternal.UsageDigitalSignature, cminternal.UsageKeyEncipherment, cminternal.UsageClientAuth, cminternal.UsageServerAuth},
				},
			},
			a:     someAdmissionRequest,
			wantE: []*field.Error{},
		},
		"Test csr with default usages and isCA": {
			cr: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   mustGenerateCSR(t, gen.Certificate("test", gen.SetCertificateDNSNames("example.com"), gen.SetCertificateKeyUsages(cmapi.UsageDigitalSignature, cmapi.UsageCertSign, cmapi.UsageKeyEncipherment), gen.SetCertificateIsCA(true))),
					IssuerRef: validIssuerRef,
					IsCA:      true,
					Usages:    nil,
				},
			},
			a:     someAdmissionRequest,
			wantE: []*field.Error{},
		},
		"Test cr with default usages": {
			cr: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					// mustGenerateCSR will set the default usages for us
					Request:   mustGenerateCSR(t, gen.Certificate("test", gen.SetCertificateDNSNames("example.com"))),
					IssuerRef: validIssuerRef,
					Usages:    []cminternal.KeyUsage{cminternal.UsageKeyEncipherment, cminternal.UsageDigitalSignature},
				},
			},
			a:     someAdmissionRequest,
			wantE: []*field.Error{},
		},
		"Test cr with default usages, without any encoded in csr": {
			cr: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					// mustGenerateCSR will set the default usages for us
					Request: mustGenerateCSR(t, gen.Certificate("test", gen.SetCertificateDNSNames("example.com")), func(cr *x509.CertificateRequest) error {
						// manually remove extensions that encode default usages
						cr.Extensions = nil
						cr.ExtraExtensions = nil

						return nil
					}),
					IssuerRef: validIssuerRef,
					Usages:    []cminternal.KeyUsage{cminternal.UsageKeyEncipherment, cminternal.UsageDigitalSignature},
				},
			},
			a:     someAdmissionRequest,
			wantE: []*field.Error{},
		},
		"Test cr with default usages, with empty set encoded in csr": {
			cr: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					// mustGenerateCSR will set the default usages for us
					Request: mustGenerateCSR(t, gen.Certificate("test", gen.SetCertificateDNSNames("example.com")), func(cr *x509.CertificateRequest) error {
						// manually remove extensions that encode default usages
						cr.Extensions = nil
						cr.ExtraExtensions = []pkix.Extension{
							{
								Id:       utilpki.OIDExtensionKeyUsage,
								Critical: false,
								Value: func(t *testing.T) []byte {
									asn1KeyUsage, err := asn1.Marshal(asn1.BitString{Bytes: []byte{}, BitLength: 0})
									if err != nil {
										t.Fatal(err)
									}

									return asn1KeyUsage
								}(t),
							},
						}

						return nil
					}),
					IssuerRef: validIssuerRef,
					Usages:    []cminternal.KeyUsage{cminternal.UsageKeyEncipherment, cminternal.UsageDigitalSignature},
				},
			},
			a: someAdmissionRequest,
			wantE: []*field.Error{
				field.Invalid(fldPath.Child("request"), nil, "encoded CSR error: the KeyUsages [] do not match the expected KeyUsages [ 'digital signature', 'key encipherment' ]"),
			},
		},
		"Error on csr not having all usages": {
			cr: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   mustGenerateCSR(t, gen.Certificate("test", gen.SetCertificateDNSNames("example.com"), gen.SetCertificateKeyUsages(cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageServerAuth))),
					IssuerRef: validIssuerRef,
					Usages:    []cminternal.KeyUsage{cminternal.UsageSigning, cminternal.UsageKeyEncipherment, cminternal.UsageServerAuth, cminternal.UsageClientAuth},
				},
			},
			a: someAdmissionRequest,
			wantE: []*field.Error{
				field.Invalid(fldPath.Child("request"), nil, "encoded CSR error: the ExtKeyUsages [ 'server auth' ] do not match the expected ExtKeyUsages [ 'server auth', 'client auth' ]"),
			},
		},
		"Error on cr not having all usages": {
			cr: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   mustGenerateCSR(t, gen.Certificate("test", gen.SetCertificateDNSNames("example.com"), gen.SetCertificateKeyUsages(cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageServerAuth, cmapi.UsageClientAuth))),
					IssuerRef: validIssuerRef,
					Usages:    []cminternal.KeyUsage{cminternal.UsageSigning, cminternal.UsageKeyEncipherment},
				},
			},
			a: someAdmissionRequest,
			wantE: []*field.Error{
				field.Invalid(fldPath.Child("request"), nil, "encoded CSR error: the ExtKeyUsages [ 'server auth', 'client auth' ] do not match the expected ExtKeyUsages []"),
			},
		},
		"Test csr with any, signing, digital signature, key encipherment, server and client auth": {
			cr: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   mustGenerateCSR(t, gen.Certificate("test", gen.SetCertificateDNSNames("example.com"), gen.SetCertificateKeyUsages(cmapi.UsageAny, cmapi.UsageSigning, cmapi.UsageKeyEncipherment, cmapi.UsageClientAuth, cmapi.UsageServerAuth), gen.SetCertificateIsCA(true))),
					IssuerRef: validIssuerRef,
					IsCA:      true,
					Usages:    []cminternal.KeyUsage{cminternal.UsageAny, cminternal.UsageSigning, cminternal.UsageKeyEncipherment, cminternal.UsageClientAuth, cminternal.UsageServerAuth},
				},
			},
			a:     someAdmissionRequest,
			wantE: []*field.Error{},
		},
		"CertificateRequest with single Approved=true condition, shouldn't error": {
			cr: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   mustGenerateCSR(t, gen.Certificate("spec", gen.SetCertificateDNSNames("example.com"), gen.SetCertificateKeyUsages(cmapi.UsageAny), gen.SetCertificateIsCA(true))),
					IssuerRef: validIssuerRef,
					IsCA:      true,
					Usages:    []cminternal.KeyUsage{cminternal.UsageAny},
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{
						{
							Type:   cminternal.CertificateRequestConditionApproved,
							Status: cminternalmeta.ConditionTrue,
						},
					},
				},
			},
			a:     someAdmissionRequest,
			wantE: []*field.Error{},
		},
		"CertificateRequest with single Denied=true condition, shouldn't error": {
			cr: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   mustGenerateCSR(t, gen.Certificate("spec", gen.SetCertificateDNSNames("example.com"), gen.SetCertificateKeyUsages(cmapi.UsageAny), gen.SetCertificateIsCA(true))),
					IssuerRef: validIssuerRef,
					IsCA:      true,
					Usages:    []cminternal.KeyUsage{cminternal.UsageAny},
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{
						{
							Type:   cminternal.CertificateRequestConditionDenied,
							Status: cminternalmeta.ConditionTrue,
						},
					},
				},
			},
			a:     someAdmissionRequest,
			wantE: []*field.Error{},
		},
		"CertificateRequest with single Approved=false condition, should error": {
			cr: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   mustGenerateCSR(t, gen.Certificate("spec", gen.SetCertificateDNSNames("example.com"), gen.SetCertificateKeyUsages(cmapi.UsageAny), gen.SetCertificateIsCA(true))),
					IssuerRef: validIssuerRef,
					IsCA:      true,
					Usages:    []cminternal.KeyUsage{cminternal.UsageAny},
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{
						{
							Type:   cminternal.CertificateRequestConditionApproved,
							Status: cminternalmeta.ConditionFalse,
							Reason: "cert-manager.io",
						},
					},
				},
			},
			a: someAdmissionRequest,
			wantE: []*field.Error{
				field.Invalid(fldPathConditions.Child("Approved"), nil,
					`"Approved" condition may only be set to True`),
			},
		},
		"CertificateRequest with single Denied=false condition, should error": {
			cr: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   mustGenerateCSR(t, gen.Certificate("spec", gen.SetCertificateDNSNames("example.com"), gen.SetCertificateKeyUsages(cmapi.UsageAny), gen.SetCertificateIsCA(true))),
					IssuerRef: validIssuerRef,
					IsCA:      true,
					Usages:    []cminternal.KeyUsage{cminternal.UsageAny},
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{
						{
							Type:   cminternal.CertificateRequestConditionDenied,
							Status: cminternalmeta.ConditionFalse,
							Reason: "Foo",
						},
					},
				},
			},
			a: someAdmissionRequest,
			wantE: []*field.Error{
				field.Invalid(fldPathConditions.Child("Denied"), nil,
					`"Denied" condition may only be set to True`),
			},
		},
		"CertificateRequest with both Denied=false and Approved=false conditions, should error": {
			cr: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   mustGenerateCSR(t, gen.Certificate("spec", gen.SetCertificateDNSNames("example.com"), gen.SetCertificateKeyUsages(cmapi.UsageAny), gen.SetCertificateIsCA(true))),
					IssuerRef: validIssuerRef,
					IsCA:      true,
					Usages:    []cminternal.KeyUsage{cminternal.UsageAny},
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{
						{
							Type:   cminternal.CertificateRequestConditionApproved,
							Status: cminternalmeta.ConditionFalse,
							Reason: "cert-manager.io",
						},
						{
							Type:   cminternal.CertificateRequestConditionDenied,
							Status: cminternalmeta.ConditionFalse,
							Reason: "Foo",
						},
					},
				},
			},
			a: someAdmissionRequest,
			wantE: []*field.Error{
				field.Invalid(field.NewPath("status", "conditions", "Approved"), nil,
					`"Approved" condition may only be set to True`),
				field.Invalid(field.NewPath("status", "conditions", "Denied"), nil,
					`"Denied" condition may only be set to True`),
				field.Forbidden(fldPathConditions, "both 'Denied' and 'Approved' conditions cannot coexist"),
			},
		},
		"CertificateRequest with both Denied=true and Approved=true conditions, should error": {
			cr: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   mustGenerateCSR(t, gen.Certificate("spec", gen.SetCertificateDNSNames("example.com"), gen.SetCertificateKeyUsages(cmapi.UsageAny), gen.SetCertificateIsCA(true))),
					IssuerRef: validIssuerRef,
					IsCA:      true,
					Usages:    []cminternal.KeyUsage{cminternal.UsageAny},
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{
						{
							Type:   cminternal.CertificateRequestConditionApproved,
							Status: cminternalmeta.ConditionTrue,
							Reason: "cert-manager.io",
						},
						{
							Type:   cminternal.CertificateRequestConditionDenied,
							Status: cminternalmeta.ConditionTrue,
							Reason: "Foo",
						},
					},
				},
			},
			a: someAdmissionRequest,
			wantE: []*field.Error{
				field.Forbidden(fldPathConditions, "both 'Denied' and 'Approved' conditions cannot coexist"),
			},
		},
		"CertificateRequest with multiple Approved conditions, should error": {
			cr: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   mustGenerateCSR(t, gen.Certificate("spec", gen.SetCertificateDNSNames("example.com"), gen.SetCertificateKeyUsages(cmapi.UsageAny), gen.SetCertificateIsCA(true))),
					IssuerRef: validIssuerRef,
					IsCA:      true,
					Usages:    []cminternal.KeyUsage{cminternal.UsageAny},
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{
						{
							Type:   cminternal.CertificateRequestConditionApproved,
							Status: cminternalmeta.ConditionTrue,
							Reason: "cert-manager.io",
						},
						{
							Type:   cminternal.CertificateRequestConditionApproved,
							Status: cminternalmeta.ConditionFalse,
							Reason: "foo",
						},
					},
				},
			},
			a: someAdmissionRequest,
			wantE: []*field.Error{
				field.Forbidden(fldPathConditions, `multiple "Approved" conditions present`),
			},
		},
		"CertificateRequest with multiple Denied conditions, should error": {
			cr: &cminternal.CertificateRequest{
				Spec: cminternal.CertificateRequestSpec{
					Request:   mustGenerateCSR(t, gen.Certificate("spec", gen.SetCertificateDNSNames("example.com"), gen.SetCertificateKeyUsages(cmapi.UsageAny), gen.SetCertificateIsCA(true))),
					IssuerRef: validIssuerRef,
					IsCA:      true,
					Usages:    []cminternal.KeyUsage{cminternal.UsageAny},
				},
				Status: cminternal.CertificateRequestStatus{
					Conditions: []cminternal.CertificateRequestCondition{
						{
							Type:   cminternal.CertificateRequestConditionDenied,
							Status: cminternalmeta.ConditionTrue,
							Reason: "Foo",
						},
						{
							Type:   cminternal.CertificateRequestConditionDenied,
							Status: cminternalmeta.ConditionFalse,
							Reason: "Foo",
						},
					},
				},
			},
			a: someAdmissionRequest,
			wantE: []*field.Error{
				field.Forbidden(fldPathConditions, `multiple "Denied" conditions present`),
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gotE, gotW := ValidateCertificateRequest(test.a, test.cr)
			for i := range gotE {
				if gotE[i].Type != field.ErrorTypeForbidden {
					// filter out the value so it does not print the full CSR in tests
					gotE[i].BadValue = nil
				}
			}
			if !reflect.DeepEqual(gotE, test.wantE) {
				t.Errorf("errors from ValidateCertificateRequest() = %v, want %v", gotE, test.wantE)
			}
			if !reflect.DeepEqual(test.wantW, gotW) {
				t.Errorf("warnings from ValidateCertificateRequest() = %v, want  %v", gotW, test.wantW)
			}
		})
	}
}

func mustGenerateCSR(t *testing.T, crt *cmapi.Certificate, modifiers ...gen.CSRModifier) []byte {
	csrPEM, _, err := gen.CSRForCertificate(crt, modifiers...)
	if err != nil {
		t.Fatal(err)
	}
	return csrPEM
}
