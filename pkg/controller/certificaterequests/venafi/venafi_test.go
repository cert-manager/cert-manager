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
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"

	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	corelisters "k8s.io/client-go/listers/core/v1"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	"github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/cmrand"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificaterequests"
	controllertest "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/pkg/issuer/venafi/client"
	"github.com/cert-manager/cert-manager/pkg/issuer/venafi/client/api"
	internalvenafifake "github.com/cert-manager/cert-manager/pkg/issuer/venafi/client/fake"
	"github.com/cert-manager/cert-manager/pkg/metrics"
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
		gen.SetCSRCommonName("test-common-name"),
		gen.SetCSRDNSNames("foo.example.com", "bar.example.com"),
	)
	if err != nil {
		t.Fatal(err)
	}

	return csr
}

func TestSign(t *testing.T) {
	metaFixedClockStart := metav1.NewTime(fixedClockStart)
	rootPK, err := pki.GenerateECPrivateKey(256)
	if err != nil {
		t.Fatal(err)
	}

	serialNumber, err := cmrand.SerialNumber()
	if err != nil {
		t.Fatal(err)
	}

	rootTmpl := &x509.Certificate{
		Version:               3,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		PublicKeyAlgorithm:    x509.ECDSA,
		PublicKey:             rootPK.Public(),
		IsCA:                  true,
		Subject: pkix.Name{
			CommonName: "root-ca",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Minute),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	rootPEM, rootCert, err := pki.SignCertificate(rootTmpl, rootTmpl, rootPK.Public(), rootPK)
	if err != nil {
		t.Fatal(err)
	}

	testPK, err := pki.GenerateECPrivateKey(256)
	if err != nil {
		t.Fatal(err)
	}

	csrPEM := generateCSR(t, testPK)

	tppSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-tpp-secret",
		},
		Data: map[string][]byte{
			"username": []byte("test-username"),
			"password": []byte("test-password"),
		},
	}

	cloudSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cloud-secret",
		},
		Data: map[string][]byte{
			"api-key": []byte("test-api-key"),
		},
	}

	baseIssuer := gen.Issuer("test-issuer",
		gen.SetIssuerVenafi(cmapi.VenafiIssuer{}),
		gen.AddIssuerCondition(cmapi.IssuerCondition{
			Type:   cmapi.IssuerConditionReady,
			Status: cmmeta.ConditionTrue,
		}),
	)

	tppIssuer := gen.IssuerFrom(baseIssuer,
		gen.SetIssuerVenafi(cmapi.VenafiIssuer{
			TPP: &cmapi.VenafiTPP{
				CredentialsRef: cmmeta.LocalObjectReference{
					Name: tppSecret.Name,
				},
			},
		}),
	)

	cloudIssuer := gen.IssuerFrom(baseIssuer,
		gen.SetIssuerVenafi(cmapi.VenafiIssuer{
			Cloud: &cmapi.VenafiCloud{
				APITokenSecretRef: cmmeta.SecretKeySelector{
					LocalObjectReference: cmmeta.LocalObjectReference{
						Name: cloudSecret.Name,
					},
				},
			},
		}),
	)

	baseCRNotApproved := gen.CertificateRequest("test-cr",
		gen.SetCertificateRequestCSR(csrPEM),
	)
	baseCRDenied := gen.CertificateRequestFrom(baseCRNotApproved,
		gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
			Type:               cmapi.CertificateRequestConditionDenied,
			Status:             cmmeta.ConditionTrue,
			Reason:             "Foo",
			Message:            "Certificate request has been denied by cert-manager.io",
			LastTransitionTime: &metaFixedClockStart,
		}),
	)
	baseCR := gen.CertificateRequestFrom(baseCRNotApproved,
		gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
			Type:               cmapi.CertificateRequestConditionApproved,
			Status:             cmmeta.ConditionTrue,
			Reason:             "cert-manager.io",
			Message:            "Certificate request has been approved by cert-manager.io",
			LastTransitionTime: &metaFixedClockStart,
		}),
	)

	tppCR := gen.CertificateRequestFrom(baseCR,
		gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
			Group: certmanager.GroupName,
			Name:  tppIssuer.Name,
			Kind:  tppIssuer.Kind,
		}),
	)

	tppCRWithCustomFields := gen.CertificateRequestFrom(tppCR, gen.SetCertificateRequestAnnotations(map[string]string{"venafi.cert-manager.io/custom-fields": `[{"name": "cert-manager-test", "value": "test ok"}]`}))

	tppCRWithInvalidCustomFields := gen.CertificateRequestFrom(tppCR, gen.SetCertificateRequestAnnotations(map[string]string{"venafi.cert-manager.io/custom-fields": `[{"name": cert-manager-test}]`}))

	tppCRWithInvalidCustomFieldType := gen.CertificateRequestFrom(tppCR, gen.SetCertificateRequestAnnotations(map[string]string{"venafi.cert-manager.io/custom-fields": `[{"name": "cert-manager-test", "value": "test ok", "type": "Bool"}]`}))

	cloudCR := gen.CertificateRequestFrom(baseCR,
		gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
			Group: certmanager.GroupName,
			Name:  cloudIssuer.Name,
			Kind:  cloudIssuer.Kind,
		}),
	)

	failGetSecretLister := &testlisters.FakeSecretLister{
		SecretsFn: func(namespace string) corelisters.SecretNamespaceLister {
			return &testlisters.FakeSecretNamespaceLister{
				GetFn: func(name string) (ret *corev1.Secret, err error) {
					return nil, errors.New("this is a network error")
				},
			}
		},
	}

	template, err := pki.CertificateTemplateFromCertificateRequest(baseCR)
	if err != nil {
		t.Fatal(err)
	}

	certPEM, _, err := pki.SignCertificate(template, rootCert, testPK.Public(), rootPK)
	if err != nil {
		t.Fatal(err)
	}

	clientReturnsPending := &internalvenafifake.Venafi{
		RequestCertificateFn: func(csrPEM []byte, duration time.Duration, customFields []api.CustomField) (string, error) {
			return "test", nil
		},
		RetrieveCertificateFn: func(string, []byte, time.Duration, []api.CustomField) ([]byte, error) {
			return nil, endpoint.ErrCertificatePending{
				CertificateID: "test-cert-id",
				Status:        "test-status-pending",
			}
		},
	}
	clientReturnsGenericError := &internalvenafifake.Venafi{
		RequestCertificateFn: func(csrPEM []byte, duration time.Duration, customFields []api.CustomField) (string, error) {
			return "", errors.New("this is an error")
		},
	}
	clientReturnsCert := &internalvenafifake.Venafi{
		RequestCertificateFn: func(csrPEM []byte, duration time.Duration, customFields []api.CustomField) (string, error) {
			return "test", nil
		},
		RetrieveCertificateFn: func(string, []byte, time.Duration, []api.CustomField) ([]byte, error) {
			return append(certPEM, rootPEM...), nil
		},
	}

	clientReturnsCertIfCustomField := &internalvenafifake.Venafi{
		RequestCertificateFn: func(csrPEM []byte, duration time.Duration, fields []api.CustomField) (string, error) {
			if len(fields) > 0 && fields[0].Name == "cert-manager-test" && fields[0].Value == "test ok" {
				return "test", nil
			}
			return "", errors.New("Custom field not set")
		},
		RetrieveCertificateFn: func(string, []byte, time.Duration, []api.CustomField) ([]byte, error) {
			return append(certPEM, rootPEM...), nil
		},
	}

	clientReturnsInvalidCustomFieldType := &internalvenafifake.Venafi{
		RequestCertificateFn: func(csrPEM []byte, duration time.Duration, fields []api.CustomField) (string, error) {
			return "", client.ErrCustomFieldsType{Type: fields[0].Type}
		},
	}

	tests := map[string]testT{
		"a CertificateRequest without an approved condition should do nothing": {
			certificateRequest: baseCRNotApproved.DeepCopy(),
			builder: &controllertest.Builder{
				KubeObjects:        []runtime.Object{},
				CertManagerObjects: []runtime.Object{baseCRNotApproved.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Normal WaitingForApproval Not signing CertificateRequest until it is Approved",
				},
			},
		},
		"a CertificateRequest with a denied condition should update Ready condition with 'Denied'": {
			certificateRequest: baseCRDenied.DeepCopy(),
			builder: &controllertest.Builder{
				KubeObjects:        []runtime.Object{},
				CertManagerObjects: []runtime.Object{baseCRDenied.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedEvents:     []string{},
				ExpectedActions: []controllertest.Action{
					controllertest.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCRDenied,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             "Denied",
								Message:            "The CertificateRequest was denied by an approval controller",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
		},
		"tpp: if fail to build client based on missing secret then return nil and hard fail": {
			certificateRequest: tppCR.DeepCopy(),
			builder: &controllertest.Builder{
				CertManagerObjects: []runtime.Object{tppCR.DeepCopy(), tppIssuer.DeepCopy()},
				ExpectedEvents: []string{
					`Normal SecretMissing Required secret resource not found: secret "test-tpp-secret" not found`,
				},
				ExpectedActions: []controllertest.Action{
					controllertest.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(tppCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            `Required secret resource not found: secret "test-tpp-secret" not found`,
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"tpp: if fail to build client based on secret lister transient error then return err and set pending": {
			certificateRequest: tppCR.DeepCopy(),
			builder: &controllertest.Builder{
				CertManagerObjects: []runtime.Object{tppCR.DeepCopy(), tppIssuer.DeepCopy()},
				ExpectedEvents: []string{
					`Normal VenafiInitError Failed to initialise venafi client for signing: this is a network error`,
				},
				ExpectedActions: []controllertest.Action{
					controllertest.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(tppCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            "Failed to initialise venafi client for signing: this is a network error",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
			fakeSecretLister: failGetSecretLister,
			expectedErr:      true,
		},
		"cloud: if fail to build client based on missing secret then return nil and hard fail": {
			certificateRequest: cloudCR.DeepCopy(),
			builder: &controllertest.Builder{
				CertManagerObjects: []runtime.Object{cloudCR.DeepCopy(), cloudIssuer.DeepCopy()},
				ExpectedEvents: []string{
					`Normal SecretMissing Required secret resource not found: secret "test-cloud-secret" not found`,
				},
				ExpectedActions: []controllertest.Action{
					controllertest.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(cloudCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            `Required secret resource not found: secret "test-cloud-secret" not found`,
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"cloud: if fail to build client based on secret lister transient error then return err and set pending": {
			certificateRequest: cloudCR.DeepCopy(),
			builder: &controllertest.Builder{
				CertManagerObjects: []runtime.Object{cloudCR.DeepCopy(), cloudIssuer.DeepCopy()},
				ExpectedEvents: []string{
					`Normal VenafiInitError Failed to initialise venafi client for signing: this is a network error`,
				},
				ExpectedActions: []controllertest.Action{
					controllertest.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(cloudCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            "Failed to initialise venafi client for signing: this is a network error",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
			fakeSecretLister: failGetSecretLister,
			expectedErr:      true,
		},
		"should exit nil and set status pending if referenced issuer is not ready": {
			certificateRequest: cloudCR.DeepCopy(),
			builder: &controllertest.Builder{
				KubeObjects: []runtime.Object{},
				CertManagerObjects: []runtime.Object{cloudCR.DeepCopy(),
					gen.Issuer(cloudIssuer.DeepCopy().Name,
						gen.SetIssuerVenafi(cmapi.VenafiIssuer{}),
					)},
				ExpectedEvents: []string{
					"Normal IssuerNotReady Referenced issuer does not have a Ready status condition",
				},
				ExpectedActions: []controllertest.Action{
					controllertest.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(cloudCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             "Pending",
								Message:            "Referenced issuer does not have a Ready status condition",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"tpp: if sign returns pending error then set pending and return err": {
			certificateRequest: tppCR.DeepCopy(),
			builder: &controllertest.Builder{
				KubeObjects:        []runtime.Object{tppSecret},
				CertManagerObjects: []runtime.Object{cloudCR.DeepCopy(), tppIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Normal IssuancePending Venafi certificate is requested",
					"Normal IssuancePending Venafi certificate still in a pending state, the request will be retried: Issuance is pending. You may try retrieving the certificate later using Pickup ID: test-cert-id\n\tStatus: test-status-pending",
				},
				ExpectedActions: []controllertest.Action{
					controllertest.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(cloudCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            "Venafi certificate is requested",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.AddCertificateRequestAnnotations(map[string]string{cmapi.VenafiPickupIDAnnotationKey: "test"}),
						),
					)),
					controllertest.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(cloudCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            "Venafi certificate still in a pending state, the request will be retried: Issuance is pending. You may try retrieving the certificate later using Pickup ID: test-cert-id\n\tStatus: test-status-pending",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.AddCertificateRequestAnnotations(map[string]string{cmapi.VenafiPickupIDAnnotationKey: "test"}),
						),
					)),
				},
			},
			fakeSecretLister: failGetSecretLister,
			fakeClient:       clientReturnsPending,
			expectedErr:      true,
		},
		"cloud: if sign returns pending error then set pending and return err": {
			certificateRequest: cloudCR.DeepCopy(),
			builder: &controllertest.Builder{
				KubeObjects:        []runtime.Object{cloudSecret},
				CertManagerObjects: []runtime.Object{cloudCR.DeepCopy(), cloudIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Normal IssuancePending Venafi certificate is requested",
					"Normal IssuancePending Venafi certificate still in a pending state, the request will be retried: Issuance is pending. You may try retrieving the certificate later using Pickup ID: test-cert-id\n\tStatus: test-status-pending",
				},
				ExpectedActions: []controllertest.Action{
					controllertest.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(cloudCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            "Venafi certificate is requested",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.AddCertificateRequestAnnotations(map[string]string{cmapi.VenafiPickupIDAnnotationKey: "test"}),
						),
					)),
					controllertest.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(cloudCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            "Venafi certificate still in a pending state, the request will be retried: Issuance is pending. You may try retrieving the certificate later using Pickup ID: test-cert-id\n\tStatus: test-status-pending",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.AddCertificateRequestAnnotations(map[string]string{cmapi.VenafiPickupIDAnnotationKey: "test"}),
						),
					)),
				},
			},
			fakeSecretLister: failGetSecretLister,
			fakeClient:       clientReturnsPending,
			expectedErr:      true,
		},
		"tpp: if sign returns generic error then set pending and return error": {
			certificateRequest: tppCR.DeepCopy(),
			builder: &controllertest.Builder{
				KubeObjects:        []runtime.Object{tppSecret},
				CertManagerObjects: []runtime.Object{tppCR.DeepCopy(), tppIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Warning RequestError Failed to request venafi certificate: this is an error",
				},
				ExpectedActions: []controllertest.Action{
					controllertest.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(tppCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonFailed,
								Message:            "Failed to request venafi certificate: this is an error",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
			fakeSecretLister:   failGetSecretLister,
			fakeClient:         clientReturnsGenericError,
			expectedErr:        true,
			skipSecondSignCall: false,
		},
		"cloud: if sign returns generic error then set pending and return error": {
			certificateRequest: cloudCR.DeepCopy(),
			builder: &controllertest.Builder{
				KubeObjects:        []runtime.Object{cloudSecret},
				CertManagerObjects: []runtime.Object{tppCR.DeepCopy(), cloudIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Warning RequestError Failed to request venafi certificate: this is an error",
				},
				ExpectedActions: []controllertest.Action{
					controllertest.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(cloudCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonFailed,
								Message:            "Failed to request venafi certificate: this is an error",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
			fakeSecretLister:   failGetSecretLister,
			fakeClient:         clientReturnsGenericError,
			expectedErr:        true,
			skipSecondSignCall: false,
		},
		"tpp: if sign returns cert then return cert and not failed": {
			certificateRequest: tppCR.DeepCopy(),
			builder: &controllertest.Builder{
				KubeObjects:        []runtime.Object{tppSecret},
				CertManagerObjects: []runtime.Object{tppCR.DeepCopy(), tppIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Normal IssuancePending Venafi certificate is requested",
					"Normal CertificateIssued Certificate fetched from issuer successfully",
				},
				ExpectedActions: []controllertest.Action{
					controllertest.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(tppCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            "Venafi certificate is requested",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.AddCertificateRequestAnnotations(map[string]string{cmapi.VenafiPickupIDAnnotationKey: "test"}),
						),
					)),
					controllertest.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(tppCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionTrue,
								Reason:             cmapi.CertificateRequestReasonIssued,
								Message:            "Certificate fetched from issuer successfully",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestCertificate(certPEM),
							gen.SetCertificateRequestCA(rootPEM),
							gen.AddCertificateRequestAnnotations(map[string]string{cmapi.VenafiPickupIDAnnotationKey: "test"}),
						),
					)),
				},
			},
			fakeSecretLister: failGetSecretLister,
			fakeClient:       clientReturnsCert,
		},
		"cloud: if sign returns cert then return cert and not failed": {
			certificateRequest: cloudCR.DeepCopy(),
			builder: &controllertest.Builder{
				KubeObjects:        []runtime.Object{cloudSecret},
				CertManagerObjects: []runtime.Object{cloudCR.DeepCopy(), cloudIssuer.DeepCopy()},
				ExpectedEvents: []string{
					`Normal IssuancePending Venafi certificate is requested`,
					"Normal CertificateIssued Certificate fetched from issuer successfully",
				},
				ExpectedActions: []controllertest.Action{
					controllertest.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(cloudCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            "Venafi certificate is requested",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.AddCertificateRequestAnnotations(map[string]string{cmapi.VenafiPickupIDAnnotationKey: "test"}),
						),
					)),
					controllertest.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(cloudCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionTrue,
								Reason:             cmapi.CertificateRequestReasonIssued,
								Message:            "Certificate fetched from issuer successfully",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestCertificate(certPEM),
							gen.SetCertificateRequestCA(rootPEM),
							gen.AddCertificateRequestAnnotations(map[string]string{cmapi.VenafiPickupIDAnnotationKey: "test"}),
						),
					)),
				},
			},
			fakeSecretLister: failGetSecretLister,
			fakeClient:       clientReturnsCert,
		},
		"annotations: Custom Fields": {
			certificateRequest: tppCRWithCustomFields.DeepCopy(),
			builder: &controllertest.Builder{
				CertManagerObjects: []runtime.Object{tppCRWithCustomFields.DeepCopy(), tppIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Normal IssuancePending Venafi certificate is requested",
					"Normal CertificateIssued Certificate fetched from issuer successfully",
				},
				ExpectedActions: []controllertest.Action{
					controllertest.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(tppCRWithCustomFields,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            "Venafi certificate is requested",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.AddCertificateRequestAnnotations(map[string]string{cmapi.VenafiPickupIDAnnotationKey: "test"}),
						),
					)),
					controllertest.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(tppCRWithCustomFields,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionTrue,
								Reason:             cmapi.CertificateRequestReasonIssued,
								Message:            "Certificate fetched from issuer successfully",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestCertificate(certPEM),
							gen.SetCertificateRequestCA(rootPEM),
							gen.AddCertificateRequestAnnotations(map[string]string{cmapi.VenafiPickupIDAnnotationKey: "test"}),
						),
					)),
				},
			},
			fakeSecretLister: failGetSecretLister,
			fakeClient:       clientReturnsCertIfCustomField,
			expectedErr:      false,
		},
		"annotations: Error on invalid JSON in custom fields": {
			certificateRequest: tppCRWithInvalidCustomFields.DeepCopy(),
			builder: &controllertest.Builder{
				CertManagerObjects: []runtime.Object{tppCRWithInvalidCustomFields.DeepCopy(), tppIssuer.DeepCopy()},
				ExpectedEvents: []string{
					`Warning CustomFieldsError Failed to parse "venafi.cert-manager.io/custom-fields" annotation: invalid character 'c' looking for beginning of value`,
				},
				ExpectedActions: []controllertest.Action{
					controllertest.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(tppCRWithInvalidCustomFields,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonFailed,
								Message:            "Failed to parse \"venafi.cert-manager.io/custom-fields\" annotation: invalid character 'c' looking for beginning of value",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
			fakeSecretLister:   failGetSecretLister,
			fakeClient:         clientReturnsPending,
			skipSecondSignCall: true,
			expectedErr:        false,
		},
		"annotations: Error on invalid type in custom fields": {
			certificateRequest: tppCRWithInvalidCustomFieldType.DeepCopy(),
			builder: &controllertest.Builder{
				CertManagerObjects: []runtime.Object{tppCRWithInvalidCustomFieldType.DeepCopy(), tppIssuer.DeepCopy()},
				ExpectedEvents: []string{
					`Warning CustomFieldsError certificate request contains an invalid Venafi custom fields type: "Bool": certificate request contains an invalid Venafi custom fields type: "Bool"`,
				},
				ExpectedActions: []controllertest.Action{
					controllertest.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(tppCRWithInvalidCustomFieldType,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonFailed,
								Message:            "certificate request contains an invalid Venafi custom fields type: \"Bool\": certificate request contains an invalid Venafi custom fields type: \"Bool\"",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
			fakeSecretLister: failGetSecretLister,
			fakeClient:       clientReturnsInvalidCustomFieldType,
			expectedErr:      false,
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
	builder            *controllertest.Builder
	certificateRequest *cmapi.CertificateRequest

	fakeClient *internalvenafifake.Venafi

	expectedErr bool

	skipSecondSignCall bool

	fakeSecretLister *testlisters.FakeSecretLister
}

func runTest(t *testing.T, test testT) {
	test.builder.T = t
	test.builder.InitWithRESTConfig()
	defer test.builder.Stop()

	v := NewVenafi(test.builder.Context).(*Venafi)

	if test.fakeSecretLister != nil {
		v.secretsLister = test.fakeSecretLister
	}

	if test.fakeClient != nil {
		v.clientBuilder = func(namespace string, secretsLister internalinformers.SecretLister,
			issuer cmapi.GenericIssuer, _ *metrics.Metrics, _ logr.Logger, _ string) (client.Interface, error) {
			return test.fakeClient, nil
		}
	}

	controller := certificaterequests.New(
		apiutil.IssuerVenafi,
		func(*controllerpkg.Context) certificaterequests.Issuer { return v },
	)
	if _, _, err := controller.Register(test.builder.Context); err != nil {
		t.Fatal(err)
	}
	test.builder.Start()

	// Deep copy the certificate request to prevent pulling condition state across tests
	err := controller.Sync(context.Background(), test.certificateRequest)

	if err == nil && test.fakeClient != nil && test.fakeClient.RetrieveCertificateFn != nil && !test.skipSecondSignCall {
		// request state is ok! simulating a 2nd sync to fetch the cert
		metav1.SetMetaDataAnnotation(&test.certificateRequest.ObjectMeta, cmapi.VenafiPickupIDAnnotationKey, "test")
		err = controller.Sync(context.Background(), test.certificateRequest)
	}

	if err != nil && !test.expectedErr {
		t.Errorf("expected to not get an error, but got: %v", err)
	}
	if err == nil && test.expectedErr {
		t.Errorf("expected to get an error but did not get one")
	}

	test.builder.CheckAndFinish(err)
}
