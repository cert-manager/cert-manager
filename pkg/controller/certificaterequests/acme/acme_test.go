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
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	"github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	cmapiv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmacmelisters "github.com/cert-manager/cert-manager/pkg/client/listers/acme/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificaterequests"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"
	testlisters "github.com/cert-manager/cert-manager/test/unit/listers"
)

var (
	fixedClockStart = time.Now()
	fixedClock      = fakeclock.NewFakeClock(fixedClockStart)
)

func generateCSR(t *testing.T, secretKey crypto.Signer, commonName string, dnsNames ...string) []byte {
	csr, err := gen.CSRWithSigner(secretKey,
		gen.SetCSRCommonName(commonName),
		gen.SetCSRDNSNames(dnsNames...),
	)
	if err != nil {
		t.Fatal(err)
	}

	return csr
}

func generateCSRWithIPs(t *testing.T, secretKey crypto.Signer, commonName string, dnsNames []string, ips []string) []byte {
	csr, err := gen.CSRWithSigner(secretKey,
		gen.SetCSRCommonName(commonName),
		gen.SetCSRDNSNames(dnsNames...),
		gen.SetCSRIPAddressesFromStrings(ips...),
	)
	if err != nil {
		t.Fatal(err)
	}

	return csr
}

func TestSign(t *testing.T) {
	metaFixedClockStart := metav1.NewTime(fixedClockStart)
	baseIssuer := gen.Issuer("test-issuer",
		gen.SetIssuerACME(cmacme.ACMEIssuer{}),
		gen.AddIssuerCondition(cmapiv1.IssuerCondition{
			Type:   cmapiv1.IssuerConditionReady,
			Status: cmmeta.ConditionTrue,
		}),
	)

	rootPK, err := pki.GenerateECPrivateKey(256)
	if err != nil {
		t.Fatal()
	}

	rootTmpl := &x509.Certificate{
		Version:               3,
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(0),
		Subject: pkix.Name{
			CommonName: "root",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Minute),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		PublicKey: rootPK.Public(),
		IsCA:      true,
	}

	_, rootCert, err := pki.SignCertificate(rootTmpl, rootTmpl, rootPK.Public(), rootPK)
	if err != nil {
		t.Fatal(err)
	}

	sk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	csrPEM := generateCSR(t, sk, "example.com", "example.com", "foo.com")
	csrPEMExampleNotPresent := generateCSR(t, sk, "example.com", "foo.com")

	baseCRNotApproved := gen.CertificateRequest("test-cr",
		gen.SetCertificateRequestCSR(csrPEM),
		gen.SetCertificateRequestIsCA(false),
		gen.SetCertificateRequestDuration(&metav1.Duration{Duration: time.Hour * 24 * 60}),
		gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
			Name:  baseIssuer.Name,
			Group: certmanager.GroupName,
			Kind:  "Issuer",
		}),
	)
	baseCRDenied := gen.CertificateRequestFrom(baseCRNotApproved,
		gen.SetCertificateRequestStatusCondition(cmapiv1.CertificateRequestCondition{
			Type:               cmapiv1.CertificateRequestConditionDenied,
			Status:             cmmeta.ConditionTrue,
			Reason:             "Foo",
			Message:            "Certificate request has been denied by cert-manager.io",
			LastTransitionTime: &metaFixedClockStart,
		}),
	)
	baseCR := gen.CertificateRequestFrom(baseCRNotApproved,
		gen.SetCertificateRequestStatusCondition(cmapiv1.CertificateRequestCondition{
			Type:               cmapiv1.CertificateRequestConditionApproved,
			Status:             cmmeta.ConditionTrue,
			Reason:             "cert-manager.io",
			Message:            "Certificate request has been approved by cert-manager.io",
			LastTransitionTime: &metaFixedClockStart,
		}),
	)

	csr, err := pki.DecodeX509CertificateRequestBytes(csrPEM)
	if err != nil {
		t.Fatal(err)
	}

	template, err := pki.CertificateTemplateFromCertificateRequest(baseCR)
	if err != nil {
		t.Errorf("error generating template: %v", err)
	}

	certBundle, err := pki.SignCSRTemplate([]*x509.Certificate{rootCert}, rootPK, template)
	if err != nil {
		t.Fatal(err)
	}

	// Another version of Key, CSR and Cert where the only difference is the signer key value.
	// For use in testing the PublicKeyMatchesCertificate check of the controller.
	sk2, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	template2, err := pki.CertificateTemplateFromCSRPEM(
		generateCSR(t, sk2, "example.com", "example.com", "foo.com"),
		pki.CertificateTemplateOverrideDuration(time.Hour),
		pki.CertificateTemplateValidateAndOverrideBasicConstraints(false, nil),
		pki.CertificateTemplateValidateAndOverrideKeyUsages(0, nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	cert2Bundle, err := pki.SignCSRTemplate([]*x509.Certificate{rootCert}, rootPK, template2)
	if err != nil {
		t.Fatal(err)
	}

	ipCSRPEM := generateCSRWithIPs(t, sk, "10.0.0.1", nil, []string{"10.0.0.1"})
	ipCSR, err := pki.DecodeX509CertificateRequestBytes(ipCSRPEM)
	if err != nil {
		t.Fatal(err)
	}
	ipBaseCR := gen.CertificateRequestFrom(baseCR, gen.SetCertificateRequestCSR(ipCSRPEM))
	ipBaseOrder, err := buildOrder(ipBaseCR, ipCSR, baseIssuer.GetSpec().ACME.EnableDurationFeature)
	if err != nil {
		t.Fatalf("failed to build order during testing: %s", err)
	}

	baseOrder, err := buildOrder(baseCR, csr, baseIssuer.GetSpec().ACME.EnableDurationFeature)
	if err != nil {
		t.Fatalf("failed to build order during testing: %s", err)
	}

	tests := map[string]testT{
		"a CertificateRequest without an approved condition should do nothing": {
			certificateRequest: baseCRNotApproved.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{},
				CertManagerObjects: []runtime.Object{baseCRNotApproved.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Normal WaitingForApproval Not signing CertificateRequest until it is Approved",
				},
			},
		},
		"a CertificateRequest with a denied condition should update Ready condition with 'Denied'": {
			certificateRequest: baseCRDenied.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{},
				CertManagerObjects: []runtime.Object{baseCRDenied.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedEvents:     []string{},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapiv1.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCRDenied,
							gen.SetCertificateRequestStatusCondition(cmapiv1.CertificateRequestCondition{
								Type:               cmapiv1.CertificateRequestConditionReady,
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
		"a badly formed CSR should report failure": {
			certificateRequest: gen.CertificateRequestFrom(baseCR,
				gen.SetCertificateRequestCSR([]byte("a bad csr")),
			),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Warning RequestParsingError Failed to decode CSR in spec.request: error decoding certificate request PEM block",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapiv1.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestCSR([]byte("a bad csr")),
							gen.SetCertificateRequestStatusCondition(cmapiv1.CertificateRequestCondition{
								Type:               cmapiv1.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapiv1.CertificateRequestReasonFailed,
								Message:            "Failed to decode CSR in spec.request: error decoding certificate request PEM block",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
		},
		"if the common name is not present in the DNS names then should hard fail": {
			certificateRequest: gen.CertificateRequestFrom(baseCR,
				gen.SetCertificateRequestCSR(csrPEMExampleNotPresent),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					`Warning InvalidOrder The CSR PEM requests a commonName that is not present in the list of dnsNames or ipAddresses. If a commonName is set, ACME requires that the value is also present in the list of dnsNames or ipAddresses: "example.com" does not exist in [foo.com] or []`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapiv1.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestCSR(csrPEMExampleNotPresent),
							gen.SetCertificateRequestStatusCondition(cmapiv1.CertificateRequestCondition{
								Type:               cmapiv1.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapiv1.CertificateRequestReasonFailed,
								Message:            `The CSR PEM requests a commonName that is not present in the list of dnsNames or ipAddresses. If a commonName is set, ACME requires that the value is also present in the list of dnsNames or ipAddresses: "example.com" does not exist in [foo.com] or []`,
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
		},

		"if the common name is not present in the IP Addresses then should hard fail": {
			certificateRequest: gen.CertificateRequestFrom(baseCR,
				gen.SetCertificateRequestCSR(generateCSR(t, sk, "10.0.0.1", "example.com")),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					`Warning InvalidOrder The CSR PEM requests a commonName that is not present in the list of dnsNames or ipAddresses. If a commonName is set, ACME requires that the value is also present in the list of dnsNames or ipAddresses: "10.0.0.1" does not exist in [example.com] or []`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapiv1.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestCSR(generateCSR(t, sk, "10.0.0.1", "example.com")),
							gen.SetCertificateRequestStatusCondition(cmapiv1.CertificateRequestCondition{
								Type:               cmapiv1.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapiv1.CertificateRequestReasonFailed,
								Message:            `The CSR PEM requests a commonName that is not present in the list of dnsNames or ipAddresses. If a commonName is set, ACME requires that the value is also present in the list of dnsNames or ipAddresses: "10.0.0.1" does not exist in [example.com] or []`,
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
		},

		"pass if the CN is set in the IPs": {
			certificateRequest: gen.CertificateRequestFrom(ipBaseCR,
				gen.SetCertificateRequestCSR(ipCSRPEM),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{ipBaseCR.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Normal OrderCreated Created Order resource default-unit-test-ns/test-cr-3104426127",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						cmacme.SchemeGroupVersion.WithResource("orders"),
						gen.DefaultTestNamespace,
						ipBaseOrder,
					)),
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapiv1.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(ipBaseCR,
							gen.SetCertificateRequestCSR(ipCSRPEM),
							gen.SetCertificateRequestStatusCondition(cmapiv1.CertificateRequestCondition{
								Type:               cmapiv1.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapiv1.CertificateRequestReasonPending,
								Message:            "Created Order resource default-unit-test-ns/test-cr-3104426127",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},

		//TODO: Think of a creative way to get `buildOrder` to fail :thinking_face:

		"if order doesn't exist then attempt to create one": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Normal OrderCreated Created Order resource default-unit-test-ns/test-cr-1733622556",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						cmacme.SchemeGroupVersion.WithResource("orders"),
						gen.DefaultTestNamespace,
						baseOrder,
					)),
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapiv1.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapiv1.CertificateRequestCondition{
								Type:               cmapiv1.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapiv1.CertificateRequestReasonPending,
								Message:            "Created Order resource default-unit-test-ns/test-cr-1733622556",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},

		"should exit nil and set status pending if referenced issuer is not ready": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(),
					gen.Issuer(baseIssuer.DeepCopy().Name,
						gen.SetIssuerACME(cmacme.ACMEIssuer{}),
					)},
				ExpectedEvents: []string{
					"Normal IssuerNotReady Referenced issuer does not have a Ready status condition",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapiv1.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapiv1.CertificateRequestCondition{
								Type:               cmapiv1.CertificateRequestConditionReady,
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

		"if we fail to get the order resource due to a transient error then we should report pending and return error to re-sync": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				ExpectedEvents: []string{
					"Normal OrderGetError Failed to get order resource default-unit-test-ns/test-cr-1733622556: this is a network error",
				},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapiv1.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapiv1.CertificateRequestCondition{
								Type:               cmapiv1.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapiv1.CertificateRequestReasonPending,
								Message:            "Failed to get order resource default-unit-test-ns/test-cr-1733622556: this is a network error",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
			fakeOrderLister: &testlisters.FakeOrderLister{
				OrdersFn: func(namespace string) cmacmelisters.OrderNamespaceLister {
					return &testlisters.FakeOrderNamespaceLister{
						GetFn: func(name string) (ret *cmacme.Order, err error) {
							return nil, errors.New("this is a network error")
						},
					}
				},
			},
			expectedErr: true,
		},

		"if the order resource is in a failed state then we should report failure": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				ExpectedEvents: []string{
					`Warning OrderFailed Failed to wait for order resource "test-cr-1733622556" to become ready: order is in "invalid" state: simulated failure`,
				},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), baseIssuer.DeepCopy(),
					gen.OrderFrom(baseOrder,
						gen.SetOrderState(cmacme.Invalid),
						gen.SetOrderReason("simulated failure"),
					),
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapiv1.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapiv1.CertificateRequestCondition{
								Type:               cmapiv1.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapiv1.CertificateRequestReasonFailed,
								Message:            `Failed to wait for order resource "test-cr-1733622556" to become ready: order is in "invalid" state: simulated failure`,
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
		},

		"if the order is in an unknown state, then report pending": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				ExpectedEvents: []string{
					`Normal OrderPending Waiting on certificate issuance from order default-unit-test-ns/test-cr-1733622556: "pending"`,
				},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), baseIssuer.DeepCopy(),
					gen.OrderFrom(baseOrder,
						gen.SetOrderState(cmacme.Pending),
					),
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapiv1.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapiv1.CertificateRequestCondition{
								Type:               cmapiv1.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapiv1.CertificateRequestReasonPending,
								Message:            `Waiting on certificate issuance from order default-unit-test-ns/test-cr-1733622556: "pending"`,
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},

		"if the order is in Valid state but Certificate has not yet been populated": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				ExpectedEvents: []string{
					"Normal OrderPending Waiting for order-controller to add certificate data to Order default-unit-test-ns/test-cr-1733622556",
				},
				CertManagerObjects: []runtime.Object{gen.OrderFrom(baseOrder,
					gen.SetOrderState(cmacme.Valid),
				), baseCR.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapiv1.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapiv1.CertificateRequestCondition{
								Type:               cmapiv1.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapiv1.CertificateRequestReasonPending,
								Message:            "Waiting for order-controller to add certificate data to Order default-unit-test-ns/test-cr-1733622556",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},

		"if the order is in Valid state but the certificate is badly formed": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.OrderFrom(baseOrder,
					gen.SetOrderState(cmacme.Valid),
					gen.SetOrderCertificate([]byte("bad certificate bytes")),
				), baseCR.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewDeleteAction(
						cmacme.SchemeGroupVersion.WithResource("orders"),
						gen.DefaultTestNamespace,
						baseOrder.Name,
					)),
				},
			},
		},

		"if the order is in Valid state but the certificate has wrong public key": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.OrderFrom(baseOrder,
					gen.SetOrderState(cmacme.Valid),
					gen.SetOrderCertificate(cert2Bundle.ChainPEM),
				), baseCR.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewDeleteAction(
						cmacme.SchemeGroupVersion.WithResource("orders"),
						gen.DefaultTestNamespace,
						baseOrder.Name,
					)),
				},
			},
		},

		"if the order is in Valid state then return the certificate as response": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				ExpectedEvents: []string{
					"Normal CertificateIssued Certificate fetched from issuer successfully",
				},
				CertManagerObjects: []runtime.Object{gen.OrderFrom(baseOrder,
					gen.SetOrderState(cmacme.Valid),
					gen.SetOrderCertificate(certBundle.ChainPEM),
				), baseCR.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapiv1.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapiv1.CertificateRequestCondition{
								Type:               cmapiv1.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionTrue,
								Reason:             cmapiv1.CertificateRequestReasonIssued,
								Message:            "Certificate fetched from issuer successfully",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestCertificate(certBundle.ChainPEM),
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
	builder            *testpkg.Builder
	certificateRequest *cmapiv1.CertificateRequest

	expectedErr bool

	fakeOrderLister *testlisters.FakeOrderLister
}

func runTest(t *testing.T, test testT) {
	test.builder.T = t
	test.builder.Init()
	defer test.builder.Stop()

	ac := NewACME(test.builder.Context).(*ACME)
	if test.fakeOrderLister != nil {
		ac.orderLister = test.fakeOrderLister
	}

	controller := certificaterequests.New(
		apiutil.IssuerACME,
		func(*controller.Context) certificaterequests.Issuer { return ac },
	)
	_, _, err := controller.Register(test.builder.Context)
	if err != nil {
		t.Errorf("Error registering the controller: %v", err)
	}
	test.builder.Start()

	err = controller.Sync(context.Background(), test.certificateRequest)
	if err != nil && !test.expectedErr {
		t.Errorf("expected to not get an error, but got: %v", err)
	}
	if err == nil && test.expectedErr {
		t.Errorf("expected to get an error but did not get one")
	}

	test.builder.CheckAndFinish(err)
}

func Test_buildOrder(t *testing.T) {
	sk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	csrPEM := generateCSR(t, sk, "example.com", "example.com")
	csr, err := pki.DecodeX509CertificateRequestBytes(csrPEM)
	if err != nil {
		t.Fatal(err)
	}

	cr := gen.CertificateRequest("test", gen.SetCertificateRequestDuration(&metav1.Duration{Duration: time.Hour}), gen.SetCertificateRequestCSR(csrPEM))
	type args struct {
		cr                    *cmapiv1.CertificateRequest
		csr                   *x509.CertificateRequest
		enableDurationFeature bool
	}
	tests := []struct {
		name    string
		args    args
		want    *cmacme.Order
		wantErr bool
	}{
		{
			name: "Normal building of order",
			args: args{
				cr:                    cr,
				csr:                   csr,
				enableDurationFeature: false,
			},
			want: &cmacme.Order{
				Spec: cmacme.OrderSpec{
					Request:    csrPEM,
					CommonName: "example.com",
					DNSNames:   []string{"example.com"},
				},
			},
			wantErr: false,
		},
		{
			name: "Building with enableDurationFeature",
			args: args{
				cr:                    cr,
				csr:                   csr,
				enableDurationFeature: true,
			},
			want: &cmacme.Order{
				Spec: cmacme.OrderSpec{
					Request:    csrPEM,
					CommonName: "example.com",
					DNSNames:   []string{"example.com"},
					Duration:   &metav1.Duration{Duration: time.Hour},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildOrder(tt.args.cr, tt.args.csr, tt.args.enableDurationFeature)
			if (err != nil) != tt.wantErr {
				t.Errorf("buildOrder() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// for the current purpose we only test the spec
			if !reflect.DeepEqual(got.Spec, tt.want.Spec) {
				t.Errorf("buildOrder() got = %v, want %v", got.Spec, tt.want.Spec)
			}
		})
	}

	longCrOne := gen.CertificateRequest(
		"test-comparison-that-is-at-the-fifty-two-character-l",
		gen.SetCertificateRequestDuration(&metav1.Duration{Duration: time.Hour}),
		gen.SetCertificateRequestCSR(csrPEM))
	orderOne, err := buildOrder(longCrOne, csr, false)
	if err != nil {
		t.Errorf("buildOrder() received error %v", err)
		return
	}

	t.Run("Builds two orders from different long CRs to guarantee unique name", func(t *testing.T) {
		longCrTwo := gen.CertificateRequest(
			"test-comparison-that-is-at-the-fifty-two-character-l-two",
			gen.SetCertificateRequestDuration(&metav1.Duration{Duration: time.Hour}),
			gen.SetCertificateRequestCSR(csrPEM))

		orderTwo, err := buildOrder(longCrTwo, csr, false)
		if err != nil {
			t.Errorf("buildOrder() received error %v", err)
			return
		}

		if orderOne.Name == orderTwo.Name {
			t.Errorf(
				"orders built from different CR have equal names: %s == %s",
				orderOne.Name,
				orderTwo.Name)
		}
	})

	t.Run("Builds two orders from the same long CRs to guarantee same name", func(t *testing.T) {
		orderOne, err := buildOrder(longCrOne, csr, false)
		if err != nil {
			t.Errorf("buildOrder() received error %v", err)
			return
		}

		orderTwo, err := buildOrder(longCrOne, csr, false)
		if err != nil {
			t.Errorf("buildOrder() received error %v", err)
			return
		}
		if orderOne.Name != orderTwo.Name {
			t.Errorf(
				"orders built from the same CR have unequal names: %s != %s",
				orderOne.Name,
				orderTwo.Name)
		}
	})
}
