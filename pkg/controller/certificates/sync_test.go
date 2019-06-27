/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package certificates

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"
	clock "k8s.io/utils/clock/testing"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/issuer/fake"
	_ "github.com/jetstack/cert-manager/pkg/issuer/selfsigned"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

func generatePrivateKey(t *testing.T) *rsa.PrivateKey {
	pk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Errorf("failed to generate private key: %v", err)
		t.FailNow()
	}
	return pk
}

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

func generateSelfSignedCert(t *testing.T, crt *cmapi.Certificate, sn *big.Int, key crypto.Signer, notBefore, notAfter time.Time) []byte {
	commonName := pki.CommonNameForCertificate(crt)
	dnsNames := pki.DNSNamesForCertificate(crt)

	if sn == nil {
		var err error
		sn, err = rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			t.Errorf("failed to generate serial number: %v", err)
			t.FailNow()
		}
	}

	template := &x509.Certificate{
		Version:               3,
		BasicConstraintsValid: true,
		SerialNumber:          sn,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		// see http://golang.org/pkg/crypto/x509/#KeyUsage
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames: dnsNames,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
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
	nowTime := time.Now()
	nowMetaTime := metav1.NewTime(nowTime)
	fixedClock := clock.NewFakeClock(nowTime)

	exampleCert := gen.Certificate("test",
		gen.SetCertificateDNSNames("example.com"),
		gen.SetCertificateIssuer(cmapi.ObjectReference{Name: "test"}),
		gen.SetCertificateSecretName("output"),
	)
	exampleCertNotFoundCondition := gen.CertificateFrom(exampleCert,
		gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
			Type:               cmapi.CertificateConditionReady,
			Status:             cmapi.ConditionFalse,
			Reason:             "NotFound",
			Message:            "Certificate does not exist",
			LastTransitionTime: &nowMetaTime,
		}),
	)
	exampleCertTemporaryCondition := gen.CertificateFrom(exampleCert,
		gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
			Type:               cmapi.CertificateConditionReady,
			Status:             cmapi.ConditionFalse,
			Reason:             "TemporaryCertificate",
			Message:            "Certificate issuance in progress. Temporary certificate issued.",
			LastTransitionTime: &nowMetaTime,
		}),
	)

	pk1 := generatePrivateKey(t)
	pk1PEM := pki.EncodePKCS1PrivateKey(pk1)
	cert1PEM := generateSelfSignedCert(t, exampleCert, nil, pk1, nowTime, nowTime.Add(time.Hour*12))
	cert1, err := pki.DecodeX509CertificateBytes(cert1PEM)
	if err != nil {
		t.Errorf("Error decoding test cert1 bytes: %v", err)
		t.FailNow()
	}

	pk2 := generatePrivateKey(t)
	// pk2PEM := pki.EncodePKCS1PrivateKey(pk2)
	cert2PEM := generateSelfSignedCert(t, exampleCert, nil, pk2, nowTime, nowTime.Add(time.Hour*24))
	cert2, err := pki.DecodeX509CertificateBytes(cert2PEM)
	if err != nil {
		t.Errorf("Error decoding test cert2 bytes: %v", err)
		t.FailNow()
	}

	localTempCert := generateSelfSignedCert(t, exampleCert, big.NewInt(staticTemporarySerialNumber), pk1, nowTime, nowTime)

	tests := map[string]controllerFixture{
		"should update certificate with NotExists if issuer does not return a keypair": {
			Issuer: gen.Issuer("test",
				gen.AddIssuerCondition(cmapi.IssuerCondition{
					Type:   cmapi.IssuerConditionReady,
					Status: cmapi.ConditionTrue,
				}),
				gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
			),
			Certificate: *exampleCert,
			IssuerImpl: &fake.Issuer{
				FakeIssue: func(context.Context, *cmapi.Certificate) (*issuer.IssueResponse, error) {
					// By not returning a response, we trigger a 'no-op' action
					// which causes the certificate controller to only update
					// the status of the Certificate and not create a Secret.
					return nil, nil
				},
			},
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.Certificate("test")},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						gen.DefaultTestNamespace,
						exampleCertNotFoundCondition,
					)),
				},
			},
			CheckFn: func(t *testing.T, s *controllerFixture, args ...interface{}) {
			},
			Err: false,
		},
		"should create a secret containing the private key only when one doesn't exist": {
			Issuer: gen.Issuer("test",
				gen.AddIssuerCondition(cmapi.IssuerCondition{
					Type:   cmapi.IssuerConditionReady,
					Status: cmapi.ConditionTrue,
				}),
				gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
			),
			Certificate: *exampleCert,
			IssuerImpl: &fake.Issuer{
				FakeIssue: func(context.Context, *cmapi.Certificate) (*issuer.IssueResponse, error) {
					return &issuer.IssueResponse{
						PrivateKey: pk1PEM,
					}, nil
				},
			},
			StaticTemporaryCert: localTempCert,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.Certificate("test")},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						gen.DefaultTestNamespace,
						exampleCertNotFoundCondition,
					)),
					testpkg.NewAction(coretesting.NewCreateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						gen.DefaultTestNamespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: gen.DefaultTestNamespace,
								Name:      "output",
								Labels: map[string]string{
									cmapi.CertificateNameKey: "test",
								},
								Annotations: map[string]string{
									"certmanager.k8s.io/alt-names":   "example.com",
									"certmanager.k8s.io/common-name": "example.com",
									"certmanager.k8s.io/ip-sans":     "",
									"certmanager.k8s.io/issuer-kind": "Issuer",
									"certmanager.k8s.io/issuer-name": "test",
								},
							},
							Type: corev1.SecretTypeTLS,
							Data: map[string][]byte{
								corev1.TLSCertKey:       localTempCert,
								corev1.TLSPrivateKeyKey: pk1PEM,
								TLSCAKey:                nil,
							},
						},
					)),
				},
			},
		},
		"should update an existing empty secret with the private key": {
			Issuer: gen.Issuer("test",
				gen.AddIssuerCondition(cmapi.IssuerCondition{
					Type:   cmapi.IssuerConditionReady,
					Status: cmapi.ConditionTrue,
				}),
				gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
			),
			Certificate: *exampleCert,
			IssuerImpl: &fake.Issuer{
				FakeIssue: func(context.Context, *cmapi.Certificate) (*issuer.IssueResponse, error) {
					return &issuer.IssueResponse{
						PrivateKey: pk1PEM,
					}, nil
				},
			},
			StaticTemporaryCert: localTempCert,
			Builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							SelfLink:  "abc",
							Labels: map[string]string{
								cmapi.CertificateNameKey: "nottest",
							},
							Annotations: map[string]string{
								"testannotation": "true",
							},
						},
					},
				},
				CertManagerObjects: []runtime.Object{gen.Certificate("test")},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						gen.DefaultTestNamespace,
						exampleCertNotFoundCondition,
					)),
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						gen.DefaultTestNamespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: gen.DefaultTestNamespace,
								Name:      "output",
								SelfLink:  "abc",
								Labels: map[string]string{
									cmapi.CertificateNameKey: "test",
								},
								Annotations: map[string]string{
									"testannotation":                 "true",
									"certmanager.k8s.io/alt-names":   "example.com",
									"certmanager.k8s.io/common-name": "example.com",
									"certmanager.k8s.io/ip-sans":     "",
									"certmanager.k8s.io/issuer-kind": "Issuer",
									"certmanager.k8s.io/issuer-name": "test",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       localTempCert,
								corev1.TLSPrivateKeyKey: pk1PEM,
								TLSCAKey:                nil,
							},
						},
					)),
				},
			},
		},
		"should create a new secret containing private key and cert": {
			Issuer: gen.Issuer("test",
				gen.AddIssuerCondition(cmapi.IssuerCondition{
					Type:   cmapi.IssuerConditionReady,
					Status: cmapi.ConditionTrue,
				}),
				gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
			),
			Certificate: *exampleCert,
			IssuerImpl: &fake.Issuer{
				FakeIssue: func(context.Context, *cmapi.Certificate) (*issuer.IssueResponse, error) {
					return &issuer.IssueResponse{
						PrivateKey:  pk1PEM,
						Certificate: cert1PEM,
					}, nil
				},
			},
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.Certificate("test")},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						gen.DefaultTestNamespace,
						exampleCertNotFoundCondition,
					)),
					testpkg.NewAction(coretesting.NewCreateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						gen.DefaultTestNamespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: gen.DefaultTestNamespace,
								Name:      "output",
								Labels: map[string]string{
									cmapi.CertificateNameKey: "test",
								},
								Annotations: map[string]string{
									"certmanager.k8s.io/alt-names":   "example.com",
									"certmanager.k8s.io/common-name": "example.com",
									"certmanager.k8s.io/ip-sans":     "",
									"certmanager.k8s.io/issuer-kind": "Issuer",
									"certmanager.k8s.io/issuer-name": "test",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       cert1PEM,
								corev1.TLSPrivateKeyKey: pk1PEM,
								TLSCAKey:                nil,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
			},
		},
		"should update an existing secret with private key and cert": {
			Issuer: gen.Issuer("test",
				gen.AddIssuerCondition(cmapi.IssuerCondition{
					Type:   cmapi.IssuerConditionReady,
					Status: cmapi.ConditionTrue,
				}),
				gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
			),
			Certificate: *exampleCert,
			IssuerImpl: &fake.Issuer{
				FakeIssue: func(context.Context, *cmapi.Certificate) (*issuer.IssueResponse, error) {
					return &issuer.IssueResponse{
						PrivateKey:  pk1PEM,
						Certificate: cert1PEM,
					}, nil
				},
			},
			Builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							SelfLink:  "abc",
							Labels: map[string]string{
								cmapi.CertificateNameKey: "nottest",
							},
							Annotations: map[string]string{
								"testannotation": "true",
							},
						},
					},
				},
				CertManagerObjects: []runtime.Object{gen.Certificate("test")},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						gen.DefaultTestNamespace,
						exampleCertNotFoundCondition,
					)),
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						gen.DefaultTestNamespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: gen.DefaultTestNamespace,
								Name:      "output",
								SelfLink:  "abc",
								Labels: map[string]string{
									cmapi.CertificateNameKey: "test",
								},
								Annotations: map[string]string{
									"testannotation":                 "true",
									"certmanager.k8s.io/alt-names":   "example.com",
									"certmanager.k8s.io/common-name": "example.com",
									"certmanager.k8s.io/ip-sans":     "",
									"certmanager.k8s.io/issuer-kind": "Issuer",
									"certmanager.k8s.io/issuer-name": "test",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       cert1PEM,
								corev1.TLSPrivateKeyKey: pk1PEM,
								TLSCAKey:                nil,
							},
						},
					)),
				},
			},
		},
		"should mark certificate with invalid private key as DoesNotMatch": {
			Issuer: gen.Issuer("test",
				gen.AddIssuerCondition(cmapi.IssuerCondition{
					Type:   cmapi.IssuerConditionReady,
					Status: cmapi.ConditionTrue,
				}),
				gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
			),
			Certificate: *exampleCert,
			IssuerImpl: &fake.Issuer{
				FakeIssue: func(context.Context, *cmapi.Certificate) (*issuer.IssueResponse, error) {
					return &issuer.IssueResponse{
						PrivateKey:  pk1PEM,
						Certificate: cert1PEM,
					}, nil
				},
			},
			Builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							SelfLink:  "abc",
							Labels: map[string]string{
								cmapi.CertificateNameKey: "nottest",
							},
							Annotations: map[string]string{
								"testannotation": "true",
								// We want ONLY invalid key, issuer annotations should be correct
								"certmanager.k8s.io/issuer-kind": "Issuer",
								"certmanager.k8s.io/issuer-name": "test",
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       cert2PEM,
							corev1.TLSPrivateKeyKey: pk1PEM,
							TLSCAKey:                nil,
						},
					},
				},
				CertManagerObjects: []runtime.Object{gen.Certificate("test")},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						gen.DefaultTestNamespace,
						gen.CertificateFrom(exampleCert,
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             "DoesNotMatch",
								Message:            "Certificate private key does not match certificate",
								LastTransitionTime: &nowMetaTime,
							}),
							gen.SetCertificateNotAfter(metav1.NewTime(cert2.NotAfter)),
						),
					)),
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						gen.DefaultTestNamespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: gen.DefaultTestNamespace,
								Name:      "output",
								SelfLink:  "abc",
								Labels: map[string]string{
									cmapi.CertificateNameKey: "test",
								},
								Annotations: map[string]string{
									"testannotation":                 "true",
									"certmanager.k8s.io/alt-names":   "example.com",
									"certmanager.k8s.io/common-name": "example.com",
									"certmanager.k8s.io/ip-sans":     "",
									"certmanager.k8s.io/issuer-kind": "Issuer",
									"certmanager.k8s.io/issuer-name": "test",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       cert1PEM,
								corev1.TLSPrivateKeyKey: pk1PEM,
								TLSCAKey:                nil,
							},
						},
					)),
				},
			},
		},
		"should update status of up to date certificate": {
			Issuer: gen.Issuer("test",
				gen.AddIssuerCondition(cmapi.IssuerCondition{
					Type:   cmapi.IssuerConditionReady,
					Status: cmapi.ConditionTrue,
				}),
				gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
			),
			Certificate: *exampleCert,
			IssuerImpl: &fake.Issuer{
				FakeIssue: func(context.Context, *cmapi.Certificate) (*issuer.IssueResponse, error) {
					return &issuer.IssueResponse{
						PrivateKey:  pk1PEM,
						Certificate: cert1PEM,
					}, nil
				},
			},
			Builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							SelfLink:  "abc",
							Labels: map[string]string{
								cmapi.CertificateNameKey: "test",
							},
							Annotations: map[string]string{
								"testannotation":                 "true",
								"certmanager.k8s.io/alt-names":   "example.com",
								"certmanager.k8s.io/common-name": "example.com",
								"certmanager.k8s.io/ip-sans":     "",
								"certmanager.k8s.io/issuer-kind": "Issuer",
								"certmanager.k8s.io/issuer-name": "test",
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       cert1PEM,
							corev1.TLSPrivateKeyKey: pk1PEM,
							TLSCAKey:                nil,
						},
					},
				},
				CertManagerObjects: []runtime.Object{gen.Certificate("test")},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						gen.DefaultTestNamespace,
						gen.CertificateFrom(exampleCert,
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionReady,
								Status:             cmapi.ConditionTrue,
								Reason:             "Ready",
								Message:            "Certificate is up to date and has not expired",
								LastTransitionTime: &nowMetaTime,
							}),
							gen.SetCertificateNotAfter(metav1.NewTime(cert1.NotAfter)),
						),
					)),
				},
			},
		},
		"should update the reason field with temporary self signed cert text": {
			Issuer: gen.Issuer("test",
				gen.AddIssuerCondition(cmapi.IssuerCondition{
					Type:   cmapi.IssuerConditionReady,
					Status: cmapi.ConditionTrue,
				}),
				gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
			),
			Certificate: *exampleCert,
			IssuerImpl: &fake.Issuer{
				FakeIssue: func(context.Context, *cmapi.Certificate) (*issuer.IssueResponse, error) {
					return &issuer.IssueResponse{
						PrivateKey: pk1PEM,
					}, nil
				},
			},
			// set this to something other than localTempCert, so that we can
			// assert that the controller doesn't enter in a loop updating the
			// Secret resource with a newly generated certificate
			StaticTemporaryCert: cert1PEM,
			Builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							SelfLink:  "abc",
							Labels: map[string]string{
								cmapi.CertificateNameKey: "nottest",
							},
							Annotations: map[string]string{
								"testannotation": "true",
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       localTempCert,
							corev1.TLSPrivateKeyKey: pk1PEM,
							TLSCAKey:                nil,
						},
					},
				},
				CertManagerObjects: []runtime.Object{gen.Certificate("test")},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						gen.DefaultTestNamespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: gen.DefaultTestNamespace,
								Name:      "output",
								SelfLink:  "abc",
								Labels: map[string]string{
									cmapi.CertificateNameKey: "test",
								},
								Annotations: map[string]string{
									"testannotation":                 "true",
									"certmanager.k8s.io/alt-names":   "example.com",
									"certmanager.k8s.io/common-name": "example.com",
									"certmanager.k8s.io/ip-sans":     "",
									"certmanager.k8s.io/issuer-kind": "Issuer",
									"certmanager.k8s.io/issuer-name": "test",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       localTempCert,
								corev1.TLSPrivateKeyKey: pk1PEM,
								TLSCAKey:                nil,
							},
						},
					)),
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						gen.DefaultTestNamespace,
						exampleCertTemporaryCondition,
					)),
				},
			},
		},
		"should mark certificate with wrong issuer name as DoesNotMatch": {
			Issuer: gen.Issuer("test",
				gen.AddIssuerCondition(cmapi.IssuerCondition{
					Type:   cmapi.IssuerConditionReady,
					Status: cmapi.ConditionTrue,
				}),
				gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
			),
			Certificate: *exampleCert,
			IssuerImpl: &fake.Issuer{
				FakeIssue: func(context.Context, *cmapi.Certificate) (*issuer.IssueResponse, error) {
					return &issuer.IssueResponse{
						PrivateKey:  pk1PEM,
						Certificate: cert1PEM,
					}, nil
				},
			},
			Builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: gen.DefaultTestNamespace,
							Name:      "output",
							SelfLink:  "abc",
							Labels: map[string]string{
								cmapi.CertificateNameKey: "test",
							},
							Annotations: map[string]string{
								"testannotation":                 "true",
								"certmanager.k8s.io/issuer-kind": "Issuer",
								"certmanager.k8s.io/issuer-name": "not-test",
							},
						},
						Data: map[string][]byte{
							corev1.TLSCertKey:       cert1PEM,
							corev1.TLSPrivateKeyKey: pk1PEM,
							TLSCAKey:                nil,
						},
					},
				},
				CertManagerObjects: []runtime.Object{gen.Certificate("test")},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						gen.DefaultTestNamespace,
						gen.CertificateFrom(exampleCert,
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             "DoesNotMatch",
								Message:            "Issuer of the certificate is not up to date: \"not-test\"",
								LastTransitionTime: &nowMetaTime,
							}),
							gen.SetCertificateNotAfter(metav1.NewTime(cert1.NotAfter)),
						),
					)),
					testpkg.NewAction(coretesting.NewUpdateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						gen.DefaultTestNamespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: gen.DefaultTestNamespace,
								Name:      "output",
								SelfLink:  "abc",
								Labels: map[string]string{
									cmapi.CertificateNameKey: "test",
								},
								Annotations: map[string]string{
									"testannotation":                 "true",
									"certmanager.k8s.io/alt-names":   "example.com",
									"certmanager.k8s.io/common-name": "example.com",
									"certmanager.k8s.io/ip-sans":     "",
									"certmanager.k8s.io/issuer-kind": "Issuer",
									"certmanager.k8s.io/issuer-name": "test",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       cert1PEM,
								corev1.TLSPrivateKeyKey: pk1PEM,
								TLSCAKey:                nil,
							},
						},
					)),
				},
			},
		},
		"should mark certificate with duplicate secretName as DuplicateSecretName": {
			Issuer: gen.Issuer("test",
				gen.AddIssuerCondition(cmapi.IssuerCondition{
					Type:   cmapi.IssuerConditionReady,
					Status: cmapi.ConditionTrue,
				}),
				gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
			),
			Certificate: *exampleCert,
			IssuerImpl: &fake.Issuer{
				FakeIssue: func(context.Context, *cmapi.Certificate) (*issuer.IssueResponse, error) {
					return &issuer.IssueResponse{
						PrivateKey:  pk1PEM,
						Certificate: cert1PEM,
					}, nil
				},
			},
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.Certificate("test"),
					gen.Certificate("dup-test",
						gen.SetCertificateDNSNames("example.com"),
						gen.SetCertificateIssuer(cmapi.ObjectReference{Name: "test"}),
						gen.SetCertificateSecretName("output"),
					),
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						gen.DefaultTestNamespace,
						gen.CertificateFrom(exampleCert,
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             "DuplicateSecretName",
								Message:            "Another Certificate is using the same secretName",
								LastTransitionTime: &nowMetaTime,
							}),
						),
					)),
				},
			},
		},
		"should allow duplicate secretName in different namespaces": {
			Issuer: gen.Issuer("test",
				gen.AddIssuerCondition(cmapi.IssuerCondition{
					Type:   cmapi.IssuerConditionReady,
					Status: cmapi.ConditionTrue,
				}),
				gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
			),
			Certificate: *exampleCert,
			IssuerImpl: &fake.Issuer{
				FakeIssue: func(context.Context, *cmapi.Certificate) (*issuer.IssueResponse, error) {
					return &issuer.IssueResponse{
						PrivateKey:  pk1PEM,
						Certificate: cert1PEM,
					}, nil
				},
			},
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.Certificate("test"),
					gen.CertificateFrom(exampleCert,
						gen.SetCertificateNamespace("other-unit-test-ns")),
				},
				ExpectedActions: []testpkg.Action{
					// specifically tests that a secret is created - behaves as usual
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						gen.DefaultTestNamespace,
						exampleCertNotFoundCondition,
					)),
					testpkg.NewAction(coretesting.NewCreateAction(
						corev1.SchemeGroupVersion.WithResource("secrets"),
						gen.DefaultTestNamespace,
						&corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: gen.DefaultTestNamespace,
								Name:      "output",
								Labels: map[string]string{
									cmapi.CertificateNameKey: "test",
								},
								Annotations: map[string]string{
									"certmanager.k8s.io/alt-names":   "example.com",
									"certmanager.k8s.io/common-name": "example.com",
									"certmanager.k8s.io/ip-sans":     "",
									"certmanager.k8s.io/issuer-kind": "Issuer",
									"certmanager.k8s.io/issuer-name": "test",
								},
							},
							Data: map[string][]byte{
								corev1.TLSCertKey:       cert1PEM,
								corev1.TLSPrivateKeyKey: pk1PEM,
								TLSCAKey:                nil,
							},
							Type: corev1.SecretTypeTLS,
						},
					)),
				},
			},
		},
		//"should add annotations to already existing secret resource": {
		//	Issuer: gen.Issuer("test",
		//		gen.AddIssuerCondition(cmapi.IssuerCondition{
		//			Type:   cmapi.IssuerConditionReady,
		//			Status: cmapi.ConditionTrue,
		//		}),
		//		gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
		//	),
		//	Certificate: *gen.CertificateFrom(exampleCert,
		//		gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
		//			Type:               cmapi.CertificateConditionReady,
		//			Status:             cmapi.ConditionTrue,
		//			Reason:             "Ready",
		//			Message:            "Certificate is up to date and has not expired",
		//			LastTransitionTime: nowMetaTime,
		//		}),
		//		gen.SetCertificateNotAfter(metav1.NewTime(cert1.NotAfter)),
		//	),
		//	IssuerImpl: &fake.Issuer{
		//		FakeIssue: func(context.Context, *cmapi.Certificate) (*issuer.IssueResponse, error) {
		//			return &issuer.IssueResponse{
		//				PrivateKey:  pk1PEM,
		//				Certificate: cert1PEM,
		//			}, nil
		//		},
		//	},
		//	Builder: &testpkg.Builder{
		//		KubeObjects: []runtime.Object{
		//			&corev1.Secret{
		//				ObjectMeta: metav1.ObjectMeta{
		//					Namespace: gen.DefaultTestNamespace,
		//					Name:      "output",
		//					SelfLink:  "abc",
		//					Labels: map[string]string{
		//						cmapi.CertificateNameKey: "nottest",
		//					},
		//					Annotations: map[string]string{
		//						"testannotation": "true",
		//					},
		//				},
		//				Data: map[string][]byte{
		//					corev1.TLSCertKey:       cert1PEM,
		//					corev1.TLSPrivateKeyKey: pk1PEM,
		//					TLSCAKey:                nil,
		//				},
		//			},
		//		},
		//		CertManagerObjects: []runtime.Object{gen.Certificate("test")},
		//		ExpectedActions: []testpkg.Action{
		//			testpkg.NewAction(coretesting.NewGetAction(
		//				corev1.SchemeGroupVersion.WithResource("secrets"),
		//				gen.DefaultTestNamespace,
		//				"output",
		//			)),
		//			testpkg.NewAction(coretesting.NewUpdateAction(
		//				corev1.SchemeGroupVersion.WithResource("secrets"),
		//				gen.DefaultTestNamespace,
		//				&corev1.Secret{
		//					ObjectMeta: metav1.ObjectMeta{
		//						Namespace: gen.DefaultTestNamespace,
		//						Name:      "output",
		//						SelfLink:  "abc",
		//						Labels: map[string]string{
		//							cmapi.CertificateNameKey: "test",
		//						},
		//						Annotations: map[string]string{
		//							"testannotation":                 "true",
		//							"certmanager.k8s.io/alt-names":   "example.com",
		//							"certmanager.k8s.io/common-name": "example.com",
		//							"certmanager.k8s.io/issuer-kind": "Issuer",
		//							"certmanager.k8s.io/issuer-name": "test",
		//						},
		//					},
		//					Data: map[string][]byte{
		//						corev1.TLSCertKey:       cert1PEM,
		//						corev1.TLSPrivateKeyKey: pk1PEM,
		//						TLSCAKey:                nil,
		//					},
		//				},
		//			)),
		//		},
		//	},
		//},
	}
	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			if test.Builder == nil {
				test.Builder = &testpkg.Builder{}
			}
			test.Clock = fixedClock
			test.Setup(t)
			crtCopy := test.Certificate.DeepCopy()
			err := test.Controller.Sync(test.Ctx, crtCopy)
			if err != nil && !test.Err {
				t.Errorf("Expected function to not error, but got: %v", err)
			}
			if err == nil && test.Err {
				t.Errorf("Expected function to get an error, but got: %v", err)
			}
			test.Finish(t, crtCopy, err)
		})
	}
}
