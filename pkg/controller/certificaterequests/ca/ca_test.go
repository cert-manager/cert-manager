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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientcorev1 "k8s.io/client-go/listers/core/v1"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	"github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/cmrand"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificaterequests"
	"github.com/cert-manager/cert-manager/pkg/controller/certificaterequests/util"
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

	baseCRNotApproved := gen.CertificateRequest("test-cr",
		gen.SetCertificateRequestIsCA(true),
		gen.SetCertificateRequestCSR(testCSR),
		gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
			Name:  baseIssuer.DeepCopy().Name,
			Group: certmanager.GroupName,
			Kind:  "Issuer",
		}),
		gen.SetCertificateRequestDuration(&metav1.Duration{Duration: time.Hour * 24 * 60}),
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

	// generate a self signed root ca valid for 60d
	rootCert, rootCertPEM := generateSelfSignedCACert(t, rootPK, "root")
	rsaCASecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "root-ca-secret",
			Namespace: gen.DefaultTestNamespace,
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: rootPKPEM,
			corev1.TLSCertKey:       rootCertPEM,
		},
	}

	badDataSecret := rsaCASecret.DeepCopy()
	badDataSecret.Data[corev1.TLSPrivateKeyKey] = []byte("bad key")

	template, err := pki.CertificateTemplateFromCertificateRequest(baseCR)
	if err != nil {
		t.Fatal(err)
	}
	certBundle, err := pki.SignCSRTemplate([]*x509.Certificate{rootCert}, rootPK, template)
	if err != nil {
		t.Fatal(err)
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
		"a missing CA key pair should set the condition to pending and wait for a re-sync": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					`Normal SecretMissing Referenced secret default-unit-test-ns/root-ca-secret not found: secret "root-ca-secret" not found`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR.DeepCopy(),
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            `Referenced secret default-unit-test-ns/root-ca-secret not found: secret "root-ca-secret" not found`,
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"a secret with invalid data should set condition to pending and wait for re-sync": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{badDataSecret},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(),
					gen.IssuerFrom(baseIssuer.DeepCopy(),
						gen.SetIssuerCA(cmapi.CAIssuer{SecretName: badDataSecret.Name}),
					),
				},
				ExpectedEvents: []string{
					"Normal SecretInvalidData Failed to parse signing CA keypair from secret default-unit-test-ns/root-ca-secret: error decoding private key PEM block",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR.DeepCopy(),
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            "Failed to parse signing CA keypair from secret default-unit-test-ns/root-ca-secret: error decoding private key PEM block",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"a CertificateRequest that transiently fails a secret lookup should backoff error to retry": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{rsaCASecret},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					`Normal SecretGetError Failed to get certificate key pair from secret default-unit-test-ns/root-ca-secret: this is a network error`,
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
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            "Failed to get certificate key pair from secret default-unit-test-ns/root-ca-secret: this is a network error",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
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
		"should exit nil and set status pending if referenced issuer is not ready": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{rsaCASecret},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(),
					gen.Issuer(baseIssuer.DeepCopy().Name,
						gen.SetIssuerCA(cmapi.CAIssuer{}),
					)},
				ExpectedEvents: []string{
					"Normal IssuerNotReady Referenced issuer does not have a Ready status condition",
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
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"a secret that fails to sign due to failing to generate the certificate template should set condition to failed": {
			certificateRequest: baseCR.DeepCopy(),
			templateGenerator: func(*cmapi.CertificateRequest) (*x509.Certificate, error) {
				return nil, errors.New("this is a template generate error")
			},
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{rsaCASecret},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Warning SigningError Error generating certificate template: this is a template generate error",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR.DeepCopy(),
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonFailed,
								Message:            "Error generating certificate template: this is a template generate error",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
		},
		"a successful signing should set condition to Ready": {
			certificateRequest: baseCR.DeepCopy(),
			templateGenerator: func(cr *cmapi.CertificateRequest) (*x509.Certificate, error) {
				_, err := pki.CertificateTemplateFromCertificateRequest(cr)
				if err != nil {
					return nil, err
				}

				return template, nil
			},
			signingFn: func(_ []*x509.Certificate, _ crypto.Signer, _ *x509.Certificate) (pki.PEMBundle, error) {
				return pki.PEMBundle{CAPEM: certBundle.CAPEM, ChainPEM: certBundle.ChainPEM}, nil
			},
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{rsaCASecret},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Normal CertificateIssued Certificate fetched from issuer successfully",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionTrue,
								Reason:             cmapi.CertificateRequestReasonIssued,
								Message:            "Certificate fetched from issuer successfully",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestCertificate(certBundle.ChainPEM),
							gen.SetCertificateRequestCA(rootCertPEM),
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
	certificateRequest *cmapi.CertificateRequest
	templateGenerator  templateGenerator
	signingFn          signingFn

	expectedErr bool

	fakeLister *testlisters.FakeSecretLister
}

func runTest(t *testing.T, test testT) {
	test.builder.T = t
	test.builder.Init()
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

	controller := certificaterequests.New(
		apiutil.IssuerCA,
		func(*controller.Context) certificaterequests.Issuer { return ca },
	)
	if _, _, err := controller.Register(test.builder.Context); err != nil {
		t.Fatal(err)
	}
	test.builder.Start()

	err := controller.Sync(context.Background(), test.certificateRequest)
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
		givenCR          *cmapi.CertificateRequest
		assertSignedCert func(t *testing.T, got *x509.Certificate)
		wantErr          string
	}{
		"when the CertificateRequest has the duration field set, it should appear as notAfter on the signed ca": {
			givenCASecret: gen.SecretFrom(gen.Secret("secret-1"), gen.SetSecretNamespace("default"), gen.SetSecretData(secretDataFor(t, rootPK, rootCert))),
			givenCAIssuer: gen.Issuer("issuer-1", gen.SetIssuerCA(cmapi.CAIssuer{
				SecretName: "secret-1",
			})),
			givenCR: gen.CertificateRequest("cr-1",
				gen.SetCertificateRequestCSR(testCSR),
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name:  "issuer-1",
					Group: certmanager.GroupName,
					Kind:  "Issuer",
				}),
				gen.SetCertificateRequestDuration(&metav1.Duration{
					Duration: 30 * time.Minute,
				}),
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
				// check the time, we use a delta of 1 second. One entire
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
				assert.LessOrEqualf(t, deltaSec, 1., "expected a time delta lower than 1 second. Time expected='%s', got='%s'", expectNotAfter.String(), got.NotAfter.String())
			},
		},
		"when the CertificateRequest has the isCA field set, it should appear on the signed ca": {
			givenCASecret: gen.SecretFrom(gen.Secret("secret-1"), gen.SetSecretNamespace("default"), gen.SetSecretData(secretDataFor(t, rootPK, rootCert))),
			givenCAIssuer: gen.Issuer("issuer-1", gen.SetIssuerCA(cmapi.CAIssuer{
				SecretName: "secret-1",
			})),
			givenCR: gen.CertificateRequest("cr-1",
				gen.SetCertificateRequestCSR(testCSR),
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name:  "issuer-1",
					Group: certmanager.GroupName,
					Kind:  "Issuer",
				}),
				gen.SetCertificateRequestIsCA(true),
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
			givenCR: gen.CertificateRequest("cr-1",
				gen.SetCertificateRequestCSR(testCSR),
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name:  "issuer-1",
					Group: certmanager.GroupName,
					Kind:  "Issuer",
				}),
			),
			assertSignedCert: func(t *testing.T, got *x509.Certificate) {
				assert.Equal(t, []string{"http://ocsp-v3.example.org"}, got.OCSPServer)
			},
		},
		"when the Issuer has IssuingCertificateURL set, it should appear on the signed ca": {
			givenCASecret: gen.SecretFrom(gen.Secret("secret-1"), gen.SetSecretNamespace("default"), gen.SetSecretData(secretDataFor(t, rootPK, rootCert))),
			givenCAIssuer: gen.Issuer("issuer-1", gen.SetIssuerCA(cmapi.CAIssuer{
				SecretName:             "secret-1",
				IssuingCertificateURLs: []string{"http://ca.letsencrypt.org/ca.crt"},
			})),
			givenCR: gen.CertificateRequest("cr-1",
				gen.SetCertificateRequestCSR(testCSR),
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name:  "issuer-1",
					Group: certmanager.GroupName,
					Kind:  "Issuer",
				}),
			),
			assertSignedCert: func(t *testing.T, got *x509.Certificate) {
				assert.Equal(t, []string{"http://ca.letsencrypt.org/ca.crt"}, got.IssuingCertificateURL)
			},
		},
		"when the Issuer has crlDistributionPoints set, it should appear on the signed ca ": {
			givenCASecret: gen.SecretFrom(gen.Secret("secret-1"), gen.SetSecretNamespace("default"), gen.SetSecretData(secretDataFor(t, rootPK, rootCert))),
			givenCAIssuer: gen.Issuer("issuer-1", gen.SetIssuerCA(cmapi.CAIssuer{
				SecretName:            "secret-1",
				CRLDistributionPoints: []string{"http://www.example.com/crl/test.crl"},
			})),
			givenCR: gen.CertificateRequest("cr-1",
				gen.SetCertificateRequestIsCA(true),
				gen.SetCertificateRequestCSR(testCSR),
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name:  "issuer-1",
					Group: certmanager.GroupName,
					Kind:  "Issuer",
				}),
			),
			assertSignedCert: func(t *testing.T, gotCA *x509.Certificate) {
				assert.Equal(t, []string{"http://www.example.com/crl/test.crl"}, gotCA.CRLDistributionPoints)
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			rec := &testpkg.FakeRecorder{}

			c := &CA{
				issuerOptions: controller.IssuerOptions{
					ClusterResourceNamespace:        "",
					ClusterIssuerAmbientCredentials: false,
					IssuerAmbientCredentials:        false,
				},
				reporter: util.NewReporter(fixedClock, rec),
				secretsLister: testlisters.FakeSecretListerFrom(testlisters.NewFakeSecretLister(),
					testlisters.SetFakeSecretNamespaceListerGet(test.givenCASecret, nil),
				),
				templateGenerator: pki.CertificateTemplateFromCertificateRequest,
				signingFn:         pki.SignCSRTemplate,
			}

			gotIssueResp, gotErr := c.Sign(context.Background(), test.givenCR, test.givenCAIssuer)
			if test.wantErr != "" {
				require.EqualError(t, gotErr, test.wantErr)
			} else {
				require.NoError(t, gotErr)

				require.NotNil(t, gotIssueResp)
				gotCert, err := pki.DecodeX509CertificateBytes(gotIssueResp.Certificate)
				require.NoError(t, err)

				test.assertSignedCert(t, gotCert)
			}
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
