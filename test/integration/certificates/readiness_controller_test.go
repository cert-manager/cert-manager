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

package certificates

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakeclock "k8s.io/utils/clock/testing"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/certificates"
	"github.com/jetstack/cert-manager/pkg/controller/certificates/readiness"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/metrics"
	"github.com/jetstack/cert-manager/test/integration/framework"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

// TestReadinessController performs a basic test to ensure that
// readiness controller sets the correct Ready condition on a Certificate.
func TestReadinessController(t *testing.T) {
	config, stopFn := framework.RunControlPlane(t)
	defer stopFn()

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second*20)
	defer cancel()

	// Fix the time to be able to test expired certificate scenario.
	fakeClock := &fakeclock.FakeClock{}
	// Build, instantiate and run the trigger controller.
	kubeClient, factory, cmCl, cmFactory := framework.NewClients(t, config)

	namespace := "testns"
	certName := "test"
	secretName := "test"
	// notBefore value on the test certificate
	notBefore := fakeClock.Now().UTC().Add(time.Hour).Truncate(time.Second)
	// notAfter value on the test certificate
	notAfter := notBefore.Add(time.Hour * 4).Truncate(time.Second)
	// expected renewal time
	renewalTime := notBefore.Add(time.Hour * 2).Truncate(time.Second)
	issuer := cmmeta.ObjectReference{
		Name:  "testissuer",
		Kind:  "IssuerKind",
		Group: "group.example.com",
	}

	// Create Namespace.
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	_, err := kubeClient.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	ctrl, queue, mustSync := readiness.NewController(logf.Log, cmCl, factory, cmFactory, readiness.NewReadinessPolicyChain(fakeClock), certificates.RenewalTimeWrapper(cmapi.DefaultRenewBefore), readiness.PolicyEvaluator)
	c := controllerpkg.NewController(
		context.Background(),
		"readiness_test",
		metrics.New(logf.Log),
		ctrl.ProcessItem,
		mustSync,
		nil,
		queue,
	)
	stopController := framework.StartInformersAndController(t, factory, cmFactory, c)
	defer stopController()

	// 1. A newly created Certificate without a Secret should not be set to Ready.

	// create the Certificate
	cert, err := cmCl.CertmanagerV1().Certificates(namespace).Create(ctx,
		gen.Certificate(certName,
			gen.SetCertificateNamespace(namespace),
			gen.SetCertificateSecretName(secretName),
			gen.SetCertificateCommonName("example.com"),
			gen.SetCertificateIssuer(issuer),
			gen.SetCertificateRenewBefore(time.Hour*2)),
		metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// ensure that Certificate does not have Ready conditon set to True
	ensureConditionNotApplied(ctx, t, cmCl, cert, cmapi.CertificateCondition{
		Type:   cmapi.CertificateConditionReady,
		Status: cmmeta.ConditionTrue,
	})

	// 2. A Certificate with a valid Secret and CertificateRequest should have Ready condition set to True
	// and updated status.RenewalTime, status.NotBefore, status.NotAfter fields

	// Create private key
	privKeyBytes := mustCreatePEMPrivateKey(t)
	// Create x509 certificate
	x509Cert := mustCreateCertWithNotBeforeAfter(t, privKeyBytes, cert, notBefore, notAfter)
	// Create a Secret
	secret, err := kubeClient.CoreV1().Secrets(namespace).Create(ctx,
		gen.Secret(secretName,
			gen.SetSecretNamespace(namespace),
			gen.SetSecretData(map[string][]byte{
				corev1.TLSPrivateKeyKey: privKeyBytes,
				corev1.TLSCertKey:       x509Cert,
			}),
			gen.SetSecretAnnotations(
				map[string]string{
					cmapi.IssuerNameAnnotationKey:  "testissuer",
					cmapi.IssuerKindAnnotationKey:  "IssuerKind",
					cmapi.IssuerGroupAnnotationKey: "group.example.com",
				}),
		),
		metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Create CertificateSigningRequest
	csrBytes := mustGenerateCSRImpl(t, privKeyBytes, cert)
	csr := gen.CertificateRequest("somerequest",
		gen.SetCertificateRequestIssuer(issuer),
		gen.SetCertificateRequestNamespace(namespace),
		gen.SetCertificateRequestCSR(csrBytes))
	// Create a CertificateRequest
	_, err = cmCl.CertmanagerV1().CertificateRequests(namespace).Create(ctx, csr, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// build some assertions to check the status of the Certificate
	assertions := []assertFunc{func(t *testing.T, c *cmapi.Certificate) {
		// we expect change of condition and change of status as part of the same update
		// assert.Equal(t, cert.Status.RenewalTime.Time, notBefore.Add(time.Hour*2))
		assert.NotNil(t, c.Status.NotBefore)
		assert.NotNil(t, c.Status.NotAfter)
		// comparing unix time for more concise log messages in case of an error
		assert.Equalf(t, c.Status.NotBefore.Unix(), notBefore.Unix(), "expected status.notBefore: %s, got: %s", notBefore, c.Status.NotBefore.String())
		assert.Equalf(t, c.Status.NotAfter.Unix(), notAfter.Unix(), "expected status.notAfter: %s, got: %s", notAfter, c.Status.NotAfter.String())
		assert.Equalf(t, c.Status.RenewalTime.Unix(), renewalTime.Unix(), "expected renewal time: %s, got: %s", renewalTime, c.Status.RenewalTime.String())

	}}
	// ensure that Ready conditon gets set to True
	ensureConditionApplied(ctx, t, cmCl, cert, cmapi.CertificateCondition{
		Type:   cmapi.CertificateConditionReady,
		Status: cmmeta.ConditionTrue,
	}, assertions...)

	// 3. A Certificate that has expired gets it's Ready condition set to False

	// advance the fake clock to after the certificate's expiry
	fakeClock.SetTime(notAfter.Add(time.Minute))

	// apply some change to Secret, to trigger reconcile of the Certificate
	secret = gen.SecretFrom(secret,
		gen.SetSecretAnnotations(map[string]string{
			"somekey": "sometext",
		}))
	_, err = kubeClient.CoreV1().Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// ensure that Ready condition gets set to False
	ensureConditionApplied(ctx, t, cmCl, cert, cmapi.CertificateCondition{
		Type:   cmapi.CertificateConditionReady,
		Status: cmmeta.ConditionFalse,
	})
}
