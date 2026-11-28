/*
Copyright 2026 The cert-manager Authors.

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
	"crypto/mldsa"
	"crypto/x509"
	"encoding/pem"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cert-manager/cert-manager/internal/controller/feature"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"
	jks "github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/cert-manager/cert-manager/integration-tests/framework"
)

// mldsaCertificateName is the name of the Certificate in each ML-DSA test.
const mldsaCertificateName = "mldsa"

// TestMLDSAPrivateKeys_IssuanceAndRenewal runs all Certificate controllers to
// issue an ML-DSA Certificate, renew it, and then change its parameter set,
// with each private key rotation policy.
func TestMLDSAPrivateKeys_IssuanceAndRenewal(t *testing.T) {
	for _, rotationPolicy := range []cmapi.PrivateKeyRotationPolicy{cmapi.RotationPolicyAlways, cmapi.RotationPolicyNever} {
		t.Run(string(rotationPolicy), func(t *testing.T) {
			featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, feature.MLDSAPrivateKeys, true)
			testMLDSAIssuanceAndRenewal(t, rotationPolicy)
		})
	}
}

func testMLDSAIssuanceAndRenewal(t *testing.T, rotationPolicy cmapi.PrivateKeyRotationPolicy) {
	const (
		namespace  = "test-mldsa-renewal"
		secretName = "mldsa-tls"
	)

	config, stopFn := framework.RunControlPlane(t)
	t.Cleanup(stopFn)

	kubeClient, _, cmCl, _, scheme := framework.NewClients(t, config)
	events, recorder := newEventCollector(t, scheme)
	t.Cleanup(runAllControllersWithRecorder(t, config, recorder))

	createNamespace(t, kubeClient, namespace)

	_, err := cmCl.CertmanagerV1().Certificates(namespace).Create(t.Context(), gen.Certificate(mldsaCertificateName,
		gen.SetCertificateNamespace(namespace),
		gen.SetCertificateDNSNames("mldsa.example.com"),
		gen.SetCertificateSecretName(secretName),
		gen.SetCertificateIssuer(cmmeta.IssuerReference{Name: "testissuer", Kind: "Issuer", Group: "foo.io"}),
		gen.SetCertificateKeyAlgorithm(cmapi.MLDSAKeyAlgorithm),
		gen.SetCertificateKeySize(utilpki.MLDSA65),
		func(crt *cmapi.Certificate) {
			crt.Spec.PrivateKey.RotationPolicy = rotationPolicy
		},
	), metav1.CreateOptions{})
	require.NoError(t, err)

	t.Log("issuing the Certificate with an ML-DSA-65 private key")
	secret := issueRevision(t, kubeClient, cmCl, namespace, 1)
	firstKey := requireMLDSASecret(t, secret, utilpki.MLDSA65)

	t.Log("renewing the Certificate, as cmctl renew does")
	crt := mustGetCertificate(t, t.Context(), cmCl, namespace, mldsaCertificateName)
	applyCertificateStatus(t, cmCl, "test-trigger", namespace, mldsaCertificateName, cmapi.CertificateStatus{
		Conditions: []cmapi.CertificateCondition{{
			Type:               cmapi.CertificateConditionIssuing,
			Status:             cmmeta.ConditionTrue,
			Reason:             "ManuallyTriggered",
			Message:            "triggered by test case manually",
			ObservedGeneration: crt.Generation,
		}},
	})

	secret = issueRevision(t, kubeClient, cmCl, namespace, 2)
	secondKey := requireMLDSASecret(t, secret, utilpki.MLDSA65)
	if rotationPolicy == cmapi.RotationPolicyAlways {
		assert.False(t, firstKey.Equal(secondKey), "expected the renewal to generate a new private key")
	} else {
		assert.True(t, firstKey.Equal(secondKey), "expected the renewal to reuse the existing private key")
	}

	t.Log("changing the parameter set to ML-DSA-87")
	updateCertificate(t, cmCl, namespace, mldsaCertificateName, func(crt *cmapi.Certificate) {
		crt.Spec.PrivateKey.Size = utilpki.MLDSA87
	})

	if rotationPolicy == cmapi.RotationPolicyAlways {
		secret = issueRevision(t, kubeClient, cmCl, namespace, 3)
		requireMLDSASecret(t, secret, utilpki.MLDSA87)
		return
	}

	t.Log("waiting for the key manager to refuse to replace the private key")
	events.waitFor(t, "CannotRegenerateKey", mldsaCertificateName)
	holdWhile(t, func(ctx context.Context) {
		requireNoRequestForRevision(t, ctx, cmCl, namespace, 3)

		current, err := kubeClient.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, secret.Data[corev1.TLSPrivateKeyKey], current.Data[corev1.TLSPrivateKeyKey], "the private key must not be replaced while the rotation policy is Never")
	})
}

// TestMLDSAPrivateKeys_ControllerRestartAndFeatureGate restarts the
// controllers, with the MLDSAPrivateKeys feature gate enabled and then
// disabled, while an ML-DSA Certificate exists. As in a real deployment, the
// feature gate only changes when the controllers restart.
func TestMLDSAPrivateKeys_ControllerRestartAndFeatureGate(t *testing.T) {
	const (
		namespace  = "test-mldsa-feature-gate"
		secretName = "mldsa-tls"
	)

	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, feature.MLDSAPrivateKeys, true)

	config, stopFn := framework.RunControlPlane(t)
	t.Cleanup(stopFn)

	kubeClient, _, cmCl, _, scheme := framework.NewClients(t, config)
	events, recorder := newEventCollector(t, scheme)
	stopControllers := runAllControllersWithRecorder(t, config, recorder)
	t.Cleanup(func() { stopControllers() })

	createNamespace(t, kubeClient, namespace)

	newCertificate := func(name string) *cmapi.Certificate {
		return gen.Certificate(name,
			gen.SetCertificateNamespace(namespace),
			gen.SetCertificateDNSNames("mldsa.example.com"),
			gen.SetCertificateSecretName(name+"-tls"),
			gen.SetCertificateIssuer(cmmeta.IssuerReference{Name: "testissuer", Kind: "Issuer", Group: "foo.io"}),
			gen.SetCertificateKeyAlgorithm(cmapi.MLDSAKeyAlgorithm),
		)
	}

	_, err := cmCl.CertmanagerV1().Certificates(namespace).Create(t.Context(), newCertificate(mldsaCertificateName), metav1.CreateOptions{})
	require.NoError(t, err)

	t.Log("issuing the Certificate, which defaults to an ML-DSA-44 private key")
	secret := issueRevision(t, kubeClient, cmCl, namespace, 1)
	requireMLDSASecret(t, secret, utilpki.MLDSA44)

	t.Log("restarting the controllers, which must reconcile the existing ML-DSA Secret without re-issuing")
	stopControllers()
	stopControllers = runAllControllersWithRecorder(t, config, recorder)
	// Nothing is written when the Certificate is up to date, so there is no
	// signal that the new controllers have reconciled it. Give them time to.
	time.Sleep(2 * time.Second)
	holdWhile(t, func(ctx context.Context) {
		requireNoRequestForRevision(t, ctx, cmCl, namespace, 2)
		crt := mustGetCertificate(t, ctx, cmCl, namespace, mldsaCertificateName)
		assert.True(t, apiutil.CertificateHasCondition(crt, cmapi.CertificateCondition{
			Type:   cmapi.CertificateConditionReady,
			Status: cmmeta.ConditionTrue,
		}), "the Certificate must stay Ready")
	})

	t.Log("restarting the controllers with the MLDSAPrivateKeys feature gate disabled")
	stopControllers()
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, feature.MLDSAPrivateKeys, false)
	stopControllers = runAllControllersWithRecorder(t, config, recorder)

	_, err = cmCl.CertmanagerV1().Certificates(namespace).Create(t.Context(), newCertificate("new-mldsa"), metav1.CreateOptions{})
	assert.ErrorContains(t, err, "MLDSA requires the MLDSAPrivateKeys feature gate to be enabled", "the webhook must reject new ML-DSA Certificates")

	t.Log("changing the DNS names, which the webhook must still allow for an existing ML-DSA Certificate")
	updateCertificate(t, cmCl, namespace, mldsaCertificateName, func(crt *cmapi.Certificate) {
		crt.Spec.DNSNames = []string{"mldsa.example.com", "renamed.example.com"}
	})

	events.waitFor(t, "MLDSAPrivateKeysDisabled", mldsaCertificateName)
	require.NoError(t, wait.PollUntilContextTimeout(t.Context(), 100*time.Millisecond, time.Minute, true, func(ctx context.Context) (bool, error) {
		crt := mustGetCertificate(t, ctx, cmCl, namespace, mldsaCertificateName)
		return apiutil.CertificateHasCondition(crt, cmapi.CertificateCondition{
			Type:   cmapi.CertificateConditionReady,
			Status: cmmeta.ConditionFalse,
		}), nil
	}), "the Certificate's status must still be updated while the feature gate is disabled")
	holdWhile(t, func(ctx context.Context) {
		requireNoRequestForRevision(t, ctx, cmCl, namespace, 2)

		crt := mustGetCertificate(t, ctx, cmCl, namespace, mldsaCertificateName)
		assert.False(t, apiutil.CertificateHasCondition(crt, cmapi.CertificateCondition{
			Type:   cmapi.CertificateConditionIssuing,
			Status: cmmeta.ConditionTrue,
		}), "issuance must not start while the feature gate is disabled")

		current, err := kubeClient.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, secret.Data, current.Data, "the existing Secret must be left alone while the feature gate is disabled")
	})

	t.Log("restarting the controllers with the MLDSAPrivateKeys feature gate enabled again, which lets the re-issuance go ahead")
	stopControllers()
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, feature.MLDSAPrivateKeys, true)
	stopControllers = runAllControllersWithRecorder(t, config, recorder)

	secret = issueRevision(t, kubeClient, cmCl, namespace, 2)
	requireMLDSASecret(t, secret, utilpki.MLDSA44)
	cert, err := utilpki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	require.NoError(t, err)
	assert.Equal(t, []string{"mldsa.example.com", "renamed.example.com"}, cert.DNSNames)
}

// TestMLDSAPrivateKeys_OutputFormats issues ML-DSA Certificates with every
// additional output format and keystore, and checks that the private key and
// certificate can be read back from each of them.
func TestMLDSAPrivateKeys_OutputFormats(t *testing.T) {
	const password = "password"

	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, feature.MLDSAPrivateKeys, true)

	config, stopFn := framework.RunControlPlane(t)
	t.Cleanup(stopFn)

	kubeClient, _, cmCl, _, _ := framework.NewClients(t, config)
	t.Cleanup(runAllControllers(t, config))

	for name, profile := range map[string]cmapi.PKCS12Profile{
		"default":    "",
		"legacydes":  cmapi.LegacyDESPKCS12Profile,
		"modern2023": cmapi.Modern2023PKCS12Profile,
		"modern2026": cmapi.Modern2026PKCS12Profile,
	} {
		t.Run(name, func(t *testing.T) {
			namespace := "test-mldsa-output-formats-" + name
			createNamespace(t, kubeClient, namespace)

			_, err := cmCl.CertmanagerV1().Certificates(namespace).Create(t.Context(), gen.Certificate(mldsaCertificateName,
				gen.SetCertificateNamespace(namespace),
				gen.SetCertificateDNSNames("mldsa.example.com"),
				gen.SetCertificateSecretName("mldsa-tls"),
				gen.SetCertificateIssuer(cmmeta.IssuerReference{Name: "testissuer", Kind: "Issuer", Group: "foo.io"}),
				gen.SetCertificateKeyAlgorithm(cmapi.MLDSAKeyAlgorithm),
				gen.SetCertificateKeySize(utilpki.MLDSA87),
				gen.SetCertificateAdditionalOutputFormats(
					cmapi.CertificateAdditionalOutputFormat{Type: cmapi.CertificateOutputFormatCombinedPEM},
					cmapi.CertificateAdditionalOutputFormat{Type: cmapi.CertificateOutputFormatDER},
				),
				gen.SetCertificateKeystore(&cmapi.CertificateKeystores{
					PKCS12: &cmapi.PKCS12Keystore{Create: true, Profile: profile, Password: new(password)},
					JKS:    &cmapi.JKSKeystore{Create: true, Password: new(password)},
				}),
			), metav1.CreateOptions{})
			require.NoError(t, err)

			secret := issueRevision(t, kubeClient, cmCl, namespace, 1)
			requireMLDSASecret(t, secret, utilpki.MLDSA87)

			keyPEM := secret.Data[corev1.TLSPrivateKeyKey]
			certPEM := secret.Data[corev1.TLSCertKey]
			sk, err := utilpki.DecodePrivateKeyBytes(keyPEM)
			require.NoError(t, err)
			cert, err := utilpki.DecodeX509CertificateBytes(certPEM)
			require.NoError(t, err)

			t.Log("checking the CombinedPEM and DER output formats")
			block, _ := pem.Decode(keyPEM)
			require.NotNil(t, block)
			assert.Equal(t, block.Bytes, secret.Data["key.der"])
			assert.Equal(t, append(append(slices.Clone(keyPEM), '\n'), certPEM...), secret.Data["tls-combined.pem"])

			t.Log("checking the PKCS#12 keystore and truststore")
			pk, pkcs12Cert, _, err := pkcs12.DecodeChain(secret.Data[cmapi.PKCS12SecretKey], password)
			require.NoError(t, err)
			assert.True(t, sk.(*mldsa.PrivateKey).Equal(pk), "the PKCS#12 keystore holds a different private key")
			assert.True(t, cert.Equal(pkcs12Cert), "the PKCS#12 keystore holds a different certificate")
			trustedCerts, err := pkcs12.DecodeTrustStore(secret.Data[cmapi.PKCS12TruststoreKey], password)
			require.NoError(t, err)
			require.Len(t, trustedCerts, 1)
			assert.True(t, cert.Equal(trustedCerts[0]), "the PKCS#12 truststore holds a different CA certificate")

			t.Log("checking the JKS keystore and truststore")
			keystore := jks.New()
			require.NoError(t, keystore.Load(bytes.NewReader(secret.Data[cmapi.JKSSecretKey]), []byte(password)))
			entry, err := keystore.GetPrivateKeyEntry("certificate", []byte(password))
			require.NoError(t, err)
			jksKey, err := x509.ParsePKCS8PrivateKey(entry.PrivateKey)
			require.NoError(t, err)
			assert.True(t, sk.(*mldsa.PrivateKey).Equal(jksKey), "the JKS keystore holds a different private key")
			require.NotEmpty(t, entry.CertificateChain)
			assert.Equal(t, cert.Raw, entry.CertificateChain[0].Content, "the JKS keystore holds a different certificate")
			truststore := jks.New()
			require.NoError(t, truststore.Load(bytes.NewReader(secret.Data[cmapi.JKSTruststoreKey]), []byte(password)))
			trusted, err := truststore.GetTrustedCertificateEntry("ca")
			require.NoError(t, err)
			assert.Equal(t, cert.Raw, trusted.Certificate.Content, "the JKS truststore holds a different CA certificate")
		})
	}
}

// eventCollector keeps the events recorded by the controllers, so that a test
// can wait for one.
type eventCollector struct {
	mu     sync.Mutex
	events []corev1.Event
}

func newEventCollector(t *testing.T, scheme *runtime.Scheme) (*eventCollector, record.EventRecorder) {
	c := &eventCollector{}
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(t.Logf)
	eventBroadcaster.StartEventWatcher(func(event *corev1.Event) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.events = append(c.events, *event)
	})
	t.Cleanup(eventBroadcaster.Shutdown)
	return c, eventBroadcaster.NewRecorder(scheme, corev1.EventSource{Component: t.Name()})
}

// waitFor waits for an event with the given reason to be recorded for the
// object with the given name.
func (c *eventCollector) waitFor(t *testing.T, reason, objectName string) {
	t.Helper()
	require.NoError(t, wait.PollUntilContextTimeout(t.Context(), 100*time.Millisecond, time.Minute, true, func(context.Context) (bool, error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		return slices.ContainsFunc(c.events, func(event corev1.Event) bool {
			return event.Reason == reason && event.InvolvedObject.Name == objectName
		}), nil
	}), "no %s event was recorded for %q", reason, objectName)
}

func createNamespace(t *testing.T, kubeClient kubernetes.Interface, namespace string) {
	t.Helper()
	_, err := kubeClient.CoreV1().Namespaces().Create(t.Context(), &corev1.Namespace{
		Name: namespace,
	}, metav1.CreateOptions{})
	require.NoError(t, err)
}

// updateCertificate changes a Certificate's spec, retrying on conflicts with
// the status updates made by the controllers.
func updateCertificate(t *testing.T, cmCl cmclient.Interface, namespace, name string, mutate func(*cmapi.Certificate)) {
	t.Helper()
	require.NoError(t, retry.RetryOnConflict(retry.DefaultRetry, func() error {
		crt, err := cmCl.CertmanagerV1().Certificates(namespace).Get(t.Context(), name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		mutate(crt)
		_, err = cmCl.CertmanagerV1().Certificates(namespace).Update(t.Context(), crt, metav1.UpdateOptions{})
		return err
	}))
}

// issueRevision completes the issuance of the given revision of a
// Certificate: it waits for the controllers to create the
// CertificateRequest, signs it, and waits for the Certificate to be issued
// and Ready. It returns the Certificate's Secret.
func issueRevision(t *testing.T, kubeClient kubernetes.Interface, cmCl cmclient.Interface, namespace string, revision int) *corev1.Secret {
	t.Helper()

	var req *cmapi.CertificateRequest
	require.NoError(t, wait.PollUntilContextTimeout(t.Context(), 100*time.Millisecond, time.Minute, true, func(ctx context.Context) (bool, error) {
		req = requestForRevision(t, ctx, cmCl, namespace, revision)
		return req != nil, nil
	}), "no CertificateRequest was created for revision %d", revision)

	certPEM := signRequest(t, kubeClient, cmCl, namespace, mldsaCertificateName, req)

	var secret *corev1.Secret
	require.NoError(t, wait.PollUntilContextTimeout(t.Context(), 100*time.Millisecond, time.Minute, true, func(ctx context.Context) (bool, error) {
		crt := mustGetCertificate(t, ctx, cmCl, namespace, mldsaCertificateName)

		// With server-side apply the Issuing condition is set to False with
		// reason Issued instead of being removed.
		if cond := apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionIssuing); cond != nil &&
			!(cond.Status == cmmeta.ConditionFalse && cond.Reason == "Issued") {
			return false, nil
		}
		if crt.Status.Revision == nil || *crt.Status.Revision != revision {
			return false, nil
		}
		if !apiutil.CertificateHasCondition(crt, cmapi.CertificateCondition{
			Type:   cmapi.CertificateConditionReady,
			Status: cmmeta.ConditionTrue,
		}) {
			return false, nil
		}

		var err error
		secret, err = kubeClient.CoreV1().Secrets(namespace).Get(ctx, crt.Spec.SecretName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return bytes.Equal(secret.Data[corev1.TLSCertKey], certPEM), nil
	}), "revision %d was never issued", revision)

	return secret
}

// requestForRevision returns the CertificateRequest for the given revision of
// the Certificate in the namespace, or nil if there isn't one.
func requestForRevision(t *testing.T, ctx context.Context, cmCl cmclient.Interface, namespace string, revision int) *cmapi.CertificateRequest {
	t.Helper()
	for _, req := range listRequests(t, ctx, cmCl, namespace) {
		if req.Annotations[cmapi.CertificateRequestRevisionAnnotationKey] == strconv.Itoa(revision) {
			return &req
		}
	}
	return nil
}

func requireNoRequestForRevision(t *testing.T, ctx context.Context, cmCl cmclient.Interface, namespace string, revision int) {
	t.Helper()
	require.Nil(t, requestForRevision(t, ctx, cmCl, namespace, revision), "no CertificateRequest must be created for revision %d", revision)
}

// requireMLDSASecret checks that a Secret holds an ML-DSA private key with the
// parameter set for the given size, and a certificate for that key with only
// the digital signature key usage. It returns the public key.
func requireMLDSASecret(t *testing.T, secret *corev1.Secret, size int) *mldsa.PublicKey {
	t.Helper()

	sk, err := utilpki.DecodePrivateKeyBytes(secret.Data[corev1.TLSPrivateKeyKey])
	require.NoError(t, err)
	mldsaKey, ok := sk.(*mldsa.PrivateKey)
	require.Truef(t, ok, "expected an ML-DSA private key, got %T", sk)
	params, err := utilpki.MLDSAParametersForSize(size)
	require.NoError(t, err)
	assert.Equal(t, params.String(), mldsaKey.PublicKey().Parameters().String())

	cert, err := utilpki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	require.NoError(t, err)
	match, err := utilpki.PublicKeyMatchesCertificate(mldsaKey.Public(), cert)
	require.NoError(t, err)
	assert.True(t, match, "the certificate is not for the private key in the Secret")
	assert.Equal(t, x509.KeyUsageDigitalSignature, cert.KeyUsage, "an ML-DSA certificate must only have the digital signature key usage by default")

	return mldsaKey.PublicKey()
}
