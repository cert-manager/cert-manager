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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cert-manager/cert-manager/internal/controller/certificates/policies"
	"github.com/cert-manager/cert-manager/internal/controller/feature"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/issuing"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/keymanager"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/requestmanager"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/trigger"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/metrics"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	"k8s.io/utils/clock"
	fakeclock "k8s.io/utils/clock/testing"

	"github.com/cert-manager/cert-manager/integration-tests/framework"
)

// TestStalledRequestRecovery covers an issuance that no controller used to be
// willing to change: a CertificateRequest that an external issuer left with a
// failureTime and no Ready condition. The issuing controller waited for a
// condition that never arrived, the request manager only recycled a request
// whose Ready reason was Failed, and the trigger controller does nothing while
// the Certificate is Issuing.
//
// Only the whole lifecycle shows the stall is gone. A Warning event, an
// Issuing condition set to False, or a delete call are each reachable without
// the Certificate ever being issued, so this drives the issuance from the
// stalled request through the backoff to a certificate in the Secret.
func TestStalledRequestRecovery(t *testing.T) {
	// The status write is an update or an apply depending on the feature gate,
	// and the two paths reach the stalled request through different code.
	//
	// The private key decides who removes the request. The keymanager drops
	// the next private key when an issuance ends, so with the default rotation
	// policy the next issuance has a new one and the stalled request no longer
	// matches it: the request manager removes it as a mismatch, before it ever
	// reaches the recycling path. Only a reused key leaves a request that
	// matches everything and can be removed for no reason but its own state.
	for _, serverSideApply := range []bool{false, true} {
		for _, reuseKey := range []bool{false, true} {
			name := "UpdateStatus"
			if serverSideApply {
				name = "ServerSideApply"
			}
			if reuseKey {
				name += "/ReusedPrivateKey"
			} else {
				name += "/RotatedPrivateKey"
			}

			t.Run(name, func(t *testing.T) {
				featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, feature.ServerSideApply, serverSideApply)
				testStalledRequestRecovery(t, reuseKey)
			})
		}
	}
}

func testStalledRequestRecovery(t *testing.T, reuseKey bool) {
	const (
		namespace  = "test-stalled-request-recovery"
		crtName    = "stalled"
		secretName = "stalled-tls"
		// The production defaults, reached by moving the clock rather than by
		// waiting them out.
		backoff    = time.Hour
		maxBackoff = 32 * time.Hour
	)

	config, stopFn := framework.RunControlPlane(t)
	t.Cleanup(stopFn)

	// The backoff here is an hour away, so a fake clock is the only way to
	// reach it. apiutil.Clock has to agree with it: the
	// Issuing transition that a failureTime is compared against is stamped
	// through that global, not through the controller's own clock.
	fakeClock := fakeclock.NewFakeClock(time.Now())
	apiutil.Clock = fakeClock
	t.Cleanup(func() { apiutil.Clock = clock.RealClock{} })

	kubeClient, factory, cmCl, cmFactory, scheme := framework.NewClients(t, config)

	// One context per controller, because a shared field manager would hide
	// exactly the server-side apply ownership this test is here to exercise.
	newContext := func(name string) *controllerpkg.Context {
		return &controllerpkg.Context{
			Scheme:                    scheme,
			Client:                    kubeClient,
			KubeSharedInformerFactory: factory,
			CMClient:                  cmCl,
			SharedInformerFactory:     cmFactory,
			Clock:                     fakeClock,
			ContextOptions: controllerpkg.ContextOptions{
				CertificateOptions: controllerpkg.CertificateOptions{
					CertificateRequestMinimumBackoffDuration: backoff,
					CertificateRequestMaximumBackoffDuration: maxBackoff,
				},
			},
			Recorder:     framework.NewEventRecorder(t, scheme),
			FieldManager: "cert-manager-certificates-" + name + "-test",
		}
	}

	// A reconcile reads the clock, works out how long is left, and only then
	// arms its timer. A clock jump landing between those two makes the timer
	// target a time the test will never reach, so jumps wait for reconciles in
	// flight. Reconciles still run concurrently with each other.
	var clockMu sync.RWMutex
	setControllerTime := func(now time.Time) {
		clockMu.Lock()
		defer clockMu.Unlock()
		fakeClock.SetTime(now)
	}

	newController := func(name string, processItem func(context.Context, types.NamespacedName) error, queue workqueue.TypedRateLimitingInterface[types.NamespacedName], mustSync []cache.InformerSynced, err error) controllerpkg.Interface {
		t.Helper()
		require.NoError(t, err)
		guarded := func(ctx context.Context, key types.NamespacedName) error {
			clockMu.RLock()
			defer clockMu.RUnlock()
			return processItem(ctx, key)
		}
		return controllerpkg.NewController(name, metrics.New(logf.Log, clock.RealClock{}), guarded, mustSync, nil, queue)
	}

	triggerCtx := newContext("trigger")
	triggerCtrl, triggerQueue, triggerSync, triggerErr := trigger.NewController(logf.Log, triggerCtx, policies.NewTriggerPolicyChain(fakeClock).Evaluate)
	keyCtx := newContext("key-manager")
	keyCtrl, keyQueue, keySync, keyErr := keymanager.NewController(logf.Log, keyCtx)
	reqCtx := newContext("request-manager")
	reqCtrl, reqQueue, reqSync, reqErr := requestmanager.NewController(logf.Log, reqCtx)
	issuingCtx := newContext("issuing")
	issuingCtrl, issuingQueue, issuingSync, issuingErr := issuing.NewController(logf.Log, issuingCtx)

	stopControllers := framework.StartInformersAndControllers(t, factory, cmFactory,
		newController("trigger_test", triggerCtrl.ProcessItem, triggerQueue, triggerSync, triggerErr),
		newController("keymanager_test", keyCtrl.ProcessItem, keyQueue, keySync, keyErr),
		newController("requestmanager_test", reqCtrl.ProcessItem, reqQueue, reqSync, reqErr),
		newController("issuing_test", issuingCtrl.ProcessItem, issuingQueue, issuingSync, issuingErr),
	)
	t.Cleanup(stopControllers)

	_, err := kubeClient.CoreV1().Namespaces().Create(t.Context(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespace},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	certificateMods := []gen.CertificateModifier{
		gen.SetCertificateNamespace(namespace),
		gen.SetCertificateCommonName("stalled.example.com"),
		gen.SetCertificateSecretName(secretName),
		gen.SetCertificateIssuer(cmmeta.IssuerReference{Name: "testissuer", Kind: "Issuer", Group: "foo.io"}),
	}
	if reuseKey {
		// A rotation policy of Never makes the keymanager reuse the key in the
		// target Secret, so both issuances share one and the stalled request
		// still matches the second. Seeded here because the policy only reuses
		// a key that already exists.
		sk, err := utilpki.GenerateRSAPrivateKey(2048)
		require.NoError(t, err)
		_, err = kubeClient.CoreV1().Secrets(namespace).Create(t.Context(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: secretName},
			Data:       map[string][]byte{corev1.TLSPrivateKeyKey: utilpki.EncodePKCS1PrivateKey(sk)},
		}, metav1.CreateOptions{})
		require.NoError(t, err)

		certificateMods = append(certificateMods, func(crt *cmapi.Certificate) {
			crt.Spec.PrivateKey = &cmapi.CertificatePrivateKey{RotationPolicy: cmapi.RotationPolicyNever}
		})
	}

	t.Log("creating the Certificate, which the trigger, keymanager and requestmanager controllers turn into a CertificateRequest")
	_, err = cmCl.CertmanagerV1().Certificates(namespace).Create(t.Context(), gen.Certificate(crtName, certificateMods...), metav1.CreateOptions{})
	require.NoError(t, err)

	requestA := waitForSingleRequest(t, cmCl, namespace, func(*cmapi.CertificateRequest) bool { return true })

	t.Log("reporting a failureTime on the CertificateRequest and no Ready condition, as a broken external issuer does")
	requestA.Status.FailureTime = new(metav1.NewTime(fakeClock.Now()))
	requestA, err = cmCl.CertmanagerV1().CertificateRequests(namespace).UpdateStatus(t.Context(), requestA, metav1.UpdateOptions{})
	require.NoError(t, err)
	require.Nil(t, apiutil.GetCertificateRequestCondition(requestA, cmapi.CertificateRequestConditionReady))

	t.Log("waiting for the issuance to be failed, which is what hands it to the trigger controller's backoff")
	require.NoError(t, wait.PollUntilContextTimeout(t.Context(), 100*time.Millisecond, time.Minute, true, func(ctx context.Context) (bool, error) {
		crt := mustGetCertificate(t, ctx, cmCl, namespace, crtName)
		cond := apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionIssuing)
		return cond != nil && cond.Status == cmmeta.ConditionFalse && cond.Reason == "Stalled", nil
	}), "the issuance was never failed")

	crt := mustGetCertificate(t, t.Context(), cmCl, namespace, crtName)
	require.NotNil(t, crt.Status.FailedIssuanceAttempts)
	assert.Equal(t, 1, *crt.Status.FailedIssuanceAttempts, "the stalled request is one failure, not one per reconcile")
	require.NotNil(t, crt.Status.LastFailureTime)

	retryAt := crt.Status.LastFailureTime.Time.Add(backoff)

	t.Log("holding a minute short of the retry deadline, where the replacement must not exist yet")
	setControllerTime(retryAt.Add(-time.Minute))
	holdWhile(t, func(ctx context.Context) {
		reqs := listRequests(t, ctx, cmCl, namespace)
		require.Len(t, reqs, 1, "a replacement must not be created before the backoff elapses")
		assert.Equal(t, requestA.UID, reqs[0].UID)

		crt := mustGetCertificate(t, ctx, cmCl, namespace, crtName)
		require.NotNil(t, crt.Status.FailedIssuanceAttempts)
		assert.Equal(t, 1, *crt.Status.FailedIssuanceAttempts, "re-reading the same state must not count a second failure")
	})

	t.Log("crossing the retry deadline, so the trigger controller starts the next issuance and the stalled request is recycled")
	setControllerTime(retryAt.Add(time.Second))
	requestB := waitForSingleRequest(t, cmCl, namespace, func(req *cmapi.CertificateRequest) bool {
		return req.UID != requestA.UID
	})
	assert.Equal(t, requestA.Name, requestB.Name, "the replacement is expected to reuse the name, which is why the recycling identifies requests by UID")

	// Which controller path removed the stalled request follows from whether
	// the key was reused, so pinning that pins the path this ran through.
	samePublicKey := csrPublicKeysEqual(t, requestA, requestB)
	if reuseKey {
		assert.True(t, samePublicKey, "the stalled request must still match the next private key, or it would be removed as a mismatch instead of recycled")
	} else {
		assert.False(t, samePublicKey, "the keymanager is expected to have rotated the next private key between issuances")
	}

	// The point of the second round: the replacement's failure has to be
	// counted as a new one rather than read as the first one replayed, or the
	// backoff would stop growing and the retries would never be paced.
	t.Log("reporting the same incomplete failure on the replacement")
	requestB.Status.FailureTime = new(metav1.NewTime(fakeClock.Now()))
	_, err = cmCl.CertmanagerV1().CertificateRequests(namespace).UpdateStatus(t.Context(), requestB, metav1.UpdateOptions{})
	require.NoError(t, err)

	require.NoError(t, wait.PollUntilContextTimeout(t.Context(), 100*time.Millisecond, time.Minute, true, func(ctx context.Context) (bool, error) {
		crt := mustGetCertificate(t, ctx, cmCl, namespace, crtName)
		return crt.Status.FailedIssuanceAttempts != nil && *crt.Status.FailedIssuanceAttempts == 2, nil
	}), "the replacement's failure was never counted as a second one")

	crt = mustGetCertificate(t, t.Context(), cmCl, namespace, crtName)
	require.NotNil(t, crt.Status.LastFailureTime)

	// Past the configured maximum, so this crossing does not depend on how the
	// second backoff is calculated. The first crossing above is the one that
	// pins the backoff being respected at all.
	t.Log("crossing the second backoff, so the stalled replacement is itself recycled")
	setControllerTime(crt.Status.LastFailureTime.Time.Add(maxBackoff + time.Second))
	requestC := waitForSingleRequest(t, cmCl, namespace, func(req *cmapi.CertificateRequest) bool {
		return req.UID != requestB.UID
	})

	t.Log("completing the CertificateRequest, as a working issuer does")
	certPEM := signRequest(t, kubeClient, cmCl, namespace, crtName, requestC)

	t.Log("waiting for the issuance to complete and the failure state to be cleared")
	require.NoError(t, wait.PollUntilContextTimeout(t.Context(), 100*time.Millisecond, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		crt := mustGetCertificate(t, ctx, cmCl, namespace, crtName)

		// With server-side apply the Issuing condition is set to False with
		// reason Issued instead of being removed.
		if cond := apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionIssuing); cond != nil &&
			!(cond.Status == cmmeta.ConditionFalse && cond.Reason == "Issued") {
			return false, nil
		}
		if crt.Status.Revision == nil || *crt.Status.Revision != 1 {
			return false, nil
		}
		if crt.Status.FailedIssuanceAttempts != nil || crt.Status.LastFailureTime != nil {
			return false, nil
		}

		secret, err := kubeClient.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return bytes.Equal(secret.Data[corev1.TLSCertKey], certPEM), nil
	}), "the issuance never recovered")
}

// holdWhile repeatedly runs assertions, to check that a state the controllers
// must wait in is one they actually stay in rather than one they happened to be
// in when it was first read.
func holdWhile(t *testing.T, assertions func(context.Context)) {
	t.Helper()
	for range 5 {
		assertions(t.Context())
		if t.Failed() {
			t.FailNow()
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func listRequests(t *testing.T, ctx context.Context, cmCl cmclient.Interface, namespace string) []cmapi.CertificateRequest {
	t.Helper()
	reqs, err := cmCl.CertmanagerV1().CertificateRequests(namespace).List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	return reqs.Items
}

func mustGetCertificate(t *testing.T, ctx context.Context, cmCl cmclient.Interface, namespace, name string) *cmapi.Certificate {
	t.Helper()
	crt, err := cmCl.CertmanagerV1().Certificates(namespace).Get(ctx, name, metav1.GetOptions{})
	require.NoError(t, err)
	return crt
}

// waitForSingleRequest waits for exactly one matching CertificateRequest to
// exist, without touching the clock. More than one would mean issuance had
// stalled a different way, so it is a failure rather than something to wait out.
func waitForSingleRequest(t *testing.T, cmCl cmclient.Interface, namespace string, match func(*cmapi.CertificateRequest) bool) *cmapi.CertificateRequest {
	t.Helper()
	var found *cmapi.CertificateRequest
	require.NoError(t, wait.PollUntilContextTimeout(t.Context(), 100*time.Millisecond, time.Minute, true, func(ctx context.Context) (bool, error) {
		reqs := listRequests(t, ctx, cmCl, namespace)
		if len(reqs) > 1 {
			return false, fmt.Errorf("expected at most one CertificateRequest, got %d", len(reqs))
		}
		if len(reqs) == 1 && match(&reqs[0]) {
			found = &reqs[0]
			return true, nil
		}
		return false, nil
	}))
	return found
}

func csrPublicKeysEqual(t *testing.T, a, b *cmapi.CertificateRequest) bool {
	t.Helper()
	csrA, err := utilpki.DecodeX509CertificateRequestBytes(a.Spec.Request)
	require.NoError(t, err)
	csrB, err := utilpki.DecodeX509CertificateRequestBytes(b.Spec.Request)
	require.NoError(t, err)
	equal, err := utilpki.PublicKeysEqual(csrA.PublicKey, csrB.PublicKey)
	require.NoError(t, err)
	return equal
}

// signRequest completes a CertificateRequest the way a working issuer would:
// self-signed with the key the CSR was built from, so the issued certificate's
// public key matches the CSR.
func signRequest(t *testing.T, kubeClient kubernetes.Interface, cmCl cmclient.Interface, namespace, crtName string, req *cmapi.CertificateRequest) []byte {
	t.Helper()

	crt := mustGetCertificate(t, t.Context(), cmCl, namespace, crtName)
	require.NotNil(t, crt.Status.NextPrivateKeySecretName)
	secret, err := kubeClient.CoreV1().Secrets(namespace).Get(t.Context(), *crt.Status.NextPrivateKeySecretName, metav1.GetOptions{})
	require.NoError(t, err)
	sk, err := utilpki.DecodePrivateKeyBytes(secret.Data[corev1.TLSPrivateKeyKey])
	require.NoError(t, err)

	template, err := utilpki.CertificateTemplateFromCertificateRequest(req)
	require.NoError(t, err)
	certPEM, _, err := utilpki.SignCertificate(template, template, sk.Public(), sk)
	require.NoError(t, err)

	req = req.DeepCopy()
	req.Status.Certificate = certPEM
	req.Status.CA = certPEM
	apiutil.SetCertificateRequestCondition(req, cmapi.CertificateRequestConditionReady, cmmeta.ConditionTrue, cmapi.CertificateRequestReasonIssued, "")
	_, err = cmCl.CertmanagerV1().CertificateRequests(namespace).UpdateStatus(t.Context(), req, metav1.UpdateOptions{})
	require.NoError(t, err)

	return certPEM
}
