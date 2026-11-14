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
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	"k8s.io/utils/clock"

	"github.com/cert-manager/cert-manager/integration-tests/framework"
	"github.com/cert-manager/cert-manager/internal/controller/certificates/policies"
	"github.com/cert-manager/cert-manager/internal/controller/feature"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	cminformers "github.com/cert-manager/cert-manager/pkg/client/informers/externalversions"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/keymanager"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/requestmanager"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/trigger"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/metrics"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

const replacementFinalizer = "example.com/holding-on"

// TestReplacementWaitsForFinalizer covers replacing a CertificateRequest that an
// external issuer has put a finalizer on. The delete is accepted but leaves the
// object in place, and with stable names the replacement is created under the
// name it still holds, so the create is rejected for as long as the issuer
// holds on.
//
// The reconcile's own result is what has to be asserted on. The rejected create
// leaves exactly one request either way, so counting objects does not separate
// the two behaviours.
func TestReplacementWaitsForFinalizer(t *testing.T) {
	// Each of these reaches the create through a different one of the request
	// manager's deletes, and the name the replacement needs is the same in both.
	t.Run("MismatchedSpec", func(t *testing.T) {
		testReplacementWaitsForFinalizer(t, "mismatched-spec",
			func(t *testing.T, cmCl cmclient.Interface, namespace, crtName string, req *cmapi.CertificateRequest) {
				crt := mustGetCertificate(t, t.Context(), cmCl, namespace, crtName)
				crt.Spec.DNSNames = []string{"replaced.example.com"}
				_, err := cmCl.CertmanagerV1().Certificates(namespace).Update(t.Context(), crt, metav1.UpdateOptions{})
				require.NoError(t, err)
			})
	})

	t.Run("FailedInPreviousIssuance", func(t *testing.T) {
		testReplacementWaitsForFinalizer(t, "failed-request",
			func(t *testing.T, cmCl cmclient.Interface, namespace, crtName string, req *cmapi.CertificateRequest) {
				crt := mustGetCertificate(t, t.Context(), cmCl, namespace, crtName)
				issuing := apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionIssuing)
				require.NotNil(t, issuing)
				require.NotNil(t, issuing.LastTransitionTime)

				// Both of the checks ahead of the failed-request branch have to
				// keep this request, or the delete under test is not the one
				// that runs. The spec is unchanged here, and no issuance has
				// ended, so the keymanager has not rotated the key either.
				violations, err := utilpki.RequestMatchesSpec(req, crt.Spec)
				require.NoError(t, err)
				require.Empty(t, violations, "the request must still match the Certificate's spec")
				require.NotNil(t, crt.Status.NextPrivateKeySecretName)
				require.Equal(t, *crt.Status.NextPrivateKeySecretName, req.Annotations[cmapi.CertificateRequestPrivateKeyAnnotationKey],
					"the request must still be for the current next private key")

				// Dated before the Issuing transition, which is what marks the
				// failure as belonging to the previous issuance of this revision.
				req = req.DeepCopy()
				req.Status.FailureTime = new(metav1.NewTime(issuing.LastTransitionTime.Add(-time.Minute)))
				apiutil.SetCertificateRequestCondition(req, cmapi.CertificateRequestConditionReady, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, "testing")
				_, err = cmCl.CertmanagerV1().CertificateRequests(namespace).UpdateStatus(t.Context(), req, metav1.UpdateOptions{})
				require.NoError(t, err)
			})
	})
}

func testReplacementWaitsForFinalizer(t *testing.T, caseName string, provokeDelete func(*testing.T, cmclient.Interface, string, string, *cmapi.CertificateRequest)) {
	const secretName = "held-tls"
	namespace := "test-replacement-finalizer-" + caseName
	crtName := "held"

	// The collision only exists under stable names; without them the
	// replacement is created under a generated one and never collides.
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, feature.StableCertificateRequestName, true)

	config, stopFn := framework.RunControlPlane(t)
	t.Cleanup(stopFn)

	kubeClient, factory, cmCl, cmFactory, scheme := framework.NewClients(t, config)

	newContext := func(name string) *controllerpkg.Context {
		return &controllerpkg.Context{
			Scheme:                    scheme,
			Client:                    kubeClient,
			KubeSharedInformerFactory: factory,
			CMClient:                  cmCl,
			SharedInformerFactory:     cmFactory,
			Clock:                     clock.RealClock{},
			Recorder:                  framework.NewEventRecorder(t, scheme),
			FieldManager:              "cert-manager-certificates-" + name + "-test",
		}
	}

	var errMu sync.Mutex
	var reqManagerErrs []string
	var recording atomic.Bool

	// recordErrors keeps what a reconcile returns, once recording is on. Whether
	// a reconcile counts is decided as it starts, so one left over from setting
	// the Certificate up cannot reach the assertions by finishing late.
	recordErrors := func(processItem func(context.Context, types.NamespacedName) error) func(context.Context, types.NamespacedName) error {
		return func(ctx context.Context, key types.NamespacedName) error {
			record := recording.Load()
			err := processItem(ctx, key)
			if err != nil && record {
				errMu.Lock()
				reqManagerErrs = append(reqManagerErrs, err.Error())
				errMu.Unlock()
			}
			return err
		}
	}

	newController := func(name string, processItem func(context.Context, types.NamespacedName) error, queue workqueue.TypedRateLimitingInterface[types.NamespacedName], mustSync []cache.InformerSynced, err error) controllerpkg.Interface {
		t.Helper()
		require.NoError(t, err)
		return controllerpkg.NewController(name, metrics.New(logf.Log, clock.RealClock{}), processItem, mustSync, nil, queue)
	}

	triggerCtx := newContext("trigger")
	triggerCtrl, triggerQueue, triggerSync, triggerErr := trigger.NewController(logf.Log, triggerCtx, policies.NewTriggerPolicyChain(clock.RealClock{}).Evaluate)
	keyCtx := newContext("key-manager")
	keyCtrl, keyQueue, keySync, keyErr := keymanager.NewController(logf.Log, keyCtx)
	reqCtx := newContext("request-manager")
	reqCtrl, reqQueue, reqSync, reqErr := requestmanager.NewController(logf.Log, reqCtx)

	stopControllers := framework.StartInformersAndControllers(t, factory, cmFactory,
		newController("trigger_test", triggerCtrl.ProcessItem, triggerQueue, triggerSync, triggerErr),
		newController("keymanager_test", keyCtrl.ProcessItem, keyQueue, keySync, keyErr),
		newController("requestmanager_test", recordErrors(reqCtrl.ProcessItem), reqQueue, reqSync, reqErr),
	)
	t.Cleanup(stopControllers)

	_, err := kubeClient.CoreV1().Namespaces().Create(t.Context(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespace},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	t.Log("creating the Certificate, which the trigger, keymanager and requestmanager controllers turn into a CertificateRequest")
	_, err = cmCl.CertmanagerV1().Certificates(namespace).Create(t.Context(), gen.Certificate(crtName,
		gen.SetCertificateNamespace(namespace),
		gen.SetCertificateCommonName("held.example.com"),
		gen.SetCertificateSecretName(secretName),
		gen.SetCertificateIssuer(cmmeta.IssuerReference{Name: "testissuer", Kind: "Issuer", Group: "foo.io"}),
	), metav1.CreateOptions{})
	require.NoError(t, err)

	requestA := waitForSingleRequest(t, cmCl, namespace, func(*cmapi.CertificateRequest) bool { return true })

	t.Log("putting a finalizer on the CertificateRequest, as an external issuer does while it works on one")
	requestA.Finalizers = append(requestA.Finalizers, replacementFinalizer)
	requestA, err = cmCl.CertmanagerV1().CertificateRequests(namespace).Update(t.Context(), requestA, metav1.UpdateOptions{})
	require.NoError(t, err)

	waitForCachedRequest(t, cmFactory, namespace, requestA)
	recording.Store(true)

	t.Log("provoking the replacement")
	provokeDelete(t, cmCl, namespace, crtName, requestA)

	require.NoError(t, wait.PollUntilContextTimeout(t.Context(), 100*time.Millisecond, time.Minute, true, func(ctx context.Context) (bool, error) {
		reqs := listRequests(t, ctx, cmCl, namespace)
		return len(reqs) == 1 && reqs[0].UID == requestA.UID && reqs[0].DeletionTimestamp != nil, nil
	}), "the CertificateRequest was never deleted")

	t.Log("holding while the finalizer is in place, where the replacement cannot be created")
	holdWhile(t, func(ctx context.Context) {
		reqs := listRequests(t, ctx, cmCl, namespace)
		require.Len(t, reqs, 1)
		assert.Equal(t, requestA.UID, reqs[0].UID)

		errMu.Lock()
		defer errMu.Unlock()
		assert.Empty(t, reqManagerErrs, "the reconcile must wait for the finalizer rather than fail on the name it holds")
	})

	t.Log("removing the finalizer, so the name is released and the replacement takes it")
	held, err := cmCl.CertmanagerV1().CertificateRequests(namespace).Get(t.Context(), requestA.Name, metav1.GetOptions{})
	require.NoError(t, err)
	held.Finalizers = nil
	_, err = cmCl.CertmanagerV1().CertificateRequests(namespace).Update(t.Context(), held, metav1.UpdateOptions{})
	require.NoError(t, err)

	requestB := waitForSingleRequest(t, cmCl, namespace, func(req *cmapi.CertificateRequest) bool {
		return req.UID != requestA.UID
	})
	assert.Equal(t, requestA.Name, requestB.Name, "the replacement is expected to take the name the deleted request held")

	// The workqueue hands one key to one worker at a time, so every reconcile
	// that ran while the finalizer was held has finished by now. An error the
	// hold above was too short to see lands here.
	errMu.Lock()
	defer errMu.Unlock()
	assert.Empty(t, reqManagerErrs, "replacing the request must not have produced a sync error")
}

// waitForCachedRequest waits for the informer the request manager reads from to
// hold req with its finalizer. Under stable names the manager covers its own
// cache lag by letting the create fail, so an error it returns before this
// point is not a failure to wait for the finalizer.
func waitForCachedRequest(t *testing.T, cmFactory cminformers.SharedInformerFactory, namespace string, req *cmapi.CertificateRequest) {
	t.Helper()
	lister := cmFactory.Certmanager().V1().CertificateRequests().Lister().CertificateRequests(namespace)
	require.NoError(t, wait.PollUntilContextTimeout(t.Context(), 50*time.Millisecond, time.Minute, true, func(context.Context) (bool, error) {
		cached, err := lister.Get(req.Name)
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return cached.UID == req.UID && slices.Contains(cached.Finalizers, replacementFinalizer), nil
	}), "the request manager's cache never caught up with the CertificateRequest")
}
