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
	"net/http"
	"regexp"
	"sync/atomic"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/integration-tests/framework"
)

// TestFilteredSecretLister exercises, against a real apiserver, the Secret
// lister that a default install of cert-manager uses: the filtered Secret
// informer factory selected by the SecretsFilteredCaching feature gate (Beta,
// on by default; pkg/controller/context.go).
//
// framework.NewClients always builds the unfiltered base factory, so until
// now no integration test has exercised this lister, and the regression
// described in #9347 — a selector that matches unlabelled Secrets turning
// List into one live GET per Secret in the namespace — could only be caught
// by the end-to-end jobs. See #9346.
//
// Both caches start empty and are populated by the initial LIST, so the
// number of live requests a lister call makes is observable: each Secret the
// metadata cache returns costs exactly one GET against the apiserver
// (core_filteredsecrets.go, secretNamespaceLister.List).
func TestFilteredSecretLister(t *testing.T) {
	config, stopFn := framework.RunControlPlane(t)
	t.Cleanup(stopFn)

	kubeClient, factory, _, _, _ := framework.NewFilteredSecretsClients(t, config, "")

	namespace := "default"

	// labelled are cert-manager's own Secrets: they are held, in full, by the
	// typed cache.
	// unlabelled are Secrets cert-manager does not manage: they are held as
	// metadata-only objects by the metadata cache.
	labelled := []*corev1.Secret{
		secretForListerTest(namespace, "cm-one", map[string]string{
			cmapi.PartOfCertManagerControllerLabelKey: "true",
			cmapi.IsNextPrivateKeySecretLabelKey:      "true",
		}),
		secretForListerTest(namespace, "cm-two", map[string]string{
			cmapi.PartOfCertManagerControllerLabelKey: "true",
		}),
	}
	unlabelled := []*corev1.Secret{
		secretForListerTest(namespace, "other-one", nil),
		secretForListerTest(namespace, "other-two", map[string]string{"app": "not-cert-manager"}),
	}

	for _, s := range append(append([]*corev1.Secret{}, labelled...), unlabelled...) {
		_, err := kubeClient.CoreV1().Secrets(namespace).Create(t.Context(), s, metav1.CreateOptions{})
		require.NoError(t, err, "failed to create Secret %s", s.Name)
	}

	// Mirror how the controller wires the lister (pkg/controller/context.go):
	// Informer() installs the transform that strips labels from metadata-cache
	// objects; Lister() builds the lister over both caches. Both must be
	// requested from the factory before Start, or the informers will not run.
	secretsInformer := factory.Secrets()
	lister := secretsInformer.Lister()
	_ = secretsInformer.Informer()

	framework.WaitForFactoryCacheSync(t, factory)

	// isNextPrivateKeyLabelSelector is the selector the keymanager uses when
	// listing next-private-key Secrets (pkg/controller/certificates/keymanager).
	isNextPrivateKeyLabelSelector := labels.SelectorFromSet(labels.Set{cmapi.IsNextPrivateKeySecretLabelKey: "true"})
	faoSelector := labels.SelectorFromSet(labels.Set{cmapi.PartOfCertManagerControllerLabelKey: "true"})

	t.Run("List with the keymanager selector is served entirely from the cache", func(t *testing.T) {
		secrets, err := lister.Secrets(namespace).List(isNextPrivateKeyLabelSelector)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"cm-one"}, secretNamesForListerTest(secrets),
			"only the fao-labelled next-private-key Secret should be listed; unlabelled Secrets must be invisible to a label selector, and no live GET should be needed")
	})

	t.Run("List with a fao selector is served entirely from the cache", func(t *testing.T) {
		secrets, err := lister.Secrets(namespace).List(faoSelector)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"cm-one", "cm-two"}, secretNamesForListerTest(secrets))
	})

	t.Run("Get of a labelled Secret is served from the typed cache", func(t *testing.T) {
		secret, err := lister.Secrets(namespace).Get("cm-two")
		require.NoError(t, err)
		assert.Equal(t, "cm-two", secret.Name)
		// Data proves the object came from the typed cache rather than from
		// the apiserver or a metadata-only representation.
		assert.Equal(t, secretDataForListerTest, secret.Data[corev1.TLSPrivateKeyKey])
	})

	// TODO(#9347): the metadata cache strips labels from every Secret it
	// holds (partialMetadataRemoveAll), so any selector that matches an
	// empty label set — labels.Everything() being the canonical case — makes
	// List fall back to one live GET per unlabelled Secret in the namespace.
	// When #9347 changes that behaviour (for example by rejecting such
	// selectors or making them cheap), replace this subtest's loose
	// correctness-only assertion with a strict one on the new behaviour.
	t.Run("List with labels.Everything returns all Secrets but costs one live GET per unlabelled Secret", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping live-GET subtest in -short mode")
		}

		secrets, err := lister.Secrets(namespace).List(labels.Everything())
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"cm-one", "cm-two", "other-one", "other-two"}, secretNamesForListerTest(secrets),
			"the filtered lister must still return a correct result for labels.Everything(); how expensive that call is, is what #9347 tracks")
	})

	t.Run("Get of an unlabelled Secret falls back to a live GET", func(t *testing.T) {
		secret, err := lister.Secrets(namespace).Get("other-one")
		require.NoError(t, err)
		assert.Equal(t, "other-one", secret.Name)
		assert.Equal(t, secretDataForListerTest, secret.Data[corev1.TLSPrivateKeyKey])
	})

	t.Run("Get of a missing Secret returns NotFound", func(t *testing.T) {
		_, err := lister.Secrets(namespace).Get("does-not-exist")
		require.Error(t, err)
		assert.True(t, apierrors.IsNotFound(err), "expected a NotFound error, got %v", err)
	})
}

var secretDataForListerTest = []byte("tls key data")

func secretForListerTest(namespace, name string, lbls map[string]string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels:    lbls,
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: secretDataForListerTest,
		},
	}
}

func secretNamesForListerTest(secrets []*corev1.Secret) []string {
	names := make([]string, 0, len(secrets))
	for _, s := range secrets {
		names = append(names, s.Name)
	}
	return names
}

// TestFilteredSecretListerServesIssuanceChain reproduces the setup of
// TestGeneratesNewPrivateKeyPerRequest (same controllers, same issuance
// chain) but runs it against the filtered Secret informer factory that a
// default install uses, with unlabelled Secrets in the namespace as noise.
//
// This is the integration-test counterpart of the #9224 incident described
// in #9346: there, a widened keymanager selector was invisible to the suite
// because every test ran the unfiltered lister, and the failure only showed
// up in the end-to-end jobs. If a change to the keymanager or the lister
// again makes Secret LISTs expensive under SecretsFilteredCaching, this test
// is where it should surface first.
//
// Note that unlike the #9224 failure, this test passes today: the keymanager
// selector matches a label, so the lister serves it from the typed cache and
// issuance proceeds. Its purpose is to keep it that way.
func TestFilteredSecretListerServesIssuanceChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping issuance-chain test in -short mode")
	}

	config, stopFn := framework.RunControlPlane(t)
	t.Cleanup(stopFn)

	// Count live GETs of individual Secrets. Informer LIST and WATCH requests
	// target the collection path (/api/v1/namespaces/<ns>/secrets); only the
	// filtered lister's fallback fetches a single Secret by name, so the
	// counter isolates exactly the request pattern that #9347 describes.
	countingConfig := rest.CopyConfig(config)
	liveSecretGETs := &atomic.Int64{}
	countingConfig.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
		return &secretGetCountingRoundTripper{base: rt, counter: liveSecretGETs}
	}

	kubeClient, factory, cmCl, cmFactory, scheme := framework.NewFilteredSecretsClients(t, countingConfig, "")

	namespace := "default"

	// Noise: unlabelled Secrets held by the metadata cache. These are what a
	// widened keymanager selector would turn into one live GET per reconcile
	// (#9224, #9347).
	for _, name := range []string{"noise-one", "noise-two", "noise-three"} {
		_, err := kubeClient.CoreV1().Secrets(namespace).Create(t.Context(), secretForListerTest(namespace, name, nil), metav1.CreateOptions{})
		require.NoError(t, err, "failed to create Secret %s", name)
	}

	stopControllers := runAllControllersWithFactory(t, config, kubeClient, factory, cmCl, cmFactory, scheme)
	defer stopControllers()

	crt := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "filtered-lister-testcrt"},
		Spec: cmapi.CertificateSpec{
			SecretName: "filtered-lister-testsecret",
			DNSNames:   []string{"something"},
			IssuerRef:  cmmeta.IssuerReference{Name: "issuer"},
		},
	}
	_, err := cmCl.CertmanagerV1().Certificates(namespace).Create(t.Context(), crt, metav1.CreateOptions{})
	require.NoError(t, err, "failed to create certificate")

	// The keymanager lists next-private-key Secrets through the filtered
	// lister on every reconcile, and the requestmanager must create a
	// CertificateRequest. If a regression again makes that list expensive
	// (one live GET per noise Secret per reconcile), issuance stalls here
	// and this wait times out — exactly what the end-to-end jobs saw in
	// #9224, and what TestGeneratesNewPrivateKeyPerRequest could not see.
	if err := wait.PollUntilContextTimeout(t.Context(), 500*time.Millisecond, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		reqs, err := cmCl.CertmanagerV1().CertificateRequests(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}
		return len(reqs.Items) == 1, nil
	}); err != nil {
		t.Fatal("no CertificateRequest was created: the issuance chain did not progress under the filtered Secret lister")
	}

	// The whole chain above ran through the filtered Secret lister. With the
	// selectors as designed (matching a label), every Secret read is served
	// from a cache: zero live GETs of individual Secrets. If this fails, a
	// selector somewhere in the chain has started matching unlabelled
	// Secrets, and each of the noise Secrets costs one live GET per
	// reconcile — the exact regression class of #9224/#9347 that the
	// end-to-end jobs took twenty minutes to surface.
	assert.Equal(t, int64(0), liveSecretGETs.Load(),
		"the issuance chain made %d live GET(s) of individual Secrets; Secret reads should be served from the filtered caches (#9347)", liveSecretGETs.Load())
}

// singleSecretPathRE matches GET requests for one Secret by name, e.g.
// /api/v1/namespaces/default/secrets/noise-one. The collection path
// (.../secrets or .../secrets?...) used by informer LIST/WATCH does not
// match: the segment after "secrets" is absent or a query string.
var singleSecretPathRE = regexp.MustCompile(`^/api/v1/namespaces/[^/]+/secrets/[^/?]+$`)

// secretGetCountingRoundTripper counts GET requests that fetch a single
// Secret by name. The filtered Secret lister issues exactly this request
// shape when it falls back to the apiserver for Secrets held in the
// metadata-only cache (internal/informers/core_filteredsecrets.go).
type secretGetCountingRoundTripper struct {
	base    http.RoundTripper
	counter *atomic.Int64
}

func (rt *secretGetCountingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodGet && singleSecretPathRE.MatchString(req.URL.Path) {
		rt.counter.Add(1)
	}
	return rt.base.RoundTrip(req)
}
