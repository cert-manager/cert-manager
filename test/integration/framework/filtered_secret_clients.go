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

package framework

import (
	"context"
	"testing"
	"time"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	certmgrscheme "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/scheme"
	cminformers "github.com/cert-manager/cert-manager/pkg/client/informers/externalversions"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
	apireg "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	gwapi "sigs.k8s.io/gateway-api/apis/v1"
)

// NewFilteredSecretsClients is like NewClients, but the returned
// KubeInformerFactory is the filtered Secret informer factory used by a
// default install of cert-manager: the one selected by the
// SecretsFilteredCaching feature gate (Beta, enabled by default) in
// pkg/controller/context.go.
//
// NewClients, by contrast, always builds the unfiltered base factory, so
// integration tests that use it never exercise the Secret lister that a
// default install uses (see #9346).
//
// The namespace argument mirrors the controller --namespace flag: pass ""
// for the default all-namespaces scope.
func NewFilteredSecretsClients(t *testing.T, config *rest.Config, namespace string) (kubernetes.Interface, internalinformers.KubeInformerFactory, cmclient.Interface, cminformers.SharedInformerFactory, *runtime.Scheme) {
	httpClient, err := rest.HTTPClientFor(config)
	if err != nil {
		t.Fatal(err)
	}

	cl, err := kubernetes.NewForConfigAndClient(config, httpClient)
	if err != nil {
		t.Fatal(err)
	}

	metadataCl, err := metadata.NewForConfigAndClient(config, httpClient)
	if err != nil {
		t.Fatal(err)
	}

	// Matches pkg/controller/context.go, which passes the controller root
	// context to NewFilteredSecretsKubeInformerFactory; the filtered Secret
	// lister uses it for live GETs of Secrets that are only present in the
	// metadata cache.
	factory := internalinformers.NewFilteredSecretsKubeInformerFactory(t.Context(), cl, metadataCl, 0, namespace)

	cmCl, err := cmclient.NewForConfigAndClient(config, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	cmFactory := cminformers.NewSharedInformerFactory(cmCl, 0)

	scheme := runtime.NewScheme()
	utilruntime.Must(kscheme.AddToScheme(scheme))
	utilruntime.Must(certmgrscheme.AddToScheme(scheme))
	utilruntime.Must(apiext.AddToScheme(scheme))
	utilruntime.Must(apireg.AddToScheme(scheme))
	utilruntime.Must(gwapi.Install(scheme))

	return cl, factory, cmCl, cmFactory, scheme
}

// WaitForFactoryCacheSync starts the given KubeInformerFactory and blocks
// until all of its informers have synced, failing the test otherwise.
//
// Callers must obtain every informer and lister they intend to use from the
// factory before calling this function: client-go only runs informers that
// have been requested from the factory.
func WaitForFactoryCacheSync(t *testing.T, factory internalinformers.KubeInformerFactory) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	t.Cleanup(cancel)

	factory.Start(ctx.Done())

	started := factory.WaitForCacheSync(ctx.Done())
	if err := ctx.Err(); err != nil {
		for name, synced := range started {
			t.Logf("informer %q synced: %t", name, synced)
		}
		t.Fatalf("failed to wait for factory caches to sync: %v", err)
	}
}
