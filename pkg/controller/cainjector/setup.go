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

package cainjector

import (
	"context"
	"fmt"
	"os"

	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/go-logr/logr"
	"golang.org/x/sync/errgroup"
	admissionreg "k8s.io/api/admissionregistration/v1"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	apireg "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// injectorSet describes a particular setup of the injector controller
type injectorSetup struct {
	resourceName string
	injector     CertInjector
	listType     runtime.Object
}

var (
	MutatingWebhookSetup = injectorSetup{
		resourceName: "mutatingwebhookconfiguration",
		injector:     mutatingWebhookInjector{},
		listType:     &admissionreg.MutatingWebhookConfigurationList{},
	}

	ValidatingWebhookSetup = injectorSetup{
		resourceName: "validatingwebhookconfiguration",
		injector:     validatingWebhookInjector{},
		listType:     &admissionreg.ValidatingWebhookConfigurationList{},
	}

	APIServiceSetup = injectorSetup{
		resourceName: "apiservice",
		injector:     apiServiceInjector{},
		listType:     &apireg.APIServiceList{},
	}

	CRDSetup = injectorSetup{
		resourceName: "customresourcedefinition",
		injector:     crdConversionInjector{},
		listType:     &apiext.CustomResourceDefinitionList{},
	}

	injectorSetups  = []injectorSetup{MutatingWebhookSetup, ValidatingWebhookSetup, APIServiceSetup, CRDSetup}
	ControllerNames []string
)

// registerAllInjectors registers all injectors and based on the
// graduation state of the injector decides how to log no kind/resource match errors
func registerAllInjectors(ctx context.Context, groupName string, mgr ctrl.Manager, sources []caDataSource, client client.Client, ca cache.Cache) error {
	controllers := make([]controller.Controller, len(injectorSetups))
	for i, setup := range injectorSetups {
		controller, err := newGenericInjectionController(ctx, groupName, mgr, setup, sources, ca, client)
		if err != nil {
			if !meta.IsNoMatchError(err) || !setup.injector.IsAlpha() {
				return err
			}
			ctrl.Log.V(logf.WarnLevel).Info("unable to register injector which is still in an alpha phase."+
				" Enable the feature on the API server in order to use this injector",
				"injector", setup.resourceName)
		}
		controllers[i] = controller
	}
	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() (err error) {
		if err = ca.Start(gctx); err != nil {
			return err
		}
		return nil
	})
	if ca.WaitForCacheSync(gctx) {
		for _, controller := range controllers {
			if gctx.Err() != nil {
				break
			}
			controller := controller
			g.Go(func() (err error) {
				return controller.Start(gctx)
			})
		}
	} else {
		// I assume that if the cache sync fails, then the already-started cache
		// will exit with a meaningful error which will be returned by the errgroup
		ctrl.Log.Error(nil, "timed out or failed while waiting for cache")
	}
	return g.Wait()
}

// newGenericInjectionController creates a controller and adds relevant watches
// and indexers to the supplied cache.
// TODO: We can't use the controller-runtime controller.Builder mechanism here
// because it doesn't allow us to specify the cache to which we link watches,
// indexes and event sources. Keep checking new controller-runtime releases for
// improvements which might make this easier:
// * https://github.com/kubernetes-sigs/controller-runtime/issues/764
func newGenericInjectionController(ctx context.Context, groupName string, mgr ctrl.Manager,
	setup injectorSetup, sources []caDataSource, ca cache.Cache,
	client client.Client) (controller.Controller, error) {
	log := ctrl.Log.WithName(groupName).WithName(setup.resourceName)
	typ := setup.injector.NewTarget().AsObject()

	c, err := controller.NewUnmanaged(
		fmt.Sprintf("controller-for-%s-%s", groupName, setup.resourceName),
		mgr,
		controller.Options{
			Reconciler: &genericInjectReconciler{
				Client:       client,
				sources:      sources,
				log:          log.WithName("generic-inject-reconciler"),
				resourceName: setup.resourceName,
				injector:     setup.injector,
			},
			LogConstructor: func(request *reconcile.Request) logr.Logger { return log },
		})
	if err != nil {
		return nil, err
	}
	if err := c.Watch(source.NewKindWithCache(typ, ca), &handler.EnqueueRequestForObject{}); err != nil {
		return nil, err
	}

	for _, s := range sources {
		if err := s.ApplyTo(ctx, mgr, setup, c, ca); err != nil {
			return nil, err
		}
	}

	return c, nil
}

// dataFromSliceOrFile returns data from the slice (if non-empty), or from the file,
// or an error if an error occurred reading the file
func dataFromSliceOrFile(data []byte, file string) ([]byte, error) {
	if len(data) > 0 {
		return data, nil
	}
	if len(file) > 0 {
		fileData, err := os.ReadFile(file)
		if err != nil {
			return []byte{}, err
		}
		return fileData, nil
	}
	return nil, nil
}

// RegisterCertificateBased registers all known injection controllers that
// target Certificate resources with the  given manager, and adds relevant
// indices.
// The registered controllers require the cert-manager API to be available
// in order to run.
func RegisterCertificateBased(ctx context.Context, mgr ctrl.Manager) error {
	cache, client, err := newIndependentCacheAndDelegatingClient(mgr)
	if err != nil {
		return err
	}
	return registerAllInjectors(
		ctx,
		"certificate",
		mgr,
		[]caDataSource{
			&certificateDataSource{client: cache},
		},
		client,
		cache,
	)
}

// RegisterSecretBased registers all known injection controllers that
// target Secret resources with the  given manager, and adds relevant
// indices.
// The registered controllers only require the corev1 APi to be available in
// order to run.
func RegisterSecretBased(ctx context.Context, mgr ctrl.Manager) error {
	cache, client, err := newIndependentCacheAndDelegatingClient(mgr)
	if err != nil {
		return err
	}
	return registerAllInjectors(
		ctx,
		"secret",
		mgr,
		[]caDataSource{
			&secretDataSource{client: cache},
			&kubeconfigDataSource{},
		},
		client,
		cache,
	)
}

// newIndependentCacheAndDelegatingClient creates a cache and a delegating
// client which are independent of the cache of the manager.
// This allows us to start the manager and secrets based injectors before the
// cert-manager Certificates CRDs have been installed and before the CA bundles
// have been injected into the cert-manager CRDs, by the secrets based injector,
// which is running in a separate goroutine.
func newIndependentCacheAndDelegatingClient(mgr ctrl.Manager) (cache.Cache, client.Client, error) {
	cacheOptions := cache.Options{
		Scheme: mgr.GetScheme(),
		Mapper: mgr.GetRESTMapper(),
	}
	ca, err := cache.New(mgr.GetConfig(), cacheOptions)
	if err != nil {
		return nil, nil, err
	}

	clientOptions := client.Options{
		Scheme: mgr.GetScheme(),
		Mapper: mgr.GetRESTMapper(),
	}

	client, err := cluster.DefaultNewClient(ca, mgr.GetConfig(), clientOptions)
	if err != nil {
		return nil, nil, err
	}
	return ca, client, nil
}
