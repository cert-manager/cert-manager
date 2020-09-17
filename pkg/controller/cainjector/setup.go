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

package cainjector

import (
	"context"
	"fmt"
	"io/ioutil"

	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	admissionreg "k8s.io/api/admissionregistration/v1beta1"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	apireg "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1beta1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
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
func registerAllInjectors(ctx context.Context, name string, mgr ctrl.Manager, sources []caDataSource, ca cache.Cache) error {
	controllers := map[string]controller.Controller{}
	for _, setup := range injectorSetups {
		controller, err := Register(fmt.Sprintf("%s-injector-%s", name, setup.resourceName), mgr, setup, sources, ca)
		if err != nil {
			if !meta.IsNoMatchError(err) || !setup.injector.IsAlpha() {
				return err
			}
			ctrl.Log.V(logf.WarnLevel).Info("unable to register injector which is still in an alpha phase."+
				" Enable the feature on the API server in order to use this injector",
				"injector", setup.resourceName)
		}
		controllers[setup.resourceName] = controller
	}
	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() (err error) {
		defer func() {
			ctrl.Log.V(logf.TraceLevel).Error(err, "DEBUG: cache routine finished", "name", name)
		}()
		ctrl.Log.V(logf.TraceLevel).Info("DEBUG: cache routine starting", "name", name)
		if err = ca.Start(gctx.Done()); err != nil {
			return errors.WithStack(err)
		}
		return nil
	})
	if ca.WaitForCacheSync(gctx.Done()) {
		for resourceName, controller := range controllers {
			if gctx.Err() != nil {
				continue
			}
			resourceName := resourceName
			controller := controller
			g.Go(func() (err error) {
				defer func() {
					ctrl.Log.V(logf.TraceLevel).Error(err, "DEBUG: controller routine finished", "name", name, "resourceName", resourceName)
				}()
				ctrl.Log.V(logf.TraceLevel).Info("DEBUG: controller routine starting", "name", name, "resourceName", resourceName)
				return controller.Start(gctx.Done())
			})
		}
	}
	return g.Wait()
}

// Register registers an injection controller with the given manager, and adds relevant indicies.
func Register(name string, mgr ctrl.Manager, setup injectorSetup, sources []caDataSource, ca cache.Cache) (controller.Controller, error) {
	typ := setup.injector.NewTarget().AsObject()

	c, err := controller.NewUnmanaged(
		// XXX:  strings.ToLower(typ.GetObjectKind().GroupVersionKind().Kind),
		name,
		mgr,
		controller.Options{
			Reconciler: &genericInjectReconciler{
				Client:       mgr.GetClient(),
				sources:      sources,
				log:          ctrl.Log.WithName("inject-controller"),
				resourceName: setup.resourceName,
				injector:     setup.injector,
			},
			MaxConcurrentReconciles: 5,
		})
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if err := c.Watch(source.NewKindWithCache(typ, ca), &handler.EnqueueRequestForObject{}); err != nil {
		return nil, errors.WithStack(err)
	}

	for _, s := range sources {
		if err := s.ApplyTo(mgr, setup, c, ca); err != nil {
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
		fileData, err := ioutil.ReadFile(file)
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
	cacheOptions := cache.Options{
		Scheme: mgr.GetScheme(),
		Mapper: mgr.GetRESTMapper(),
	}
	ca, err := cache.New(mgr.GetConfig(), cacheOptions)
	if err != nil {
		return errors.WithStack(err)
	}
	return registerAllInjectors(
		ctx,
		"certificate",
		mgr,
		[]caDataSource{
			&certificateDataSource{client: ca},
		},
		ca,
	)
}

// RegisterSecretBased registers all known injection controllers that
// target Secret resources with the  given manager, and adds relevant
// indices.
// The registered controllers only require the corev1 APi to be available in
// order to run.
func RegisterSecretBased(ctx context.Context, mgr ctrl.Manager) error {
	cacheOptions := cache.Options{
		Scheme: mgr.GetScheme(),
		Mapper: mgr.GetRESTMapper(),
	}
	ca, err := cache.New(mgr.GetConfig(), cacheOptions)
	if err != nil {
		return errors.WithStack(err)
	}
	return registerAllInjectors(
		ctx,
		"secret",
		mgr,
		[]caDataSource{
			&secretDataSource{client: ca},
			&kubeconfigDataSource{},
		},
		ca,
	)
}
