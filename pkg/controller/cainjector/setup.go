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
	admissionreg "k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	apireg "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	certmanager "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
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

	injectorSetups  = []injectorSetup{MutatingWebhookSetup, ValidatingWebhookSetup, APIServiceSetup}
	ControllerNames []string
)

// Register registers an injection controller with the given manager, and adds relevant indicies.
func Register(mgr ctrl.Manager, setup injectorSetup) error {
	typ := setup.injector.NewTarget().AsObject()
	if err := mgr.GetFieldIndexer().IndexField(typ, injectFromPath, injectableIndexer); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(typ).
		Watches(&source.Kind{Type: &certmanager.Certificate{}},
			&handler.EnqueueRequestsFromMapFunc{ToRequests: &certMapper{
				Client:       mgr.GetClient(),
				log:          ctrl.Log.WithName("cert-mapper"),
				toInjectable: certToInjectableFunc(setup.listType, setup.resourceName),
			}}).
		Watches(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestsFromMapFunc{
			ToRequests: &secretMapper{
				Client:       mgr.GetClient(),
				log:          ctrl.Log.WithName("secret-mapper"),
				toInjectable: certToInjectableFunc(setup.listType, setup.resourceName),
			}}).
		Complete(&genericInjectReconciler{
			Client:       mgr.GetClient(),
			log:          ctrl.Log.WithName("inject-controller"),
			resourceName: setup.resourceName,
			injector:     setup.injector,
		})
}

// RegisterALL registers all known injection controllers with the given manager, and adds relevant indicides.
func RegisterAll(mgr ctrl.Manager) error {
	for _, setup := range injectorSetups {
		if err := Register(mgr, setup); err != nil {
			return err
		}
	}

	return nil
}
