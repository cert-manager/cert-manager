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

	admissionreg "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apireg "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// injectorSet describes a particular setup of the injector controller
type injectorSetup struct {
	resourceName string
	injector     CertInjector
	listType     runtime.Object
	objType      client.Object
}

var (
	MutatingWebhookSetup = injectorSetup{
		resourceName: "mutatingwebhookconfiguration",
		injector:     mutatingWebhookInjector{},
		listType:     &admissionreg.MutatingWebhookConfigurationList{},
		objType:      &admissionreg.MutatingWebhookConfiguration{},
	}

	ValidatingWebhookSetup = injectorSetup{
		resourceName: "validatingwebhookconfiguration",
		injector:     validatingWebhookInjector{},
		listType:     &admissionreg.ValidatingWebhookConfigurationList{},
		objType:      &admissionreg.ValidatingWebhookConfiguration{},
	}

	APIServiceSetup = injectorSetup{
		resourceName: "apiservice",
		injector:     apiServiceInjector{},
		listType:     &apireg.APIServiceList{},
		objType:      &apireg.APIService{},
	}

	CRDSetup = injectorSetup{
		resourceName: "customresourcedefinition",
		injector:     crdConversionInjector{},
		listType:     &apiext.CustomResourceDefinitionList{},
		objType:      &apiext.CustomResourceDefinition{},
	}

	injectorSetups = []injectorSetup{MutatingWebhookSetup, ValidatingWebhookSetup, APIServiceSetup, CRDSetup}
)

// registerAllInjectors registers all injectors and based on the
// graduation state of the injector decides how to log no kind/resource match errors
func RegisterAllInjectors(ctx context.Context, mgr ctrl.Manager, namespace string) error {
	// TODO: refactor
	sds := &secretDataSource{
		client: mgr.GetClient(),
	}
	cds := &certificateDataSource{
		client: mgr.GetClient(),
	}
	cfg := mgr.GetConfig()
	caBundle, err := dataFromSliceOrFile(cfg.CAData, cfg.CAFile)
	if err != nil {
		return err
	}
	kds := &kubeconfigDataSource{
		apiserverCABundle: caBundle,
	}
	// Registers a c/r controller for each of APIService, CustomResourceDefinition, Mutating/ValidatingWebhookConfiguration
	// TODO: add a flag to allow users to configure which of these controllers should be registered
	for _, setup := range injectorSetups {
		log := ctrl.Log.WithName(setup.objType.GetName())
		log.Info("Registering new controller")
		r := &genericInjectReconciler{
			injector:  setup.injector,
			namespace: namespace,
			log:       log,
			Client:    mgr.GetClient(),
			// TODO: refactor
			sources: []caDataSource{
				sds,
				cds,
				kds,
			},
		}

		// This code does some magic to make it possible to filter
		// injectables by whether they have the annotations we're
		// interested in when determining whether to trigger reconcilers
		secretTyp := setup.injector.NewTarget().AsObject()
		if err := mgr.GetFieldIndexer().IndexField(ctx, secretTyp, injectFromSecretPath, injectableCAFromSecretIndexer); err != nil {
			err := fmt.Errorf("error making injectable indexable by inject-ca-from-secret annotation: %w", err)
			return err
		}

		certTyp := setup.injector.NewTarget().AsObject()
		if err := mgr.GetFieldIndexer().IndexField(ctx, certTyp, injectFromPath, injectableCAFromIndexer); err != nil {
			err := fmt.Errorf("error making injectable indexable by inject-ca-from path: %w", err)
			return err
		}

		if err := ctrl.NewControllerManagedBy(mgr).
			For(setup.objType).
			Watches(&source.Kind{Type: new(corev1.Secret)}, handler.EnqueueRequestsFromMapFunc((&secretForInjectableMapper{
				Client:             mgr.GetClient(),
				log:                log,
				secretToInjectable: buildSecretToInjectableFunc(setup.listType, setup.resourceName),
			}).Map)).
			Watches(&source.Kind{Type: new(corev1.Secret)}, handler.EnqueueRequestsFromMapFunc((&secretForCertificateMapper{
				Client:                  mgr.GetClient(),
				log:                     log,
				certificateToInjectable: buildCertToInjectableFunc(setup.listType, setup.resourceName),
			}).Map)).
			// TODO: make this bit optional
			Watches(&source.Kind{Type: new(cmapi.Certificate)},
				handler.EnqueueRequestsFromMapFunc((&certMapper{
					Client:       mgr.GetClient(),
					log:          log,
					toInjectable: buildCertToInjectableFunc(setup.listType, setup.resourceName),
				}).Map)).
			Complete(r); err != nil {
			err = fmt.Errorf("error registering controller for %s: %w", setup.objType.GetName(), err)
			return err
		}
	}
	return nil
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
