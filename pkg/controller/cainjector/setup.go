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
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util"
)

// this file contains the logic to set up the different reconcile loops run by cainjector
// each reconciler corresponds to a type of injectable

const (
	MutatingWebhookConfigurationName   = "mutatingwebhookconfiguration"
	ValidatingWebhookConfigurationName = "validatingwebhookconfiguration"
	APIServiceName                     = "apiservice"
	CustomResourceDefinitionName       = "customresourcedefinition"
)

// setup is setup for a reconciler for a particular injectable type
type setup struct {
	resourceName string
	// newInjectableTarget knows how to create an InjectableTarget for a particular injectable type
	newInjectableTarget NewInjectableTarget
	listType            runtime.Object
	objType             client.Object
}

type SetupOptions struct {
	Namespace                    string
	EnableCertificatesDataSource bool
	EnabledReconcilersFor        map[string]bool
}

var (
	MutatingWebhookSetup = setup{
		resourceName:        "mutatingwebhookconfiguration",
		newInjectableTarget: newMutatingWebhookInjectable,
		listType:            &admissionreg.MutatingWebhookConfigurationList{},
		objType:             &admissionreg.MutatingWebhookConfiguration{},
	}

	ValidatingWebhookSetup = setup{
		resourceName:        "validatingwebhookconfiguration",
		newInjectableTarget: newValidatingWebhookInjectable,
		listType:            &admissionreg.ValidatingWebhookConfigurationList{},
		objType:             &admissionreg.ValidatingWebhookConfiguration{},
	}

	APIServiceSetup = setup{
		resourceName:        "apiservice",
		newInjectableTarget: newAPIServiceInjectable,
		listType:            &apireg.APIServiceList{},
		objType:             &apireg.APIService{},
	}

	CRDSetup = setup{
		resourceName:        "customresourcedefinition",
		newInjectableTarget: newCRDConversionInjectable,
		listType:            &apiext.CustomResourceDefinitionList{},
		objType:             &apiext.CustomResourceDefinition{},
	}
)

// RegisterAllInjectors sets up watches for all injectable and injector types that cainjector should watch
func RegisterAllInjectors(ctx context.Context, mgr ctrl.Manager, opts SetupOptions) error {
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
	injectorSetups := []setup{MutatingWebhookSetup, ValidatingWebhookSetup, APIServiceSetup, CRDSetup}
	// Registers a c/r controller for each of APIService, CustomResourceDefinition, Mutating/ValidatingWebhookConfiguration
	for _, setup := range injectorSetups {
		log := ctrl.Log.WithValues("kind", setup.resourceName)
		if !opts.EnabledReconcilersFor[setup.resourceName] {
			log.Info("Not registering a reconcile for injectable kind as it's disabled")
			continue
		}
		log.Info("Registering a reconciler for injectable")
		r := &reconciler{
			namespace:           opts.Namespace,
			resourceName:        setup.resourceName,
			newInjectableTarget: setup.newInjectableTarget,
			log:                 log,
			Client:              mgr.GetClient(),
			// TODO: refactor
			sources: []caDataSource{
				sds,
				cds,
				kds,
			},
			fieldManager: util.PrefixFromUserAgent(mgr.GetConfig().UserAgent),
		}

		// Index injectable with a new field. If the injectable's CA is
		// to be sourced from a Secret, the field's value will be the
		// namespaced name of the Secret.
		// This field can then be used as a field selector when listing injectables of this type.
		secretTyp := setup.newInjectableTarget().AsObject()
		if err := mgr.GetFieldIndexer().IndexField(ctx, secretTyp, injectFromSecretPath, injectableCAFromSecretIndexer); err != nil {
			err := fmt.Errorf("error making injectable indexable by inject-ca-from-secret annotation: %w", err)
			return err
		}
		predicates := predicate.Funcs{
			UpdateFunc: func(e event.UpdateEvent) bool {
				return hasInjectableAnnotation(e.ObjectNew)
			},
			CreateFunc: func(e event.CreateEvent) bool {
				return hasInjectableAnnotation(e.Object)
			},
			DeleteFunc: func(e event.DeleteEvent) bool {
				return hasInjectableAnnotation(e.Object)
			},
		}

		b := ctrl.NewControllerManagedBy(mgr).
			For(setup.objType,
				// We watch all CRDs,
				// Validating/MutatingWebhookConfigurations,
				// APIServices because the only way how to tell
				// if an object is an injectable is from
				// annotation value and this cannot be used to
				// filter List/Watch. The earliest point where
				// we can use the annotation to filter
				// injectables is here where we define which
				// objects' events should trigger a reconcile.
				builder.WithPredicates(predicates)).
			Watches(new(corev1.Secret), handler.EnqueueRequestsFromMapFunc(secretForInjectableMapFuncBuilder(mgr.GetClient(), log, setup)))
		if opts.EnableCertificatesDataSource {
			// Index injectable with a new field. If the injectable's CA is
			// to be sourced from a Certificate's Secret, the field's value will be the
			// namespaced name of the Certificate.
			// This field can then be used as a field selector when listing injectables of this type.
			certTyp := setup.newInjectableTarget().AsObject()
			if err := mgr.GetFieldIndexer().IndexField(ctx, certTyp, injectFromPath, injectableCAFromIndexer); err != nil {
				err := fmt.Errorf("error making injectable indexable by inject-ca-from path: %w", err)
				return err
			}
			b.Watches(new(corev1.Secret), handler.EnqueueRequestsFromMapFunc(
				certFromSecretToInjectableMapFuncBuilder(mgr.GetClient(), log, setup))).
				Watches(new(cmapi.Certificate),
					handler.EnqueueRequestsFromMapFunc(certToInjectableMapFuncBuilder(mgr.GetClient(), log, setup)))
		}
		if err := b.Complete(r); err != nil {
			return fmt.Errorf("error registering controller for %s: %w", setup.objType.GetName(), err)
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
