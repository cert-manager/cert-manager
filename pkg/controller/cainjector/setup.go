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
	"io/ioutil"

	admissionreg "k8s.io/api/admissionregistration/v1beta1"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	apireg "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1beta1"
	ctrl "sigs.k8s.io/controller-runtime"
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

// Register registers an injection controller with the given manager, and adds relevant indicies.
func Register(mgr ctrl.Manager, setup injectorSetup, sources ...caDataSource) error {
	typ := setup.injector.NewTarget().AsObject()
	builder := ctrl.NewControllerManagedBy(mgr).For(typ)
	for _, s := range sources {
		if err := s.ApplyTo(mgr, setup, builder); err != nil {
			return err
		}
	}

	return builder.Complete(&genericInjectReconciler{
		Client:       mgr.GetClient(),
		sources:      sources,
		log:          ctrl.Log.WithName("inject-controller"),
		resourceName: setup.resourceName,
		injector:     setup.injector,
	})
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
func RegisterCertificateBased(mgr ctrl.Manager) error {
	sources := []caDataSource{
		&certificateDataSource{client: mgr.GetClient()},
	}
	for _, setup := range injectorSetups {
		if err := Register(mgr, setup, sources...); err != nil {
			return err
		}
	}

	return nil
}

// RegisterSecretBased registers all known injection controllers that
// target Secret resources with the  given manager, and adds relevant
// indices.
// The registered controllers only require the corev1 APi to be available in
// order to run.
func RegisterSecretBased(mgr ctrl.Manager) error {
	sources := []caDataSource{
		&secretDataSource{client: mgr.GetClient()},
		&kubeconfigDataSource{},
	}
	for _, setup := range injectorSetups {
		if err := Register(mgr, setup, sources...); err != nil {
			return err
		}
	}

	return nil
}
