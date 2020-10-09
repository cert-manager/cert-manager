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
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	apireg "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1beta1"
)

// this contains implementations of CertInjector (and dependents)
// for various older Kubernetes types that contain CA bundles.
// this file should be deleted once the minimum supported version is Kubernetes 1.16

// mutatingWebhookv1beta1Injector knows how to create an InjectTarget a MutatingWebhookConfiguration v1beta1.
type mutatingWebhookv1beta1Injector struct{}

func (i mutatingWebhookv1beta1Injector) IsAlpha() bool {
	return false
}

func (i mutatingWebhookv1beta1Injector) NewTarget() InjectTarget {
	return &mutatingWebhookv1beta1Target{}
}

// mutatingWebhookTarget knows how to set CA data for all the webhooks
// in a mutatingWebhookConfiguration.
type mutatingWebhookv1beta1Target struct {
	obj admissionreg.MutatingWebhookConfiguration
}

func (t *mutatingWebhookv1beta1Target) AsObject() runtime.Object {
	return &t.obj
}
func (t *mutatingWebhookv1beta1Target) SetCA(data []byte) {
	for ind := range t.obj.Webhooks {
		t.obj.Webhooks[ind].ClientConfig.CABundle = data
	}
}

// validatingWebhookv1beta1Injector knows how to create an InjectTarget a ValidatingWebhookConfiguration.
type validatingWebhookv1beta1Injector struct{}

func (i validatingWebhookv1beta1Injector) NewTarget() InjectTarget {
	return &validatingWebhookv1beta1Target{}
}

func (i validatingWebhookv1beta1Injector) IsAlpha() bool {
	return false
}

// validatingWebhookv1beta1Target knows how to set CA data for all the webhooks
// in a validatingWebhookv1beta1Configuration.
type validatingWebhookv1beta1Target struct {
	obj admissionreg.ValidatingWebhookConfiguration
}

func (t *validatingWebhookv1beta1Target) AsObject() runtime.Object {
	return &t.obj
}

func (t *validatingWebhookv1beta1Target) SetCA(data []byte) {
	for ind := range t.obj.Webhooks {
		t.obj.Webhooks[ind].ClientConfig.CABundle = data
	}
}

// apiServicev1beta1Injector knows how to create an InjectTarget for APICAReferences
type apiServicev1beta1Injector struct{}

func (i apiServicev1beta1Injector) NewTarget() InjectTarget {
	return &apiServicev1beta1Target{}
}

func (i apiServicev1beta1Injector) IsAlpha() bool {
	return false
}

// apiServicev1beta1Target knows how to set CA data for the CA bundle in
// the APIService.
type apiServicev1beta1Target struct {
	obj apireg.APIService
}

func (t *apiServicev1beta1Target) AsObject() runtime.Object {
	return &t.obj
}

func (t *apiServicev1beta1Target) SetCA(data []byte) {
	t.obj.Spec.CABundle = data
}

// crdConversionv1beta1Injector knows how to create an InjectTarget for CRD conversion webhooks
type crdConversionv1beta1Injector struct{}

func (i crdConversionv1beta1Injector) NewTarget() InjectTarget {
	return &crdConversionv1beta1Target{}
}

func (i crdConversionv1beta1Injector) IsAlpha() bool {
	return false
}

// crdConversionv1beta1Target knows how to set CA data for the conversion webhook in CRDs
type crdConversionv1beta1Target struct {
	obj apiext.CustomResourceDefinition
}

func (t *crdConversionv1beta1Target) AsObject() runtime.Object {
	return &t.obj
}

func (t *crdConversionv1beta1Target) SetCA(data []byte) {
	if t.obj.Spec.Conversion == nil || t.obj.Spec.Conversion.Strategy != apiext.WebhookConverter {
		return
	}
	if t.obj.Spec.Conversion.WebhookClientConfig == nil {
		t.obj.Spec.Conversion.WebhookClientConfig = &apiext.WebhookClientConfig{}
	}
	t.obj.Spec.Conversion.WebhookClientConfig.CABundle = data
}
