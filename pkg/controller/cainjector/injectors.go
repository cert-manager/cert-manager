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
	admissionreg "k8s.io/api/admissionregistration/v1"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apireg "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// this contains implementations of CertInjector (and dependents)
// for various Kubernetes types that contain CA bundles.
// This allows us to build a generic "injection" controller, and parameterize
// it with these.
// Ideally, we'd have some generic way to express this as well.

// mutatingWebhookInjector knows how to create an InjectTarget a MutatingWebhookConfiguration.
type mutatingWebhookInjector struct{}

func (i mutatingWebhookInjector) IsAlpha() bool {
	return false
}

func (i mutatingWebhookInjector) NewTarget() InjectTarget {
	return &mutatingWebhookTarget{}
}

// mutatingWebhookTarget knows how to set CA data for all the webhooks
// in a mutatingWebhookConfiguration.
type mutatingWebhookTarget struct {
	obj admissionreg.MutatingWebhookConfiguration
}

func (t *mutatingWebhookTarget) AsObject() client.Object {
	return &t.obj
}
func (t *mutatingWebhookTarget) SetCA(data []byte) {
	for ind := range t.obj.Webhooks {
		t.obj.Webhooks[ind].ClientConfig.CABundle = data
	}
}

// validatingWebhookInjector knows how to create an InjectTarget a ValidatingWebhookConfiguration.
type validatingWebhookInjector struct{}

func (i validatingWebhookInjector) NewTarget() InjectTarget {
	return &validatingWebhookTarget{}
}

func (i validatingWebhookInjector) IsAlpha() bool {
	return false
}

// validatingWebhookTarget knows how to set CA data for all the webhooks
// in a validatingWebhookConfiguration.
type validatingWebhookTarget struct {
	obj admissionreg.ValidatingWebhookConfiguration
}

func (t *validatingWebhookTarget) AsObject() client.Object {
	return &t.obj
}

func (t *validatingWebhookTarget) SetCA(data []byte) {
	for ind := range t.obj.Webhooks {
		t.obj.Webhooks[ind].ClientConfig.CABundle = data
	}
}

// apiServiceInjector knows how to create an InjectTarget for APICAReferences
type apiServiceInjector struct{}

func (i apiServiceInjector) NewTarget() InjectTarget {
	return &apiServiceTarget{}
}

func (i apiServiceInjector) IsAlpha() bool {
	return false
}

// apiServiceTarget knows how to set CA data for the CA bundle in
// the APIService.
type apiServiceTarget struct {
	obj apireg.APIService
}

func (t *apiServiceTarget) AsObject() client.Object {
	return &t.obj
}

func (t *apiServiceTarget) SetCA(data []byte) {
	t.obj.Spec.CABundle = data
}

// TODO(directxman12): conversion webhooks
// crdConversionInjector knows how to create an InjectTarget for CRD conversion webhooks
type crdConversionInjector struct{}

func (i crdConversionInjector) NewTarget() InjectTarget {
	return &crdConversionTarget{}
}

func (i crdConversionInjector) IsAlpha() bool {
	return false
}

// crdConversionTarget knows how to set CA data for the conversion webhook in CRDs
type crdConversionTarget struct {
	obj apiext.CustomResourceDefinition
}

func (t *crdConversionTarget) AsObject() client.Object {
	return &t.obj
}

func (t *crdConversionTarget) SetCA(data []byte) {
	if t.obj.Spec.Conversion == nil || t.obj.Spec.Conversion.Strategy != apiext.WebhookConverter {
		return
	}
	if t.obj.Spec.Conversion.Webhook == nil {
		t.obj.Spec.Conversion.Webhook = &apiext.WebhookConversion{}
	}
	if t.obj.Spec.Conversion.Webhook.ClientConfig == nil {
		t.obj.Spec.Conversion.Webhook.ClientConfig = &apiext.WebhookClientConfig{}
	}
	t.obj.Spec.Conversion.Webhook.ClientConfig.CABundle = data
}
