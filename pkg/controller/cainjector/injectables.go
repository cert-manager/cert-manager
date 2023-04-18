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

// This file contains logic for dealing with injectables, such as injecting CA
// data to an instance of an injectable.

// NewInjectableTarget knows how to create InjectTarget for a particular type of
// injectable.
type NewInjectableTarget func() InjectTarget

var _ NewInjectableTarget = newMutatingWebhookInjectable

func newMutatingWebhookInjectable() InjectTarget {
	return &mutatingWebhookTarget{}
}

var _ NewInjectableTarget = newValidatingWebhookInjectable

func newValidatingWebhookInjectable() InjectTarget {
	return &validatingWebhookTarget{}
}

var _ NewInjectableTarget = newAPIServiceInjectable

func newAPIServiceInjectable() InjectTarget {
	return &apiServiceTarget{}
}

var _ NewInjectableTarget = newCRDConversionInjectable

func newCRDConversionInjectable() InjectTarget {
	return &crdConversionTarget{}
}

// InjectTarget knows how to set CA data to a particular instance of injectable,
// for example an instance of ValidatingWebhookConfiguration.
type InjectTarget interface {
	// AsObject returns this injectable as an object.
	// It should be a pointer suitable for mutation.
	AsObject() client.Object

	// SetCA sets the CA of this target to the given certificate data (in the standard
	// PEM format used across Kubernetes).  In cases where multiple CA fields exist per
	// target (like admission webhook configs), all CAs are set to the given value.
	SetCA(data []byte)
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

// apiServiceTarget knows how to set CA data for the CA bundle in
// the APIService spec.
type apiServiceTarget struct {
	obj apireg.APIService
}

func (t *apiServiceTarget) AsObject() client.Object {
	return &t.obj
}

func (t *apiServiceTarget) SetCA(data []byte) {
	t.obj.Spec.CABundle = data
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
