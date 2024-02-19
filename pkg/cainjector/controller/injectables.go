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
	"encoding/json"

	admissionreg "k8s.io/api/admissionregistration/v1"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/types"
	applyadmissionreg "k8s.io/client-go/applyconfigurations/admissionregistration/v1"
	applymetav1 "k8s.io/client-go/applyconfigurations/meta/v1"
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

	// AsApplyObject returns this injectable as an object that only contains
	// fields which are managed by the cainjector (CA Data) and immutable fields
	// that must be present in Apply calls; intended for use for Apply Patch
	// calls.
	AsApplyObject() (client.Object, client.Patch)

	// SetCA sets the CA of this target to the given certificate data (in the standard
	// PEM format used across Kubernetes).  In cases where multiple CA fields exist per
	// target (like admission webhook configs), all CAs are set to the given value.
	SetCA(data []byte)
}

type ssaPatch struct {
	patch []byte
	err   error
}

func newSSAPatch(patch interface{}) *ssaPatch {
	jsonPatch, err := json.Marshal(patch)
	return &ssaPatch{patch: jsonPatch, err: err}
}

func (p *ssaPatch) Type() types.PatchType {
	return types.ApplyPatchType
}

func (p *ssaPatch) Data(obj client.Object) ([]byte, error) {
	return p.patch, nil
}

var _ client.Patch = &ssaPatch{}

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

func (t *mutatingWebhookTarget) AsApplyObject() (client.Object, client.Patch) {
	patch := applyadmissionreg.MutatingWebhookConfiguration(t.obj.Name)

	for i := range t.obj.Webhooks {
		patch = patch.WithWebhooks(
			applyadmissionreg.
				MutatingWebhook().
				WithName(t.obj.Webhooks[i].Name). // Name is used as slice key.
				WithClientConfig(
					&applyadmissionreg.WebhookClientConfigApplyConfiguration{
						CABundle: t.obj.Webhooks[i].ClientConfig.CABundle,
					},
				),
		)
	}

	return &t.obj, newSSAPatch(patch)
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

func (t *validatingWebhookTarget) AsApplyObject() (client.Object, client.Patch) {
	patch := applyadmissionreg.ValidatingWebhookConfiguration(t.obj.Name)

	for i := range t.obj.Webhooks {
		patch = patch.WithWebhooks(
			applyadmissionreg.
				ValidatingWebhook().
				WithName(t.obj.Webhooks[i].Name). // Name is used as slice key.
				WithClientConfig(
					&applyadmissionreg.WebhookClientConfigApplyConfiguration{
						CABundle: t.obj.Webhooks[i].ClientConfig.CABundle,
					},
				),
		)
	}

	return &t.obj, newSSAPatch(patch)
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

type apiServiceTargetPatch struct {
	applymetav1.TypeMetaApplyConfiguration    `json:",inline"`
	*applymetav1.ObjectMetaApplyConfiguration `json:"metadata,omitempty"`
	Spec                                      *apiServiceTargetSpecPatch `json:"spec,omitempty"`
}

type apiServiceTargetSpecPatch struct {
	CABundle []byte `json:"caBundle,omitempty"`
}

func (t *apiServiceTarget) AsApplyObject() (client.Object, client.Patch) {
	return &t.obj, newSSAPatch(&apiServiceTargetPatch{
		TypeMetaApplyConfiguration: *applymetav1.
			TypeMeta().
			WithAPIVersion(apireg.SchemeGroupVersion.String()).
			WithKind("APIService"),
		ObjectMetaApplyConfiguration: applymetav1.
			ObjectMeta().
			WithName(t.obj.Name),
		Spec: &apiServiceTargetSpecPatch{
			CABundle: t.obj.Spec.CABundle,
		},
	})
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

type customResourceDefinitionPatch struct {
	applymetav1.TypeMetaApplyConfiguration    `json:",inline"`
	*applymetav1.ObjectMetaApplyConfiguration `json:"metadata,omitempty"`
	Spec                                      *customResourceDefinitionSpecPatch `json:"spec,omitempty"`
}

type customResourceDefinitionSpecPatch struct {
	Conversion *customResourceConversionPatch `json:"conversion,omitempty"`
}

type customResourceConversionPatch struct {
	Webhook *customResourceWebhookConversionPatch `json:"webhook,omitempty"`
}

type customResourceWebhookConversionPatch struct {
	ClientConfig *customResourceWebhookClientConfigPatch `json:"clientConfig,omitempty"`
}

type customResourceWebhookClientConfigPatch struct {
	CABundle []byte `json:"caBundle,omitempty"`
}

func (t *crdConversionTarget) AsApplyObject() (client.Object, client.Patch) {
	if t.obj.Spec.Conversion == nil || t.obj.Spec.Conversion.Webhook == nil || t.obj.Spec.Conversion.Webhook.ClientConfig == nil {
		return &t.obj, nil
	}

	return &t.obj, newSSAPatch(&customResourceDefinitionPatch{
		TypeMetaApplyConfiguration: *applymetav1.
			TypeMeta().
			WithAPIVersion(apiext.SchemeGroupVersion.String()).
			WithKind("CustomResourceDefinition"),
		ObjectMetaApplyConfiguration: applymetav1.
			ObjectMeta().
			WithName(t.obj.Name),
		Spec: &customResourceDefinitionSpecPatch{
			Conversion: &customResourceConversionPatch{
				Webhook: &customResourceWebhookConversionPatch{
					ClientConfig: &customResourceWebhookClientConfigPatch{
						CABundle: t.obj.Spec.Conversion.Webhook.ClientConfig.CABundle,
					},
				},
			},
		},
	})
}
