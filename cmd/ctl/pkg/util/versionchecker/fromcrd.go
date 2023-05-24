/*
Copyright 2021 The cert-manager Authors.

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

package versionchecker

import (
	"context"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (o *VersionChecker) extractVersionFromCrd(ctx context.Context, crdName string) error {
	crdKey := client.ObjectKey{Name: crdName}

	objv1 := &apiextensionsv1.CustomResourceDefinition{}
	err := o.client.Get(ctx, crdKey, objv1)
	if err == nil {
		if label := extractVersionFromLabels(objv1.Labels); label != "" {
			o.versionSources["crdLabelVersion"] = label
		}

		return o.extractVersionFromCrdv1(ctx, objv1)
	}

	// If error differs from not found, don't continue and return error
	if !apierrors.IsNotFound(err) {
		return err
	}

	objv1beta1 := &apiextensionsv1beta1.CustomResourceDefinition{}
	err = o.client.Get(ctx, crdKey, objv1beta1)
	if err == nil {
		if label := extractVersionFromLabels(objv1beta1.Labels); label != "" {
			o.versionSources["crdLabelVersion"] = label
		}

		return o.extractVersionFromCrdv1beta1(ctx, objv1beta1)
	}

	// If error differs from not found, don't continue and return error
	if !apierrors.IsNotFound(err) {
		return err
	}

	return ErrCertManagerCRDsNotFound
}

func (o *VersionChecker) extractVersionFromCrdv1(ctx context.Context, crd *apiextensionsv1.CustomResourceDefinition) error {
	if (crd.Spec.Conversion == nil) ||
		(crd.Spec.Conversion.Webhook == nil) ||
		(crd.Spec.Conversion.Webhook.ClientConfig == nil) ||
		(crd.Spec.Conversion.Webhook.ClientConfig.Service == nil) {
		return nil
	}

	return o.extractVersionFromService(
		ctx,
		crd.Spec.Conversion.Webhook.ClientConfig.Service.Namespace,
		crd.Spec.Conversion.Webhook.ClientConfig.Service.Name,
	)
}

func (o *VersionChecker) extractVersionFromCrdv1beta1(ctx context.Context, crd *apiextensionsv1beta1.CustomResourceDefinition) error {
	if (crd.Spec.Conversion == nil) ||
		(crd.Spec.Conversion.WebhookClientConfig == nil) ||
		(crd.Spec.Conversion.WebhookClientConfig.Service == nil) {
		return nil
	}

	return o.extractVersionFromService(
		ctx,
		crd.Spec.Conversion.WebhookClientConfig.Service.Namespace,
		crd.Spec.Conversion.WebhookClientConfig.Service.Name,
	)
}
