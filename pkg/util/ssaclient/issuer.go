/*
Copyright 2023 The cert-manager Authors.

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

package ssaclient

import (
	"encoding/json"

	"github.com/cert-manager/issuer-lib/api/v1alpha1"
	v1 "k8s.io/client-go/applyconfigurations/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

type issuerApplyConfiguration struct {
	v1.TypeMetaApplyConfiguration    `json:",inline"`
	*v1.ObjectMetaApplyConfiguration `json:"metadata,omitempty"`
	Status                           *cmv1.IssuerStatus `json:"status,omitempty"`
}

func GenerateIssuerStatusPatch(
	issuerType v1alpha1.Issuer,
	name string,
	namespace string,
	status *cmv1.IssuerStatus,
) (client.Object, client.Patch, error) {
	gvk := issuerType.GetObjectKind().GroupVersionKind()
	if (gvk.Group == "") && (gvk.Version == "") && (gvk.Kind == "") {
		panic("first call kubeutil.SetGroupVersionKind on issuerType before passing it to GenerateIssuerStatusPatch")
	}

	// This object is used to deduce the name & namespace + unmarshall the return value in
	issuerObject := issuerType.DeepCopyObject().(v1alpha1.Issuer)
	issuerObject.SetName(name)
	issuerObject.SetNamespace(namespace)

	// This object is used to render the patch
	b := &issuerApplyConfiguration{
		ObjectMetaApplyConfiguration: &v1.ObjectMetaApplyConfiguration{},
	}
	b.WithName(name)
	b.WithNamespace(namespace)
	b.WithKind(gvk.Kind)
	b.WithAPIVersion(gvk.GroupVersion().Identifier())
	b.Status = status

	encodedPatch, err := json.Marshal(b)
	if err != nil {
		return issuerObject, nil, err
	}

	return issuerObject, applyPatch{encodedPatch}, nil
}
