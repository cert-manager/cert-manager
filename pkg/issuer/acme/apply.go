/*
Copyright 2024 The cert-manager Authors.

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

package acme

import (
	"context"
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	v1 "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

func applyACMEStatus(
	ctx context.Context,
	ctrlclient client.Client, fieldManager string,
	issuer cmapi.GenericIssuer,
	acmeStatus *cmacme.ACMEIssuerStatus,
) error {
	patch, err := serializeApplyACMEStatus(issuer, acmeStatus)
	if err != nil {
		return err
	}

	obj := issuer.DeepCopyObject().(client.Object)

	if err := ctrlclient.Status().Patch(ctx, obj, applyPatch{patch: patch}, &client.SubResourcePatchOptions{
		PatchOptions: client.PatchOptions{
			FieldManager: fieldManager,
			Force:        ptr.To(true),
		},
	}); err != nil {
		return err
	}

	return err
}

type issuerApplyConfiguration struct {
	v1.TypeMetaApplyConfiguration    `json:",inline"`
	*v1.ObjectMetaApplyConfiguration `json:"metadata,omitempty"`
	Status                           *cmapi.IssuerStatus `json:"status,omitempty"`
}

func serializeApplyACMEStatus(
	issuer cmapi.GenericIssuer,
	acmeStatus *cmacme.ACMEIssuerStatus,
) ([]byte, error) {
	patch := issuerApplyConfiguration{
		ObjectMetaApplyConfiguration: &v1.ObjectMetaApplyConfiguration{},
		Status: &cmapi.IssuerStatus{
			ACME: acmeStatus,
		},
	}

	switch tissuer := issuer.(type) {
	case *cmapi.Issuer:
		patch.WithAPIVersion(cmapi.SchemeGroupVersion.Identifier())
		patch.WithKind("Issuer")
		patch.WithName(tissuer.Name)
		patch.WithNamespace(tissuer.Namespace)
	case *cmapi.ClusterIssuer:
		patch.WithAPIVersion(cmapi.SchemeGroupVersion.Identifier())
		patch.WithKind("ClusterIssuer")
		patch.WithName(tissuer.Name)
	default:
		return nil, fmt.Errorf("[programming error]: issuer is not of type Issuer or ClusterIssuer")
	}

	crtData, err := json.Marshal(patch)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate object: %w", err)
	}

	return crtData, nil
}

type applyPatch struct {
	patch []byte
}

var _ client.Patch = applyPatch{}

func (p applyPatch) Data(_ client.Object) ([]byte, error) {
	return p.patch, nil
}

func (p applyPatch) Type() types.PatchType {
	return types.ApplyPatchType
}

func (p applyPatch) String() string {
	return string(p.patch)
}
