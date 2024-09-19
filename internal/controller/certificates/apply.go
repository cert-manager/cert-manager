/*
Copyright 2022 The cert-manager Authors.

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

package certificates

import (
	"context"
	"encoding/json"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
)

// Apply will make an Apply API call with the given client to the certificates
// resource endpoint. All data in the given Certificate's status field is
// dropped.
// The given fieldManager is will be used as the FieldManager in the Apply
// call.
// Always sets Force Apply to true.
func Apply(ctx context.Context, cl cmclient.Interface, fieldManager string, crt *cmapi.Certificate) error {
	crtData, err := serializeApply(crt)
	if err != nil {
		return err
	}

	_, err = cl.CertmanagerV1().Certificates(crt.Namespace).Patch(
		ctx, crt.Name, apitypes.ApplyPatchType, crtData,
		metav1.PatchOptions{Force: ptr.To(true), FieldManager: fieldManager},
	)

	return err
}

// ApplyStatus will make a Patch API call with the given client to the
// certificates status sub-resource endpoint. All data in the given Certificate
// object is dropped; expect for the name, namespace, and status object. The
// given fieldManager is will be used as the FieldManager in the Patch call.
// Always sets Force Patch to true.
func ApplyStatus(ctx context.Context, cl cmclient.Interface, fieldManager string, crt *cmapi.Certificate) error {
	crtData, err := serializeApplyStatus(crt)
	if err != nil {
		return err
	}

	_, err = cl.CertmanagerV1().Certificates(crt.Namespace).Patch(
		ctx, crt.Name, apitypes.ApplyPatchType, crtData,
		metav1.PatchOptions{Force: ptr.To(true), FieldManager: fieldManager}, "status",
	)

	return err
}

// serializeApply converts the given Certificate object in JSON.
// The status field will be set empty before serializing.
// TypeMeta will be populated with the Kind "Certificate" and API Version
// "cert-manager.io/v1" respectively.
func serializeApply(crt *cmapi.Certificate) ([]byte, error) {
	crt = &cmapi.Certificate{
		TypeMeta:   metav1.TypeMeta{Kind: cmapi.CertificateKind, APIVersion: cmapi.SchemeGroupVersion.Identifier()},
		ObjectMeta: *crt.ObjectMeta.DeepCopy(),
		Spec:       *crt.Spec.DeepCopy(),
		Status:     cmapi.CertificateStatus{},
	}
	crtData, err := json.Marshal(crt)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate object: %w", err)
	}
	return crtData, nil
}

// serializeApplyStatus converts the given Certificate object in JSON. Only the
// name, namespace, and status field values will be copied and encoded into the
// serialized slice. All other fields will be left at their zero value.
// TypeMeta will be populated with the Kind "Certificate" and API Version
// "cert-manager.io/v1" respectively.
func serializeApplyStatus(crt *cmapi.Certificate) ([]byte, error) {
	crt = &cmapi.Certificate{
		TypeMeta:   metav1.TypeMeta{Kind: cmapi.CertificateKind, APIVersion: cmapi.SchemeGroupVersion.Identifier()},
		ObjectMeta: metav1.ObjectMeta{Namespace: crt.Namespace, Name: crt.Name},
		Status:     crt.Status,
	}
	crtData, err := json.Marshal(crt)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate object: %w", err)
	}
	return crtData, nil
}
