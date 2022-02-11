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

package issuers

import (
	"context"
	"encoding/json"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/pointer"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
)

// ApplyIssuerStatus will make an Apply API call with the given client to the
// Issuer's status sub-resource endpoint. All data in the given Issuer object
// is dropped; expect for the name, namespace, and status object.
// The given fieldManager is will be used as the FieldManager in the Apply
// call.
// Always sets Force Apply to true.
func ApplyIssuerStatus(ctx context.Context, cl cmclient.Interface, fieldManager string, issuer *cmapi.Issuer) error {
	issuerData, err := serializeApplyIssuerStatus(issuer)
	if err != nil {
		return err
	}

	_, err = cl.CertmanagerV1().Issuers(issuer.Namespace).Patch(
		ctx, issuer.Name, apitypes.ApplyPatchType, issuerData,
		metav1.PatchOptions{Force: pointer.Bool(true), FieldManager: fieldManager}, "status",
	)

	return err
}

// ApplyClusterIssuerStatus will make an Apply API call with the given client
// to the ClusterIssuer's status sub-resource endpoint. All data in the given
// ClusterIssuer object is dropped; expect for the name, and status
// object.
// The given fieldManager is will be used as the FieldManager in the Apply
// call.
// Always sets Force Apply to true.
func ApplyClusterIssuerStatus(ctx context.Context, cl cmclient.Interface, fieldManager string, issuer *cmapi.ClusterIssuer) error {
	issuerData, err := serializeApplyClusterIssuerStatus(issuer)
	if err != nil {
		return err
	}

	_, err = cl.CertmanagerV1().ClusterIssuers().Patch(
		ctx, issuer.Name, apitypes.ApplyPatchType, issuerData,
		metav1.PatchOptions{Force: pointer.Bool(true), FieldManager: fieldManager}, "status",
	)

	return err
}

// serializeApplyIssuerStatus converts the given ClusterIssuer object to JSON.
// Only the name, namespace, and status field values will be copied and encoded
// into the serialized slice. All other fields will be left at their zero
// value.  TypeMeta will be populated with the Kind "Issuer" and API Version
// "cert-manager.io/v1" respectively.
func serializeApplyIssuerStatus(issuer *cmapi.Issuer) ([]byte, error) {
	issuer = &cmapi.Issuer{
		TypeMeta:   metav1.TypeMeta{Kind: cmapi.IssuerKind, APIVersion: cmapi.SchemeGroupVersion.Identifier()},
		ObjectMeta: metav1.ObjectMeta{Namespace: issuer.Namespace, Name: issuer.Name},
		Status:     *issuer.Status.DeepCopy(),
	}
	issuerData, err := json.Marshal(issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal issuer object: %w", err)
	}
	return issuerData, nil
}

// serializeApplyClusterIssuerStatus converts the given ClusterIssuer object to
// JSON. Only the name, and status field values will be copied and encoded into
// the serialized slice. All other fields will be left at their zero value.
// TypeMeta will be populated with the Kind "ClusterIssuer" and API Version
// "cert-manager.io/v1" respectively.
func serializeApplyClusterIssuerStatus(issuer *cmapi.ClusterIssuer) ([]byte, error) {
	issuer = &cmapi.ClusterIssuer{
		TypeMeta:   metav1.TypeMeta{Kind: cmapi.ClusterIssuerKind, APIVersion: cmapi.SchemeGroupVersion.Identifier()},
		ObjectMeta: metav1.ObjectMeta{Name: issuer.Name},
		Status:     *issuer.Status.DeepCopy(),
	}
	issuerData, err := json.Marshal(issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal clusterissuer object: %w", err)
	}
	return issuerData, nil
}
