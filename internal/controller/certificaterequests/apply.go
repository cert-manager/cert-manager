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

package certificaterequests

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

// Apply will make an Apply API call with the given client to the
// CertificateRequest's resource endpoint. All status data in the given
// CertificateRequest object is dropped.
// The given fieldManager will be used as the FieldManager in the Apply call.
// Always sets Force Apply to true.
func Apply(ctx context.Context, cl cmclient.Interface, fieldManager string, req *cmapi.CertificateRequest) (*cmapi.CertificateRequest, error) {
	reqData, err := serializeApply(req)
	if err != nil {
		return nil, err
	}

	return cl.CertmanagerV1().CertificateRequests(req.Namespace).Patch(
		ctx, req.Name, apitypes.ApplyPatchType, reqData,
		metav1.PatchOptions{Force: ptr.To(true), FieldManager: fieldManager})
}

// ApplyStatus will make an Apply API call with the given client to the
// CertificateRequests's status sub-resource endpoint. All data in the given
// CertificateRequest object is dropped; expect for the name, namespace, and
// status object.
// The given fieldManager will be used as the FieldManager in the Apply call.
// Always sets Force Apply to true.
func ApplyStatus(ctx context.Context, cl cmclient.Interface, fieldManager string, req *cmapi.CertificateRequest) error {
	reqData, err := serializeApplyStatus(req)
	if err != nil {
		return err
	}

	_, err = cl.CertmanagerV1().CertificateRequests(req.Namespace).Patch(
		ctx, req.Name, apitypes.ApplyPatchType, reqData,
		metav1.PatchOptions{Force: ptr.To(true), FieldManager: fieldManager}, "status",
	)

	return err
}

// serializeApply converts the given CertificateRequest object to JSON.
// The status object is unset.
// TypeMeta will be populated with the Kind "CertificateRequest" and API
// Version "cert-manager.io/v1" respectively.
// Manually marshalling the object into JSON is required when using the Patch
// API call for the cert-manager client.
func serializeApply(req *cmapi.CertificateRequest) ([]byte, error) {
	req = &cmapi.CertificateRequest{
		TypeMeta:   metav1.TypeMeta{Kind: cmapi.CertificateRequestKind, APIVersion: cmapi.SchemeGroupVersion.Identifier()},
		ObjectMeta: *req.ObjectMeta.DeepCopy(),
		Spec:       *req.Spec.DeepCopy(),
		Status:     cmapi.CertificateRequestStatus{},
	}
	req.ObjectMeta.ManagedFields = nil

	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificaterequest object: %w", err)
	}
	return reqData, nil
}

// serializeApplyStatus converts the given CertificateRequest object to JSON.
// Only the name, namespace, and status field values will be copied and encoded
// into the serialized slice. All other fields will be left at their zero
// value.
// TypeMeta will be populated with the Kind "CertificateRequest" and API
// Version "cert-manager.io/v1" respectively.
// Manually marshalling the object into JSON is required when using the Patch
// API call for the cert-manager client.
func serializeApplyStatus(req *cmapi.CertificateRequest) ([]byte, error) {
	req = &cmapi.CertificateRequest{
		TypeMeta:   metav1.TypeMeta{Kind: cmapi.CertificateRequestKind, APIVersion: cmapi.SchemeGroupVersion.Identifier()},
		ObjectMeta: metav1.ObjectMeta{Namespace: req.Namespace, Name: req.Name},
		Spec:       cmapi.CertificateRequestSpec{},
		Status:     *req.Status.DeepCopy(),
	}
	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificaterequest object: %w", err)
	}
	return reqData, nil
}
