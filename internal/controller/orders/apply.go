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

package orders

import (
	"context"
	"encoding/json"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
)

// ApplyStatus will make an Apply API call with the given client to the order's
// status sub-resource endpoint. All data in the given Order object is dropped;
// expect for the name, namespace, and status object. The given fieldManager is
// will be used as the FieldManager in the Apply call.
// Always sets Force Apply to true.
func ApplyStatus(ctx context.Context, cl cmclient.Interface, fieldManager string, order *cmacme.Order) error {
	orderData, err := serializeApplyStatus(order)
	if err != nil {
		return err
	}

	_, err = cl.AcmeV1().Orders(order.Namespace).Patch(
		ctx, order.Name, apitypes.ApplyPatchType, orderData,
		metav1.PatchOptions{Force: ptr.To(true), FieldManager: fieldManager}, "status",
	)

	return err
}

// serializeApplyStatus converts the given Order object in JSON. Only the name,
// namespace, and status field values will be copied and encoded into the
// serialized slice. All other fields will be left at their zero value.
// TypeMeta will be populated with the Kind "Order" and API Version
// "acme.cert-manager.io/v1" respectively.
func serializeApplyStatus(order *cmacme.Order) ([]byte, error) {
	order = &cmacme.Order{
		TypeMeta:   metav1.TypeMeta{Kind: cmacme.OrderKind, APIVersion: cmacme.SchemeGroupVersion.Identifier()},
		ObjectMeta: metav1.ObjectMeta{Namespace: order.Namespace, Name: order.Name},
		Status:     order.Status,
	}
	orderData, err := json.Marshal(order)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal order object: %w", err)
	}
	return orderData, nil
}
