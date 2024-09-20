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

package challenges

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

// Apply will make an Apply API call with the given client to the challenges
// endpoint. All data in the given Challenges object is dropped; expect for the
// name, namespace, and spec object. The given fieldManager is will be used as
// the FieldManager in the Apply call.  Always sets Force Apply to true.
func Apply(ctx context.Context, cl cmclient.Interface, fieldManager string, challenge *cmacme.Challenge) (*cmacme.Challenge, error) {
	challengeData, err := serializeApply(challenge)
	if err != nil {
		return nil, err
	}

	return cl.AcmeV1().Challenges(challenge.Namespace).Patch(
		ctx, challenge.Name, apitypes.ApplyPatchType, challengeData,
		metav1.PatchOptions{Force: ptr.To(true), FieldManager: fieldManager},
	)
}

// ApplyStatus will make an Apply API call with the given client to the
// challenges status sub-resource endpoint. All data in the given Challenges
// object is dropped; expect for the name, namespace, and status object. The
// given fieldManager is will be used as the FieldManager in the Apply call.
// Always sets Force Apply to true.
func ApplyStatus(ctx context.Context, cl cmclient.Interface, fieldManager string, challenge *cmacme.Challenge) (*cmacme.Challenge, error) {
	challengeData, err := serializeApplyStatus(challenge)
	if err != nil {
		return nil, err
	}

	return cl.AcmeV1().Challenges(challenge.Namespace).Patch(
		ctx, challenge.Name, apitypes.ApplyPatchType, challengeData,
		metav1.PatchOptions{Force: ptr.To(true), FieldManager: fieldManager}, "status",
	)
}

// serializeApply converts the given Challenge object in JSON. Only the
// objectmeta, and spec fields will be copied and encoded into the serialized
// slice. All other fields will be left at their zero value.
// TypeMeta will be populated with the Kind "Challenge" and API Version
// "acme.cert-manager.io/v1" respectively.
func serializeApply(challenge *cmacme.Challenge) ([]byte, error) {
	ch := &cmacme.Challenge{
		TypeMeta:   metav1.TypeMeta{Kind: cmacme.ChallengeKind, APIVersion: cmacme.SchemeGroupVersion.Identifier()},
		ObjectMeta: *challenge.ObjectMeta.DeepCopy(),
		Spec:       *challenge.Spec.DeepCopy(),
	}
	ch.ManagedFields = nil
	challengeData, err := json.Marshal(ch)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal challenge object: %w", err)
	}
	return challengeData, nil
}

// serializeApplyStatus converts the given Challenge object in JSON. Only the
// name, namespace, and status field values will be copied and encoded into the
// serialized slice. All other fields will be left at their zero value.
// TypeMeta will be populated with the Kind "Challenge" and API Version
// "acme.cert-manager.io/v1" respectively.
func serializeApplyStatus(challenge *cmacme.Challenge) ([]byte, error) {
	ch := &cmacme.Challenge{
		TypeMeta:   metav1.TypeMeta{Kind: cmacme.ChallengeKind, APIVersion: cmacme.SchemeGroupVersion.Identifier()},
		ObjectMeta: metav1.ObjectMeta{Namespace: challenge.Namespace, Name: challenge.Name},
		Spec:       cmacme.ChallengeSpec{},
		Status:     *challenge.Status.DeepCopy(),
	}
	challengeData, err := json.Marshal(ch)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal challenge object: %w", err)
	}
	return challengeData, nil
}
