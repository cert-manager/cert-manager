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

package acmechallenges

import (
	"context"
	"errors"
	"fmt"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/csaupgrade"

	"github.com/cert-manager/cert-manager/internal/controller/feature"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmacmeac "github.com/cert-manager/cert-manager/pkg/client/applyconfigurations/acme/v1"
	"github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

var errArgument = errors.New("invalid arguments")

type objectUpdater interface {
	updateStatus(context.Context, *cmacme.Challenge, *cmacme.Challenge) error
	applyFinalizers(context.Context, *cmacme.Challenge, []string) error
	upgradeManagedFields(context.Context, *cmacme.Challenge) (bool, error)
}

type defaultObjectUpdater struct {
	*objectUpdateClientDefault
	*objectUpdateClientSSA
}

func newObjectUpdater(cl versioned.Interface, fieldManager string) objectUpdater {
	o := &defaultObjectUpdater{
		objectUpdateClientDefault: &objectUpdateClientDefault{cl: cl},
		objectUpdateClientSSA: &objectUpdateClientSSA{
			fieldManager: fieldManager,
			cl:           cl,
		},
	}
	return o
}

// updateStatus updates the Status if it has changed.
// Only the Status fields may be modified. If there are any modifications to new object, outside of
// the Status fields, this function return an error.
func (o *defaultObjectUpdater) updateStatus(ctx context.Context, oldChallenge, newChallenge *cmacme.Challenge) error {
	if !apiequality.Semantic.DeepEqual(
		gen.ChallengeFrom(oldChallenge, gen.ResetChallengeStatus()),
		gen.ChallengeFrom(newChallenge, gen.ResetChallengeStatus()),
	) {
		return fmt.Errorf(
			"%w: in updateObject: unexpected differences between old and new: only the status fields may be modified",
			errArgument,
		)
	}

	if apiequality.Semantic.DeepEqual(oldChallenge.Status, newChallenge.Status) {
		// No changes to the status, return early.
		return nil
	}

	updateStatus := o.objectUpdateClientDefault.updateStatus
	if utilfeature.DefaultFeatureGate.Enabled(feature.ServerSideApply) {
		updateStatus = o.objectUpdateClientSSA.updateStatus
	}

	if _, err := updateStatus(ctx, newChallenge); err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	return nil
}

type objectUpdateClientDefault struct {
	cl versioned.Interface
}

func (o *objectUpdateClientDefault) updateStatus(ctx context.Context, challenge *cmacme.Challenge) (*cmacme.Challenge, error) {
	return o.cl.AcmeV1().Challenges(challenge.Namespace).UpdateStatus(ctx, challenge, metav1.UpdateOptions{})
}

type objectUpdateClientSSA struct {
	cl           versioned.Interface
	fieldManager string
}

func (o *objectUpdateClientSSA) applyFinalizers(ctx context.Context, challenge *cmacme.Challenge, finalizers []string) error {
	ac := cmacmeac.Challenge(challenge.Name, challenge.Namespace).
		// Set UID to ensure we never create a new challenge.
		// Apply semantics are always create-or-update,
		// and the challenge might have been deleted.
		WithUID(challenge.UID).
		WithFinalizers(finalizers...)
	if _, err := o.cl.AcmeV1().Challenges(challenge.Namespace).Apply(
		ctx, ac,
		metav1.ApplyOptions{Force: true, FieldManager: o.fieldManager},
	); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

func (o *objectUpdateClientSSA) updateStatus(ctx context.Context, challenge *cmacme.Challenge) (*cmacme.Challenge, error) {
	challengeStatus := cmacmeac.ChallengeStatus().
		WithProcessing(challenge.Status.Processing).
		WithPresented(challenge.Status.Presented)
	if challenge.Status.Reason != "" {
		challengeStatus = challengeStatus.WithReason(challenge.Status.Reason)
	}
	if challenge.Status.State != "" {
		challengeStatus = challengeStatus.WithState(challenge.Status.State)
	}
	ac := cmacmeac.Challenge(challenge.Name, challenge.Namespace).
		WithStatus(challengeStatus)
	return o.cl.AcmeV1().Challenges(challenge.Namespace).ApplyStatus(
		ctx, ac,
		metav1.ApplyOptions{Force: true, FieldManager: o.fieldManager},
	)
}

// upgradeManagedFields upgrades the managed fields from CSA to SSA.
// This is required to ensure a server side apply request can reset/unset fields based on
// field manager managed fields.
func (o *objectUpdateClientSSA) upgradeManagedFields(ctx context.Context, challenge *cmacme.Challenge) (bool, error) {
	var upgradeOptions [][]csaupgrade.Option
	if !utilfeature.DefaultFeatureGate.Enabled(feature.ServerSideApply) {
		upgradeOptions = [][]csaupgrade.Option{
			nil, // Upgrade the main object managed fields.
		}
	} else {
		upgradeOptions = [][]csaupgrade.Option{
			nil,                                // Upgrade the main object managed fields.
			{csaupgrade.Subresource("status")}, // Upgrade the status subresource managed fields.
		}
	}
	for _, opts := range upgradeOptions {
		patchData, err := csaupgrade.UpgradeManagedFieldsPatch(challenge, sets.New(o.fieldManager), o.fieldManager, opts...)
		if err != nil {
			return false, fmt.Errorf("when creating managed fields patch: %w", err)
		}

		if len(patchData) == 0 {
			continue
		}

		_, err = o.cl.AcmeV1().Challenges(challenge.Namespace).Patch(
			ctx, challenge.Name,
			types.JSONPatchType, patchData,
			metav1.PatchOptions{},
		)
		if err != nil {
			return false, fmt.Errorf("when patching managed fields: %w", err)
		}

		return true, nil // Return early if we patched the managed fields, to avoid patching twice, which would cause a conflict.
	}

	return false, nil // No managed fields needed to be upgraded, continue with the sync.
}
