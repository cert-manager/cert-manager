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
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
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

type objectUpdateClient interface {
	update(context.Context, *cmacme.Challenge) (*cmacme.Challenge, error)
	updateStatus(context.Context, *cmacme.Challenge) (*cmacme.Challenge, error)
}

type objectUpdater interface {
	updateObject(context.Context, *cmacme.Challenge, *cmacme.Challenge) error
}

type defaultObjectUpdater struct {
	objectUpdateClient
}

func newObjectUpdater(cl versioned.Interface, fieldManager string) objectUpdater {
	o := &defaultObjectUpdater{
		objectUpdateClient: &objectUpdateClientDefault{cl: cl},
	}
	if utilfeature.DefaultFeatureGate.Enabled(feature.ServerSideApply) {
		o.objectUpdateClient = &objectUpdateClientSSA{
			fieldManager: fieldManager,
			cl:           cl,
		}
	}
	return o
}

// updateObject updates the Finalizers if they have changed and updates the Status if it has changed.
// Finalizers are updated using the Update method while Status is updated using
// the UpdateStatus method.
// Both updates will be attempted, even if one fails, except in the case where
// one of the updates fails with a Not Found error.
// If any of the API operations results in a Not Found error, updateObject
// will exit without error and the remaining operations will be skipped.
// Only the Finalizers and Status fields may be modified. If there are any
// modifications to new object, outside of the Finalizers and Status fields,
// this function return an error.
func (o *defaultObjectUpdater) updateObject(ctx context.Context, oldChallenge, newChallenge *cmacme.Challenge) error {
	if !apiequality.Semantic.DeepEqual(
		gen.ChallengeFrom(oldChallenge, gen.SetChallengeFinalizers(nil), gen.ResetChallengeStatus()),
		gen.ChallengeFrom(newChallenge, gen.SetChallengeFinalizers(nil), gen.ResetChallengeStatus()),
	) {
		return fmt.Errorf(
			"%w: in updateObject: unexpected differences between old and new: only the finalizers and status fields may be modified",
			errArgument,
		)
	}

	var updateFunctions []func() (*cmacme.Challenge, error)
	if !apiequality.Semantic.DeepEqual(oldChallenge.Status, newChallenge.Status) {
		updateFunctions = append(
			updateFunctions,
			func() (*cmacme.Challenge, error) {
				if obj, err := o.updateStatus(ctx, newChallenge); err != nil {
					return obj, fmt.Errorf("when updating the status: %w", err)
				} else {
					return obj, nil
				}
			},
		)
	}
	if !apiequality.Semantic.DeepEqual(oldChallenge.Finalizers, newChallenge.Finalizers) {
		updateFunctions = append(
			updateFunctions,
			func() (*cmacme.Challenge, error) {
				if obj, err := o.update(ctx, newChallenge); err != nil {
					return obj, fmt.Errorf("when updating the finalizers: %w", err)
				} else {
					return obj, nil
				}
			},
		)
	}
	var errors []error
	for _, f := range updateFunctions {
		if o, err := f(); err != nil {
			errors = append(errors, err)
			if k8sErrors.IsNotFound(err) {
				return nil
			}
		} else {
			newChallenge = o
		}
	}
	return utilerrors.NewAggregate(errors)
}

type objectUpdateClientDefault struct {
	cl versioned.Interface
}

func (o *objectUpdateClientDefault) update(ctx context.Context, challenge *cmacme.Challenge) (*cmacme.Challenge, error) {
	return o.cl.AcmeV1().Challenges(challenge.Namespace).Update(ctx, challenge, metav1.UpdateOptions{})
}

func (o *objectUpdateClientDefault) updateStatus(ctx context.Context, challenge *cmacme.Challenge) (*cmacme.Challenge, error) {
	return o.cl.AcmeV1().Challenges(challenge.Namespace).UpdateStatus(ctx, challenge, metav1.UpdateOptions{})
}

type objectUpdateClientSSA struct {
	cl           versioned.Interface
	fieldManager string
}

func (o *objectUpdateClientSSA) update(ctx context.Context, challenge *cmacme.Challenge) (*cmacme.Challenge, error) {
	if err := o.upgradeManagedFields(ctx, challenge); err != nil {
		return nil, err
	}

	ac := cmacmeac.Challenge(challenge.Name, challenge.Namespace).
		// Set UID to ensure we never create a new challenge.
		// Apply semantics are always create-or-update,
		// and the challenge might have been deleted.
		WithUID(challenge.UID).
		// FIXME: This will claim ownership of all finalizers, which is obviously wrong.
		WithFinalizers(challenge.Finalizers...)
	return o.cl.AcmeV1().Challenges(challenge.Namespace).Apply(
		ctx, ac,
		metav1.ApplyOptions{Force: true, FieldManager: o.fieldManager},
	)
}

func (o *objectUpdateClientSSA) updateStatus(ctx context.Context, challenge *cmacme.Challenge) (*cmacme.Challenge, error) {
	if err := o.upgradeManagedFields(ctx, challenge, csaupgrade.Subresource("status")); err != nil {
		return nil, err
	}

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
func (o *objectUpdateClientSSA) upgradeManagedFields(ctx context.Context, challenge *cmacme.Challenge, opts ...csaupgrade.Option) error {
	patchData, err := csaupgrade.UpgradeManagedFieldsPatch(challenge, sets.New(o.fieldManager), o.fieldManager, opts...)
	if err != nil {
		return fmt.Errorf("when creating managed fields patch: %w", err)
	}

	if len(patchData) == 0 {
		// No work to be done, return early
		return nil
	}

	_, err = o.cl.AcmeV1().Challenges(challenge.Namespace).Patch(
		ctx, challenge.Name,
		types.JSONPatchType, patchData,
		metav1.PatchOptions{},
	)
	if err != nil {
		return fmt.Errorf("when patching managed fields: %w", err)
	}
	return nil
}
