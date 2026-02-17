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
	"fmt"

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
)

var ignoreNotFound = func(err error) error {
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

type objectUpdater interface {
	applyFinalizers(context.Context, *cmacme.Challenge, []string) (*cmacme.Challenge, error)
	updateStatus(context.Context, *cmacme.Challenge) (*cmacme.Challenge, error)
}

type defaultObjectUpdater struct {
	cl           versioned.Interface
	fieldManager string
}

func newObjectUpdater(cl versioned.Interface, fieldManager string) objectUpdater {
	return &defaultObjectUpdater{
		cl:           cl,
		fieldManager: fieldManager,
	}
}

func (o *defaultObjectUpdater) updateStatus(ctx context.Context, challenge *cmacme.Challenge) (*cmacme.Challenge, error) {
	if utilfeature.DefaultFeatureGate.Enabled(feature.ServerSideApply) {
		obj, err := o.updateStatusSSA(ctx, challenge)
		return obj, ignoreNotFound(err)
	}
	obj, err := o.updateStatusCSA(ctx, challenge)
	return obj, ignoreNotFound(err)
}

func (o *defaultObjectUpdater) updateStatusCSA(ctx context.Context, challenge *cmacme.Challenge) (*cmacme.Challenge, error) {
	return o.cl.AcmeV1().Challenges(challenge.Namespace).UpdateStatus(ctx, challenge, metav1.UpdateOptions{})
}

func (o *defaultObjectUpdater) applyFinalizers(ctx context.Context, challenge *cmacme.Challenge, finalizers []string) (*cmacme.Challenge, error) {
	if err := o.upgradeManagedFields(ctx, challenge); err != nil {
		return nil, ignoreNotFound(err)
	}

	ac := cmacmeac.Challenge(challenge.Name, challenge.Namespace).
		// Set UID to ensure we never create a new challenge.
		// Apply semantics are always create-or-update,
		// and the challenge might have been deleted.
		WithUID(challenge.UID).
		WithFinalizers(finalizers...)
	obj, err := o.cl.AcmeV1().Challenges(challenge.Namespace).Apply(
		ctx, ac,
		metav1.ApplyOptions{Force: true, FieldManager: o.fieldManager},
	)
	return obj, ignoreNotFound(err)
}

func (o *defaultObjectUpdater) updateStatusSSA(ctx context.Context, challenge *cmacme.Challenge) (*cmacme.Challenge, error) {
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
func (o *defaultObjectUpdater) upgradeManagedFields(ctx context.Context, challenge *cmacme.Challenge, opts ...csaupgrade.Option) error {
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
