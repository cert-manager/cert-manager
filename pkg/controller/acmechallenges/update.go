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

type objectUpdateClient interface {
	updateStatus(context.Context, *cmacme.Challenge) (*cmacme.Challenge, error)
}

type objectUpdater interface {
	objectUpdateClient
	applyFinalizers(context.Context, *cmacme.Challenge, []string) (*cmacme.Challenge, error)
}

type defaultObjectUpdater struct {
	objectUpdateClient
	cl           versioned.Interface
	fieldManager string
}

func (o *defaultObjectUpdater) applyFinalizers(ctx context.Context, challenge *cmacme.Challenge, finalizers []string) (*cmacme.Challenge, error) {
	// SSA MIGRATION: Can be removed after some releases
	patch, err := csaupgrade.UpgradeManagedFieldsPatch(challenge, sets.New(o.fieldManager), o.fieldManager)
	if err != nil {
		return challenge, ignoreNotFound(err)
	}
	if len(patch) > 0 {
		challenge, err = o.cl.AcmeV1().Challenges(challenge.Namespace).Patch(ctx, challenge.Name,
			types.JSONPatchType, patch,
			metav1.PatchOptions{},
		)
		if err != nil {
			return challenge, ignoreNotFound(err)
		}
	}

	ac := cmacmeac.Challenge(challenge.Name, challenge.Namespace).
		// Set resourceVersion to ensure we never create a new challenge
		WithResourceVersion(challenge.ResourceVersion).
		WithFinalizers(finalizers...)
	challenge, err = o.cl.AcmeV1().Challenges(challenge.Namespace).Apply(
		ctx, ac,
		metav1.ApplyOptions{Force: true, FieldManager: o.fieldManager},
	)
	return challenge, ignoreNotFound(err)
}

func (o *defaultObjectUpdater) updateStatus(ctx context.Context, challenge *cmacme.Challenge) (*cmacme.Challenge, error) {
	challenge, err := o.objectUpdateClient.updateStatus(ctx, challenge)
	return challenge, ignoreNotFound(err)
}

func newObjectUpdater(cl versioned.Interface, fieldManager string) objectUpdater {
	o := &defaultObjectUpdater{
		cl:                 cl,
		fieldManager:       fieldManager,
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
