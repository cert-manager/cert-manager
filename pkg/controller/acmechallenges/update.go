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
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	internalchallenges "github.com/cert-manager/cert-manager/internal/controller/challenges"
	"github.com/cert-manager/cert-manager/internal/controller/feature"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	"github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

var argumentError = errors.New("invalid arguments")

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
			argumentError,
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
	return internalchallenges.Apply(ctx, o.cl, o.fieldManager, challenge)
}

func (o *objectUpdateClientSSA) updateStatus(ctx context.Context, challenge *cmacme.Challenge) (*cmacme.Challenge, error) {
	return internalchallenges.ApplyStatus(ctx, o.cl, o.fieldManager, challenge)
}
