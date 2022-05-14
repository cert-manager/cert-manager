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
	stderrors "errors"
	"fmt"

	"github.com/pkg/errors"
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

var argumentError = stderrors.New("invalid arguments")

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
// If the any of the API operations results in a Not Found error, updateObject
// will exit without error and the remaining operations will be skipped.
// Only the Finalizers and Status fields may be modified. If there are any
// modifications to new object, outside of the Finalizers and Status fields,
// this function return an error.
func (o *defaultObjectUpdater) updateObject(ctx context.Context, old, new *cmacme.Challenge) error {
	if !apiequality.Semantic.DeepEqual(
		gen.ChallengeFrom(old, gen.SetChallengeFinalizers(nil), gen.ResetChallengeStatus()),
		gen.ChallengeFrom(new, gen.SetChallengeFinalizers(nil), gen.ResetChallengeStatus()),
	) {
		return errors.WithStack(
			fmt.Errorf(
				"%w: in updateObject: unexpected differences between old and new: only the finalizers and status fields may be modified",
				argumentError,
			),
		)
	}

	var updateFunctions []func() (*cmacme.Challenge, error)
	if !apiequality.Semantic.DeepEqual(old.Status, new.Status) {
		updateFunctions = append(
			updateFunctions,
			func() (*cmacme.Challenge, error) {
				obj, err := o.updateStatus(ctx, new)
				return obj, errors.Wrap(err, "when updating the status")
			},
		)
	}
	if !apiequality.Semantic.DeepEqual(old.Finalizers, new.Finalizers) {
		updateFunctions = append(
			updateFunctions,
			func() (*cmacme.Challenge, error) {
				obj, err := o.update(ctx, new)
				return obj, errors.Wrap(err, "when updating the finalizers")
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
			new = o
		}
	}
	return utilerrors.NewAggregate(errors)
}

type objectUpdateClientDefault struct {
	cl versioned.Interface
}

func (o *objectUpdateClientDefault) update(ctx context.Context, new *cmacme.Challenge) (*cmacme.Challenge, error) {
	return o.cl.AcmeV1().Challenges(new.Namespace).Update(ctx, new, metav1.UpdateOptions{})
}

func (o *objectUpdateClientDefault) updateStatus(ctx context.Context, new *cmacme.Challenge) (*cmacme.Challenge, error) {
	return o.cl.AcmeV1().Challenges(new.Namespace).UpdateStatus(ctx, new, metav1.UpdateOptions{})
}

type objectUpdateClientSSA struct {
	cl           versioned.Interface
	fieldManager string
}

func (o *objectUpdateClientSSA) update(ctx context.Context, new *cmacme.Challenge) (*cmacme.Challenge, error) {
	return internalchallenges.Apply(ctx, o.cl, o.fieldManager, new)
}

func (o *objectUpdateClientSSA) updateStatus(ctx context.Context, new *cmacme.Challenge) (*cmacme.Challenge, error) {
	return internalchallenges.ApplyStatus(ctx, o.cl, o.fieldManager, new)
}
