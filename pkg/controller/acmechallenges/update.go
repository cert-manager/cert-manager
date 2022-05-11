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

type updater interface {
	update(context.Context, *cmacme.Challenge) (*cmacme.Challenge, error)
	updateStatus(context.Context, *cmacme.Challenge) (*cmacme.Challenge, error)
}

type objectUpdater struct {
	updater
}

func newObjectUpdater(cl versioned.Interface, fieldManager string) *objectUpdater {
	o := &objectUpdater{
		updater: &objectUpdaterDefault{cl: cl},
	}
	if utilfeature.DefaultFeatureGate.Enabled(feature.ServerSideApply) {
		o.updater = &objectUpdaterSSA{
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
// this function will panic.
func (o *objectUpdater) updateObject(ctx context.Context, old, new *cmacme.Challenge) error {
	if !apiequality.Semantic.DeepEqual(
		gen.ChallengeFrom(old, gen.SetChallengeFinalizers(nil), gen.ResetChallengeStatus()),
		gen.ChallengeFrom(new, gen.SetChallengeFinalizers(nil), gen.ResetChallengeStatus()),
	) {
		panic("only the finalizers and status fields may be modified")
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

type objectUpdaterDefault struct {
	cl versioned.Interface
}

func (o *objectUpdaterDefault) update(ctx context.Context, new *cmacme.Challenge) (*cmacme.Challenge, error) {
	return o.cl.AcmeV1().Challenges(new.Namespace).Update(ctx, new, metav1.UpdateOptions{})
}

func (o *objectUpdaterDefault) updateStatus(ctx context.Context, new *cmacme.Challenge) (*cmacme.Challenge, error) {
	return o.cl.AcmeV1().Challenges(new.Namespace).UpdateStatus(ctx, new, metav1.UpdateOptions{})
}

type objectUpdaterSSA struct {
	cl           versioned.Interface
	fieldManager string
}

func (o *objectUpdaterSSA) update(ctx context.Context, new *cmacme.Challenge) (*cmacme.Challenge, error) {
	return internalchallenges.Apply(ctx, o.cl, o.fieldManager, new)
}

func (o *objectUpdaterSSA) updateStatus(ctx context.Context, new *cmacme.Challenge) (*cmacme.Challenge, error) {
	return internalchallenges.ApplyStatus(ctx, o.cl, o.fieldManager, new)
}
