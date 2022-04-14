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

	"k8s.io/apimachinery/pkg/util/sets"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
)

// Functions for adding and checking the cleanup finalizer of a challenge.
// This ensures that the challenge is not garbage collected before cert-manager
// has a chance to clean up resources created for the challenge.
// When the challenge is marked for deletion, another step cleans up any
// deployed ("presented") resources and if successful, removes this finalizer
// allowing the garbage collector to remove the challenge.

// challengeUpdater allows the spec and metadata of a Challenge to be modified.
type challengeUpdater interface {
	updateOrApply(context.Context, *cmacme.Challenge) (*cmacme.Challenge, error)
}

// finalizerRequired returns true if the finalizer is not found on the challenge.
func finalizerRequired(ch *cmacme.Challenge) bool {
	return !sets.NewString(ch.Finalizers...).Has(cmacme.ACMEFinalizer)
}

// addFinalizer adds the finalizer to the challenge and saves the change to the API
// server.
func addFinalizer(client challengeUpdater, ctx context.Context, ch *cmacme.Challenge) (*cmacme.Challenge, error) {
	ch = ch.DeepCopy()
	ch.Finalizers = append(ch.Finalizers, cmacme.ACMEFinalizer)
	ch, err := client.updateOrApply(ctx, ch)
	if err != nil {
		return nil, err
	}
	return ch, nil
}
