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
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/cert-manager/cert-manager/pkg/acme"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// Functions for adding and checking the cleanup finalizer of a challenge.
// This ensures that the challenge is not garbage collected before cert-manager
// has a chance to clean up resources created for the challenge.
// When the challenge is marked for deletion, another step cleans up any
// deployed ("presented") resources and if successful, removes this finalizer
// allowing the garbage collector to remove the challenge.

// addCleanupFinalizer adds the cleanup finalizer if it is not already present,
// and returns true if the finalizer is added.
func addCleanupFinalizer(ch *cmacme.Challenge) bool {
	if controllerutil.ContainsFinalizer(ch, cmacme.ACMEFinalizer) {
		return false
	}
	controllerutil.AddFinalizer(ch, cmacme.ACMEFinalizer)
	return true
}

// challengeFinished returns true if either the DeletionTimestamp is set or the
// challenge is in a "final" state
func challengeFinished(ch *cmacme.Challenge) bool {
	if !ch.DeletionTimestamp.IsZero() {
		return true
	}
	if acme.IsFinalState(ch.Status.State) {
		return true
	}
	return false
}

// handleCleanup invokes solver.Cleanup if the finalizer is present and removes
// the cleanup finalizer if that succeeds.
// And if cleanup is skipped or succeeds it resets the Presented and Processing
// fields to false.
func handleCleanup(ctx context.Context, solver solver, issuer cmapi.GenericIssuer, ch *cmacme.Challenge) error {
	if controllerutil.ContainsFinalizer(ch, cmacme.ACMEFinalizer) {
		if err := solver.CleanUp(ctx, issuer, ch); err != nil {
			return errors.WithMessage(err, "Error cleaning up challenge")
		}
		controllerutil.RemoveFinalizer(ch, cmacme.ACMEFinalizer)
	}
	ch.Status.Presented = false
	ch.Status.Processing = false
	return nil
}
