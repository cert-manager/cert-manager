/*
Copyright 2020 The cert-manager Authors.

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

package solver

import (
	"context"
	"time"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

type Solver interface {
	// Present the challenge value with the given solver.
	Present(ctx context.Context, issuer cmapi.GenericIssuer, ch *cmacme.Challenge) error

	// Check returns an Error if the propagation check didn't succeed.
	//
	// The result indicates if the challenge is solved, along with a reason and
	// message explaining the state. It also returns RetryAfter that indicates
	// when the Check function should be re-called.
	//
	// The status should be persisted on the Challenge.
	Check(ctx context.Context, issuer cmapi.GenericIssuer, ch *cmacme.Challenge) (SolverCheckResult, cmacme.ChallengeSolverStatus, error)

	// CleanUp will remove challenge records for a given solver.
	//
	// This may involve deleting resources in the Kubernetes API Server, or
	// communicating with other external components (e.g., DNS providers).
	CleanUp(ctx context.Context, ch *cmacme.Challenge) error
}

type SolverCheckResult struct {
	// Status is the result of the check, if this is cmmeta.ConditionFalse then
	// the check will be re-attempted after a delay. The delay can be controlled
	// by using the RetryAfter field.
	Status cmmeta.ConditionStatus

	// Reason is a short PascalCase reason that the solver is in its current
	// state, this can be used in conditions or events.
	Reason string

	// Message is a long description of why the solver is in its current
	// state, this can be used in conditions or events.
	Message string

	// RetryAfter can be used if a specific duration should be waited before the
	// next attempt. For example this allows the check to be re-attempted after
	// the TTL of a DNS record.
	RetryAfter time.Duration
}
