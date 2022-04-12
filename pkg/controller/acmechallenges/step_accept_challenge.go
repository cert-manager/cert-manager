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

package acmechallenges

import (
	"context"
	"fmt"

	acmeapi "golang.org/x/crypto/acme"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"

	acmecl "github.com/cert-manager/cert-manager/pkg/acme/client"
	cmapiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

type acceptChallenge struct {
	acmeClient acmecl.Interface
	recorder   record.EventRecorder
}

var _ syncStep = &acceptChallenge{}

func (o *acceptChallenge) Initialize(_ context.Context, state *syncState) error {
	o.acmeClient = state.acmeClient
	o.recorder = state.controller.recorder
	return nil
}

func (o *acceptChallenge) Evaluate(ctx context.Context, ch *cmacme.Challenge) (syncAction, error) {
	if allReadinessGateConditionsAreTrue(ch) {
		return nil, nil
	}
	return o, nil
}

func (o *acceptChallenge) Run(ctx context.Context, ch *cmacme.Challenge) error {
	log := logf.FromContext(ctx, "acceptChallenge")

	log.V(logf.DebugLevel).Info("accepting challenge with ACME server")
	// We manually construct an ACME challenge here from our own internal type
	// to save additional round trips to the ACME server.
	acmeChal := &acmeapi.Challenge{
		URI:   ch.Spec.URL,
		Token: ch.Spec.Token,
	}
	acmeChal, err := o.acmeClient.Accept(ctx, acmeChal)
	if acmeChal != nil {
		ch.Status.State = cmacme.State(acmeChal.Status)
	}
	if err != nil {
		log.Error(err, "error accepting challenge")
		ch.Status.Reason = fmt.Sprintf("Error accepting challenge: %v", err)
		return handleError(ch, err)
	}

	log.V(logf.DebugLevel).Info("waiting for authorization for domain")
	authorization, err := o.acmeClient.WaitAuthorization(ctx, ch.Spec.AuthorizationURL)
	if err != nil {
		log.Error(err, "error waiting for authorization")
		return o.handleAuthorizationError(ch, err)
	}

	ch.Status.State = cmacme.State(authorization.Status)
	ch.Status.Reason = "Successfully authorized domain"
	o.recorder.Eventf(ch, corev1.EventTypeNormal, reasonDomainVerified, "Domain %q verified with %q validation", ch.Spec.DNSName, ch.Spec.Type)

	return nil
}

func (o *acceptChallenge) handleAuthorizationError(ch *cmacme.Challenge, err error) error {
	authErr, ok := err.(*acmeapi.AuthorizationError)
	if !ok {
		return handleError(ch, err)
	}

	// TODO: the AuthorizationError above could technically contain the final
	//   state of the authorization in its raw JSON form. This isn't currently
	//   exposed by the ACME client implementation, so for now we fix this to
	//   'invalid' if the returned type here is an AuthorizationError, which
	//   should be safe as the client library only returns an AuthorizationError
	//   if the returned state is 'invalid'
	ch.Status.State = cmacme.Invalid
	ch.Status.Reason = fmt.Sprintf("Error accepting authorization: %v", authErr)
	o.recorder.Eventf(ch, corev1.EventTypeWarning, reasonFailed, "Accepting challenge authorization failed: %v", authErr)

	// return nil here, as accepting the challenge did not error, the challenge
	// simply failed
	return nil
}

func allReadinessGateConditionsAreTrue(ch *cmacme.Challenge) bool {
	allGatesPassed := true
	for _, gate := range ch.Spec.Solver.ReadinessGates {
		if !cmapiutil.ChallengeHasCondition(ch, cmacme.ChallengeCondition{
			Type:   cmacme.ChallengeConditionType(gate.ConditionType),
			Status: cmmeta.ConditionTrue,
		}) {
			allGatesPassed = false
			break
		}
	}
	return allGatesPassed
}
