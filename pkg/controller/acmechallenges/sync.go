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
	"errors"
	"fmt"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	"github.com/cert-manager/cert-manager/pkg/acme"
	acmecl "github.com/cert-manager/cert-manager/pkg/acme/client"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/solver"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	acmeapi "github.com/cert-manager/cert-manager/third_party/forked/acme"
)

const (
	reasonDomainVerified = "DomainVerified"
	reasonCleanUpError   = "CleanUpError"
	reasonPresentError   = "PresentError"
	reasonPresented      = "Presented"
	reasonSolveError     = "SolveError"
	reasonSolved         = "Solved"
	reasonAcceptError    = "AcceptError"
	reasonAccepted       = "Accepted"
	reasonFailed         = "Failed"
)

// Sync is the core reconciliation function for ACME Challenge resources.
//
// Each call to Sync is responsible for performing **at most one step** in the challenge lifecycle.
// This includes steps such as status synchronization, presenting the challenge, verifying propagation,
// accepting the challenge, and checking final authorization.
//
// The lifecycle is split into distinct steps to ensure reconciliation remains atomic and observable.
// After performing a step, any change to the Challenge object (e.g., status updates) will trigger
// a re-reconciliation, allowing the controller to evaluate and proceed with the next step in the sequence.
//
// To support polling behaviors across different challenge phases (e.g., propagation checks or
// authorization polling), a `NextReconcile` timestamp is stored in the Challenge's status. This timestamp
// determines when the controller should requeue the object for the next polling attempt, and it enables
// fine-grained, step-specific backoff control.
//
// Only **terminal or retryable errors** are returned by this method. These are intended to trigger
// controller-runtime’s standard exponential backoff and are generally used for unexpected or fatal failures.
// In contrast, expected polling delays or re-checks (e.g., waiting for DNS propagation) are handled by
// setting `NextReconcile` and returning `nil`, ensuring consistent control flow and efficient retry handling.
//
// This structured approach guarantees eventual progress of the challenge lifecycle while avoiding duplicate
// solver execution or premature ACME calls.
func (c *controller) Sync(ctx context.Context, chOriginal *cmacme.Challenge) (err error) {
	log := logf.FromContext(ctx).WithValues("dnsName", chOriginal.Spec.DNSName, "type", chOriginal.Spec.Type)
	ctx = logf.NewContext(ctx, log)
	ch := chOriginal.DeepCopy()

	// When this function returns we update the challenge object with any
	// changes
	defer func() {
		if updateError := c.updateObject(ctx, chOriginal, ch); updateError != nil {
			if errors.Is(updateError, errArgument) {
				log.Error(updateError, "If this error occurs there is a bug in cert-manager. Please report it. Not retrying.")
				return
			}
			err = utilerrors.NewAggregate([]error{err, updateError})
		}
	}()

	// If the deletion timestamp is zero, we need to clean up and remove the
	// finalizer
	if !ch.DeletionTimestamp.IsZero() {
		return c.handleFinalizer(ctx, ch)
	}

	// Bail out early on if processing=false, as this challenge has not been
	// scheduled yet.
	if !ch.Status.Processing {
		return nil
	}

	// Remove legacy finalizer
	ch.Finalizers = slices.DeleteFunc(ch.Finalizers, func(finalizer string) bool {
		return finalizer == cmacme.ACMELegacyFinalizer
	})

	// This finalizer ensures that the challenge is not garbage collected before
	// cert-manager has a chance to clean up resources created for the
	// challenge.
	if finalizerRequired(ch) {
		ch.Finalizers = append(ch.Finalizers, cmacme.ACMEDomainQualifiedFinalizer)
		return nil
	}

	genericIssuer, err := c.helper.GetGenericIssuer(ch.Spec.IssuerRef, ch.Namespace)
	if err != nil {
		return fmt.Errorf("error reading (cluster)issuer %q: %v", ch.Spec.IssuerRef.Name, err)
	}

	solver, err := c.solverFor(ch.Spec.Type)
	if err != nil {
		return err
	}

	// if a challenge is in a final state, we bail out early as there is nothing
	// left for us to do here.
	if acme.IsFinalState(ch.Status.State) {
		if ch.Status.Presented {
			if err = solver.CleanUp(ctx, ch); err != nil {
				c.recorder.Eventf(ch, corev1.EventTypeWarning, reasonCleanUpError, "Error cleaning up challenge: %v", err)
				ch.Status.Reason = err.Error()
				log.Error(err, "error cleaning up challenge")
				return err
			}

			ch.Status.Presented = false
		}

		ch.Status.Processing = false
		return nil
	}

	cl, err := c.accountRegistry.GetClient(string(genericIssuer.GetUID()))
	if err != nil {
		return err
	}

	now := c.clock.Now()

	// Perform a single step, each step will update the status of the object
	// with its result
	switch {
	case c.shouldBackoff(now, ch):
		return c.stepBackoff(now, ch)
	case ch.Status.State == "":
		return c.stepSyncStatus(ctx, cl, ch)
	case !ch.Status.Presented:
		return c.stepPresent(ctx, solver, genericIssuer, ch)
	case !apiutil.ChallengeSolved(ch):
		return c.stepCheckPropagation(ctx, solver, genericIssuer, ch)
	case !apiutil.ChallengeAccepted(ch):
		return c.stepAcceptChallenge(ctx, cl, ch)
	default:
		return c.stepCheckAuthorization(ctx, cl, ch)
	}
}

func (c *controller) shouldBackoff(now time.Time, ch *cmacme.Challenge) bool {
	if ch.Status.NextReconcile != nil {
		if now.Before(ch.Status.NextReconcile.Time) {
			return true
		}

		// Reset NextReconcile
		ch.Status.NextReconcile = nil
	}

	return false
}

//nolint:unparam // error return is so it has the same signature to the other steps, linter complains it's always nil
func (c *controller) stepBackoff(now time.Time, ch *cmacme.Challenge) error {
	c.queue.AddAfter(types.NamespacedName{
		Namespace: ch.Namespace,
		Name:      ch.Name,
	}, ch.Status.NextReconcile.Time.Sub(now))
	return nil
}

func (c *controller) stepSyncStatus(ctx context.Context, cl acmecl.Interface, ch *cmacme.Challenge) error {
	err := c.syncChallengeStatus(ctx, cl, ch)
	if err != nil {
		return handleError(ctx, ch, err)
	}

	// if the state has not changed, return an error
	if ch.Status.State == "" {
		return fmt.Errorf("could not determine acme challenge status. retrying after applying back-off")
	}

	// the change in the challenges status will trigger a resync.
	// this ensures our cache is consistent so we don't call Present twice
	// due to the http01 solver creating resources that this controller
	// watches/syncs on
	return nil
}

func (c *controller) stepPresent(ctx context.Context, solver solver.Solver, issuer cmapi.GenericIssuer, ch *cmacme.Challenge) error {
	if err := solver.Present(ctx, issuer, ch); err != nil {
		// Update the status
		ch.Status.Reason = err.Error()
		apiutil.SetChallengeCondition(ch, cmacme.ChallengeConditionTypePresented, cmmeta.ConditionFalse,
			reasonPresentError, "Error presenting challenge: %v", err)

		// Emit an event
		c.recorder.Eventf(ch, corev1.EventTypeWarning, reasonPresentError, "Error presenting challenge: %v", err)

		return err
	}

	// Update the status
	ch.Status.Presented = true
	ch.Status.Reason = fmt.Sprintf("Presented challenge using %s challenge mechanism", ch.Spec.Type)
	apiutil.SetChallengeCondition(ch, cmacme.ChallengeConditionTypePresented, cmmeta.ConditionTrue,
		reasonPresented, "Presented challenge using %s challenge mechanism", ch.Spec.Type)

	// Emit an event
	c.recorder.Eventf(ch, corev1.EventTypeNormal, reasonPresented, "Presented challenge using %s challenge mechanism", ch.Spec.Type)

	return nil
}

func (c *controller) stepCheckPropagation(ctx context.Context, solver solver.Solver, issuer cmapi.GenericIssuer, ch *cmacme.Challenge) error {
	// Perform the check with the checker
	result, status, err := solver.Check(ctx, issuer, ch)
	if err != nil {
		return err
	}

	// Update the status based on the result of the checker
	ch.Status.Solver = status
	apiutil.SetChallengeCondition(ch, cmacme.ChallengeConditionTypeSolved,
		result.Status, result.Reason, "%s", result.Message)

	// Challenge has propagated
	if result.Status == cmmeta.ConditionTrue {
		ch.Status.Reason = fmt.Sprintf("Challenge propagated using %s challenge mechanism", ch.Spec.Type)
		c.recorder.Eventf(ch, corev1.EventTypeNormal, result.Reason, result.Message)
		return nil
	}

	// Update the global status
	ch.Status.Reason = fmt.Sprintf("Waiting for %s challenge propagation: %s", ch.Spec.Type, result.Message)

	// If the challenge has not yet propagated then either use the provided
	// retry, or the default.
	retryAfter := result.RetryAfter
	if retryAfter == 0 {
		retryAfter = c.DNS01CheckRetryPeriod
	}

	// By changing this value we will re-reconcile, which in turn will trigger
	// the code path to queue after a delay
	ch.Status.NextReconcile = &metav1.Time{Time: c.clock.Now().Add(retryAfter)}

	return nil
}

func (c *controller) stepAcceptChallenge(ctx context.Context, cl acmecl.Interface, ch *cmacme.Challenge) error {
	log := logf.FromContext(ctx, "acceptChallenge")
	ctx = logf.NewContext(ctx, log)

	log.V(logf.DebugLevel).Info("accepting challenge with ACME server")

	// We manually construct an ACME challenge here from our own internal type
	// to save additional round trips to the ACME server.
	acmeChal := &acmeapi.Challenge{
		URI:   ch.Spec.URL,
		Token: ch.Spec.Token,
	}

	// Accept the challenge
	acmeChal, err := cl.Accept(ctx, acmeChal)

	// Persist the state in the Challenge
	if acmeChal != nil {
		ch.Status.State = cmacme.State(acmeChal.Status)
	}

	// Error accepting the challenge
	if err != nil {
		log.Error(err, "error accepting challenge")

		ch.Status.Reason = fmt.Sprintf("Error accepting challenge: %v", err)
		apiutil.SetChallengeCondition(ch, cmacme.ChallengeConditionTypeAccepted, cmmeta.ConditionFalse,
			reasonAcceptError, "Error accepting challenge: %v", err)

		return handleError(ctx, ch, err)
	}

	// Update the condition, challenge has been accepted
	ch.Status.Reason = "Accepted challenge with ACME server"
	apiutil.SetChallengeCondition(ch, cmacme.ChallengeConditionTypeAccepted, cmmeta.ConditionTrue,
		reasonAccepted, "Accepted challenge with ACME server")

	return nil
}

func (c *controller) stepCheckAuthorization(ctx context.Context, cl acmecl.Interface, ch *cmacme.Challenge) error {
	log := logf.FromContext(ctx, "stepCheckAuthorization")
	ctx = logf.NewContext(ctx, log)

	log.V(logf.DebugLevel).Info("waiting for authorization for domain")
	authorization, err := cl.GetAuthorization(ctx, ch.Spec.AuthorizationURL)
	if err != nil {
		return handleError(ctx, ch, err)
	}

	// The original WaitAuthorization we used only checks for the StatusInvalid
	// and StatusValid.
	//
	// Since GetAuthorization now returns other status we mirror those back to
	// the challenge object. We also handle StatusPending by re-queueing the
	// object.
	switch authorization.Status {
	case acmeapi.StatusPending:
		// If RetryAfter is not provided we mirror the behavior of
		// WaitAuthorization and default to a second.
		retryAfter := authorization.RetryAfter
		if retryAfter == 0 {
			retryAfter = time.Second
		}

		log.V(logf.DebugLevel).Info("waiting for authorization", "retryAfter", retryAfter.String())
		ch.Status.State = cmacme.Pending
		ch.Status.NextReconcile = &metav1.Time{Time: c.clock.Now().Add(retryAfter)}
	case acmeapi.StatusInvalid:
		// Build synthetic error that mirrors what WaitAuthorization would
		// return when the state is "invalid". This means errors should be
		// consistent between this implementation and previous ones.
		authErr := &acmeapi.AuthorizationError{
			Identifier: authorization.Identifier.Value,
			URI:        authorization.URI,
			Errors:     nil,
		}

		for _, challenge := range authorization.Challenges {
			if challenge.Error != nil {
				authErr.Errors = append(authErr.Errors, challenge.Error)
			}
		}

		ch.Status.State = cmacme.Invalid
		ch.Status.Reason = fmt.Sprintf("Error accepting authorization: %v", authErr)
		c.recorder.Eventf(ch, corev1.EventTypeWarning, reasonFailed, "Accepting challenge authorization failed: %v", authErr)
	case acmeapi.StatusValid:
		ch.Status.State = cmacme.State(authorization.Status)
		ch.Status.Reason = "Successfully authorized domain"
		c.recorder.Eventf(ch, corev1.EventTypeNormal, reasonDomainVerified, "Domain %q verified with %q validation", ch.Spec.DNSName, ch.Spec.Type)
	default:
		return c.setStatusFromAuthorization(ch, authorization)
	}

	return nil
}

// handleError will handle ACME error types, updating the challenge resource
// with any new information found whilst inspecting the error response.
// This may include marking the challenge as expired.
func handleError(ctx context.Context, ch *cmacme.Challenge, err error) error {
	if err == nil {
		return nil
	}

	var acmeErr *acmeapi.Error
	var ok bool
	if acmeErr, ok = err.(*acmeapi.Error); !ok {
		ch.Status.State = cmacme.Errored
		ch.Status.Reason = fmt.Sprintf("unexpected non-ACME API error: %v", err)
		logf.FromContext(ctx).V(logf.ErrorLevel).Error(err, "unexpected non-ACME API error")
		return err
	}

	// This response type is returned when an authorization has expired or the
	// request is in some way malformed.
	// In this case, we should mark the challenge as expired so that the order
	// can be retried.
	// TODO: don't mark *all* malformed errors as expired, we may be able to be
	// more informative to the user by further inspecting the Error response.
	if acmeErr.ProblemType == "urn:ietf:params:acme:error:malformed" {
		ch.Status.State = cmacme.Expired
		// absorb the error as updating the challenge's status will trigger a sync
		return nil
	}

	if acmeErr.StatusCode >= 400 && acmeErr.StatusCode < 500 {
		ch.Status.State = cmacme.Errored
		ch.Status.Reason = fmt.Sprintf("Failed to retrieve Order resource: %v", err)
		return nil
	}

	return err
}

// handleFinalizer will attempt to 'finalize' the Challenge resource by calling
// CleanUp if the resource is in a 'processing' state.
func (c *controller) handleFinalizer(ctx context.Context, ch *cmacme.Challenge) (err error) {
	log := logf.FromContext(ctx, "finalizer")
	if len(ch.Finalizers) == 0 {
		return nil
	}
	if otherFinalizerPresent(ch) {
		log.V(logf.DebugLevel).Info("waiting to run challenge finalization...")
		return nil
	}

	defer func() {
		// call Update to remove the metadata.finalizers entry
		ch.Finalizers = slices.DeleteFunc(ch.Finalizers, func(finalizer string) bool {
			return finalizer == cmacme.ACMEDomainQualifiedFinalizer || finalizer == cmacme.ACMELegacyFinalizer
		})
	}()

	if !ch.Status.Processing {
		return nil
	}

	solver, err := c.solverFor(ch.Spec.Type)
	if err != nil {
		log.Error(err, "error getting solver for challenge")
		return nil
	}

	err = solver.CleanUp(ctx, ch)
	if err != nil {
		c.recorder.Eventf(ch, corev1.EventTypeWarning, reasonCleanUpError, "Error cleaning up challenge: %v", err)
		ch.Status.Reason = err.Error()
		log.Error(err, "error cleaning up challenge")
		return nil
	}

	return nil
}

// syncChallengeStatus will communicate with the ACME server to retrieve the current
// state of the Challenge. It will then update the Challenge's status block with the new
// state of the Challenge.
func (c *controller) syncChallengeStatus(ctx context.Context, cl acmecl.Interface, ch *cmacme.Challenge) error {
	if ch.Spec.URL == "" {
		return fmt.Errorf("challenge URL is blank - challenge has not been created yet")
	}

	// Here we GetAuthorization and prune out the Challenge we are concerned with
	// to gather the current state of the Challenge. In older versions of
	// cert-manager we called the Challenge endpoint directly using a POST-as-GET
	// request (GetChallenge). This caused issues with some ACME server
	// implementations whereby they either interpreted this call as an Accept
	// which would invalidate the Order as Challenge resources were not ready yet
	// to complete the Challenge, or otherwise bork their state machines.
	// While the ACME RFC[1] is left ambiguous as to whether this call is indeed
	// supported, it is the general consensus by the cert-manager team that it
	// should be. In any case, in an effort to support as many current and future
	// ACME server implementations as possible, we have decided to use a
	// POST-as-GET to the Authorization endpoint instead which unequivocally is
	// part of the RFC explicitly.
	// This issue was brought to the RFC mailing list[2].
	// [1] - https://datatracker.ietf.org/doc/html/rfc8555#section-7.5.1
	// [2] - https://mailarchive.ietf.org/arch/msg/acme/NknXHBXl3aRG0nBmgsFH-SP90A4/
	acmeAuthorization, err := cl.GetAuthorization(ctx, ch.Spec.AuthorizationURL)
	if err != nil {
		return err
	}

	return c.setStatusFromAuthorization(ch, acmeAuthorization)
}

func (c *controller) setStatusFromAuthorization(ch *cmacme.Challenge, acmeAuthorization *acmeapi.Authorization) error {
	var acmeChallenge *acmeapi.Challenge
	for _, challenge := range acmeAuthorization.Challenges {
		if challenge.URI == ch.Spec.URL {
			acmeChallenge = challenge
			break
		}
	}

	if acmeChallenge == nil {
		return errors.New("challenge was not present in authorization")
	}

	// TODO: should we validate the State returned by the ACME server here?
	cmState := cmacme.State(acmeChallenge.Status)
	// be nice to our users and check if there is an error that we
	// can tell them about in the reason field
	// TODO(dmo): problems may be compound and they may be tagged with
	// a type field that suggests changes we should make (like provisioning
	// an account). We might be able to handle errors more gracefully using
	// this info
	ch.Status.Reason = ""
	if acmeChallenge.Error != nil {
		if acmeErr, ok := acmeChallenge.Error.(*acmeapi.Error); ok {
			ch.Status.Reason = acmeErr.Detail
		} else {
			ch.Status.Reason = acmeChallenge.Error.Error()
		}
	}

	ch.Status.State = cmState

	return nil
}

func (c *controller) solverFor(challengeType cmacme.ACMEChallengeType) (solver.Solver, error) {
	switch challengeType {
	case cmacme.ACMEChallengeTypeHTTP01:
		return c.httpSolver, nil
	case cmacme.ACMEChallengeTypeDNS01:
		return c.dnsSolver, nil
	}
	return nil, fmt.Errorf("no solver for %q implemented", challengeType)
}
