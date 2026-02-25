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
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/digitalocean/godo"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cert-manager/cert-manager/pkg/acme"
	acmecl "github.com/cert-manager/cert-manager/pkg/acme/client"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	acmeapi "github.com/cert-manager/cert-manager/third_party/forked/acme"
)

const (
	reasonDomainVerified = "DomainVerified"
	reasonCleanUpError   = "CleanUpError"
	reasonPresentError   = "PresentError"
	reasonPresented      = "Presented"
	reasonFailed         = "Failed"

	// How long to wait for an authorization response from the ACME server in acceptChallenge()
	// before giving up
	authorizationTimeout = 2 * time.Minute
)

var solverResourceNamePattern = regexp.MustCompile(`cm-acme-http-solver-[a-z0-9]+`)

// solver solves ACME challenges by presenting the given token and key in an
// appropriate way given the config in the Issuer and Certificate.
type solver interface {
	// Present the challenge value with the given solver.
	Present(ctx context.Context, issuer cmapi.GenericIssuer, ch *cmacme.Challenge) error
	// Check returns an Error if the propagation check didn't succeed.
	Check(ctx context.Context, issuer cmapi.GenericIssuer, ch *cmacme.Challenge) error
	// CleanUp will remove challenge records for a given solver.
	// This may involve deleting resources in the Kubernetes API Server, or
	// communicating with other external components (e.g., DNS providers).
	CleanUp(ctx context.Context, ch *cmacme.Challenge) error
}

// Sync will process this ACME Challenge.
// It is the core control function for ACME challenges.
func (c *controller) Sync(ctx context.Context, chOriginal *cmacme.Challenge) (err error) {
	log := logf.FromContext(ctx).WithValues("dnsName", chOriginal.Spec.DNSName, "type", chOriginal.Spec.Type)
	ctx = logf.NewContext(ctx, log)
	ch := chOriginal.DeepCopy()

	defer func() {
		if updateError := c.updateObject(ctx, chOriginal, ch); updateError != nil {
			if errors.Is(updateError, errArgument) {
				log.Error(updateError, "If this error occurs there is a bug in cert-manager. Please report it. Not retrying.")
				return
			}
			err = utilerrors.NewAggregate([]error{err, updateError})
		}
	}()

	// If the challenge has been deleted or is in a finished state then attempt
	// to cleanup any presented resources, remove the finalizer and reset the
	// processing and presented status fields.
	// Once the challenge reaches this final state, we always return here.
	challengeFinished := !ch.DeletionTimestamp.IsZero() || acme.IsFinalState(ch.Status.State)
	if challengeFinished {
		if finalizers := sets.New(ch.Finalizers...); finalizers.Has(cmacme.ACMELegacyFinalizer) ||
			finalizers.Has(cmacme.ACMEDomainQualifiedFinalizer) {
			// the resource still has ACME finalizers, we attempt to finalize the resource
			// by calling CleanUp and then remove the finalizers if successful
			if err := c.finalize(ctx, ch); err != nil {
				return err
			}

			// remove the ACME finalizers since cleanup has been completed successfully
			ch.Finalizers = slices.DeleteFunc(ch.Finalizers, func(finalizer string) bool {
				return finalizer == cmacme.ACMELegacyFinalizer || finalizer == cmacme.ACMEDomainQualifiedFinalizer
			})
		}

		ch.Status.Presented = false
		ch.Status.Processing = false

		return nil
	}

	// bail out early on if processing=false, as this challenge has not been
	// scheduled yet or has finished.
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
	if finalizers := sets.New(ch.Finalizers...); !finalizers.Has(cmacme.ACMEDomainQualifiedFinalizer) {
		ch.Finalizers = append(ch.Finalizers, cmacme.ACMEDomainQualifiedFinalizer)
		return nil
	}

	genericIssuer, err := c.helper.GetGenericIssuer(ch.Spec.IssuerRef, ch.Namespace)
	if err != nil {
		return fmt.Errorf("error reading (cluster)issuer %q: %v", ch.Spec.IssuerRef.Name, err)
	}

	cl, err := c.accountRegistry.GetClient(string(genericIssuer.GetUID()))
	if err != nil {
		return err
	}

	if ch.Status.State == "" {
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

	solver, err := c.solverFor(ch.Spec.Type)
	if err != nil {
		return err
	}

	if !ch.Status.Presented {
		err := solver.Present(ctx, genericIssuer, ch)
		if err != nil {
			c.recorder.Eventf(ch, corev1.EventTypeWarning, reasonPresentError, "Error presenting challenge: %v", err)
			// stabilize the error message to avoid spurious updates which would
			// cause repeated reconciles
			ch.Status.Reason = stabilizeSolverErrorMessage(err)
			return err
		}

		ch.Status.Presented = true
		c.recorder.Eventf(ch, corev1.EventTypeNormal, reasonPresented, "Presented challenge using %s challenge mechanism", ch.Spec.Type)
	}

	err = solver.Check(ctx, genericIssuer, ch)
	if err != nil {
		log.Error(err, "propagation check failed")
		ch.Status.Reason = fmt.Sprintf("Waiting for %s challenge propagation: %s", ch.Spec.Type, err)

		c.queue.AddAfter(types.NamespacedName{
			Namespace: ch.Namespace,
			Name:      ch.Name,
		}, c.DNS01CheckRetryPeriod)

		return nil
	}

	err = c.acceptChallenge(ctx, cl, ch)
	if err != nil {
		return err
	}

	return nil
}

// stabilizeSolverErrorMessage will attempt to remove any unique IDs from the given
// error message so that it can be assigned to the Challenge.Status.Reason
// field without causing spurious updates.
//
// For example,
// - Azure SDK returns the contents of the HTTP requests in its error messages.
// - AWS SDK adds request UIDs to its error messages.
// - DigitalOcean SDK adds request UIDs to its error messages.
//
// TODO(wallrj): Ideally this would not be necessary. It should be possible to
// add the unique error message to the status without triggering another
// reconcile.
//
// TODO(wallrj): This won't work if one of the unstable errors is wrapped inside
// another unstable error, because we only unwrap the first instance and the
// strings.ReplaceAll calls won't find it. At time of wriging none of the DNS
// SDKs returns nested unstable errors, so we do not expect this to be a problem
// in practice.
func stabilizeSolverErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	fullMessage := err.Error()
	{
		var target *awshttp.ResponseError
		if errors.As(err, &target) {
			fullMessage = strings.ReplaceAll(
				fullMessage,
				target.Error(),
				"<redacted AWS SDK error: http.ResponseError: see events and logs for details>",
			)
		}
	}
	{
		var target *azidentity.AuthenticationFailedError
		if errors.As(err, &target) {
			fullMessage = strings.ReplaceAll(
				fullMessage,
				target.Error(),
				"<redacted Azure SDK error: azidentity.AuthenticationFailedError: see events and logs for details>",
			)
		}
	}
	{
		var target *azcore.ResponseError
		if errors.As(err, &target) {
			fullMessage = strings.ReplaceAll(
				fullMessage,
				target.Error(),
				"<redacted Azure SDK error: azcore.ResponseError: see events and logs for details>",
			)
		}
	}
	{
		var target *godo.ErrorResponse
		if errors.As(err, &target) {
			fullMessage = strings.ReplaceAll(
				fullMessage,
				target.Error(),
				"<redacted DigitalOcean SDK error: godo.ErrorResponse: see events and logs for details>",
			)
		}
	}
	fullMessage = solverResourceNamePattern.ReplaceAllString(fullMessage, "cm-acme-http-solver-<redacted>")
	return fullMessage
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

// finalize will attempt to 'finalize' the Challenge resource by calling CleanUp
func (c *controller) finalize(ctx context.Context, ch *cmacme.Challenge) (err error) {
	log := logf.FromContext(ctx, "finalizer")

	solver, err := c.solverFor(ch.Spec.Type)
	if err != nil {
		log.Error(err, "error getting solver for challenge")
		return err
	}

	err = solver.CleanUp(ctx, ch)
	if err != nil {
		err := fmt.Errorf("Error cleaning up challenge: %v", err)
		c.recorder.Eventf(ch, corev1.EventTypeWarning, reasonCleanUpError, err.Error())
		// stabilize the error message to avoid spurious updates which would
		// cause repeated reconciles
		ch.Status.Reason = stabilizeSolverErrorMessage(err)
		log.Error(err, "error cleaning up challenge")
		return err
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

// acceptChallenge will accept the challenge with the acme server and then wait
// for the authorization to reach a 'final' state.
// It will update the challenge's status to reflect the final state of the
// challenge if it failed, or the final state of the challenge's authorization
// if accepting the challenge succeeds.
func (c *controller) acceptChallenge(ctx context.Context, cl acmecl.Interface, ch *cmacme.Challenge) error {
	log := logf.FromContext(ctx, "acceptChallenge")

	log.V(logf.DebugLevel).Info("accepting challenge with ACME server")
	// We manually construct an ACME challenge here from our own internal type
	// to save additional round trips to the ACME server.
	acmeChal := &acmeapi.Challenge{
		URI:   ch.Spec.URL,
		Token: ch.Spec.Token,
	}
	acmeChal, err := cl.Accept(ctx, acmeChal)
	if acmeChal != nil {
		ch.Status.State = cmacme.State(acmeChal.Status)
	}
	if err != nil {
		log.Error(err, "error accepting challenge")
		ch.Status.Reason = fmt.Sprintf("Error accepting challenge: %v", err)
		return handleError(ctx, ch, err)
	}

	log.V(logf.DebugLevel).Info("waiting for authorization for domain")
	// The underlying ACME implementation from golang.org/x/crypto of WaitAuthorization retries on
	// response parsing errors.  In the event that an ACME server is not returning expected JSON
	// responses, the call to WaitAuthorization can and has been seen to not return and loop forever,
	// blocking the challenge's processing. Here, we defensively add a timeout for this exchange
	// with the ACME server and a "context deadline reached" error will be returned by WaitAuthorization
	// in the err variable.
	ctxTimeout, cancelAuthorization := context.WithTimeout(ctx, authorizationTimeout)
	defer cancelAuthorization()
	authorization, err := cl.WaitAuthorization(ctxTimeout, ch.Spec.AuthorizationURL)
	if err != nil {
		log.Error(err, "error waiting for authorization")
		return c.handleAuthorizationError(ctxTimeout, ch, err)
	}

	ch.Status.State = cmacme.State(authorization.Status)
	ch.Status.Reason = "Successfully authorized domain"
	c.recorder.Eventf(ch, corev1.EventTypeNormal, reasonDomainVerified, "Domain %q verified with %q validation", ch.Spec.DNSName, ch.Spec.Type)

	return nil
}

func (c *controller) handleAuthorizationError(ctx context.Context, ch *cmacme.Challenge, err error) error {
	authErr, ok := err.(*acmeapi.AuthorizationError)
	if !ok {
		return handleError(ctx, ch, err)
	}

	// TODO: the AuthorizationError above could technically contain the final
	//   state of the authorization in its raw JSON form. This isn't currently
	//   exposed by the ACME client implementation, so for now we fix this to
	//   'invalid' if the returned type here is an AuthorizationError, which
	//   should be safe as the client library only returns an AuthorizationError
	//   if the returned state is 'invalid'
	ch.Status.State = cmacme.Invalid
	ch.Status.Reason = fmt.Sprintf("Error accepting authorization: %v", authErr)
	c.recorder.Eventf(ch, corev1.EventTypeWarning, reasonFailed, "Accepting challenge authorization failed: %v", authErr)

	// return nil here, as accepting the challenge did not error, the challenge
	// simply failed
	return nil
}

func (c *controller) solverFor(challengeType cmacme.ACMEChallengeType) (solver, error) {
	switch challengeType {
	case cmacme.ACMEChallengeTypeHTTP01:
		return c.httpSolver, nil
	case cmacme.ACMEChallengeTypeDNS01:
		return c.dnsSolver, nil
	}
	return nil, fmt.Errorf("no solver for %q implemented", challengeType)
}
