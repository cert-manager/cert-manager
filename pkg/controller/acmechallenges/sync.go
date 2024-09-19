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

	acmeapi "golang.org/x/crypto/acme"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	"github.com/cert-manager/cert-manager/internal/controller/feature"
	"github.com/cert-manager/cert-manager/pkg/acme"
	acmecl "github.com/cert-manager/cert-manager/pkg/acme/client"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	dnsutil "github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
)

const (
	reasonDomainVerified = "DomainVerified"
	reasonCleanUpError   = "CleanUpError"
	reasonPresentError   = "PresentError"
	reasonPresented      = "Presented"
	reasonFailed         = "Failed"

	// How long to wait for an authorization response from the ACME server in acceptChallenge()
	// before giving up
	authorizationTimeout = 20 * time.Second
)

// solver solves ACME challenges by presenting the given token and key in an
// appropriate way given the config in the Issuer and Certificate.
type solver interface {
	// Present the challenge value with the given solver.
	Present(ctx context.Context, issuer cmapi.GenericIssuer, ch *cmacme.Challenge) error
	// Check returns an Error if the propagation check didn't succeed.
	Check(ctx context.Context, issuer cmapi.GenericIssuer, ch *cmacme.Challenge) error
	// CleanUp will remove challenge records for a given solver.
	// This may involve deleting resources in the Kubernetes API Server, or
	// communicating with other external components (e.g. DNS providers).
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
			if errors.Is(updateError, argumentError) {
				log.Error(updateError, "If this error occurs there is a bug in cert-manager. Please report it. Not retrying.")
				return
			}
			err = utilerrors.NewAggregate([]error{err, updateError})
		}
	}()

	if !ch.DeletionTimestamp.IsZero() {
		return c.handleFinalizer(ctx, ch)
	}

	// bail out early on if processing=false, as this challenge has not been
	// scheduled yet.
	if !ch.Status.Processing {
		return nil
	}

	// This finalizer ensures that the challenge is not garbage collected before
	// cert-manager has a chance to clean up resources created for the
	// challenge.
	//
	// API Transition
	// -- Until UseDomainQualifiedFinalizer is active, we add cmacme.ACMELegacyFinalizer.
	// -- When it is active we add cmacme.ACMEDomainQualifiedFinalizer instead.
	//
	// -- Both finalizers are supported, the flag just controls the one we add.
	//
	// -- We only need to add a finalizer label if no supported finalizer label is present.
	if finalizerRequired(ch) {
		finalizer := cmacme.ACMELegacyFinalizer
		if utilfeature.DefaultFeatureGate.Enabled(feature.UseDomainQualifiedFinalizer) {
			finalizer = cmacme.ACMEDomainQualifiedFinalizer
		}
		ch.Finalizers = append(ch.Finalizers, finalizer)
		return nil
	}

	genericIssuer, err := c.helper.GetGenericIssuer(ch.Spec.IssuerRef, ch.Namespace)
	if err != nil {
		return fmt.Errorf("error reading (cluster)issuer %q: %v", ch.Spec.IssuerRef.Name, err)
	}

	// if a challenge is in a final state, we bail out early as there is nothing
	// left for us to do here.
	if acme.IsFinalState(ch.Status.State) {
		if ch.Status.Presented {
			solver, err := c.solverFor(ch.Spec.Type)
			if err != nil {
				log.Error(err, "error getting solver for challenge")
				return err
			}

			err = solver.CleanUp(ctx, ch)
			if err != nil {
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

	if ch.Status.State == "" {
		err := c.syncChallengeStatus(ctx, cl, ch)
		if err != nil {
			return handleError(ch, err)
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

	if utilfeature.DefaultFeatureGate.Enabled(feature.ValidateCAA) {
		// check for CAA records.
		// CAA records are static, so we don't have to present anything
		// before we check for them.

		// Find out which identity the ACME server says it will use.
		dir, err := cl.Discover(ctx)
		if err != nil {
			return handleError(ch, err)
		}
		// TODO(dmo): figure out if missing CAA identity in directory
		// means no CAA check is performed by ACME server or if any valid
		// CAA would stop issuance (strongly suspect the former)
		if len(dir.CAA) != 0 {
			err := dnsutil.ValidateCAA(ctx, ch.Spec.DNSName, dir.CAA, ch.Spec.Wildcard, c.dns01Nameservers)
			if err != nil {
				ch.Status.Reason = fmt.Sprintf("CAA self-check failed: %s", err)
				return err
			}
		}
	}

	solver, err := c.solverFor(ch.Spec.Type)
	if err != nil {
		return err
	}

	if !ch.Status.Presented {
		err := solver.Present(ctx, genericIssuer, ch)
		if err != nil {
			c.recorder.Eventf(ch, corev1.EventTypeWarning, reasonPresentError, "Error presenting challenge: %v", err)
			ch.Status.Reason = err.Error()
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

// handleError will handle ACME error types, updating the challenge resource
// with any new information found whilst inspecting the error response.
// This may include marking the challenge as expired.
func handleError(ch *cmacme.Challenge, err error) error {
	if err == nil {
		return nil
	}

	var acmeErr *acmeapi.Error
	var ok bool
	if acmeErr, ok = err.(*acmeapi.Error); !ok {
		ch.Status.State = cmacme.Errored
		ch.Status.Reason = fmt.Sprintf("unexpected non-ACME API error: %v", err)
		logf.V(logf.ErrorLevel).ErrorS(err, "unexpected non-ACME API error")
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
			return finalizer == cmacme.ACMELegacyFinalizer || finalizer == cmacme.ACMEDomainQualifiedFinalizer
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
		return handleError(ch, err)
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
		return c.handleAuthorizationError(ch, err)
	}

	ch.Status.State = cmacme.State(authorization.Status)
	ch.Status.Reason = "Successfully authorized domain"
	c.recorder.Eventf(ch, corev1.EventTypeNormal, reasonDomainVerified, "Domain %q verified with %q validation", ch.Spec.DNSName, ch.Spec.Type)

	return nil
}

func (c *controller) handleAuthorizationError(ch *cmacme.Challenge, err error) error {
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
