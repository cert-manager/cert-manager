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

	acmeapi "golang.org/x/crypto/acme"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	internalchallenges "github.com/cert-manager/cert-manager/internal/controller/challenges"
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
	CleanUp(ctx context.Context, issuer cmapi.GenericIssuer, ch *cmacme.Challenge) error
}

// Sync will process this ACME Challenge.
// It is the core control function for ACME challenges.
func (c *controller) Sync(ctx context.Context, ch *cmacme.Challenge) (err error) {
	log := logf.FromContext(ctx).WithValues("dnsName", ch.Spec.DNSName, "type", ch.Spec.Type)
	ctx = logf.NewContext(ctx, log)

	oldChal := ch
	ch = ch.DeepCopy()

	if ch.DeletionTimestamp != nil {
		return c.handleFinalizer(ctx, ch)
	}

	defer func() {
		if apiequality.Semantic.DeepEqual(oldChal.Status, ch.Status) {
			return
		}
		if _, updateErr := c.updateStatusOrApply(ctx, ch); updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
		}
	}()

	// bail out early on if processing=false, as this challenge has not been
	// scheduled yet.
	if !ch.Status.Processing {
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

			err = solver.CleanUp(ctx, genericIssuer, ch)
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
			err := dnsutil.ValidateCAA(ch.Spec.DNSName, dir.CAA, ch.Spec.Wildcard, c.dns01Nameservers)
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
	challengeWithRuntimeDefaults := copyOfChallengeWithDefaultsApplied(ch)
	syncState := &syncState{
		controller: c,
		challenge:  challengeWithRuntimeDefaults,
		acmeClient: cl,
		solver:     solver,
		issuer:     genericIssuer,
	}

	syncSteps := []syncStep{
		// &waitToBeScheduled{},
		&presentChallenge{},
		&checkChallengeReadiness{},
		&acceptChallenge{},
		// &waitForACMEResult{},
		// &cleanupChallenge{},
	}

	for _, step := range syncSteps {
		log = log.WithValues("step", fmt.Sprintf("%T", step))
		if err := step.Initialize(ctx, syncState); err != nil {
			log.Error(err, "Unable to initialize sync step")
			return nil
		}
		action, err := step.Evaluate(ctx, challengeWithRuntimeDefaults)
		if err != nil {
			log.Error(err, "Unable to evaluate sync step. Retrying.")
			return err
		}
		if action == nil {
			log.Info("Step has already been run. Skipping.")
			continue
		}
		if err := action.Run(ctx, ch); err != nil {
			log.Error(err, "Unable to run sync step. Retrying.")
			return err
		}
		return nil
	}
	return nil
}

type syncState struct {
	controller *controller
	challenge  *cmacme.Challenge
	acmeClient acmecl.Interface
	solver     solver
	issuer     cmapi.GenericIssuer
}

type syncAction interface {
	Run(context.Context, *cmacme.Challenge) error
}

type syncStep interface {
	Initialize(context.Context, *syncState) error
	Evaluate(context.Context, *cmacme.Challenge) (syncAction, error)
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
		return err
	}
	switch acmeErr.ProblemType {
	// This response type is returned when an authorization has expired or the
	// request is in some way malformed.
	// In this case, we should mark the challenge as expired so that the order
	// can be retried.
	// TODO: don't mark *all* malformed errors as expired, we may be able to be
	// more informative to the user by further inspecting the Error response.
	case "urn:ietf:params:acme:error:malformed":
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
	if ch.Finalizers[0] != cmacme.ACMEFinalizer {
		log.V(logf.DebugLevel).Info("waiting to run challenge finalization...")
		return nil
	}

	defer func() {
		// call UpdateStatus first as we may have updated the challenge.status.reason field
		ch, updateErr := c.updateStatusOrApply(ctx, ch)
		if updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
			return
		}
		// call Update to remove the metadata.finalizers entry
		ch.Finalizers = ch.Finalizers[1:]
		_, updateErr = c.updateOrApply(ctx, ch)
		if updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
			return
		}
	}()

	if !ch.Status.Processing {
		return nil
	}

	genericIssuer, err := c.helper.GetGenericIssuer(ch.Spec.IssuerRef, ch.Namespace)
	if err != nil {
		return fmt.Errorf("error reading (cluster)issuer %q: %v", ch.Spec.IssuerRef.Name, err)
	}

	solver, err := c.solverFor(ch.Spec.Type)
	if err != nil {
		log.Error(err, "error getting solver for challenge")
		return nil
	}

	err = solver.CleanUp(ctx, genericIssuer, ch)
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

func (c *controller) solverFor(challengeType cmacme.ACMEChallengeType) (solver, error) {
	switch challengeType {
	case cmacme.ACMEChallengeTypeHTTP01:
		return c.httpSolver, nil
	case cmacme.ACMEChallengeTypeDNS01:
		return c.dnsSolver, nil
	}
	return nil, fmt.Errorf("no solver for %q implemented", challengeType)
}

func (c *controller) updateOrApply(ctx context.Context, challenge *cmacme.Challenge) (*cmacme.Challenge, error) {
	if utilfeature.DefaultFeatureGate.Enabled(feature.ServerSideApply) {
		return internalchallenges.Apply(ctx, c.cmClient, c.fieldManager, challenge)
	} else {
		return c.cmClient.AcmeV1().Challenges(challenge.Namespace).Update(ctx, challenge, metav1.UpdateOptions{})
	}
}

func (c *controller) updateStatusOrApply(ctx context.Context, challenge *cmacme.Challenge) (*cmacme.Challenge, error) {
	if utilfeature.DefaultFeatureGate.Enabled(feature.ServerSideApply) {
		return internalchallenges.ApplyStatus(ctx, c.cmClient, c.fieldManager, challenge)
	} else {
		return c.cmClient.AcmeV1().Challenges(challenge.Namespace).UpdateStatus(ctx, challenge, metav1.UpdateOptions{})
	}
}
