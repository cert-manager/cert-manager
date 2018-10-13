/*
Copyright 2018 The Jetstack cert-manager contributors.

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
	"reflect"

	"github.com/golang/glog"
	corev1 "k8s.io/api/core/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	"github.com/jetstack/cert-manager/pkg/acme"
	acmecl "github.com/jetstack/cert-manager/pkg/acme/client"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	acmeapi "github.com/jetstack/cert-manager/third_party/crypto/acme"
)

const (
	reasonDomainVerified = "DomainVerified"
)

// solver solves ACME challenges by presenting the given token and key in an
// appropriate way given the config in the Issuer and Certificate.
type solver interface {
	// Present the challenge value with the given solver.
	Present(ctx context.Context, issuer cmapi.GenericIssuer, ch *cmapi.Challenge) error
	// Check should return Error only if propagation check cannot be performed.
	// It MUST return `false, nil` if can contact all relevant services and all is
	// doing is waiting for propagation
	Check(ch *cmapi.Challenge) (bool, error)
	// CleanUp will remove challenge records for a given solver.
	// This may involve deleting resources in the Kubernetes API Server, or
	// communicating with other external components (e.g. DNS providers).
	CleanUp(ctx context.Context, issuer cmapi.GenericIssuer, ch *cmapi.Challenge) error
}

// Sync will process this ACME Challenge.
// It is the core control function for ACME challenges, and handles:
// - TODO
func (c *Controller) Sync(ctx context.Context, ch *cmapi.Challenge) (err error) {
	oldChal := ch
	ch = ch.DeepCopy()

	defer func() {
		// TODO: replace with more efficient comparison
		if reflect.DeepEqual(oldChal.Status, ch.Status) {
			return
		}
		_, updateErr := c.CMClient.CertmanagerV1alpha1().Challenges(ch.Namespace).Update(ch)
		if err != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
		}
	}()

	// if a challenge is in a final state, we bail out early as there is nothing
	// left for us to do here.
	if acme.IsFinalState(ch.Status.State) {
		return nil
	}

	genericIssuer, err := c.helper.GetGenericIssuer(ch.Spec.IssuerRef, ch.Namespace)
	if err != nil {
		return fmt.Errorf("error reading (cluster)issuer %q: %v", ch.Spec.IssuerRef.Name, err)
	}

	cl, err := c.acmeHelper.ClientForIssuer(genericIssuer)
	if err != nil {
		return err
	}

	if ch.Status.State == "" {
		err := c.syncChallengeStatus(ctx, cl, ch)
		if err != nil {
			// TODO: check acme error types and potentially mark the challenge
			// as failed if there is some known error
			return err
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
			return err
		}

		ch.Status.Presented = true
	}

	ok, err := solver.Check(ch)
	if err != nil {
		return err
	}
	if !ok {
		ch.Status.Reason = fmt.Sprintf("Waiting for %s challenge propagation", ch.Spec.Type)
		return fmt.Errorf(ch.Status.Reason)
	}

	err = c.acceptChallenge(ctx, cl, ch)
	if err != nil {
		return err
	}

	glog.Infof("Cleaning up challenge %s/%s", ch.Namespace, ch.Name)
	err = solver.CleanUp(ctx, genericIssuer, ch)
	if err != nil {
		return err
	}

	return nil
}

// syncChallengeStatus will communicate with the ACME server to retrieve the current
// state of the Challenge. It will then update the Challenge's status block with the new
// state of the Challenge.
func (c *Controller) syncChallengeStatus(ctx context.Context, cl acmecl.Interface, ch *cmapi.Challenge) error {
	if ch.Spec.URL == "" {
		return fmt.Errorf("challenge URL is blank - challenge has not been created yet")
	}

	acmeChallenge, err := cl.GetChallenge(ctx, ch.Spec.URL)
	if err != nil {
		return err
	}

	// TODO: should we validate the State returned by the ACME server here?
	cmState := cmapi.State(acmeChallenge.Status)
	ch.Status.State = cmState

	return nil
}

// acceptChallenge will accept the challenge with the acme server and then wait
// for the authorization to reach a 'final' state.
// It will update the challenge's status to reflect the final state of the
// challenge if it failed, or the final state of the challenge's authorization
// if accepting the challenge succeeds.
func (c *Controller) acceptChallenge(ctx context.Context, cl acmecl.Interface, ch *cmapi.Challenge) error {
	glog.Infof("Accepting challenge for domain %q", ch.Spec.DNSName)
	// We manually construct an ACME challenge here from our own internal type
	// to save additional round trips to the ACME server.
	acmeChal := &acmeapi.Challenge{
		URL:   ch.Spec.URL,
		Token: ch.Spec.Token,
	}
	acmeChal, err := cl.AcceptChallenge(ctx, acmeChal)
	if acmeChal != nil {
		ch.Status.State = cmapi.State(acmeChal.Status)
	}
	if err != nil {
		glog.Infof("%s: Error accepting challenge: %v", ch.Name, err)
		ch.Status.Reason = fmt.Sprintf("Error accepting challenge: %v", err)
		return err
	}

	glog.Infof("Waiting for authorization for domain %q", ch.Spec.DNSName)
	authorization, err := cl.WaitAuthorization(ctx, ch.Spec.AuthzURL)
	if err != nil {
		authErr, ok := err.(acmeapi.AuthorizationError)
		if !ok {
			glog.Infof("%s: Unexpected error waiting for authorization: %v", ch.Name, err)
			return err
		}

		ch.Status.State = cmapi.State(authErr.Authorization.Status)
		ch.Status.Reason = fmt.Sprintf("Error accepting authorization: %v", authErr)

		// return nil here, as accepting the challenge did not error, the challenge
		// simply failed
		return nil
	}

	ch.Status.State = cmapi.State(authorization.Status)
	ch.Status.Reason = "Successfully authorized domain"
	c.Context.Recorder.Eventf(ch, corev1.EventTypeNormal, reasonDomainVerified, "Domain %q verified with %q validation", ch.Spec.DNSName, ch.Spec.Type)

	return nil
}

func (c *Controller) solverFor(challengeType string) (solver, error) {
	switch challengeType {
	case "http-01":
		return c.httpSolver, nil
	case "dns-01":
		return c.dnsSolver, nil
	}
	return nil, fmt.Errorf("no solver for %q implemented", challengeType)
}
