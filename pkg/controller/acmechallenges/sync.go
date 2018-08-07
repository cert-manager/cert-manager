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
	if acme.IsFinalState(ch.Status.State) || ch.Status.State == cmapi.Valid {
		return nil
	}

	acmeHelper := &acme.Helper{
		SecretLister:             c.secretLister,
		ClusterResourceNamespace: c.Context.ClusterResourceNamespace,
	}

	genericIssuer, err := c.helper.GetGenericIssuer(ch.Spec.IssuerRef, ch.Namespace)
	if err != nil {
		return fmt.Errorf("error reading (cluster)issuer %q: %v", ch.Spec.IssuerRef.Name, err)
	}

	cl, err := acmeHelper.ClientForIssuer(genericIssuer)
	if err != nil {
		return err
	}

	if ch.Status.State == "" {
		err := c.syncChallengeStatus(ctx, cl, ch)
		if err != nil {
			return err
		}

		// we reperform the check from above now that we have updated the status
		// if a challenge is in a final state, we bail out early as there is nothing
		// left for us to do here.
		if acme.IsFinalState(ch.Status.State) || ch.Status.State == cmapi.Valid {
			return nil
		}
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
		ch.Status.Reason = fmt.Sprintf("Self check failed - %s challenge still propagating. Will retry after applying back-off.", ch.Spec.Type)
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

// presentChallenge will process a challenge by talking to the acme server and
// obtaining up to date status information.
// If the challenge is still in a pending state, it will first check propagation
// status of a challenge from previous attempt, and if missing it will 'present' the
// new challenge using the appropriate solver.
// If the check fails, an error will be returned.
// Otherwise, it will return nil.
func (c *Controller) presentChallenge(ctx context.Context, issuer cmapi.GenericIssuer, ch *cmapi.Challenge) error {
	solver, err := c.solverFor(ch.Spec.Type)
	if err != nil {
		return err
	}

	// TODO: make sure that solver.Present is noop if challenge
	//       is already present and all we do is waiting for propagation,
	//       otherwise it is spamming with errors which are not really erros
	//       as we are just waiting for propagation
	err = solver.Present(ctx, issuer, ch)
	if err != nil {
		return err
	}

	ch.Status.Presented = true

	// We return an error here instead of nil, as the only way for 'presentChallenge'
	// to return without error is if the self check passes, which we check above.
	return nil
}

func (c *Controller) acceptChallenge(ctx context.Context, cl acmecl.Interface, ch *cmapi.Challenge) error {
	glog.Infof("Accepting challenge for domain %q", ch.Spec.DNSName)
	// We manually construct an ACME challenge here from our own internal type
	// to save additional round trips to the ACME server.
	acmeChal := &acmeapi.Challenge{
		URL:   ch.Spec.URL,
		Token: ch.Spec.Token,
	}
	acmeChal, err := cl.AcceptChallenge(ctx, acmeChal)
	if err != nil {
		ch.Status.State = cmapi.State(acmeChal.Status)
		if acmeErr, ok := err.(*acmeapi.Error); ok {
			ch.Status.Reason = fmt.Sprintf("Error accepting challenge: %v", acmeErr)
		}
		return err
	}

	glog.Infof("Waiting for authorization for domain %q", ch.Spec.DNSName)
	authorization, err := cl.WaitAuthorization(ctx, ch.Spec.AuthzURL)
	if err != nil {
		ch.Status.State = cmapi.State(authorization.Status)
		if acmeErr, ok := err.(*acmeapi.Error); ok {
			ch.Status.Reason = fmt.Sprintf("Error accepting challenge: %v", acmeErr)
		}
		return err
	}

	ch.Status.State = cmapi.State(authorization.Status)

	if authorization.Status != acmeapi.StatusValid {
		ch.Status.Reason = fmt.Sprintf("Authorization status is %q and not 'valid'", authorization.Status)
		return fmt.Errorf("expected acme domain authorization status for %q to be valid, but it is %q", authorization.Identifier.Value, authorization.Status)
	}

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
