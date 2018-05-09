package acme

import (
	"context"
	"fmt"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/golang/glog"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/client"
	"github.com/jetstack/cert-manager/third_party/crypto/acme"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
)

const (
	reasonCreateOrder    = "CreateOrder"
	reasonDomainVerified = "DomainVerified"
	reasonSelfCheck      = "SelfCheck"

	errorInvalidConfig = "InvalidConfig"
	errorCleanupError  = "CleanupError"
	errorValidateError = "ValidateError"
	errorBackoff       = "Backoff"

	messagePresentChallenge = "Presenting %s challenge for domain %s"
	messageSelfCheck        = "Performing self-check for domain %s"

	// the amount of time to wait before attempting to create a new order after
	// an order has failed.s
	prepareAttemptWaitPeriod = time.Minute * 5
)

// Prepare will ensure the issuer has been initialised and is ready to issue
// certificates for the domains listed on the Certificate resource.
//
// It will send the appropriate Letsencrypt authorizations, and complete
// challenge requests if neccessary.
func (a *Acme) Prepare(ctx context.Context, crt *v1alpha1.Certificate) error {
	if crt.Spec.ACME == nil {
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorInvalidConfig, "spec.acme must be specified", false)
		return fmt.Errorf("spec.acme not specified on certificate %s/%s", crt.Namespace, crt.Name)
	}

	glog.V(4).Infof("Getting ACME client")
	// obtain an ACME client
	cl, err := a.acmeClient()
	if err != nil {
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorValidateError, fmt.Sprintf("Failed to get ACME client: %v", err), false)
		return err
	}

	// Determine how long until we should attempt validation again.
	// We perform this near the start of the function to reduce calls to the
	// acme server.
	nextPresentIn, order, err := a.shouldAttemptValidation(ctx, cl, crt)
	if err != nil {
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorValidateError, fmt.Sprintf("Failed to determine order status: %v", err), false)
		return err
	}

	// If the order here is nil, the last order must have failed or there was
	// not one previously. Either way, we should clean up the ACME status block
	if order == nil {
		err := a.cleanupLastOrder(ctx, crt)
		if err != nil {
			crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorValidateError, fmt.Sprintf("Failed to clean up previous order: %v", err), false)
			return err
		}
	}

	// if we should not attempt validation yet, return an error so the item
	// will be requeued.
	if nextPresentIn > 0 {
		nextPresentTimeStr := time.Now().Add(nextPresentIn).Format(time.RFC822Z)
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorBackoff, fmt.Sprintf("Backing off %s until attempting re-validation", nextPresentIn), false)
		return fmt.Errorf("not attempting acme validation until %s", nextPresentTimeStr)
	}

	// if the current order is nil and it is time to attempt validation, we
	// need to create a new order.
	if order == nil {
		order, err = a.createOrder(ctx, cl, crt)
		if err != nil {
			crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorValidateError, fmt.Sprintf("Failed to create new order: %v", err), false)
			return err
		}
		a.recorder.Eventf(crt, corev1.EventTypeNormal, reasonCreateOrder, "Created new ACME order, attempting validation...")
	}

	// attempt to present/validate the order
	return a.presentOrder(ctx, cl, crt, order)
}

func (a *Acme) presentOrder(ctx context.Context, cl client.Interface, crt *v1alpha1.Certificate, order *acme.Order) error {
	allAuthorizations, err := getRemainingAuthorizations(ctx, cl, order.Authorizations...)
	if err != nil {
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorValidateError, fmt.Sprintf("Failed to determine authorizations to obtain: %v", err), false)
		return err
	}

	// this may return challenges even if an error occured. we use the partial
	// list of challenges in order to cleanup challenges that are no longer
	// required.
	chs, err := a.selectChallengesForAuthorizations(ctx, cl, crt, allAuthorizations...)
	errCleanup := a.cleanupIrrelevantChallenges(ctx, crt, chs)
	if errCleanup != nil {
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorCleanupError, fmt.Sprintf("Failed to clean up old challenges: %v", err), false)
		// perhaps we should just throw a warning here instead of erroring.
		// for now, return an error to pick up bugs in this codepath
		return err
	}
	if err != nil {
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorInvalidConfig, err.Error(), false)
		return err
	}

	// set the challenges field of the status block
	crt.Status.ACMEStatus().Order.Challenges = chs

	// compute the new challenge list after cleaning up successful challenges
	var newChallengeList []v1alpha1.ACMEOrderChallenge

	var errs []error

	// we use this field to ensure we don't attempt to present the same identifier
	// twice in a single sync.
	// Without this, if a Certificate specifies both *.domain.com and domain.com on
	// a Certificate, the DNS provider will race with itself and fail to solve either
	// challenge.
	var presentedIdentifiers []string
Outer:
	for _, ch := range chs {
		// don't present challenges for the same domain more than once
		for _, i := range presentedIdentifiers {
			if ch.Domain == i {
				newChallengeList = append(newChallengeList, ch)
				errs = append(errs, fmt.Errorf("another authorization for domain %q is in progress", ch.Domain))
				continue Outer
			}
		}

		presentedIdentifiers = append(presentedIdentifiers, ch.Domain)
		err := a.processChallenge(ctx, cl, crt, ch)
		if err != nil {
			newChallengeList = append(newChallengeList, ch)
			errs = append(errs, err)
		}

	}

	crt.Status.ACMEStatus().Order.Challenges = newChallengeList

	// we aggregate the errors here before beginning to accept challenges.
	// This will mean we only accept challenges once all self checks are
	// passing, to save the number of 'accept' operations sent to the acme server.
	err = utilerrors.NewAggregate(errs)
	if err != nil {
		// we set forceTime to true so the user can see the self check is being
		// performed regularly
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorValidateError, err.Error(), true)
		return err
	}

	crt.UpdateStatusCondition(v1alpha1.CertificateConditionValidationFailed, v1alpha1.ConditionFalse, "OrderValidated", fmt.Sprintf("Order validated"), true)

	return nil
}

func (a *Acme) processChallenge(ctx context.Context, cl client.Interface, crt *v1alpha1.Certificate, ch v1alpha1.ACMEOrderChallenge) error {
	err := a.presentChallenge(ctx, cl, crt, ch)
	if err != nil {
		return err
	}

	err = a.acceptChallenge(ctx, cl, crt, ch)
	if err != nil {
		return err
	}

	err = a.cleanupChallenge(ctx, crt, ch)
	if err != nil {
		return err
	}

	return nil
}

// presentChallenge will process a challenge by talking to the acme server and
// obtaining up to date status information.
// If the challenge is still in a pending state, it will first check propagation
// status of a challenge from previous attempt, and if missing it will 'present' the
// new challenge using the appropriate solver.
// If the check fails, an error will be returned.
// Otherwise, it will return nil.
func (a *Acme) presentChallenge(ctx context.Context, cl client.Interface, crt *v1alpha1.Certificate, ch v1alpha1.ACMEOrderChallenge) error {
	acmeCh, err := cl.GetChallenge(ctx, ch.URL)
	if err != nil {
		return err
	}

	switch acmeCh.Status {
	case acme.StatusValid:
		return nil
	case acme.StatusInvalid, acme.StatusDeactivated, acme.StatusRevoked:
		acmeErrReason := "unknown reason"
		if acmeCh.Error != nil {
			acmeErrReason = acmeCh.Error.Error()
		}
		return fmt.Errorf("challenge for domain %q failed: %s", ch.Domain, acmeErrReason)
	case acme.StatusPending, acme.StatusProcessing:
	default:
		return fmt.Errorf("unknown acme challenge status %q for domain %q", acmeCh.Status, ch.Domain)
	}

	solver, err := a.solverFor(ch.Type)
	if err != nil {
		return err
	}

	ok, err := solver.Check(ch)
	if err != nil {
		return err
	}

	if ok {
		return nil
	}

	// TODO: make sure that solver.Present is noop if challenge
	//       is already present and all we do is waiting for propagation,
	//       otherwise it is spamming with errors which are not really erros
	//       as we are just waiting for propagation
	err = solver.Present(ctx, crt, ch)
	if err != nil {
		return err
	}

	// We return an error here instead of nil, as the only way for 'presentChallenge'
	// to return without error is if the self check passes, which we check above.
	return fmt.Errorf("%s self check failed for domain %q", ch.Type, ch.Domain)
}

func (a *Acme) cleanupLastOrder(ctx context.Context, crt *v1alpha1.Certificate) error {
	glog.Infof("Cleaning up previous order for certificate %s/%s", crt.Namespace, crt.Name)

	err := a.cleanupIrrelevantChallenges(ctx, crt, nil)
	if err != nil {
		return err
	}

	crt.Status.ACMEStatus().Order.Challenges = nil
	crt.Status.ACMEStatus().Order.URL = ""

	return nil
}

// TODO: ensure all DNS challenge solvers return non-error if the challenge
// record doesn't exist
func (a *Acme) cleanupIrrelevantChallenges(ctx context.Context, crt *v1alpha1.Certificate, keepChals []v1alpha1.ACMEOrderChallenge) error {
	glog.Infof("Cleaning up old/expired challenges for Certificate %s/%s", crt.Namespace, crt.Name)
	var toCleanUp []v1alpha1.ACMEOrderChallenge
	for _, c := range crt.Status.ACMEStatus().Order.Challenges {
		keep := false
		for _, kc := range keepChals {
			if reflect.DeepEqual(kc, c) {
				keep = true
				break
			}
		}
		if !keep {
			toCleanUp = append(toCleanUp, c)
		}
	}
	for _, c := range toCleanUp {
		err := a.cleanupChallenge(ctx, crt, c)
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *Acme) cleanupChallenge(ctx context.Context, crt *v1alpha1.Certificate, c v1alpha1.ACMEOrderChallenge) error {
	glog.Infof("Cleaning up challenge for domain %q as part of Certificate %s/%s", c.Domain, crt.Namespace, crt.Name)
	solver, err := a.solverFor(c.Type)
	if err != nil {
		return err
	}
	err = solver.CleanUp(ctx, crt, c)
	if err != nil {
		return err
	}
	return nil
}

func (a *Acme) selectChallengesForAuthorizations(ctx context.Context, cl client.Interface, crt *v1alpha1.Certificate, allAuthorizations ...*acme.Authorization) ([]v1alpha1.ACMEOrderChallenge, error) {
	chals := make([]v1alpha1.ACMEOrderChallenge, len(allAuthorizations))
	var errs []error
	for i, authz := range allAuthorizations {
		cfg, err := acmeSolverConfigurationForAuthorization(crt.Spec.ACME, authz)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		var challenge *acme.Challenge
		for _, ch := range authz.Challenges {
			switch {
			case ch.Type == "http-01" && cfg.HTTP01 != nil:
				challenge = ch
			case ch.Type == "dns-01" && cfg.DNS01 != nil:
				challenge = ch
			}
		}

		domain := authz.Identifier.Value
		if challenge == nil {
			errs = append(errs, fmt.Errorf("ACME server does not allow selected challenge type for domain %q", domain))
			continue
		}

		internalCh, err := buildInternalChallengeType(cl, challenge, *cfg, domain, authz.URL, authz.Wildcard)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		chals[i] = internalCh
	}
	return chals, utilerrors.NewAggregate(errs)
}

func buildInternalChallengeType(cl client.Interface, ch *acme.Challenge, cfg v1alpha1.ACMESolverConfig, domain, authzURL string, wildcard bool) (v1alpha1.ACMEOrderChallenge, error) {
	var key string
	var err error
	switch ch.Type {
	case "http-01":
		key, err = cl.HTTP01ChallengeResponse(ch.Token)
	case "dns-01":
		key, err = cl.DNS01ChallengeRecord(ch.Token)
	default:
		return v1alpha1.ACMEOrderChallenge{}, fmt.Errorf("unsupported challenge type %q", ch.Type)
	}
	if err != nil {
		return v1alpha1.ACMEOrderChallenge{}, err
	}

	return v1alpha1.ACMEOrderChallenge{
		URL:              ch.URL,
		AuthzURL:         authzURL,
		Type:             ch.Type,
		Domain:           domain,
		Token:            ch.Token,
		Key:              key,
		ACMESolverConfig: cfg,
		Wildcard:         wildcard,
	}, nil
}

func keyForChallenge(cl *acme.Client, challenge *acme.Challenge) (string, error) {
	var err error
	switch challenge.Type {
	case "http-01":
		return cl.HTTP01ChallengeResponse(challenge.Token)
	case "dns-01":
		return cl.DNS01ChallengeRecord(challenge.Token)
	default:
		err = fmt.Errorf("unsupported challenge type %s", challenge.Type)
	}
	return "", err
}

// shouldAttemptValidation determines whether Present should actually run by
// evaluating when the last present for the current desired certificate was
// last attempted.
//
// It returns the duration that cert-manager should wait until attempting
// another authorization, or an error.
// If an existing order for the Certificate exists and is not invalid, it
// will be returned as well.
// Returning <= 0 indicates that an authorization should be attempted now.
//
// - If the existing order URL is not set, it will return 0
//
// - If the existing order URL is set, but querying it fails, an error is
//   returned
//
// - If the existing order is pending or valid, it will return 0
//
// - If the existing order has failed, it will return
//
//               (5 minutes) - (time.Now() - lastFailureTime)
//
//   This causes cert-manager to only attempt authorizations every 5 minutes
//   if the previous attempt for the same configuration failed
//
// TODO:
// - If the existing order has failed, but the previously attempted
//   configuration is different to the new configuration, it should return 0
func (a *Acme) shouldAttemptValidation(ctx context.Context, cl client.Interface, crt *v1alpha1.Certificate) (time.Duration, *acme.Order, error) {
	orderURL := crt.Status.ACMEStatus().Order.URL
	if orderURL == "" {
		return 0, nil, nil
	}

	// attempt to obtain a copy of the existing order url from the acme server
	// TODO: should we cache some of this info? Specific the 'order state'?
	// This would help reduce calls to the ACME server.
	order, err := cl.GetOrder(ctx, orderURL)
	if err != nil {
		// check if the error is a 'not found' or unauthorized type error. If
		// it is, we should attempt to authorize as either the issuer identity
		// has changed, or the order URL is very old
		if acmeErr, ok := err.(*acme.Error); ok {
			if acmeErr.StatusCode >= 400 && acmeErr.StatusCode <= 499 {
				return 0, nil, nil
			}
		}
		// return the error otherwise
		return 0, nil, err
	}

	// if the previously attempted order was for a different set of domains to
	// that of the current Certificate resource, we should immediately attempt
	// authorizations
	if !orderIsValidForCertificate(order, crt) {
		return 0, nil, nil
	}

	switch order.Status {
	case acme.StatusPending, acme.StatusProcessing, acme.StatusValid:
		// if the order has not failed, attempt authorization
		return 0, order, nil
	case acme.StatusRevoked, acme.StatusUnknown:
		// if the order is revoked (i.e. expired), we should create a new one
		return 0, nil, nil
	case acme.StatusInvalid:
		// if the certificate is not marked as failed, we should set the
		// condition on the resource
		if !crt.HasCondition(v1alpha1.CertificateCondition{
			Type:   v1alpha1.CertificateConditionValidationFailed,
			Status: v1alpha1.ConditionTrue,
		}) {
			var extraText = ""
			if order.Error != nil {
				extraText = fmt.Sprintf(": %v", order.Error.Error())
			}
			crt.UpdateStatusCondition(v1alpha1.CertificateConditionValidationFailed, v1alpha1.ConditionTrue, "OrderFailed", "Order status is invalid"+extraText, true)
		}

		// we know that we'll be able to find the appropriate condition because
		// HasCondition returned true above
		// If we don't, the lastTransitionTime will be set to 0, meaning we'll
		// trigger an immediate re-issue anyway
		var condition v1alpha1.CertificateCondition
		for _, cond := range crt.Status.Conditions {
			if cond.Type == v1alpha1.CertificateConditionValidationFailed {
				condition = cond
			}
		}

		return prepareAttemptWaitPeriod - (time.Now().Sub(condition.LastTransitionTime.Time)), order, nil
	}

	return 0, nil, fmt.Errorf("unrecognised existing acme order status: %q", order.Status)
}

func (a *Acme) acceptChallenge(ctx context.Context, cl client.Interface, crt *v1alpha1.Certificate, ch v1alpha1.ACMEOrderChallenge) error {
	glog.Infof("Accepting challenge for domain %q", ch.Domain)
	// We manually construct an ACME challenge here from our own internal type
	// to save additional round trips to the ACME server.
	acmeChal := &acme.Challenge{
		URL:   ch.URL,
		Token: ch.Token,
	}
	_, err := cl.AcceptChallenge(ctx, acmeChal)
	if err != nil {
		return err
	}

	glog.Infof("Waiting for authorization for domain %q", ch.Domain)
	authorization, err := cl.WaitAuthorization(ctx, ch.AuthzURL)
	if err != nil {
		return err
	}

	if authorization.Status != acme.StatusValid {
		return fmt.Errorf("expected acme domain authorization status for %q to be valid, but it is %q", authorization.Identifier.Value, authorization.Status)
	}

	glog.Infof("Successfully authorized domain %q", authorization.Identifier.Value)
	a.recorder.Eventf(crt, corev1.EventTypeNormal, reasonDomainVerified, "Domain %q verified with %q validation", ch.Domain, ch.Type)

	return nil
}

// getRemainingAuthorizations will query the ACME server for the Authorization
// resources for the given list of authorization URLs using the given ACME
// client.
// It will filter out any authorizations that are in a 'Valid' state.
// It will return an error if obtaining any of the given authorizations fails.
func getRemainingAuthorizations(ctx context.Context, cl client.Interface, urls ...string) ([]*acme.Authorization, error) {
	var authzs []*acme.Authorization
	for _, url := range urls {
		a, err := cl.GetAuthorization(ctx, url)
		if err != nil {
			return nil, err
		}
		if a.Status == acme.StatusInvalid || a.Status == acme.StatusDeactivated || a.Status == acme.StatusRevoked {
			return nil, fmt.Errorf("authorization for dmain %q is in a failed state", a.Identifier.Value)
		}
		if a.Status == acme.StatusPending {
			authzs = append(authzs, a)
		}
	}
	return authzs, nil
}

func acmeSolverConfigurationForAuthorization(cfg *v1alpha1.ACMECertificateConfig, authz *acme.Authorization) (*v1alpha1.ACMESolverConfig, error) {
	domain := authz.Identifier.Value
	if authz.Wildcard {
		domain = "*." + domain
	}
	for _, d := range cfg.Config {
		for _, dom := range d.Domains {
			if dom != domain {
				continue
			}
			return &d.ACMESolverConfig, nil
		}
	}
	return nil, fmt.Errorf("solver configuration for domain %q not found. Ensure you have configured a challenge mechanism using the certificate.spec.acme.config field", domain)
}
