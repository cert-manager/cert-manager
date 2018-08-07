package acmeorders

import (
	"context"
	"fmt"
	"reflect"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	"github.com/golang/glog"
	"github.com/jetstack/cert-manager/pkg/acme"
	acmecl "github.com/jetstack/cert-manager/pkg/acme/client"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	acmeapi "github.com/jetstack/cert-manager/third_party/crypto/acme"
)

var (
	orderGvk = cmapi.SchemeGroupVersion.WithKind("Order")
)

// Sync will process this ACME Order.
// It is the core control function for ACME Orders, and handles:
// - creating orders
// - deciding/validated configured challenge mechanisms
// - create a Challenge resource in order to fulfill required validations
// - waiting for Challenge resources to enter the 'ready' state
func (c *Controller) Sync(ctx context.Context, o *cmapi.Order) (err error) {
	oldOrder := o
	o = o.DeepCopy()

	defer func() {
		// TODO: replace with more efficient comparison
		if reflect.DeepEqual(oldOrder.Status, o.Status) {
			return
		}
		_, updateErr := c.CMClient.CertmanagerV1alpha1().Orders(o.Namespace).Update(o)
		if err != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
		}
	}()

	acmeHelper := &acme.Helper{
		SecretLister:             c.secretLister,
		ClusterResourceNamespace: c.Context.ClusterResourceNamespace,
	}

	genericIssuer, err := c.helper.GetGenericIssuer(o.Spec.IssuerRef, o.Namespace)
	if err != nil {
		return fmt.Errorf("error reading (cluster)issuer %q: %v", o.Spec.IssuerRef.Name, err)
	}

	cl, err := acmeHelper.ClientForIssuer(genericIssuer)
	if err != nil {
		return err
	}

	if o.Status.URL == "" {
		err := c.createOrder(ctx, cl, genericIssuer, o)
		// TODO: check for error types (perm or transient?)
		if err != nil {
			return err
		}
	}

	// if an order is in a final state, we bail out early as there is nothing
	// left for us to do here.
	if acme.IsFinalState(o.Status.State) {
		return nil
	}

	switch o.Status.State {

	// if the status field is not set, we should check the Order with the ACME
	// server to try and populate it.
	// If this is not possible - what should we do? (???)
	case cmapi.Unknown:
		err := c.syncOrderStatus(ctx, cl, o)
		if err != nil {
			return err
		}
		// TODO: we should do something more intelligent than just returning an
		// error here.
		return fmt.Errorf("updated unknown order state. Retrying processing after applying back-off")

	// if the current state is 'valid', we should keep polling the ACME server
	// until the Order automatically progresses to the 'ready' state.
	// This *should* happen automatically, after **some period of time**.
	case cmapi.Valid:
		waitTimeout := time.Second * 60
		// wait up to 60s for the order to enter 'ready' state
		ctx, cancel := context.WithTimeout(ctx, waitTimeout)
		defer cancel()

		existingState := o.Status.State
		// wait for a state change (i.e. transitioning to a 'ready' state)
		newState, err := c.pollForStateChange(ctx, cl, o, time.Second*5)
		if err != nil {
			return err
		}

		// if the state has not changed, we return an error so the order can be
		// re-queued.
		if existingState == newState {
			// TODO: should we mark the order as failed if the state doesn't transition?
			// For now, we will return an error which will cause the Order to be
			// requeued after a back-off has been applied.
			return fmt.Errorf("expected order to transition from %q to 'ready' state, but it did not after %s", existingState, waitTimeout)
		}

		// if the state has changed, but is not in a 'ready' state, then we return
		// an error here.
		// When the Sync function gets called again, the appropriate action will
		// be taken if the order is now in a failed 'final' state for some reason.
		if newState != cmapi.Ready {
			return fmt.Errorf("expected order to transition to the %q state, but it is %q", cmapi.Ready, newState)
		}

		if acme.IsFinalState(newState) {
			return nil
		}

		// this *should* be unreachable, because an order cannot transition from 'valid'
		// to another non-final state, and if it does then it should be caught by
		// the clauses above
		return fmt.Errorf("unexpected error: order state is %q - this case should not occur, and is likely a bug", newState)

	// if the order is still pending or processing, we should continue to check
	// the state of all Challenge resources (or create challenge resources)
	case cmapi.Pending, cmapi.Processing:
		// continue

	// this is the catch-all base case for order states that we do not recognise
	default:
		return fmt.Errorf("unknown order state %q", o.Status.State)
	}

	// create a selector that we can use to find all existing Challenges for the order
	sel, err := challengeSelectorForOrder(o)
	if err != nil {
		return err
	}

	// get the list of exising challenges for this order
	existingChallenges, err := c.challengeLister.Challenges(o.Namespace).List(sel)
	if err != nil {
		return err
	}

	var specsToCreate []cmapi.ChallengeSpec
	for _, s := range o.Status.Challenges {
		create := true
		for _, ch := range existingChallenges {
			if s.DNSName == ch.Spec.DNSName {
				create = false
				break
			}
		}

		if !create {
			break
		}

		specsToCreate = append(specsToCreate, s)
	}

	glog.Infof("Need to create %d challenges", len(specsToCreate))

	var errs []error
	for _, spec := range specsToCreate {
		ch, err := buildChallenge(o, spec)
		if err != nil {
			// TODO: check if this is a perma-fail
			return err
		}

		ch, err = c.CMClient.CertmanagerV1alpha1().Challenges(o.Namespace).Create(ch)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		existingChallenges = append(existingChallenges, ch)
	}

	err = utilerrors.NewAggregate(errs)
	if err != nil {
		return fmt.Errorf("error ensuring Challenge resources for Order: %v", err)
	}

	// if all
	recheckOrderStatus := true
	anyChallengesFailed := false
	for _, ch := range existingChallenges {
		switch ch.Status.State {
		case cmapi.Pending, cmapi.Processing:
			recheckOrderStatus = false
		case cmapi.Failed, cmapi.Expired:
			anyChallengesFailed = true
		}
	}

	// if at least 1 order is not valid, AND no orders have failed, we should
	// just return early and not query the ACME API.
	if !recheckOrderStatus && !anyChallengesFailed {
		glog.Infof("Waiting for all challenges for order %q to enter 'ready' state", o.Name)
		return nil
	}

	// otherwise, sync the order state with the ACME API.
	err = c.syncOrderStatus(ctx, cl, o)
	if err != nil {
		return err
	}

	return nil
}

const (
	orderNameLabelKey = "acme.cert-manager.io/order-name"
)

func (c *Controller) createOrder(ctx context.Context, cl acmecl.Interface, issuer cmapi.GenericIssuer, o *cmapi.Order) error {
	if o.Status.URL != "" {
		return fmt.Errorf("refusing to recreate a new order for Order %q. Please create a new Order resource to initiate a new order", o.Name)
	}

	// create a new order with the acme server
	orderTemplate := acmeapi.NewOrder(o.Spec.DNSNames...)
	acmeOrder, err := cl.CreateOrder(ctx, orderTemplate)
	if err != nil {
		return fmt.Errorf("error creating new order: %v", err)
	}

	setOrderStatus(&o.Status, acmeOrder)

	chals := make([]cmapi.ChallengeSpec, len(acmeOrder.Authorizations))
	// we only set the status.challenges field when we first create the order,
	// because we only create one order per Order resource.
	for i, authzURL := range acmeOrder.Authorizations {
		authz, err := cl.GetAuthorization(ctx, authzURL)
		if err != nil {
			return err
		}

		cs, err := c.challengeSpecForAuthorization(ctx, cl, issuer, o, authz)
		if err != nil {
			return fmt.Errorf("Error constructing Challenge resource for Authorization: %v", err)
		}

		chals[i] = *cs
	}
	o.Status.Challenges = chals

	return nil
}

func (c *Controller) challengeSpecForAuthorization(ctx context.Context, cl acmecl.Interface, issuer cmapi.GenericIssuer, o *cmapi.Order, authz *acmeapi.Authorization) (*cmapi.ChallengeSpec, error) {
	cfg, err := solverConfigurationForAuthorization(o.Spec.Config, authz)
	if err != nil {
		return nil, err
	}

	acmeSpec := issuer.GetSpec().ACME
	if acmeSpec == nil {
		return nil, fmt.Errorf("issuer %q is not configured as an ACME Issuer. Cannot be used for creating ACME orders", issuer.GetObjectMeta().Name)
	}

	var challenge *acmeapi.Challenge
	for _, ch := range authz.Challenges {
		switch {
		case ch.Type == "http-01" && cfg.HTTP01 != nil && acmeSpec.HTTP01 != nil:
			challenge = ch
		case ch.Type == "dns-01" && cfg.DNS01 != nil && acmeSpec.DNS01 != nil:
			challenge = ch
		}
	}

	domain := authz.Identifier.Value
	if challenge == nil {
		return nil, fmt.Errorf("ACME server does not allow selected challenge type or no provider is configured for domain %q", domain)
	}

	key, err := keyForChallenge(cl, challenge)
	if err != nil {
		return nil, err
	}

	return &cmapi.ChallengeSpec{
		AuthzURL:  authz.URL,
		Type:      challenge.Type,
		URL:       challenge.URL,
		DNSName:   domain,
		Token:     challenge.Token,
		Key:       key,
		Config:    *cfg,
		Wildcard:  authz.Wildcard,
		IssuerRef: o.Spec.IssuerRef,
	}, nil
}

func keyForChallenge(cl acmecl.Interface, challenge *acmeapi.Challenge) (string, error) {
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

func solverConfigurationForAuthorization(cfgs []cmapi.DomainSolverConfig, authz *acmeapi.Authorization) (*cmapi.SolverConfig, error) {
	domainToFind := authz.Identifier.Value
	if authz.Wildcard {
		domainToFind = "*." + domainToFind
	}
	for _, d := range cfgs {
		for _, dom := range d.Domains {
			if dom != domainToFind {
				continue
			}
			return &d.SolverConfig, nil
		}
	}
	return nil, fmt.Errorf("solver configuration for domain %q not found. Ensure you have configured a challenge mechanism using the certificate.spec.acme.config field", domainToFind)
}

// syncOrderStatus will communicate with the ACME server to retrieve the current
// state of the Order. It will then update the Order's status block with the new
// state of the order.
func (c *Controller) syncOrderStatus(ctx context.Context, cl acmecl.Interface, o *cmapi.Order) error {
	if o.Status.URL == "" {
		return fmt.Errorf("order URL is blank - order has not been created yet")
	}

	acmeOrder, err := cl.GetOrder(ctx, o.Status.URL)
	if err != nil {
		// TODO: handle 404 acme responses and mark the order as failed
		return err
	}

	setOrderStatus(&o.Status, acmeOrder)

	return nil
}

func buildChallenge(o *cmapi.Order, chalSpec cmapi.ChallengeSpec) (*cmapi.Challenge, error) {
	// TODO: select challenge to use and set these fields appropriately
	ch := &cmapi.Challenge{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName:    o.Name + "-",
			Labels:          challengeLabelsForOrder(o),
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(o, orderGvk)},
		},
		Spec: chalSpec,
	}

	return ch, nil
}

// setOrderStatus will populate the given OrderStatus struct with the details from
// the provided ACME Order.
func setOrderStatus(o *cmapi.OrderStatus, acmeOrder *acmeapi.Order) {
	// TODO: should we validate the State returned by the ACME server here?
	cmState := cmapi.State(acmeOrder.Status)
	setOrderState(o, cmState)

	o.URL = acmeOrder.URL
	o.FinalizeURL = acmeOrder.FinalizeURL
}

func challengeLabelsForOrder(o *cmapi.Order) map[string]string {
	return map[string]string{
		orderNameLabelKey: o.Name,
	}
}

// challengeSelectorForOrder will construct a labels.Selector that can be used to
// find Challenges associated with the given Order.
func challengeSelectorForOrder(o *cmapi.Order) (labels.Selector, error) {
	lbls := challengeLabelsForOrder(o)
	var reqs []labels.Requirement
	for k, v := range lbls {
		req, err := labels.NewRequirement(k, selection.Equals, []string{v})
		if err != nil {
			return nil, err
		}
		reqs = append(reqs, *req)
	}
	return labels.NewSelector().Add(reqs...), nil
}

// pollForStateChange will poll the ACME API every pollInterval for a change in
// the Orders state.
// This is primarily used to wait for the Order to transition from a 'valid' to
// a 'ready' state.
// If the state does not change before the context deadline is reached, the old
// state will be returned and **no error** will be returned. It is up to the caller
// to detect and handle this case appropriately.
func (c *Controller) pollForStateChange(ctx context.Context, cl acmecl.Interface, o *cmapi.Order, pollInterval time.Duration) (cmapi.State, error) {
	oldState := o.Status.State
	for {
		// we define err here outside of the go func, so we can detect errors
		// caused by attempting to sync the order state without an extra struct
		// that contains (cmapi.State, error).
		// This should be okay (at least for now), because there will never be two
		// go funcs that are running at once which may access err at the same time.
		// If this assumption is wrong however, a race may occur, so we may want
		// to consider create a 'wrapper struct' in future.
		var err error
		select {
		case newState := <-func() <-chan cmapi.State {
			out := make(chan cmapi.State)
			go func() {
				defer close(out)
				err = c.syncOrderStatus(ctx, cl, o)
				out <- o.Status.State
			}()
			return out
		}():
			if err != nil {
				return newState, err
			}
			if newState != oldState {
				return newState, nil
			}
		case <-ctx.Done():
			return oldState, fmt.Errorf("timeout whilst waiting for ACME order state to change from %q", oldState)
		}

		// wait for pollInterval until we re-poll the ACME server for a new state
		time.Sleep(pollInterval)
	}
}

// setOrderState will set the 'State' field of the given Order to 's'.
// It will set the Orders failureTime field if the state provided is classed as
// a failure state.
func setOrderState(o *cmapi.OrderStatus, s cmapi.State) {
	o.State = s
	// if the order is in a failure state, we should set the `failureTime` field
	if acme.IsFailureState(o.State) {
		t := metav1.NewTime(time.Now())
		o.FailureTime = &t
	}
}
