/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package acmeorders

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/jetstack/cert-manager/pkg/acme"
	acmecl "github.com/jetstack/cert-manager/pkg/acme/client"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	acmeapi "github.com/jetstack/cert-manager/third_party/crypto/acme"
	"k8s.io/klog"
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

	genericIssuer, err := c.helper.GetGenericIssuer(o.Spec.IssuerRef, o.Namespace)
	if err != nil {
		return fmt.Errorf("error reading (cluster)issuer %q: %v", o.Spec.IssuerRef.Name, err)
	}

	cl, err := c.acmeHelper.ClientForIssuer(genericIssuer)
	if err != nil {
		return err
	}

	if o.Status.URL == "" {
		err := c.createOrder(ctx, cl, genericIssuer, o)

		if err != nil {
			// If we get a 4xx error, we mark the Order as 'error'.
			// 4xx error codes include rate limit errors (429).
			// This will cause the Certificate controller to retry the Order
			// after the regular back-off algorithm has been applied.
			acmeErr, ok := err.(*acmeapi.Error)
			if ok && acmeErr.StatusCode >= 400 && acmeErr.StatusCode < 500 {
				c.setOrderState(&o.Status, cmapi.Errored)
				o.Status.Reason = fmt.Sprintf("Failed to create order: %v", err)
				return err
			}

			return err
		}

		// Return here and allow the updating of the Status field to trigger
		// a resync.
		// This ensures we have observed the `status.url` field being set, preventing
		// us accidentally creating duplicate orders with the ACME server.
		return nil
	}

	// Handle an edge case where the Order has entered a 'valid' state but the
	// actual Certificate resource has not been set on the Order.
	// This shouldn't ever really happen, but can occasionally occur if
	// cert-manager has failed to persist the Certificate and/or status field
	// for whatever reason.
	if o.Status.State == acmeapi.StatusValid && o.Status.Certificate == nil {
		acmeOrder, err := cl.GetOrder(ctx, o.Status.URL)
		if err != nil {
			// TODO: mark the order as 'errored' if this is a 404 or similar
			return err
		}

		// If the Order state has actually changed and we've not observed it,
		// update the order status and let the change in the resource trigger
		// a resync
		if acmeOrder.Status != acmeapi.StatusValid {
			c.setOrderStatus(&o.Status, acmeOrder)
			return nil
		}

		certs, err := cl.GetCertificate(ctx, acmeOrder.CertificateURL)
		if err != nil {
			// TODO: mark the order as 'errored' if this is a 404 or similar
			return err
		}

		err = c.storeCertificateOnStatus(o, certs)
		if err != nil {
			return err
		}

		return nil
	}

	// If an order is in a final state, we bail out early as there is nothing
	// left for us to do here.
	// TODO: we should find a way to periodically update the state of the resource
	// to reflect the current/actual state in the ACME server.
	// TODO: if the certificate bytes are nil, we should attempt to retrieve
	// the certificate for the order using GetCertificate
	if acme.IsFinalState(o.Status.State) {
		existingChallenges, err := c.listChallengesForOrder(o)
		if err != nil {
			return err
		}

		// Don't cleanup challenge resources if the order has failed.
		// This will make it easier for users to debug failing challenges.
		// The challenge resources will be cleaned up when the Order is deleted.
		if acme.IsFailureState(o.Status.State) {
			return nil
		}

		// Cleanup challenge resources once a final state has been reached
		for _, ch := range existingChallenges {
			err := c.CMClient.CertmanagerV1alpha1().Challenges(ch.Namespace).Delete(ch.Name, nil)
			if err != nil {
				return err
			}
		}

		return nil
	}

	switch o.Status.State {

	// If the status field is not set, we should check the Order with the ACME
	// server to try and populate it.
	// If this is not possible - what should we do? (???)
	case cmapi.Unknown:
		err := c.syncOrderStatus(ctx, cl, o)
		if err != nil {
			// If we get a 4xx error, we mark the Order as 'error'.
			// 4xx error codes include rate limit errors (429).
			// This will cause the Certificate controller to retry the Order
			// after the regular back-off algorithm has been applied.
			acmeErr, ok := err.(*acmeapi.Error)
			if ok && acmeErr.StatusCode >= 400 && acmeErr.StatusCode < 500 {
				c.setOrderState(&o.Status, cmapi.Errored)
				o.Status.Reason = fmt.Sprintf("Failed to create order: %v", err)
				return nil
			}

			return err
		}

		// If the state has changed, return nil here as the change in state will
		// cause the controller to sync again once the new state has been observed
		// by the informer.
		if o.Status.State != cmapi.Unknown {
			return nil
		}

		// Return an error if the state is still unknown. This is an edge case
		// that *should* be unreachable, but in case it does happen we will requeue
		// the order to attempt to get a valid state after applying a back-off.
		return fmt.Errorf("order %s/%s state unknown", o.Namespace, o.Name)

	// if the current state is 'ready', we need to generate a CSR and finalize
	// the order
	case cmapi.Ready:
		// TODO: we could retrieve a copy of the certificate resource here and
		// stored it on the Order resource to prevent extra calls to the API
		certSlice, err := cl.FinalizeOrder(ctx, o.Status.FinalizeURL, o.Spec.CSR)

		// always update the order status after calling Finalize - this allows
		// us to record the current orders status on this order resource
		// despite it not being returned directly by the acme client.
		// This will catch cases where the Order cannot be finalized because it
		// if it is already in the 'valid' state, as upon retry we will
		// then retrieve the Certificate resource.
		errUpdate := c.syncOrderStatus(ctx, cl, o)
		if errUpdate != nil {
			// TODO: mark permenant failure?
			return fmt.Errorf("error syncing order status: %v", errUpdate)
		}

		// check for errors from FinalizeOrder
		if err != nil {
			// TODO: check for acme error type and potentially mark order as errored
			return fmt.Errorf("error finalizing order: %v", err)
		}

		err = c.storeCertificateOnStatus(o, certSlice)
		if err != nil {
			// TODO: mark Order as 'errored'
			return err
		}

		return nil

	// if the order is still pending or processing, we should continue to check
	// the state of all Challenge resources (or create challenge resources)
	case cmapi.Pending, cmapi.Processing:
		// continue

	// this is the catch-all base case for order states that we do not recognise
	default:
		return fmt.Errorf("unknown order state %q", o.Status.State)
	}

	// get the list of exising challenges for this order
	existingChallenges, err := c.listChallengesForOrder(o)
	if err != nil {
		return err
	}

	// to avoid creating multiple challenge objects for the same challenge due
	// to cache timing issues with the informers, we use a deterministic name
	// for each challenge we create. each challenge will have have a name of
	// the form `{order-name}-{index}` where index is the index of the challenge
	// as is stored on the `order.status.challenges` array.
	// therefore, if there is a cache timing issue, the Create will fail as the
	// challenge with that name will already exist.
	specsToCreate := make(map[int]cmapi.ChallengeSpec)
	// TODO: we could potentially parse the challenge's name to find the index
	// expected here instead of iterating over both lists
	for i, s := range o.Status.Challenges {
		create := true
		for _, ch := range existingChallenges {
			if s.Wildcard == ch.Spec.Wildcard &&
				s.DNSName == ch.Spec.DNSName {
				create = false
				break
			}
		}

		if !create {
			break
		}

		specsToCreate[i] = s
	}

	klog.Infof("Need to create %d challenges", len(specsToCreate))

	// create a Challenge resource for each challenge we need to create.
	var errs []error
	for i, spec := range specsToCreate {
		ch := buildChallenge(i, o, spec)

		ch, err = c.CMClient.CertmanagerV1alpha1().Challenges(o.Namespace).Create(ch)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		domainName := spec.DNSName
		if spec.Wildcard {
			domainName = "*." + domainName
		}
		c.Recorder.Eventf(o, corev1.EventTypeNormal, "Created", "Created Challenge resource %q for domain %q", ch.Name, ch.Spec.DNSName)

		existingChallenges = append(existingChallenges, ch)
	}

	// if any errors occured creating the challenge resources, retry after back-off
	err = utilerrors.NewAggregate(errs)
	if err != nil {
		return fmt.Errorf("error ensuring Challenge resources for Order: %v", err)
	}

	// if any of the challenges have failed, we will sync the order status.
	// if all of the challenges are valid, we will sync the order status.
	allChallengesValid := true
	anyChallengesFailed := false
	for _, ch := range existingChallenges {
		if ch.Status.State != cmapi.Valid {
			allChallengesValid = false
		}
		if ch.Status.State == cmapi.Invalid || ch.Status.State == cmapi.Expired {
			anyChallengesFailed = true
		}
	}

	if allChallengesValid || anyChallengesFailed {
		err = c.syncOrderStatus(ctx, cl, o)
		if err != nil {
			return err
		}
		return nil
	}

	klog.Infof("Waiting for all challenges for order %q to enter 'valid' state", o.Name)

	return nil
}

func (c *Controller) listChallengesForOrder(o *cmapi.Order) ([]*cmapi.Challenge, error) {
	// create a selector that we can use to find all existing Challenges for the order
	sel, err := challengeSelectorForOrder(o)
	if err != nil {
		return nil, err
	}

	// get the list of exising challenges for this order
	return c.challengeLister.Challenges(o.Namespace).List(sel)
}

const (
	orderNameLabelKey = "acme.cert-manager.io/order-name"
)

func (c *Controller) createOrder(ctx context.Context, cl acmecl.Interface, issuer cmapi.GenericIssuer, o *cmapi.Order) error {
	if o.Status.URL != "" {
		return fmt.Errorf("refusing to recreate a new order for Order %q. Please create a new Order resource to initiate a new order", o.Name)
	}

	identifierSet := sets.NewString(o.Spec.DNSNames...)
	if o.Spec.CommonName != "" {
		identifierSet.Insert(o.Spec.CommonName)
	}
	// create a new order with the acme server
	orderTemplate := acmeapi.NewOrder(identifierSet.List()...)
	acmeOrder, err := cl.CreateOrder(ctx, orderTemplate)
	if err != nil {
		return fmt.Errorf("error creating new order: %v", err)
	}

	c.setOrderStatus(&o.Status, acmeOrder)

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
		// TODO: mark the order as errored if this is a 404 or similar
		return err
	}

	c.setOrderStatus(&o.Status, acmeOrder)

	return nil
}

func buildChallenge(i int, o *cmapi.Order, chalSpec cmapi.ChallengeSpec) *cmapi.Challenge {
	ch := &cmapi.Challenge{
		ObjectMeta: metav1.ObjectMeta{
			Name:            fmt.Sprintf("%s-%d", o.Name, i),
			Namespace:       o.Namespace,
			Labels:          challengeLabelsForOrder(o),
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(o, orderGvk)},
			Finalizers:      []string{cmapi.ACMEFinalizer},
		},
		Spec: chalSpec,
	}

	return ch
}

// setOrderStatus will populate the given OrderStatus struct with the details from
// the provided ACME Order.
func (c *Controller) setOrderStatus(o *cmapi.OrderStatus, acmeOrder *acmeapi.Order) {
	// TODO: should we validate the State returned by the ACME server here?
	cmState := cmapi.State(acmeOrder.Status)
	// be nice to our users and check if there is an error that we
	// can tell them about in the reason field
	// TODO(dmo): problems may be compound and they may be tagged with
	// a type field that suggests changes we should make (like provisioning
	// an account). We might be able to handle errors more gracefully using
	// this info
	o.Reason = ""
	if acmeOrder.Error != nil {
		o.Reason = acmeOrder.Error.Detail
	}
	c.setOrderState(o, cmState)

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

// setOrderState will set the 'State' field of the given Order to 's'.
// It will set the Orders failureTime field if the state provided is classed as
// a failure state.
func (c *Controller) setOrderState(o *cmapi.OrderStatus, s cmapi.State) {
	o.State = s
	// if the order is in a failure state, we should set the `failureTime` field
	if acme.IsFailureState(o.State) {
		t := metav1.NewTime(c.clock.Now())
		o.FailureTime = &t
	}
}

func (c *Controller) storeCertificateOnStatus(o *cmapi.Order, certs [][]byte) error {
	// encode the retrieved certificates (including the chain)
	certBuffer := bytes.NewBuffer([]byte{})
	for _, cert := range certs {
		err := pem.Encode(certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
		if err != nil {
			// TODO: something else?
			return err
		}
	}

	o.Status.Certificate = certBuffer.Bytes()
	c.Recorder.Event(o, corev1.EventTypeNormal, "OrderValid", "Order completed successfully")

	return nil
}
