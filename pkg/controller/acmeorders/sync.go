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
	"github.com/jetstack/cert-manager/pkg/controller/acmeorders/selectors"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/metrics"
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
func (c *controller) Sync(ctx context.Context, o *cmapi.Order) (err error) {
	log := logf.WithResource(logf.FromContext(ctx), o)
	dbg := log.V(logf.DebugLevel)
	ctx = logf.NewContext(ctx, log)

	metrics.Default.IncrementSyncCallCount(ControllerName)

	oldOrder := o
	o = o.DeepCopy()

	defer func() {
		// TODO: replace with more efficient comparison
		if reflect.DeepEqual(oldOrder.Status, o.Status) {
			dbg.Info("skipping updating resource as new status == existing status")
			return
		}
		log.Info("updating Order resource status")
		_, updateErr := c.cmClient.CertmanagerV1alpha1().Orders(o.Namespace).Update(o)
		if err != nil {
			log.Error(err, "failed to update status")
			err = utilerrors.NewAggregate([]error{err, updateErr})
			return
		}
		dbg.Info("updated Order resource status successfully")
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
		log.Info("creating Order with ACME server as one does not currently exist")
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
			err := c.cmClient.CertmanagerV1alpha1().Challenges(ch.Namespace).Delete(ch.Name, nil)
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

		// Due to a bug in the initial release of this controller, we previously
		// only supported DER encoded CSRs and not PEM encoded as they are intended
		// to be as part of our API.
		// To work around this, we first attempt to decode the CSR into DER bytes
		// by running pem.Decode. If the PEM block is empty, we assume that the CSR
		// is DER encoded and continue to call FinalizeOrder.
		var derBytes []byte
		block, _ := pem.Decode(o.Spec.CSR)
		if block == nil {
			log.Info("failed to parse CSR as PEM data, attempting to treat CSR as DER encoded for compatibility reasons")
			derBytes = o.Spec.CSR
		} else {
			derBytes = block.Bytes
		}

		// TODO: we could retrieve a copy of the certificate resource here and
		// stored it on the Order resource to prevent extra calls to the API
		certSlice, err := cl.FinalizeOrder(ctx, o.Status.FinalizeURL, derBytes)

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

	log.Info("need to create challenges", "number", len(specsToCreate))

	// create a Challenge resource for each challenge we need to create.
	var errs []error
	for i, spec := range specsToCreate {
		ch := buildChallenge(i, o, spec)

		ch, err = c.cmClient.CertmanagerV1alpha1().Challenges(o.Namespace).Create(ch)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		c.recorder.Eventf(o, corev1.EventTypeNormal, "Created", "Created Challenge resource %q for domain %q", ch.Name, ch.Spec.DNSName)

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

	log.Info("waiting for all challenges to enter 'valid' state")

	return nil
}

func (c *controller) listChallengesForOrder(o *cmapi.Order) ([]*cmapi.Challenge, error) {
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

func (c *controller) createOrder(ctx context.Context, cl acmecl.Interface, issuer cmapi.GenericIssuer, o *cmapi.Order) error {
	log := logf.FromContext(ctx)
	dbg := log.V(logf.DebugLevel)

	if o.Status.URL != "" {
		return fmt.Errorf("refusing to recreate a new order for Order %q. Please create a new Order resource to initiate a new order", o.Name)
	}
	log.Info("order URL not set, submitting Order to ACME server")

	identifierSet := sets.NewString(o.Spec.DNSNames...)
	if o.Spec.CommonName != "" {
		identifierSet.Insert(o.Spec.CommonName)
	}
	log.Info("build set of domains for Order", "domains", identifierSet.List())

	// create a new order with the acme server
	orderTemplate := acmeapi.NewOrder(identifierSet.List()...)
	dbg.Info("constructed order template", "template", orderTemplate)
	acmeOrder, err := cl.CreateOrder(ctx, orderTemplate)
	if err != nil {
		return fmt.Errorf("error creating new order: %v", err)
	}

	log.Info("submitted Order to ACME server")
	c.setOrderStatus(&o.Status, acmeOrder)

	log.Info("computing Challenge resources to create for this Order")
	useOldFormat := len(o.Spec.Config) > 0
	if useOldFormat {
		log.Info("spec.acme field found on Order resource. Using old style ACME configuration format. For more details, read: https://docs.cert-manager.io/en/latest/tasks/upgrading/upgrading-0.7-0.8.html")
	}
	chals := make([]cmapi.ChallengeSpec, len(acmeOrder.Authorizations))
	// we only set the status.challenges field when we first create the order,
	// because we only create one order per Order resource.
	for i, authzURL := range acmeOrder.Authorizations {
		dbg.Info("querying details for authorization", "url", authzURL)
		authz, err := cl.GetAuthorization(ctx, authzURL)
		if err != nil {
			return err
		}

		log := log.WithValues("url", authzURL, "domain", authz.Identifier.Value, "wildcard", authz.Wildcard)
		log.Info("determining challenge solver to use for challenge")
		var cs *cmapi.ChallengeSpec
		if useOldFormat {
			cs, err = c.oldFormatChallengeSpecForAuthorization(ctx, cl, issuer, o, authz)
			if err != nil {
				return fmt.Errorf("error constructing old format Challenge resource for authorization: %v", err)
			}
		} else {
			cs, err = challengeSpecForAuthorization(ctx, cl, issuer, o, authz)
			if err != nil {
				c.recorder.Eventf(o, corev1.EventTypeWarning, "NoMatchingSolver", "Failed to create challenge for domain %q: %v", authz.Identifier.Value, err)
				return fmt.Errorf("error constructing Challenge resource for authorization: %v", err)
			}
		}

		chals[i] = *cs
	}
	o.Status.Challenges = chals

	return nil
}

func challengeSpecForAuthorization(ctx context.Context, cl acmecl.Interface, issuer cmapi.GenericIssuer, o *cmapi.Order, authz *acmeapi.Authorization) (*cmapi.ChallengeSpec, error) {
	log := logf.FromContext(ctx, "challengeSpecForAuthorization")
	dbg := log.V(logf.DebugLevel)

	// 1. fetch solvers from issuer
	solvers := issuer.GetSpec().ACME.Solvers

	domainToFind := authz.Identifier.Value
	if authz.Wildcard {
		domainToFind = "*." + domainToFind
	}

	var selectedSolver *cmapi.ACMEChallengeSolver
	var selectedChallenge *acmeapi.Challenge
	selectedNumLabelsMatch := 0
	selectedNumDNSNamesMatch := 0
	selectedNumDNSZonesMatch := 0

	challengeForSolver := func(solver *cmapi.ACMEChallengeSolver) *acmeapi.Challenge {
		for _, ch := range authz.Challenges {
			switch {
			case ch.Type == "http-01" && solver.HTTP01 != nil:
				return ch
			case ch.Type == "dns-01" && solver.DNS01 != nil:
				return ch
			}
		}
		return nil
	}

	// 2. filter solvers to only those that matchLabels
	for _, cfg := range solvers {
		acmech := challengeForSolver(&cfg)
		if acmech == nil {
			dbg.Info("cannot use solver as the ACME authorization does not allow solvers of this type")
			continue
		}

		if cfg.Selector == nil {
			if selectedSolver != nil {
				dbg.Info("not selecting solver as previously selected solver has a just as or more specific selector")
				continue
			}
			dbg.Info("selecting solver due to match all selector and no previously selected solver")
			selectedSolver = cfg.DeepCopy()
			selectedChallenge = acmech
			continue
		}

		labelsMatch, numLabelsMatch := selectors.Labels(*cfg.Selector).Matches(o.ObjectMeta, domainToFind)
		dnsNamesMatch, numDNSNamesMatch := selectors.DNSNames(*cfg.Selector).Matches(o.ObjectMeta, domainToFind)
		dnsZonesMatch, numDNSZonesMatch := selectors.DNSZones(*cfg.Selector).Matches(o.ObjectMeta, domainToFind)

		if !labelsMatch || !dnsNamesMatch || !dnsZonesMatch {
			dbg.Info("not selecting solver", "labels_match", labelsMatch, "dnsnames_match", dnsNamesMatch, "dnszones_match", dnsZonesMatch)
			continue
		}

		dbg.Info("selector matches")

		selectSolver := func() {
			selectedSolver = cfg.DeepCopy()
			selectedChallenge = acmech
			selectedNumLabelsMatch = numLabelsMatch
			selectedNumDNSNamesMatch = numDNSNamesMatch
			selectedNumDNSZonesMatch = numDNSZonesMatch
		}

		if selectedSolver == nil {
			dbg.Info("selecting solver as there is no previously selected solver")
			selectSolver()
			continue
		}

		dbg.Info("determining whether this match is more significant than last")

		// because we don't count multiple dnsName matches as extra 'weight'
		// in the selection process, we normalise the numDNSNamesMatch vars
		// to be either 1 or 0 (i.e. true or false)
		selectedHasMatchingDNSNames := selectedNumDNSNamesMatch > 0
		hasMatchingDNSNames := numDNSNamesMatch > 0

		// dnsName selectors have the highest precedence, so check them first
		switch {
		case !selectedHasMatchingDNSNames && hasMatchingDNSNames:
			dbg.Info("selecting solver as this solver has matching DNS names and the previous one does not")
			selectSolver()
			continue
		case selectedHasMatchingDNSNames && !hasMatchingDNSNames:
			dbg.Info("not selecting solver as the previous one has matching DNS names and this one does not")
			continue
		case !selectedHasMatchingDNSNames && !hasMatchingDNSNames:
			dbg.Info("solver does not have any matching DNS names, checking dnsZones")
			// check zones
		case selectedHasMatchingDNSNames && hasMatchingDNSNames:
			dbg.Info("both this solver and the previously selected one matches dnsNames, comparing zones")
			if numDNSZonesMatch > selectedNumDNSZonesMatch {
				dbg.Info("selecting solver as this one has a more specific dnsZone match than the previously selected one")
				selectSolver()
				continue
			}
			if selectedNumDNSZonesMatch > numDNSZonesMatch {
				dbg.Info("not selecting this solver as the previously selected one has a more specific dnsZone match")
				continue
			}
			dbg.Info("both this solver and the previously selected one match dnsZones, comparing labels")
			// choose the one with the most labels
			if numLabelsMatch > selectedNumLabelsMatch {
				dbg.Info("selecting solver as this one has more labels than the previously selected one")
				selectSolver()
				continue
			}
			dbg.Info("not selecting this solver as previous one has either the same number of or more labels")
			continue
		}

		selectedHasMatchingDNSZones := selectedNumDNSZonesMatch > 0
		hasMatchingDNSZones := numDNSZonesMatch > 0

		switch {
		case !selectedHasMatchingDNSZones && hasMatchingDNSZones:
			dbg.Info("selecting solver as this solver has matching DNS zones and the previous one does not")
			selectSolver()
			continue
		case selectedHasMatchingDNSZones && !hasMatchingDNSZones:
			dbg.Info("not selecting solver as the previous one has matching DNS zones and this one does not")
			continue
		case !selectedHasMatchingDNSZones && !hasMatchingDNSZones:
			dbg.Info("solver does not have any matching DNS zones, checking labels")
			// check labels
		case selectedHasMatchingDNSZones && hasMatchingDNSZones:
			dbg.Info("both this solver and the previously selected one matches dnsZones")
			dbg.Info("comparing number of matching domain segments")
			// choose the one with the most matching DNS zone segments
			if numDNSZonesMatch > selectedNumDNSZonesMatch {
				dbg.Info("selecting solver because this one has more matching DNS zone segments")
				selectSolver()
				continue
			}
			if selectedNumDNSZonesMatch > numDNSZonesMatch {
				dbg.Info("not selecting solver because previous one has more matching DNS zone segments")
				continue
			}
			// choose the one with the most labels
			if numLabelsMatch > selectedNumLabelsMatch {
				dbg.Info("selecting solver because this one has more labels than the previous one")
				selectSolver()
				continue
			}
			dbg.Info("not selecting solver as this one's number of matching labels is equal to or less than the last one")
			continue
		}

		if numLabelsMatch > selectedNumLabelsMatch {
			dbg.Info("selecting solver as this one has more labels than the last one")
			selectSolver()
			continue
		}

		dbg.Info("not selecting solver as this one's number of matching labels is equal to or less than the last one (reached end of loop)")
		// if we get here, the number of matches is less than or equal so we
		// fallback to choosing the first in the list
	}

	if selectedSolver == nil || selectedChallenge == nil {
		return nil, fmt.Errorf("no configured challenge solvers can be used for this challenge")
	}

	key, err := keyForChallenge(cl, selectedChallenge)
	if err != nil {
		return nil, err
	}

	// 4. construct Challenge resource with spec.solver field set
	return &cmapi.ChallengeSpec{
		AuthzURL:  authz.URL,
		Type:      selectedChallenge.Type,
		URL:       selectedChallenge.URL,
		DNSName:   authz.Identifier.Value,
		Token:     selectedChallenge.Token,
		Key:       key,
		Solver:    selectedSolver,
		Wildcard:  authz.Wildcard,
		IssuerRef: o.Spec.IssuerRef,
	}, nil
}

func (c *controller) oldFormatChallengeSpecForAuthorization(ctx context.Context, cl acmecl.Interface, issuer cmapi.GenericIssuer, o *cmapi.Order, authz *acmeapi.Authorization) (*cmapi.ChallengeSpec, error) {
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
		Config:    cfg,
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
func (c *controller) syncOrderStatus(ctx context.Context, cl acmecl.Interface, o *cmapi.Order) error {
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
func (c *controller) setOrderStatus(o *cmapi.OrderStatus, acmeOrder *acmeapi.Order) {
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
func (c *controller) setOrderState(o *cmapi.OrderStatus, s cmapi.State) {
	o.State = s
	// if the order is in a failure state, we should set the `failureTime` field
	if acme.IsFailureState(o.State) {
		t := metav1.NewTime(c.clock.Now())
		o.FailureTime = &t
	}
}

func (c *controller) storeCertificateOnStatus(o *cmapi.Order, certs [][]byte) error {
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
	c.recorder.Event(o, corev1.EventTypeNormal, "OrderValid", "Order completed successfully")

	return nil
}
