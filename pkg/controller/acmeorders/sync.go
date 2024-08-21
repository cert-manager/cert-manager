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

package acmeorders

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	acmeapi "golang.org/x/crypto/acme"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cert-manager/cert-manager/internal/controller/feature"
	internalorders "github.com/cert-manager/cert-manager/internal/controller/orders"
	"github.com/cert-manager/cert-manager/pkg/acme"
	acmecl "github.com/cert-manager/cert-manager/pkg/acme/client"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
)

const (
	reasonSolver  = "Solver"
	reasonCreated = "Created"
)

var (
	// RequeuePeriod is the default period after which an Order should be re-queued.
	// It can be overridden in tests.
	RequeuePeriod = time.Second * 5
)

func (c *controller) Sync(ctx context.Context, o *cmacme.Order) (err error) {
	log := logf.FromContext(ctx)
	dbg := log.V(logf.DebugLevel)

	oldOrder := o
	o = o.DeepCopy()

	defer func() {
		if apiequality.Semantic.DeepEqual(oldOrder.Status, o.Status) {
			dbg.Info("skipping updating resource as new status == existing status")
			return
		}
		log.V(logf.DebugLevel).Info("updating Order resource status")
		updateErr := c.updateOrApplyStatus(ctx, o)
		if updateErr != nil {
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
	cl, err := c.accountRegistry.GetClient(string(genericIssuer.GetUID()))
	if err != nil {
		return err
	}

	switch {
	case acme.IsFailureState(o.Status.State):
		log.V(logf.DebugLevel).Info("Doing nothing as Order is in a failed state")
		// if the Order is failed there's nothing left for us to do, return nil
		return nil
	case o.Status.URL == "":
		log.V(logf.DebugLevel).Info("Creating new ACME order as status.url is not set")
		return c.createOrder(ctx, cl, o)
	case o.Status.FinalizeURL == "":
		log.V(logf.DebugLevel).Info("Updating Order status as status.finalizeURL is not set")
		_, err := c.updateOrderStatus(ctx, cl, o)
		if acmeErr, ok := err.(*acmeapi.Error); ok {
			if acmeErr.StatusCode >= 400 && acmeErr.StatusCode < 500 {
				log.Error(err, "failed to update Order status due to a 4xx error, marking Order as failed")
				c.setOrderState(&o.Status, string(cmacme.Errored))
				o.Status.Reason = fmt.Sprintf("Failed to retrieve Order resource: %v", err)
				return nil
			}
		}
		return err
	case anyAuthorizationsMissingMetadata(o):
		log.V(logf.DebugLevel).Info("Fetching Authorizations from ACME server as status.authorizations contains unpopulated authorizations")
		return c.fetchMetadataForAuthorizations(ctx, o, cl)
	// TODO: is this state possible? Either remove this case or add a comment as to what path could lead to it
	case o.Status.State == cmacme.Valid && o.Status.Certificate == nil:
		log.V(logf.DebugLevel).Info("Order is in a Valid state but the Certificate data is empty, fetching existing Certificate")
		return c.syncCertificateData(ctx, cl, o, genericIssuer)
	case o.Status.State == cmacme.Valid && len(o.Status.Certificate) > 0:
		log.V(logf.DebugLevel).Info("Order has already been completed, cleaning up any owned Challenge resources")
		// if the Order is valid and the certificate data has been set, clean
		// up any owned Challenge resources and do nothing
		return c.deleteAllChallenges(ctx, o)
	}

	dbg.Info("Computing list of Challenge resources that need to exist to complete this Order")
	requiredChallenges, err := buildPartialRequiredChallenges(ctx, genericIssuer, o)
	if err != nil {
		log.Error(err, "Failed to determine the list of Challenge resources needed for the Order")
		c.recorder.Eventf(o, corev1.EventTypeWarning, reasonSolver, "Failed to determine a valid solver configuration for the set of domains on the Order: %v", err)
		return nil
	}

	dbg.Info("Determining if any challenge resources need to be created")
	needToCreateChallenges, err := c.anyRequiredChallengesDoNotExist(requiredChallenges)
	if err != nil {
		return err
	}
	dbg.Info("Determining if any challenge resources need to be cleaned up")
	needToDeleteChallenges, err := c.anyLeftoverChallengesExist(o, requiredChallenges)
	if err != nil {
		return err
	}

	switch {
	case needToCreateChallenges:
		log.V(logf.DebugLevel).Info("Creating additional Challenge resources to complete Order")
		requiredChallenges, err = ensureKeysForChallenges(cl, requiredChallenges)
		if err != nil {
			return err
		}
		return c.createRequiredChallenges(ctx, o, requiredChallenges)
	case needToDeleteChallenges:
		log.V(logf.DebugLevel).Info("Deleting leftover Challenge resources no longer required by Order")
		return c.deleteLeftoverChallenges(ctx, o, requiredChallenges)
	}

	// we know that this list only contains the 'required' challenges as we use
	// the same lister above to determine whether we need to create or delete
	// any Challenge resources
	challenges, err := c.listOwnedChallenges(o)
	if err != nil {
		return err
	}

	if o.Status.State == cmacme.Ready {
		log.V(logf.DebugLevel).Info("Finalizing Order as order state is 'Ready'")
		return c.finalizeOrder(ctx, cl, o, genericIssuer)
	}

	// At this point, if no Challenges have failed or reached a final state,
	// we can return without taking any action. This controller will resync
	// the Order on any owned Challenge events.
	if !anyChallengesFailed(challenges) && !allChallengesFinal(challenges) {
		log.V(logf.DebugLevel).Info("No action taken")
		return nil
	}

	// Note: each of the following code paths uses the ACME Order retrieved
	// here. Be mindful when adding new code below this call to ACME server-
	// if the new code does not need this ACME order, try to place it above
	// this call to avoid extra calls to ACME.
	acmeOrder, err := getACMEOrder(ctx, cl, o)
	// Order probably has been deleted, we cannot recover here.
	if acmeErr, ok := err.(*acmeapi.Error); ok {
		if acmeErr.StatusCode >= 400 && acmeErr.StatusCode < 500 {
			log.Error(err, "failed to retrieve the ACME order (4xx error) marking Order as failed")
			c.setOrderState(&o.Status, string(cmacme.Errored))
			o.Status.Reason = fmt.Sprintf("Failed to retrieve Order resource: %v", err)
			return nil
		}
	}
	if err != nil {
		return err
	}

	switch {
	case anyChallengesFailed(challenges):
		// TODO (@munnerz): instead of waiting for the ACME server to
		// mark this Order as failed, we could just mark the Order as
		// failed as there is no way that we will attempt and continue
		// the order anyway. This might, however, be a breaking change
		// in edge cases where the status of the order resource in ACME
		// server cannot be determined from challenge resource statuses
		// correctly. Do not change this unless there is a real need for
		// it.
		log.V(logf.DebugLevel).Info("Update Order status as at least one Challenge has failed")
		_, err := c.updateOrderStatusFromACMEOrder(o, acmeOrder)
		if acmeErr, ok := err.(*acmeapi.Error); ok {
			if acmeErr.StatusCode >= 400 && acmeErr.StatusCode < 500 {
				log.Error(err, "failed to update Order status due to a 4xx error, marking Order as failed")
				c.setOrderState(&o.Status, string(cmacme.Errored))
				o.Status.Reason = fmt.Sprintf("Failed to retrieve Order resource: %v", err)
				return nil
			}
		}
		return err

	// anyChallengesFailed(challenges) == false is already implied by the above
	// case, but explicitly check it in the following cases for if anything changes in future.

	// This is to avoid stuck Orders in edge cases where all the Challenges have
	// been finalized, but the ACME server has not yet updated the ACME Order's
	// status to valid. This is not an expected behaviour from an ACME server
	// https://tools.ietf.org/html/rfc8555#section-7.1.6
	// https://github.com/cert-manager/cert-manager/issues/2868
	case !anyChallengesFailed(challenges) && allChallengesFinal(challenges) && acmeOrder.Status == acmeapi.StatusPending:
		log.V(logf.InfoLevel).Info("All challenges in a final state, waiting for ACME server to update the status of the order...")
		// This is probably not needed as at this point the Order's status
		// should already be Pending, but set it anyway to be explicit.
		c.setOrderState(&o.Status, string(cmacme.Pending))

		// Re-queue the Order to be processed again after 5 seconds.
		c.scheduledWorkQueue.Add(types.NamespacedName{
			Name:      o.Name,
			Namespace: o.Namespace,
		}, RequeuePeriod)

		return nil

	case !anyChallengesFailed(challenges) && allChallengesFinal(challenges):
		log.V(logf.DebugLevel).Info("All challenges are in a final state, updating order state")
		_, err := c.updateOrderStatusFromACMEOrder(o, acmeOrder)
		if acmeErr, ok := err.(*acmeapi.Error); ok {
			if acmeErr.StatusCode >= 400 && acmeErr.StatusCode < 500 {
				log.Error(err, "failed to update Order status due to a 4xx error, marking Order as failed")
				c.setOrderState(&o.Status, string(cmacme.Errored))
				o.Status.Reason = fmt.Sprintf("Failed to retrieve Order resource: %v", err)
				return nil
			}
		}
		return err
	}

	log.V(logf.DebugLevel).Info("No action taken")

	return nil
}

func (c *controller) createOrder(ctx context.Context, cl acmecl.Interface, o *cmacme.Order) error {
	log := logf.FromContext(ctx)

	if o.Status.URL != "" {
		return fmt.Errorf("refusing to recreate a new order for Order %q. Please create a new Order resource to initiate a new order", o.Name)
	}
	log.V(logf.DebugLevel).Info("order URL not set, submitting Order to ACME server")

	dnsIdentifierSet := sets.New[string](o.Spec.DNSNames...)
	if o.Spec.CommonName != "" {
		dnsIdentifierSet.Insert(o.Spec.CommonName)
	}
	log.V(logf.DebugLevel).Info("build set of domains for Order", "domains", sets.List(dnsIdentifierSet))

	ipIdentifierSet := sets.New[string](o.Spec.IPAddresses...)
	log.V(logf.DebugLevel).Info("build set of IPs for Order", "domains", sets.List(dnsIdentifierSet))

	authzIDs := acmeapi.DomainIDs(sets.List(dnsIdentifierSet)...)
	authzIDs = append(authzIDs, acmeapi.IPIDs(sets.List(ipIdentifierSet)...)...)
	// create a new order with the acme server

	var options []acmeapi.OrderOption
	if o.Spec.Duration != nil {
		options = append(options, acmeapi.WithOrderNotAfter(c.clock.Now().Add(o.Spec.Duration.Duration)))
	}
	acmeOrder, err := cl.AuthorizeOrder(ctx, authzIDs, options...)
	if acmeErr, ok := err.(*acmeapi.Error); ok {
		if acmeErr.StatusCode >= 400 && acmeErr.StatusCode < 500 {
			log.Error(err, "failed to create Order resource due to bad request, marking Order as failed")
			c.setOrderState(&o.Status, string(cmacme.Errored))
			o.Status.Reason = fmt.Sprintf("Failed to create Order: %v", err)
			return nil
		}
	}
	if err != nil {
		return fmt.Errorf("error creating new order: %v", err)
	}
	log.V(logf.DebugLevel).Info("submitted Order to ACME server")

	o.Status.URL = acmeOrder.URI
	o.Status.FinalizeURL = acmeOrder.FinalizeURL
	o.Status.Authorizations = constructAuthorizations(acmeOrder)
	c.setOrderState(&o.Status, acmeOrder.Status)

	return nil
}

func (c *controller) updateOrderStatus(ctx context.Context, cl acmecl.Interface, o *cmacme.Order) (*acmeapi.Order, error) {
	acmeOrder, err := getACMEOrder(ctx, cl, o)
	if err != nil {
		return nil, err
	}

	return c.updateOrderStatusFromACMEOrder(o, acmeOrder)
}

func (c *controller) updateOrderStatusFromACMEOrder(o *cmacme.Order, acmeOrder *acmeapi.Order) (*acmeapi.Order, error) {
	// Workaround bug in golang.org/x/crypto/acme implementation whereby the
	// order's URI field will be empty when calling GetOrder due to the
	// 'Location' header not being set on the response from the ACME server.
	if acmeOrder.URI != "" {
		o.Status.URL = acmeOrder.URI
	}
	o.Status.FinalizeURL = acmeOrder.FinalizeURL
	c.setOrderState(&o.Status, acmeOrder.Status)
	// once the 'authorizations' slice contains at least one item, it cannot be
	// updated. If it does not contain any items, update it containing the list
	// of authorizations returned on the Order.
	if len(o.Status.Authorizations) == 0 {
		o.Status.Authorizations = constructAuthorizations(acmeOrder)
	}

	return acmeOrder, nil
}

// setOrderState will set the 'State' field of the given Order to 's'.
// It will set the Orders failureTime field if the state provided is classed as
// a failure state.
func (c *controller) setOrderState(o *cmacme.OrderStatus, s string) {
	o.State = cmacme.State(s)
	// if the order is in a failure state, we should set the `failureTime` field
	if acme.IsFailureState(o.State) {
		t := metav1.NewTime(c.clock.Now())
		o.FailureTime = &t
	}
}

// constructAuthorizations will construct a slice of ACMEAuthorizations must be
// completed for the given ACME order.
// It does *not* perform a query against the ACME server for each authorization
// named on the Order to fetch additional metadata, instead, use
// populateAuthorization on each authorization in turn.
func constructAuthorizations(o *acmeapi.Order) []cmacme.ACMEAuthorization {
	authzs := make([]cmacme.ACMEAuthorization, len(o.AuthzURLs))
	for i, url := range o.AuthzURLs {
		authzs[i].URL = url
	}
	return authzs
}

func anyAuthorizationsMissingMetadata(o *cmacme.Order) bool {
	for _, a := range o.Status.Authorizations {
		if a.Identifier == "" {
			return true
		}
	}
	return false
}

func (c *controller) fetchMetadataForAuthorizations(ctx context.Context, o *cmacme.Order, cl acmecl.Interface) error {
	log := logf.FromContext(ctx)
	for i, authz := range o.Status.Authorizations {
		// only fetch metadata for each authorization once
		if authz.Identifier != "" {
			continue
		}

		acmeAuthz, err := cl.GetAuthorization(ctx, authz.URL)
		if acmeErr, ok := err.(*acmeapi.Error); ok {
			if acmeErr.StatusCode >= 400 && acmeErr.StatusCode < 500 {
				log.Error(err, "failed to fetch authorization metadata from acme server")
				c.setOrderState(&o.Status, string(cmacme.Errored))
				o.Status.Reason = fmt.Sprintf("Failed to fetch authorization: %v", err)
				return nil
			}
		}
		if err != nil {
			return err
		}

		authz.InitialState = cmacme.State(acmeAuthz.Status)
		authz.Identifier = acmeAuthz.Identifier.Value
		authz.Wildcard = &acmeAuthz.Wildcard
		authz.Challenges = make([]cmacme.ACMEChallenge, len(acmeAuthz.Challenges))
		for i, acmech := range acmeAuthz.Challenges {
			authz.Challenges[i].URL = acmech.URI
			authz.Challenges[i].Token = acmech.Token
			authz.Challenges[i].Type = acmech.Type
		}
		o.Status.Authorizations[i] = authz
	}
	return nil
}

func (c *controller) anyRequiredChallengesDoNotExist(requiredChallenges []*cmacme.Challenge) (bool, error) {
	for _, ch := range requiredChallenges {
		_, err := c.challengeLister.Challenges(ch.Namespace).Get(ch.Name)
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
	}
	return false, nil
}

func (c *controller) createRequiredChallenges(ctx context.Context, o *cmacme.Order, requiredChallenges []*cmacme.Challenge) error {
	for _, ch := range requiredChallenges {
		_, err := c.cmClient.AcmeV1().Challenges(ch.Namespace).Create(ctx, ch, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			continue
		}
		if err != nil {
			return err
		}
		c.recorder.Eventf(o, corev1.EventTypeNormal, reasonCreated, "Created Challenge resource %q for domain %q", ch.Name, ch.Spec.DNSName)
	}
	return nil
}

func (c *controller) anyLeftoverChallengesExist(o *cmacme.Order, requiredChallenges []*cmacme.Challenge) (bool, error) {
	leftoverChallenges, err := c.determineLeftoverChallenges(o, requiredChallenges)
	if err != nil {
		return false, err
	}

	return len(leftoverChallenges) > 0, nil
}

func (c *controller) deleteLeftoverChallenges(ctx context.Context, o *cmacme.Order, requiredChallenges []*cmacme.Challenge) error {
	leftover, err := c.determineLeftoverChallenges(o, requiredChallenges)
	if err != nil {
		return err
	}

	for _, ch := range leftover {
		if err := c.cmClient.AcmeV1().Challenges(ch.Namespace).Delete(ctx, ch.Name, metav1.DeleteOptions{}); err != nil {
			return err
		}
	}

	return nil
}

func (c *controller) deleteAllChallenges(ctx context.Context, o *cmacme.Order) error {
	challenges, err := c.listOwnedChallenges(o)
	if err != nil {
		return err
	}

	for _, ch := range challenges {
		if err := c.cmClient.AcmeV1().Challenges(ch.Namespace).Delete(ctx, ch.Name, metav1.DeleteOptions{}); err != nil {
			return err
		}
	}

	return nil
}

func (c *controller) determineLeftoverChallenges(o *cmacme.Order, requiredChallenges []*cmacme.Challenge) ([]*cmacme.Challenge, error) {
	requiredNames := map[string]struct{}{}
	for _, ch := range requiredChallenges {
		requiredNames[ch.Name] = struct{}{}
	}

	ownedChallenges, err := c.listOwnedChallenges(o)
	if err != nil {
		return nil, err
	}

	var leftover []*cmacme.Challenge
	for _, ch := range ownedChallenges {
		if _, ok := requiredNames[ch.Name]; ok {
			continue
		}
		leftover = append(leftover, ch)
	}

	return leftover, nil
}

func (c *controller) listOwnedChallenges(o *cmacme.Order) ([]*cmacme.Challenge, error) {
	chs, err := c.challengeLister.Challenges(o.Namespace).List(labels.Everything())
	if err != nil {
		return nil, err
	}

	var ownedChs []*cmacme.Challenge
	for _, ch := range chs {
		if !metav1.IsControlledBy(ch, o) {
			continue
		}
		ownedChs = append(ownedChs, ch)
	}

	return ownedChs, nil
}

func (c *controller) finalizeOrder(ctx context.Context, cl acmecl.Interface, o *cmacme.Order, issuer cmapi.GenericIssuer) error {
	log := logf.FromContext(ctx)

	// Due to a bug in the initial release of this controller, we previously
	// only supported DER encoded CSRs and not PEM encoded as they are intended
	// to be as part of our API.
	// To work around this, we first attempt to decode the Request into DER bytes
	// by running pem.Decode. If the PEM block is empty, we assume that the Request
	// is DER encoded and continue to call FinalizeOrder.
	var derBytes []byte
	block, _ := pem.Decode(o.Spec.Request)
	if block == nil {
		log.V(logf.WarnLevel).Info("failed to parse Request as PEM data, attempting to treat Request as DER encoded for compatibility reasons")
		derBytes = o.Spec.Request
	} else {
		derBytes = block.Bytes
	}

	// Call to CreateOrderCert finalizes the ACME order. This call can only be made once.
	certSlice, certURL, err := cl.CreateOrderCert(ctx, o.Status.FinalizeURL, derBytes, true)

	acmeErr, ok := err.(*acmeapi.Error)

	// If finalizing the order returns a 403 error, the order may already be finalized.
	// This scenario is possible if the ACME order has already been
	// finalized in an earlier reconcile, but the reconciler failed
	// to update the status of the Order CR.
	// https://datatracker.ietf.org/doc/html/rfc8555#:~:text=A%20request%20to%20finalize%20an%20order%20will%20result%20in%20error,will%20indicate%20what%20action%20the%20client%20should%20take%20(see%20below).
	if ok && acmeErr.StatusCode == http.StatusForbidden {

		acmeOrder, getOrderErr := getACMEOrder(ctx, cl, o)
		acmeGetOrderErr, ok := getOrderErr.(*acmeapi.Error)
		if ok && acmeGetOrderErr.StatusCode >= 400 && acmeGetOrderErr.StatusCode < 500 {
			log.Error(err, "failed to retrieve the ACME order (4xx error) marking Order as failed")
			c.setOrderState(&o.Status, string(cmacme.Errored))
			o.Status.Reason = fmt.Sprintf("Failed to retrieve Order resource: %v", err)
			return nil
		}
		if getOrderErr != nil {
			return getOrderErr
		}
		if acmeOrder.Status == acmeapi.StatusValid {
			log.V(logf.DebugLevel).Info("an attempt was made to finalize an order that has already been finalized. Marking the order as valid and fetching certificate data")
			c.setOrderState(&o.Status, string(cmacme.Valid))
			return c.syncCertificateDataWithOrder(ctx, cl, *acmeOrder, o, issuer)
		}

	}

	// Any other ACME 4xx error means that the Order can be considered failed.
	if ok && acmeErr.StatusCode >= 400 && acmeErr.StatusCode < 500 {
		log.Error(err, "failed to finalize Order resource due to bad request, marking Order as failed")
		c.setOrderState(&o.Status, string(cmacme.Errored))
		o.Status.Reason = fmt.Sprintf("Failed to finalize Order: %v", err)
		return nil
	}

	// Before checking whether the call to CreateOrderCert returned a
	// non-4xx error, ensure the order status is up-to-date.
	_, errUpdate := c.updateOrderStatus(ctx, cl, o)
	if acmeErr, ok := errUpdate.(*acmeapi.Error); ok {
		if acmeErr.StatusCode >= 400 && acmeErr.StatusCode < 500 {
			log.Error(err, "failed to update Order status due to a 4xx error, marking Order as failed")
			c.setOrderState(&o.Status, string(cmacme.Errored))
			o.Status.Reason = fmt.Sprintf("Failed to retrieve Order resource: %v", errUpdate)
			return nil
		}
	}
	if errUpdate != nil {
		return fmt.Errorf("error syncing order status: %v", errUpdate)
	}
	// Check for non-4xx errors from CreateOrderCert
	if err != nil {
		return fmt.Errorf("error finalizing order: %v", err)
	}

	if issuer.GetSpec().ACME != nil && issuer.GetSpec().ACME.PreferredChain != "" {
		preferredChainName := issuer.GetSpec().ACME.PreferredChain
		found, preferredCertChain, err := getPreferredCertChain(ctx, cl, certURL, certSlice, preferredChainName)
		if err != nil {
			return fmt.Errorf("error retrieving preferred chain: %w", err)
		}
		if found {
			return c.storeCertificateOnStatus(ctx, o, preferredCertChain)
		}
		// if no match is found we return to the actual cert
		// it is a *preferred* chain after all
		log.V(logf.DebugLevel).Info(fmt.Sprintf("Preferred chain %s not found, fall back to the default cert", preferredChainName))
	}

	return c.storeCertificateOnStatus(ctx, o, certSlice)
}

func (c *controller) storeCertificateOnStatus(ctx context.Context, o *cmacme.Order, certs [][]byte) error {
	log := logf.FromContext(ctx)
	// encode the retrieved certificates (including the chain)
	certBuffer := bytes.NewBuffer([]byte{})
	for _, cert := range certs {
		err := pem.Encode(certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
		if err != nil {
			log.Error(err, "invalid certificate data returned by ACME server")
			c.setOrderState(&o.Status, string(cmacme.Errored))
			o.Status.Reason = fmt.Sprintf("Invalid certificate retrieved from ACME server: %v", err)
			return nil
		}
	}

	o.Status.Certificate = certBuffer.Bytes()
	c.recorder.Event(o, corev1.EventTypeNormal, "Complete", "Order completed successfully")

	return nil
}

// syncCertificateData fetches the issued certificate data from ACME and stores
// it on Order's status.
func (c *controller) syncCertificateData(ctx context.Context, cl acmecl.Interface, o *cmacme.Order, issuer cmapi.GenericIssuer) error {
	log := logf.FromContext(ctx)
	acmeOrder, err := c.updateOrderStatus(ctx, cl, o)
	if acmeErr, ok := err.(*acmeapi.Error); ok {
		if acmeErr.StatusCode >= 400 && acmeErr.StatusCode < 500 {
			log.Error(err, "failed to update Order status due to a 4xx error, marking Order as failed")
			c.setOrderState(&o.Status, string(cmacme.Errored))
			o.Status.Reason = fmt.Sprintf("Failed to retrieve Order resource: %v", err)
			return nil
		}
	}
	if err != nil {
		return err
	}
	if acmeOrder == nil {
		log.V(logf.WarnLevel).Info("Failed to fetch Order from ACME server as it no longer exists. Not retrying.")
		return nil
	}

	return c.syncCertificateDataWithOrder(ctx, cl, *acmeOrder, o, issuer)
}

func (c *controller) syncCertificateDataWithOrder(ctx context.Context, cl acmecl.Interface, acmeOrder acmeapi.Order, o *cmacme.Order, issuer cmapi.GenericIssuer) error {
	log := logf.FromContext(ctx)
	// Certificate data can only be fetched for a valid order
	if acmeOrder.Status != acmeapi.StatusValid {
		return nil
	}

	certs, err := cl.FetchCert(ctx, acmeOrder.CertURL, true)
	if acmeErr, ok := err.(*acmeapi.Error); ok {
		if acmeErr.StatusCode >= 400 && acmeErr.StatusCode < 500 {
			log.Error(err, "failed to retrieve issued certificate from ACME server")
			c.setOrderState(&o.Status, string(cmacme.Errored))
			o.Status.Reason = fmt.Sprintf("Failed to retrieve signed certificate: %v", err)
			return nil
		}
	}
	if err != nil {
		return err
	}

	if issuer.GetSpec().ACME != nil && issuer.GetSpec().ACME.PreferredChain != "" {
		found, preferredCertChain, err := getPreferredCertChain(ctx, cl, acmeOrder.CertURL, certs, issuer.GetSpec().ACME.PreferredChain)
		if err != nil {
			return err
		}
		if found {
			return c.storeCertificateOnStatus(ctx, o, preferredCertChain)
		}
	}

	err = c.storeCertificateOnStatus(ctx, o, certs)
	if err != nil {
		return err
	}

	return nil
}

// getACMEOrder returns the ACME Order for an Order Custom Resource.
func getACMEOrder(ctx context.Context, cl acmecl.Interface, o *cmacme.Order) (*acmeapi.Order, error) {
	log := logf.FromContext(ctx)
	if o.Status.URL == "" {
		return nil, fmt.Errorf("internal error: order URL not set")
	}

	log.V(logf.DebugLevel).Info("Fetching Order metadata from ACME server")
	acmeOrder, err := cl.GetOrder(ctx, o.Status.URL)
	if err != nil {
		return nil, err
	}

	log.V(logf.DebugLevel).Info("Retrieved ACME order from server", "raw_data", acmeOrder)
	return acmeOrder, nil
}

func getPreferredCertChain(
	ctx context.Context,
	cl acmecl.Interface,
	certURL string,
	certBundle [][]byte,
	preferredChain string,
) (bool, [][]byte, error) {
	log := logf.FromContext(ctx)

	isMatch := func(name string, chain [][]byte) (bool, error) {
		if len(chain) == 0 {
			return false, nil
		}

		// Check topmost certificate
		cert, err := x509.ParseCertificate(chain[len(chain)-1])
		if err != nil {
			return false, fmt.Errorf("error parsing certificate chain: %w", err)
		}

		log.V(logf.DebugLevel).WithValues("Issuer CN", cert.Issuer.CommonName).Info("Found ACME bundle")
		if cert.Issuer.CommonName == preferredChain {
			// if the issuer's CN matched the preferred chain it means this bundle is
			// signed by the requested chain
			log.V(logf.DebugLevel).
				WithValues("Issuer CN", cert.Issuer.CommonName).
				Info("Selecting preferred ACME bundle with a matching Common Name from chain", "chainName", name)
			return true, nil
		}

		return false, nil
	}

	// Check if the default chain matches the preferred chain
	{
		match, err := isMatch("default", certBundle)
		if err != nil {
			return false, nil, err
		}
		if match {
			return true, certBundle, nil
		}
	}

	// Check if any alternate chain matches the preferred chain
	{
		altURLs, err := cl.ListCertAlternates(ctx, certURL)
		if err != nil {
			return false, nil, fmt.Errorf("error listing alternate certificate URLs: %w", err)
		}

		for _, chainURL := range altURLs {
			certChain, err := cl.FetchCert(ctx, chainURL, true)
			if err != nil {
				return false, nil, fmt.Errorf("error fetching certificate chain from %s: %w", chainURL, err)
			}

			match, err := isMatch(chainURL, certChain)
			if err != nil {
				return false, nil, err
			}

			if match {
				return true, certChain, nil
			}
		}
	}

	return false, nil, nil
}

// updateOrApplyStatus will update the order status.
// If the ServerSideApply feature is enabled, the managed fields will instead
// get applied using the relevant Patch API call.
func (c *controller) updateOrApplyStatus(ctx context.Context, order *cmacme.Order) error {
	if utilfeature.DefaultFeatureGate.Enabled(feature.ServerSideApply) {
		return internalorders.ApplyStatus(ctx, c.cmClient, c.fieldManager, &cmacme.Order{
			ObjectMeta: metav1.ObjectMeta{Namespace: order.Namespace, Name: order.Name},
			Status:     *order.Status.DeepCopy(),
		})
	} else {
		_, err := c.cmClient.AcmeV1().Orders(order.Namespace).UpdateStatus(ctx, order, metav1.UpdateOptions{})
		return err
	}
}
