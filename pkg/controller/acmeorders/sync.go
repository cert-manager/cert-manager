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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/jetstack/cert-manager/pkg/acme"
	acmecl "github.com/jetstack/cert-manager/pkg/acme/client"
	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1alpha2"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/metrics"
	acmeapi "github.com/jetstack/cert-manager/third_party/crypto/acme"
)

func (c *controller) Sync(ctx context.Context, o *cmacme.Order) (err error) {
	log := logf.FromContext(ctx)
	dbg := log.V(logf.DebugLevel)

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
		_, updateErr := c.cmClient.AcmeV1alpha2().Orders(o.Namespace).UpdateStatus(o)
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
	cl, err := c.acmeHelper.ClientForIssuer(genericIssuer)
	if err != nil {
		return err
	}

	switch {
	case o.Status.URL == "":
		log.Info("Creating new ACME order as status.url is not set")
		return c.createOrder(ctx, cl, o)
	case o.Status.FinalizeURL == "":
		log.Info("Updating Order status as status.finalizeURL is not set")
		_, err := c.updateOrderStatus(ctx, cl, o)
		return err
	case anyAuthorizationsMissingMetadata(o):
		log.Info("Fetching Authorizations from ACME server as status.authorizations contains unpopulated authorizations")
		return c.fetchMetadataForAuthorizations(ctx, o, cl)
	case acme.IsFailureState(o.Status.State):
		log.Info("Doing nothing as Order is in a failed state")
		// if the Order is failed there's nothing left for us to do, return nil
		return nil
	case o.Status.State == cmacme.Valid && o.Status.Certificate == nil:
		log.Info("Order is in a Valid state but the Certificate data is empty, fetching existing Certificate")
		return c.fetchCertificateData(ctx, cl, o)
	case o.Status.State == cmacme.Valid && len(o.Status.Certificate) > 0:
		log.Info("Order has already been completed, cleaning up any owned Challenge resources")
		// if the Order is valid and the certificate data has been set, clean
		// up any owned Challenge resources and do nothing
		return c.deleteAllChallenges(o)
	}

	dbg.Info("Computing list of Challenge resources that need to exist to complete this Order")
	requiredChallenges, err := buildRequiredChallenges(ctx, cl, genericIssuer, o)
	if err != nil {
		log.Error(err, "Failed to determine the list of Challenge resources needed for the Order")
		c.recorder.Eventf(o, corev1.EventTypeWarning, "Solver", "Failed to determine a valid solver configuration for the set of domains on the Order: %v", err)
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
		log.Info("Creating additional Challenge resources to complete Order")
		return c.createRequiredChallenges(o, requiredChallenges)
	case needToDeleteChallenges:
		log.Info("Deleting leftover Challenge resources no longer required by Order")
		return c.deleteLeftoverChallenges(o, requiredChallenges)
	}

	// we know that this list only contains the 'required' challenges as we use
	// the same lister above to determine whether we need to create or delete
	// any Challenge resources
	challenges, err := c.listOwnedChallenges(o)
	if err != nil {
		return err
	}

	switch {
	case o.Status.State == cmacme.Ready:
		log.Info("Finalizing Order as order state is 'Ready'")
		return c.finalizeOrder(ctx, cl, o)
	case anyChallengesFailed(challenges):
		// TODO (@munnerz): instead of waiting for the ACME server to mark this
		//  Order as failed, we could just mark the Order as failed as there is
		//  no way that we will attempt and continue the order anyway.
		log.Info("Update Order status as at least one Challenge has failed")
		_, err := c.updateOrderStatus(ctx, cl, o)
		return err
	// anyChallengesFailed(challenges) == false is already implied by the above
	// case, but explicitly check it here in case anything changes in future.
	case !anyChallengesFailed(challenges) && allChallengesFinal(challenges):
		log.Info("All challenges are in a final state, updating order state")
		_, err := c.updateOrderStatus(ctx, cl, o)
		return err
	}

	log.Info("No action taken")

	return nil
}

func (c *controller) createOrder(ctx context.Context, cl acmecl.Interface, o *cmacme.Order) error {
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
		// TODO: handle transient vs permanent failures here
		return fmt.Errorf("error creating new order: %v", err)
	}
	log.Info("submitted Order to ACME server")

	o.Status.URL = acmeOrder.URL
	o.Status.FinalizeURL = acmeOrder.FinalizeURL
	o.Status.Authorizations = constructAuthorizations(acmeOrder)
	c.setOrderState(&o.Status, acmeOrder.Status)

	return nil
}

func (c *controller) updateOrderStatus(ctx context.Context, cl acmecl.Interface, o *cmacme.Order) (*acmeapi.Order, error) {
	log := logf.FromContext(ctx)
	if o.Status.URL == "" {
		return nil, fmt.Errorf("internal error: order URL not set")
	}

	log.Info("Fetching Order metadata from ACME server")
	acmeOrder, err := cl.GetOrder(ctx, o.Status.URL)
	if acmeErr, ok := err.(*acmeapi.Error); ok {
		if acmeErr.StatusCode >= 400 && acmeErr.StatusCode < 500 {
			log.Error(err, "failed to update Order status due to a 4xx error, marking Order as failed")
			c.setOrderState(&o.Status, string(cmacme.Errored))
			o.Status.Reason = fmt.Sprintf("Failed to retrieve Order resource: %v", err)
			return nil, nil
		}
	}
	if err != nil {
		// TODO: handle different ACME error types
		return nil, err
	}

	log.V(logf.DebugLevel).Info("Retrieved ACME order from server", "raw_data", acmeOrder)
	o.Status.URL = acmeOrder.URL
	o.Status.FinalizeURL = acmeOrder.FinalizeURL
	c.setOrderState(&o.Status, acmeOrder.Status)
	// only set the authorizations field if the lengths mismatch.
	// state can be rebuilt in this case on the next call to ProcessItem.
	if len(o.Status.Authorizations) != len(acmeOrder.Authorizations) {
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
	authzs := make([]cmacme.ACMEAuthorization, len(o.Authorizations))
	for i, url := range o.Authorizations {
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

		authz.Identifier = acmeAuthz.Identifier.Value
		authz.Wildcard = acmeAuthz.Wildcard
		authz.Challenges = make([]cmacme.ACMEChallenge, len(acmeAuthz.Challenges))
		for i, acmech := range acmeAuthz.Challenges {
			authz.Challenges[i].URL = acmech.URL
			authz.Challenges[i].Token = acmech.Token
			authz.Challenges[i].Type = cmacme.ACMEChallengeType(acmech.Type)
		}
		o.Status.Authorizations[i] = authz
	}
	return nil
}

func (c *controller) anyRequiredChallengesDoNotExist(requiredChallenges []cmacme.Challenge) (bool, error) {
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

func (c *controller) createRequiredChallenges(o *cmacme.Order, requiredChallenges []cmacme.Challenge) error {
	for _, ch := range requiredChallenges {
		_, err := c.cmClient.AcmeV1alpha2().Challenges(ch.Namespace).Create(&ch)
		if apierrors.IsAlreadyExists(err) {
			continue
		}
		if err != nil {
			return err
		}
		c.recorder.Eventf(o, corev1.EventTypeNormal, "Created", "Created Challenge resource %q for domain %q", ch.Name, ch.Spec.DNSName)
	}
	return nil
}

func (c *controller) anyLeftoverChallengesExist(o *cmacme.Order, requiredChallenges []cmacme.Challenge) (bool, error) {
	leftoverChallenges, err := c.determineLeftoverChallenges(o, requiredChallenges)
	if err != nil {
		return false, err
	}

	return len(leftoverChallenges) > 0, nil
}

func (c *controller) deleteLeftoverChallenges(o *cmacme.Order, requiredChallenges []cmacme.Challenge) error {
	leftover, err := c.determineLeftoverChallenges(o, requiredChallenges)
	if err != nil {
		return err
	}

	for _, ch := range leftover {
		if err := c.cmClient.AcmeV1alpha2().Challenges(ch.Namespace).Delete(ch.Name, nil); err != nil {
			return err
		}
	}

	return nil
}

func (c *controller) deleteAllChallenges(o *cmacme.Order) error {
	challenges, err := c.listOwnedChallenges(o)
	if err != nil {
		return err
	}

	for _, ch := range challenges {
		if err := c.cmClient.AcmeV1alpha2().Challenges(ch.Namespace).Delete(ch.Name, nil); err != nil {
			return err
		}
	}

	return nil
}

func (c *controller) determineLeftoverChallenges(o *cmacme.Order, requiredChallenges []cmacme.Challenge) ([]*cmacme.Challenge, error) {
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

func (c *controller) finalizeOrder(ctx context.Context, cl acmecl.Interface, o *cmacme.Order) error {
	log := logf.FromContext(ctx)

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

	certSlice, err := cl.FinalizeOrder(ctx, o.Status.FinalizeURL, derBytes)
	// always update the order status after calling Finalize - this allows
	// us to record the current orders status on this order resource
	// despite it not being returned directly by the acme client.
	// This will catch cases where the Order cannot be finalized because it
	// if it is already in the 'valid' state, as upon retry we will
	// then retrieve the Certificate resource.
	_, errUpdate := c.updateOrderStatus(ctx, cl, o)
	if errUpdate != nil {
		// TODO: mark permanent failure?
		return fmt.Errorf("error syncing order status: %v", errUpdate)
	}
	// check for errors from FinalizeOrder
	if err != nil {
		return fmt.Errorf("error finalizing order: %v", err)
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

func (c *controller) fetchCertificateData(ctx context.Context, cl acmecl.Interface, o *cmacme.Order) error {
	log := logf.FromContext(ctx)
	acmeOrder, err := c.updateOrderStatus(ctx, cl, o)
	if err != nil {
		return err
	}
	if acmeOrder == nil {
		log.Info("Failed to fetch Order from ACME server as it no longer exists. Not retrying.")
		return nil
	}

	// If the Order state has actually changed and we've not observed it,
	// update the order status and let the change in the resource trigger
	// a resync
	if acmeOrder.Status != acmeapi.StatusValid {
		return nil
	}

	certs, err := cl.GetCertificate(ctx, acmeOrder.CertificateURL)
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

	err = c.storeCertificateOnStatus(ctx, o, certs)
	if err != nil {
		return err
	}

	return nil
}
