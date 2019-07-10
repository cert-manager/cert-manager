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

package acme

import (
	"context"
	"crypto"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/fnv"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	"github.com/jetstack/cert-manager/pkg/acme"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	createOrderWaitDuration = time.Hour * 1
)

var (
	certificateGvk = v1alpha1.SchemeGroupVersion.WithKind("Certificate")
)

func (a *Acme) Issue(ctx context.Context, crt *v1alpha1.Certificate) (*issuer.IssueResponse, error) {
	log := logf.FromContext(ctx)

	key, generated, err := a.getCertificatePrivateKey(ctx, crt)
	if err != nil {
		log.Error(err, "error getting certificate private key")
		return nil, err
	}
	if generated {
		// If we have generated a new private key, we return here to ensure we
		// successfully persist the key before creating any CSRs with it.
		log.V(logf.DebugLevel).Info("storing newly generated certificate private key")
		a.Recorder.Eventf(crt, corev1.EventTypeNormal, "Generated", "Generated new private key")

		keyPem, err := pki.EncodePrivateKey(key, crt.Spec.KeyEncoding)
		if err != nil {
			return nil, err
		}

		// Replace the existing secret with one containing only the new private key.
		return &issuer.IssueResponse{
			PrivateKey: keyPem,
		}, nil
	} else {
		log.V(logf.DebugLevel).Info("using existing private key stored in secret")
	}

	// Initially, we do not set the csr on the order resource we build.
	// This is to save having the overhead of generating a new CSR in the case
	// where the Order resource is up to date already, and also because we have
	// not actually read the existing certificate private key yet to ensure it
	// exists.
	expectedOrder, err := buildOrder(crt, nil)
	if err != nil {
		a.Recorder.Eventf(crt, corev1.EventTypeWarning, "Unknown", "Error building Order resource: %v", err)
		return nil, err
	}

	// Cleanup Order resources that are owned by this Certificate but are not
	// up to date (i.e. do not match the requirements on the Certificate).
	// Because the order name returned by buildOrder is a hash of its spec, we
	// can simply delete all order resources that are owned by us that do not
	// have the same name.
	err = a.cleanupOwnedOrders(ctx, crt, expectedOrder.Name)
	if err != nil {
		a.Recorder.Eventf(crt, corev1.EventTypeWarning, "CleanupError", "Cleaning up existing Order resources failed: %v", err)
		return nil, err
	}

	// Obtain the existing Order for this Certificate from the API server.
	// If it does not exist, we continue on as it will be created from
	// the generated expectedOrder.
	existingOrder, err := a.orderLister.Orders(expectedOrder.Namespace).Get(expectedOrder.Name)
	if err != nil && !apierrors.IsNotFound(err) {
		log.WithValues(
			logf.RelatedResourceNamespaceKey, expectedOrder.Namespace,
			logf.RelatedResourceNameKey, expectedOrder.Name,
			logf.RelatedResourceKindKey, v1alpha1.OrderKind,
		).Error(err, "error getting existing Order resource")
		return nil, err
	}
	if existingOrder == nil {
		err := a.createNewOrder(ctx, crt, expectedOrder, key)
		if err != nil {
			a.Recorder.Eventf(crt, corev1.EventTypeWarning, "CreateError", "Failed to create Order resource: %v", err)
			return nil, err
		}
		return nil, nil
	}
	log = logf.WithRelatedResource(log, existingOrder)

	// if there is an existing order, we check to make sure it is up to date
	// with the current certificate & issuer configuration.
	// if it is not, we will abandon the old order and create a new one.
	// The 'retry' cases here will bypass the controller's rate-limiting, as
	// well as the back-off applied to failing ACME Orders.
	// They should therefore *only* match on changes to the actual Certificate
	// resource, or underlying Order (i.e. user interaction).
	log.V(4).Info("Validating existing CSR on Order for Certificate")

	validForKey, err := existingOrderIsValidForKey(existingOrder, key)
	if err != nil {
		return nil, err
	}
	if !validForKey {
		log.V(4).Info("CSR on existing order resource does not match current private key")
		return nil, a.retryOrder(crt, existingOrder)
	}

	// If the existing order has expired, we should create a new one
	// TODO: implement setting this order state in the acmeorders controller
	if existingOrder.Status.State == v1alpha1.Expired {
		a.Recorder.Eventf(crt, corev1.EventTypeNormal, "OrderExpired", "Existing certificate for Order %q expired", existingOrder.Name)
		return nil, a.retryOrder(crt, existingOrder)
	}

	// If the existing order has failed, we should check if the Certificate
	// already has a LastFailureTime
	// - If it does not, then this is a new failure and we record the LastFailureTime
	//   as Now() and return
	// - If it does, and it is more than the 'back-off' period ago, we retry the order
	// - Otherwise we return an error to attempt re-processing at a later time
	if acme.IsFailureState(existingOrder.Status.State) {
		if crt.Status.LastFailureTime == nil {
			nowTime := metav1.NewTime(a.clock.Now())
			crt.Status.LastFailureTime = &nowTime
			a.Recorder.Eventf(crt, corev1.EventTypeWarning, "FailedOrder", "Order %q failed. Waiting %s before retrying issuance.", existingOrder.Name, createOrderWaitDuration)
		}

		if time.Now().Sub(crt.Status.LastFailureTime.Time) < createOrderWaitDuration {
			return nil, fmt.Errorf("applying acme order back-off for certificate %s/%s because it has failed within the last %s", crt.Namespace, crt.Name, createOrderWaitDuration)
		}

		return nil, a.retryOrder(crt, existingOrder)
	}

	if existingOrder.Status.State != v1alpha1.Valid {
		log.Info("Order is not in 'valid' state. Waiting for Order to transition before attempting to issue Certificate.")

		// We don't immediately requeue, as the change to the Order resource on
		// transition should trigger the certificate to be re-synced.
		return nil, nil
	}

	// this should never happen
	if existingOrder.Status.Certificate == nil {
		a.Recorder.Eventf(crt, corev1.EventTypeWarning, "NoCertificate", "Empty certificate data retrieved from ACME server")
		return nil, fmt.Errorf("order in a valid state but certificate data not set")
	}

	// TODO: replace with a call to a function that returns the whole chain
	x509Cert, err := pki.DecodeX509CertificateBytes(existingOrder.Status.Certificate)
	if err != nil {
		log.Error(err, "error parsing existing x509 certificate on Order resource")
		a.Recorder.Eventf(crt, corev1.EventTypeWarning, "ParseError", "Error decoding certificate issued by Order: %v", err)
		// if parsing the certificate fails, recreate the order
		return nil, a.retryOrder(crt, existingOrder)
	}

	a.Recorder.Eventf(crt, corev1.EventTypeNormal, "OrderComplete", "Order %q completed successfully", existingOrder.Name)

	// we check if the certificate stored on the existing order resource is
	// nearing expiry.
	// If it is, we recreate the order so we can obtain a fresh certificate.
	// If not, we return the existing order's certificate to save additional
	// orders.
	if a.Context.IssuerOptions.CertificateNeedsRenew(ctx, x509Cert, crt) {
		a.Recorder.Eventf(crt, corev1.EventTypeNormal, "OrderExpired", "Order %q contains a certificate nearing expiry. "+
			"Creating new order...")
		// existing order's certificate is near expiry
		return nil, a.retryOrder(crt, existingOrder)
	}

	// encode the private key and return
	keyPem, err := pki.EncodePrivateKey(key, crt.Spec.KeyEncoding)
	if err != nil {
		// TODO: this is probably an internal error - we should fail safer here
		return nil, err
	}

	return &issuer.IssueResponse{
		Certificate: existingOrder.Status.Certificate,
		PrivateKey:  keyPem,
	}, nil
}

func (a *Acme) cleanupOwnedOrders(ctx context.Context, crt *v1alpha1.Certificate, retain string) error {
	log := logf.FromContext(ctx)

	// TODO: don't use a label selector at all here, instead we can index orders by their ownerRef and query based on owner reference alone
	// construct a label selector
	req, err := labels.NewRequirement(certificateNameLabelKey, selection.Equals, []string{crt.Name})
	if err != nil {
		return err
	}
	selector := labels.NewSelector().Add(*req)

	existingOrders, err := a.orderLister.Orders(crt.Namespace).List(selector)
	if err != nil {
		return err
	}

	var errs []error
	for _, o := range existingOrders {
		log := logf.WithRelatedResource(log, o)
		// Don't touch any objects that don't have this certificate set as the
		// owner reference.
		if !metav1.IsControlledBy(o, crt) {
			continue
		}

		if o.Name == retain {
			log.V(4).Info("Skipping cleanup for active order resource")
			continue
		}

		// delete any old order resources
		log.Info("Deleting Order resource")
		a.Recorder.Eventf(crt, corev1.EventTypeNormal, "Cleanup",
			fmt.Sprintf("Deleting old Order resource %q", o.Name))

		err := a.CMClient.CertmanagerV1alpha1().Orders(o.Namespace).Delete(o.Name, nil)
		if err != nil && !apierrors.IsNotFound(err) {
			log.Error(err, "error deleting Order resource")
			errs = append(errs, err)
			continue
		}
	}

	return utilerrors.NewAggregate(errs)
}

func (a *Acme) getCertificatePrivateKey(ctx context.Context, crt *v1alpha1.Certificate) (crypto.Signer, bool, error) {
	log := logf.FromContext(ctx)
	log = log.WithValues(
		logf.RelatedResourceNameKey, crt.Spec.SecretName,
		logf.RelatedResourceNamespaceKey, crt.Namespace,
		logf.RelatedResourceKindKey, "Secret",
	)

	log.V(4).Info("attempting to fetch existing certificate private key")

	// If a private key already exists, reuse it.
	// TODO: if we have not observed the update to the Secret resource with the
	// private key yet, we may in some cases loop and re-generate the private key
	// over and over. We could attempt to use the live clientset to read the
	// private key too to avoid this case.
	key, err := kube.SecretTLSKey(ctx, a.secretsLister, crt.Namespace, crt.Spec.SecretName)
	if err == nil {
		return key, false, nil
	}

	// We only generate a new private key if the existing one is not found or
	// contains invalid data.
	// TODO: should we re-generate on InvalidData?
	if !apierrors.IsNotFound(err) && !errors.IsInvalidData(err) {
		return nil, false, err
	}

	log.V(4).Info("Generating new private key")

	// generate a new private key.
	privateKey, err := pki.GeneratePrivateKeyForCertificate(crt)
	if err != nil {
		return nil, false, err
	}

	return privateKey, true, nil
}

func (a *Acme) createNewOrder(ctx context.Context, crt *v1alpha1.Certificate, template *v1alpha1.Order, key crypto.Signer) error {
	log := logf.FromContext(ctx)
	log = logf.WithRelatedResource(log, template)

	log.V(4).Info("Creating new Order resource for Certificate")

	csr, err := pki.GenerateCSR(crt)
	if err != nil {
		// TODO: what errors can be produced here? some error types might
		// be permanent, and we should handle that properly.
		return err
	}

	csrDER, err := pki.EncodeCSR(csr, key)
	if err != nil {
		return err
	}

	// encode the DER CSR bytes into PEM format
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrDER,
	})

	// set the CSR field on the order to be created
	template.Spec.CSR = csrPEM

	o, err := a.CMClient.CertmanagerV1alpha1().Orders(template.Namespace).Create(template)
	if err != nil {
		return err
	}

	a.Recorder.Eventf(crt, corev1.EventTypeNormal, "OrderCreated", "Created Order resource %q", o.Name)
	log.V(4).Info("Created new Order resource for Certificate")

	return nil
}

// retryOrder will delete the existing order with the foreground
// deletion policy.
// If delete successfully (i.e. cleaned up), the order name will be
// reset to empty and a resync of the resource will begin.
func (a *Acme) retryOrder(crt *v1alpha1.Certificate, existingOrder *v1alpha1.Order) error {
	foregroundDeletion := metav1.DeletePropagationForeground
	err := a.CMClient.CertmanagerV1alpha1().Orders(existingOrder.Namespace).Delete(existingOrder.Name, &metav1.DeleteOptions{
		PropagationPolicy: &foregroundDeletion,
	})
	if err != nil {
		return err
	}

	crt.Status.LastFailureTime = nil

	// Updating the certificate status will trigger a requeue once the change
	// has been observed by the informer.
	// If we set Requeue: true here, we may cause a race where the lister has
	// not observed the updated orderRef.
	return nil
}

func existingOrderIsValidForKey(o *v1alpha1.Order, key crypto.Signer) (bool, error) {
	// check the CSR is created by the private key that we hold
	csrBytes := o.Spec.CSR
	if len(csrBytes) == 0 {
		// Handles a weird case where an Order exists *without* a CSR set
		return false, nil
	}
	existingCSR, err := pki.DecodeX509CertificateRequestBytes(csrBytes)
	if err != nil {
		// Absorb invalid CSR data as 'not valid'
		return false, nil
	}

	matches, err := pki.PublicKeyMatchesCSR(key.Public(), existingCSR)
	if err != nil {
		// If this returns an error, something bad happened parsing somewhere
		return false, err
	}
	if !matches {
		return false, nil
	}

	return true, nil
}

func buildOrder(crt *v1alpha1.Certificate, csr []byte) (*v1alpha1.Order, error) {
	var oldConfig []v1alpha1.DomainSolverConfig
	if crt.Spec.ACME != nil {
		oldConfig = crt.Spec.ACME.Config
	}
	spec := v1alpha1.OrderSpec{
		CSR:        csr,
		IssuerRef:  crt.Spec.IssuerRef,
		CommonName: crt.Spec.CommonName,
		DNSNames:   crt.Spec.DNSNames,
		Config:     oldConfig,
	}
	hash, err := hashOrder(spec)
	if err != nil {
		return nil, err
	}

	// truncate certificate name so final name will be <= 63 characters.
	// hash (uint32) will be at most 10 digits long, and we account for
	// the hyphen.
	return &v1alpha1.Order{
		ObjectMeta: metav1.ObjectMeta{
			Name:            fmt.Sprintf("%.52s-%d", crt.Name, hash),
			Namespace:       crt.Namespace,
			Labels:          orderLabels(crt),
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(crt, certificateGvk)},
		},
		Spec: spec,
	}, nil
}

const certificateNameLabelKey = "acme.cert-manager.io/certificate-name"

func orderLabels(crt *v1alpha1.Certificate) map[string]string {
	lbls := make(map[string]string, len(crt.Labels)+1)
	// copy across labels from the Certificate resource onto the Order.
	// In future, determining which challenge solver to use will be solely
	// calculated in the orders controller, and copying the label values
	// across saves the Order controller depending on the existence of a
	// Certificate resource in order to calculate challenge solvers to use.
	for k, v := range crt.Labels {
		lbls[k] = v
	}
	lbls[certificateNameLabelKey] = crt.Name
	return lbls
}

func hashOrder(orderSpec v1alpha1.OrderSpec) (uint32, error) {
	// create a shallow copy of the OrderSpec so we can overwrite the CSR field
	orderSpec.CSR = nil

	orderSpecBytes, err := json.Marshal(orderSpec)
	if err != nil {
		return 0, err
	}

	hashF := fnv.New32()
	_, err = hashF.Write(orderSpecBytes)
	if err != nil {
		return 0, err
	}

	return hashF.Sum32(), nil
}
