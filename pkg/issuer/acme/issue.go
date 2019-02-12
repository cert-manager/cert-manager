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

package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/fnv"
	"time"

	"github.com/golang/glog"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	"github.com/jetstack/cert-manager/pkg/acme"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	createOrderWaitDuration = time.Minute * 5
)

var (
	certificateGvk = v1alpha1.SchemeGroupVersion.WithKind("Certificate")
)

func (a *Acme) Issue(ctx context.Context, crt *v1alpha1.Certificate) (issuer.IssueResponse, error) {
	key, generated, err := a.getCertificatePrivateKey(crt)
	if err != nil {
		glog.Errorf("Error getting certificate private key: %v", err)
		return issuer.IssueResponse{}, err
	}
	if generated {
		// If we have generated a new private key, we return here to ensure we
		// successfully persist the key before creating any CSRs with it.
		glog.V(4).Infof("Storing new certificate private key for %s/%s", crt.Namespace, crt.Name)

		keyPem, err := pki.EncodePrivateKey(key)
		if err != nil {
			return issuer.IssueResponse{}, err
		}

		return issuer.IssueResponse{
			PrivateKey: keyPem,
		}, nil
	}

	// Initially, we do not set the csr on the order resource we build.
	// This is to save having the overhead of generating a new CSR in the case
	// where the Order resource is up to date already, and also because we have
	// not actually read the existing certificate private key yet to ensure it
	// exists.
	expectedOrder, err := buildOrder(crt, nil)
	if err != nil {
		return issuer.IssueResponse{}, err
	}

	// Cleanup Order resources that are owned by this Certificate but are not
	// up to date (i.e. do not match the requirements on the Certificate).
	// Because the order name returned by buildOrder is a hash of its spec, we
	// can simply delete all order resources that are owned by us that do not
	// have the same name.
	err = a.cleanupOwnedOrders(crt, expectedOrder.Name)
	if err != nil {
		glog.Errorf("Error cleaning up old orders: %v", err)
		return issuer.IssueResponse{}, err
	}

	// Obtain the existing Order for this Certificate from the API server.
	// If it does not exist, we continue on as it will be created from
	// the generated expectedOrder.
	existingOrder, err := a.orderLister.Orders(expectedOrder.Namespace).Get(expectedOrder.Name)
	if err != nil && !apierrors.IsNotFound(err) {
		glog.Errorf("Error getting existing Order resource: %v", err)
		return issuer.IssueResponse{}, err
	}
	if existingOrder == nil {
		return issuer.IssueResponse{}, a.createNewOrder(crt, expectedOrder, key)
	}

	// if there is an existing order, we check to make sure it is up to date
	// with the current certificate & issuer configuration.
	// if it is not, we will abandon the old order and create a new one.
	// The 'retry' cases here will bypass the controller's rate-limiting, as
	// well as the back-off applied to failing ACME Orders.
	// They should therefore *only* match on changes to the actual Certificate
	// resource, or underlying Order (i.e. user interaction).
	glog.V(4).Infof("Validating existing order CSR for Certificate %s/%s", crt.Namespace, crt.Name)

	validForKey, err := existingOrderIsValidForKey(existingOrder, key)
	if err != nil {
		return issuer.IssueResponse{}, err
	}
	if !validForKey {
		glog.V(4).Infof("CSR on existing order resource does not match certificate %s/%s private key. Creating new order.", crt.Namespace, crt.Name)
		return a.retryOrder(crt, existingOrder)
	}

	// If the existing order has expired, we should create a new one
	// TODO: implement setting this order state in the acmeorders controller
	if existingOrder.Status.State == v1alpha1.Expired {
		return a.retryOrder(crt, existingOrder)
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
		}

		if time.Now().Sub(crt.Status.LastFailureTime.Time) < createOrderWaitDuration {
			return issuer.IssueResponse{}, fmt.Errorf("applying acme order back-off for certificate %s/%s because it has failed within the last %s", crt.Namespace, crt.Name, createOrderWaitDuration)
		}

		return a.retryOrder(crt, existingOrder)
	}

	if existingOrder.Status.State != v1alpha1.Valid {
		glog.Infof("Order %s/%s is not in 'valid' state. Waiting for Order to transition before attempting to issue Certificate.", existingOrder.Namespace, existingOrder.Name)

		// We don't immediately requeue, as the change to the Order resource on
		// transition should trigger the certificate to be re-synced.
		return issuer.IssueResponse{}, nil
	}

	// If the order is valid, we can attempt to retrieve the Certificate.
	// First obtain an ACME client to make this easier.
	cl, err := a.helper.ClientForIssuer(a.issuer)
	if err != nil {
		return issuer.IssueResponse{}, err
	}

	// We check the current Order's Certificate resource to see if it's nearing expiry.
	// If it is, this implies that it is an old order that is now out of date.
	certSlice, err := cl.GetCertificate(ctx, existingOrder.Status.CertificateURL)
	if err != nil {
		// TODO: parse returned ACME error and potentially re-create order.
		return issuer.IssueResponse{}, err
	}

	if len(certSlice) == 0 {
		// TODO: parse returned ACME error and potentially re-create order.
		return issuer.IssueResponse{}, fmt.Errorf("invalid certificate returned from acme server")
	}

	x509Cert, err := x509.ParseCertificate(certSlice[0])
	if err != nil {
		// if parsing the certificate fails, recreate the order
		return a.retryOrder(crt, existingOrder)
	}

	if a.Context.IssuerOptions.CertificateNeedsRenew(x509Cert) {
		// existing order's certificate is near expiry
		return a.retryOrder(crt, existingOrder)
	}

	// encode the retrieved certificates (including the chain)
	certBuffer := bytes.NewBuffer([]byte{})
	for _, cert := range certSlice {
		err := pem.Encode(certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
		if err != nil {
			return issuer.IssueResponse{}, err
		}
	}

	// encode the private key and return
	keyPem, err := pki.EncodePrivateKey(key)
	if err != nil {
		// TODO: this is probably an internal error - we should fail safer here
		return issuer.IssueResponse{}, err
	}

	return issuer.IssueResponse{
		Certificate: certBuffer.Bytes(),
		PrivateKey:  keyPem,
	}, nil
}

func (a *Acme) cleanupOwnedOrders(crt *v1alpha1.Certificate, retain string) error {
	labelMap := certLabels(crt.Name)
	selector := labels.NewSelector()
	for k, v := range labelMap {
		req, err := labels.NewRequirement(k, selection.Equals, []string{v})
		if err != nil {
			return err
		}
		selector.Add(*req)
	}
	existingOrders, err := a.orderLister.Orders(crt.Namespace).List(selector)
	if err != nil {
		return err
	}

	var errs []error
	for _, o := range existingOrders {
		// Don't touch any objects that don't have this certificate set as the
		// owner reference.
		if !metav1.IsControlledBy(o, crt) {
			continue
		}

		if o.Name == retain {
			glog.V(4).Infof("Skipping cleanup for active order resource %q", retain)
			continue
		}

		// delete any old order resources
		glog.Infof("Deleting Order resource %s/%s", o.Namespace, o.Name)
		a.Recorder.Eventf(crt, corev1.EventTypeNormal, "Cleanup",
			fmt.Sprintf("Deleting old Order resource %q", o.Name))

		err := a.CMClient.CertmanagerV1alpha1().Orders(o.Namespace).Delete(o.Name, nil)
		if err != nil && !apierrors.IsNotFound(err) {
			glog.Errorf("Error deleting Order resource %s/%s: %v", o.Namespace, o.Name, err)
			errs = append(errs, err)
			continue
		}
	}

	return utilerrors.NewAggregate(errs)
}

func (a *Acme) getCertificatePrivateKey(crt *v1alpha1.Certificate) (crypto.Signer, bool, error) {
	glog.V(4).Infof("Attempting to fetch existing certificate private key")

	// If a private key already exists, reuse it.
	// TODO: if we have not observed the update to the Secret resource with the
	// private key yet, we may in some cases loop and re-generate the private key
	// over and over. We could attempt to use the live clientset to read the
	// private key too to avoid this case.
	key, err := kube.SecretTLSKey(a.secretsLister, crt.Namespace, crt.Spec.SecretName)
	if err == nil {
		return key, false, nil
	}

	// We only generate a new private key if the existing one is not found or
	// contains invalid data.
	// TODO: should we re-generate on InvalidData?
	if !apierrors.IsNotFound(err) && !errors.IsInvalidData(err) {
		return nil, false, err
	}

	glog.V(4).Infof("Generating new private key for %s/%s", crt.Namespace, crt.Name)

	// generate a new private key.
	rsaKey, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		return nil, false, err
	}

	return rsaKey, true, nil
}

func (a *Acme) createNewOrder(crt *v1alpha1.Certificate, template *v1alpha1.Order, key crypto.Signer) error {
	glog.V(4).Infof("Creating new Order resource for Certificate %s/%s", crt.Namespace, crt.Name)

	csr, err := pki.GenerateCSR(a.issuer, crt)
	if err != nil {
		// TODO: what errors can be produced here? some error types might
		// be permenant, and we should handle that properly.
		return err
	}

	csrBytes, err := pki.EncodeCSR(csr, key)
	if err != nil {
		return err
	}

	// set the CSR field on the order to be created
	template.Spec.CSR = csrBytes

	_, err = a.CMClient.CertmanagerV1alpha1().Orders(template.Namespace).Create(template)
	if err != nil {
		return err
	}

	glog.V(4).Infof("Created new Order resource named %q for Certificate %s/%s", template.Name, crt.Namespace, crt.Name)

	return nil
}

// retryOrder will delete the existing order with the foreground
// deletion policy.
// If delete successfully (i.e. cleaned up), the order name will be
// reset to empty and a resync of the resource will begin.
func (a *Acme) retryOrder(crt *v1alpha1.Certificate, existingOrder *v1alpha1.Order) (issuer.IssueResponse, error) {
	foregroundDeletion := metav1.DeletePropagationForeground
	err := a.CMClient.CertmanagerV1alpha1().Orders(existingOrder.Namespace).Delete(existingOrder.Name, &metav1.DeleteOptions{
		PropagationPolicy: &foregroundDeletion,
	})
	if err != nil {
		return issuer.IssueResponse{}, err
	}

	crt.Status.LastFailureTime = nil

	// Updating the certificate status will trigger a requeue once the change
	// has been observed by the informer.
	// If we set Requeue: true here, we may cause a race where the lister has
	// not observed the updated orderRef.
	return issuer.IssueResponse{}, nil
}

func existingOrderIsValidForKey(o *v1alpha1.Order, key crypto.Signer) (bool, error) {
	// check the CSR is created by the private key that we hold
	csrBytes := o.Spec.CSR
	if len(csrBytes) == 0 {
		// Handles a weird case where an Order exists *without* a CSR set
		return false, nil
	}
	existingCSR, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		// Absorb invalid CSR datas as 'not valid'
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
	spec := v1alpha1.OrderSpec{
		CSR:        csr,
		IssuerRef:  crt.Spec.IssuerRef,
		CommonName: crt.Spec.CommonName,
		DNSNames:   crt.Spec.DNSNames,
		Config:     crt.Spec.ACME.Config,
	}
	hash, err := hashOrder(spec)
	if err != nil {
		return nil, err
	}

	return &v1alpha1.Order{
		ObjectMeta: metav1.ObjectMeta{
			Name:            fmt.Sprintf("%s-%d", crt.Name, hash),
			Namespace:       crt.Namespace,
			Labels:          certLabels(crt.Name),
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(crt, certificateGvk)},
		},
		Spec: spec,
	}, nil
}

func certLabels(crtName string) map[string]string {
	return map[string]string{
		"acme.cert-manager.io/certificate-name": crtName,
	}
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
