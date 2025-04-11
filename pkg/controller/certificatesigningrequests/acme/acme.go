/*
Copyright 2021 The cert-manager Authors.

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
	"crypto/x509"
	"errors"
	"fmt"
	"slices"

	"github.com/go-logr/logr"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	certificatesclient "k8s.io/client-go/kubernetes/typed/certificates/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	"github.com/cert-manager/cert-manager/pkg/acme"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmacmeclientset "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/typed/acme/v1"
	cmacmelisters "github.com/cert-manager/cert-manager/pkg/client/listers/acme/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests"
	ctrlutil "github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/util"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

const (
	CSRControllerName = "certificatesigningrequests-issuer-acme"
)

// ACME is a Kubernetes CertificateSigningRequest controller, responsible for
// signing CertificateSigningRequests that reference a cert-manager ACME Issuer
// or ClusterIssuer.
type ACME struct {
	issuerOptions controllerpkg.IssuerOptions

	orderLister cmacmelisters.OrderLister
	acmeClientV cmacmeclientset.AcmeV1Interface
	certClient  certificatesclient.CertificateSigningRequestInterface

	recorder record.EventRecorder

	copiedAnnotationPrefixes []string

	// fieldManager is the manager name used for Create and Apply operations.
	fieldManager string
}

func init() {
	controllerpkg.Register(CSRControllerName, func(ctx *controllerpkg.ContextFactory) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, CSRControllerName).
			For(controllerBuilder()).
			Complete()
	})
}

func controllerBuilder() *certificatesigningrequests.Controller {
	return certificatesigningrequests.New(apiutil.IssuerACME, NewACME,
		func(ctx *controllerpkg.Context, log logr.Logger, queue workqueue.TypedRateLimitingInterface[types.NamespacedName]) ([]cache.InformerSynced, error) {
			orderInformer := ctx.SharedInformerFactory.Acme().V1().Orders().Informer()
			csrLister := ctx.KubeSharedInformerFactory.CertificateSigningRequests().Lister()

			if _, err := orderInformer.AddEventHandler(&controllerpkg.BlockingEventHandler{
				WorkFunc: controllerpkg.HandleOwnedResourceNamespacedFunc(
					log, queue,
					certificatesv1.SchemeGroupVersion.WithKind("CertificateSigningRequest"),
					func(_, name string) (*certificatesv1.CertificateSigningRequest, error) {
						return csrLister.Get(name)
					},
				),
			}); err != nil {
				return nil, fmt.Errorf("error setting up event handler: %v", err)
			}
			return []cache.InformerSynced{orderInformer.HasSynced}, nil
		},
	)
}

func NewACME(ctx *controllerpkg.Context) certificatesigningrequests.Signer {
	return &ACME{
		issuerOptions:            ctx.IssuerOptions,
		orderLister:              ctx.SharedInformerFactory.Acme().V1().Orders().Lister(),
		acmeClientV:              ctx.CMClient.AcmeV1(),
		certClient:               ctx.Client.CertificatesV1().CertificateSigningRequests(),
		recorder:                 ctx.Recorder,
		copiedAnnotationPrefixes: ctx.CertificateOptions.CopiedAnnotationPrefixes,
		fieldManager:             ctx.FieldManager,
	}
}

// Sign attempts to sign the given CertificateSigningRequest based on the
// provided ACME Issuer or ClusterIssuer.
//
// If no order exists for a CertificateSigningRequest, an order is constructed
// and sent back to the Kubernetes API server for processing.  The order
// controller then processes the order. The CertificateSigningRequest is then
// updated with the result.
func (a *ACME) Sign(ctx context.Context, csr *certificatesv1.CertificateSigningRequest, issuerObj cmapi.GenericIssuer) error {
	log := logf.FromContext(ctx, "sign")

	// If we can't decode the CSR PEM we have to hard fail.
	req, err := pki.DecodeX509CertificateRequestBytes(csr.Spec.Request)
	if err != nil {
		message := fmt.Sprintf("Failed to decode CSR in spec.request: %s", err)
		log.Error(err, message)
		a.recorder.Event(csr, corev1.EventTypeWarning, "RequestParsingError", message)
		ctrlutil.CertificateSigningRequestSetFailed(csr, "RequestParsingError", message)
		_, uerr := ctrlutil.UpdateOrApplyStatus(ctx, a.certClient, csr, certificatesv1.CertificateFailed, a.fieldManager)
		return uerr
	}

	// If the CommonName is also not present in the DNS names or IP Addresses of
	// the Request then hard fail.
	if len(req.Subject.CommonName) > 0 && !slices.Contains(req.DNSNames, req.Subject.CommonName) && !slices.Contains(pki.IPAddressesToString(req.IPAddresses), req.Subject.CommonName) {
		err = fmt.Errorf("%q does not exist in %s or %s", req.Subject.CommonName, req.DNSNames, pki.IPAddressesToString(req.IPAddresses))
		message := fmt.Sprintf("The CSR PEM requests a commonName that is not present in the list of dnsNames or ipAddresses. If a commonName is set, ACME requires that the value is also present in the list of dnsNames or ipAddresses: %s", err)

		log.Error(err, message)
		a.recorder.Event(csr, corev1.EventTypeWarning, "InvalidOrder", message)
		ctrlutil.CertificateSigningRequestSetFailed(csr, "InvalidOrder", message)
		_, uerr := ctrlutil.UpdateOrApplyStatus(ctx, a.certClient, csr, certificatesv1.CertificateFailed, a.fieldManager)
		return uerr
	}

	// If we fail to build the order we have to hard fail.
	expectedOrder, err := a.buildOrder(csr, req, issuerObj)
	if err != nil {
		message := fmt.Sprintf("Failed to build order: %s", err)

		log.Error(err, message)
		a.recorder.Event(csr, corev1.EventTypeWarning, "OrderBuildingError", message)
		ctrlutil.CertificateSigningRequestSetFailed(csr, "OrderBuildingError", message)
		_, uerr := ctrlutil.UpdateOrApplyStatus(ctx, a.certClient, csr, certificatesv1.CertificateFailed, a.fieldManager)
		return uerr
	}

	order, err := a.orderLister.Orders(expectedOrder.Namespace).Get(expectedOrder.Name)
	if apierrors.IsNotFound(err) {
		_, err = a.acmeClientV.Orders(expectedOrder.Namespace).Create(ctx, expectedOrder, metav1.CreateOptions{FieldManager: a.fieldManager})
		if err != nil {
			// Failing to create the order here is most likely network related. We
			// should backoff and keep trying.
			return fmt.Errorf("failed create new order resource %s/%s: %w",
				expectedOrder.Namespace, expectedOrder.Name, err)
		}

		message := fmt.Sprintf("Created Order resource %s/%s",
			expectedOrder.Namespace, expectedOrder.Name)
		a.recorder.Event(csr, corev1.EventTypeNormal, "OrderCreated", message)
		log.V(logf.DebugLevel).Info(message)
		return nil
	}

	if err != nil {
		// We are probably in a network error here so we should backoff and retry.
		message := fmt.Sprintf("Failed to get order resource %s/%s", expectedOrder.Namespace, expectedOrder.Name)
		log.Error(err, message)
		return err
	}

	if !metav1.IsControlledBy(order, csr) {
		// This error should never really happen since CertificateSigningRequests
		// are cluster scoped and so hashes won't conflict. This is likely from
		// someone manually creating the order out of band. We can only error.
		return errors.New("found Order resource not owned by this CertificateSigningRequest, retrying")
	}

	log = logf.WithRelatedResource(log, order)

	// If the acme order has failed then so too does the
	// CertificateSigningRequest meet the same fate.
	if acme.IsFailureState(order.Status.State) {
		err := fmt.Errorf("order is in %q state: %s", order.Status.State, order.Status.Reason)
		message := fmt.Sprintf("Failed to wait for order resource %s/%s to become ready: %s", expectedOrder.Namespace, expectedOrder.Name, err)

		a.recorder.Event(csr, corev1.EventTypeWarning, "OrderFailed", message)
		ctrlutil.CertificateSigningRequestSetFailed(csr, "OrderFailed", message)
		_, uerr := ctrlutil.UpdateOrApplyStatus(ctx, a.certClient, csr, certificatesv1.CertificateFailed, a.fieldManager)
		return uerr
	}

	if order.Status.State != cmacme.Valid {
		a.recorder.Event(csr, corev1.EventTypeNormal, "OrderPending",
			fmt.Sprintf("Waiting on certificate issuance from order %s/%s: %q",
				expectedOrder.Namespace, order.Name, order.Status.State))

		log.V(logf.DebugLevel).Info("acme Order resource is not in a ready state, waiting...")
		return nil
	}

	if len(order.Status.Certificate) == 0 {
		a.recorder.Event(csr, corev1.EventTypeNormal, "OrderPending",
			fmt.Sprintf("Waiting for order-controller to add certificate data to Order %s/%s",
				expectedOrder.Namespace, order.Name))

		log.V(logf.DebugLevel).Info("order controller has not added certificate data to the Order, waiting...")
		return nil
	}

	x509Cert, err := pki.DecodeX509CertificateBytes(order.Status.Certificate)
	if err != nil {
		message := fmt.Sprintf("Deleting Order with bad certificate: %s", err)
		a.recorder.Event(csr, corev1.EventTypeWarning, "OrderBadCertificate", message)
		log.Error(err, "failed to decode x509 certificate data on Order resource.")
		// Deleting the order here will cause a re-sync since the Order is owned by
		// this CertificateSigningRequest.
		return a.acmeClientV.Orders(order.Namespace).Delete(ctx, order.Name, metav1.DeleteOptions{})
	}

	if ok, err := pki.PublicKeyMatchesCertificate(req.PublicKey, x509Cert); err != nil || !ok {
		a.recorder.Event(csr, corev1.EventTypeWarning, "OrderBadCertificate", "Deleting Order as the signed certificate's key does not match the request")
		log.Error(err, "The public key in Order.Status.Certificate does not match the public key in CertificateSigningRequest.Spec.Request. Deleting the order.")
		// Deleting the order here will cause a re-sync since the Order is owned by
		// this CertificateSigningRequest.
		return a.acmeClientV.Orders(order.Namespace).Delete(ctx, order.Name, metav1.DeleteOptions{})
	}

	csr.Status.Certificate = order.Status.Certificate
	csr, err = ctrlutil.UpdateOrApplyStatus(ctx, a.certClient, csr, "", a.fieldManager)
	if err != nil {
		message := "Error updating certificate"
		a.recorder.Eventf(csr, corev1.EventTypeWarning, "SigningError", "%s: %s", message, err)
		return err
	}

	log.V(logf.DebugLevel).Info("certificate issued")
	a.recorder.Event(csr, corev1.EventTypeNormal, "CertificateIssued", "Certificate fetched from issuer successfully")

	return nil
}

// Build order. If we error here it is a terminating failure.
func (a *ACME) buildOrder(csr *certificatesv1.CertificateSigningRequest, req *x509.CertificateRequest, iss cmapi.GenericIssuer) (*cmacme.Order, error) {
	var ipAddresses []string
	for _, ip := range req.IPAddresses {
		ipAddresses = append(ipAddresses, ip.String())
	}

	var dnsNames []string
	if req.DNSNames != nil {
		dnsNames = req.DNSNames
	}

	ref, ok := ctrlutil.SignerIssuerRefFromSignerName(csr.Spec.SignerName)
	if !ok {
		return nil, errors.New("failed to construct issuer reference from signer name")
	}

	kind, ok := ctrlutil.IssuerKindFromType(ref.Type)
	if !ok {
		return nil, errors.New("failed to construct issuer kind from signer name")
	}

	spec := cmacme.OrderSpec{
		Request: csr.Spec.Request,
		IssuerRef: cmmeta.ObjectReference{
			Name:  ref.Name,
			Kind:  kind,
			Group: ref.Group,
		},
		CommonName:  req.Subject.CommonName,
		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
	}

	if iss.GetSpec().ACME.EnableDurationFeature {
		duration, err := pki.DurationFromCertificateSigningRequest(csr)
		if err != nil {
			// This should never happen as caller would have errored
			// before calling the ACME signer if the duration was
			// invalid.
			return nil, err
		}
		spec.Duration = &metav1.Duration{Duration: duration}
	}

	computeNameSpec := spec.DeepCopy()
	// Create a deep copy of the OrderSpec so we can overwrite the Request and
	// NotAfter field.
	computeNameSpec.Request = nil

	var hashObj interface{}
	hashObj = computeNameSpec
	if len(csr.Name) >= 52 {
		// Pass a unique struct for hashing so that names at or longer than 52
		// characters receive a unique hash. Otherwise, orders will have truncated
		// names with colliding hashes, possibly leading to non-renewal.
		hashObj = struct {
			CSRName string            `json:"certificateSigningRequestName"`
			Spec    *cmacme.OrderSpec `json:"spec"`
		}{
			CSRName: csr.Name,
			Spec:    computeNameSpec,
		}
	}
	name, err := apiutil.ComputeName(csr.Name, hashObj)
	if err != nil {
		return nil, err
	}

	// Filter the annotations copied from CertificateSigningRequest to the Order.
	annotations := controllerpkg.BuildAnnotationsToCopy(csr.Annotations, a.copiedAnnotationPrefixes)

	// Truncate certificate name so final name will be <= 63 characters. Hash
	// (uint32) will be at most 10 digits long, and we account for the hyphen.
	return &cmacme.Order{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   a.issuerOptions.ResourceNamespace(iss),
			Labels:      csr.Labels,
			Annotations: annotations,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(csr, schema.GroupVersionKind{Group: "certificates.k8s.io", Version: "v1", Kind: "CertificateSigningRequest"}),
			},
		},
		Spec: spec,
	}, nil
}
