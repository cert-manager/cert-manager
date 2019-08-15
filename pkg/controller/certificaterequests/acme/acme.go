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
	"crypto/x509"
	"encoding/json"
	"fmt"
	"hash/fnv"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"

	"github.com/jetstack/cert-manager/pkg/acme"
	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	cmclientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1alpha1"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/certificaterequests"
	crutil "github.com/jetstack/cert-manager/pkg/controller/certificaterequests/util"
	issuerpkg "github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	CRControllerName = "certificaterequests-issuer-acme"
)

type ACME struct {
	// used to record Events about resources to the API
	recorder      record.EventRecorder
	issuerOptions controllerpkg.IssuerOptions

	orderLister cmlisters.OrderLister
	cmClientV   cmclientset.CertmanagerV1alpha1Interface

	reporter *crutil.Reporter
}

func init() {
	// create certificate request controller for acme issuer
	controllerpkg.Register(CRControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		acme := NewACME(ctx)

		orderInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().Orders().Informer()
		controller := certificaterequests.New(apiutil.IssuerACME, acme, orderInformer)

		c, err := controllerpkg.New(ctx, CRControllerName, controller)
		if err != nil {
			return nil, err
		}

		return c.Run, nil
	})
}

func NewACME(ctx *controllerpkg.Context) *ACME {
	return &ACME{
		recorder:      ctx.Recorder,
		issuerOptions: ctx.IssuerOptions,
		orderLister:   ctx.SharedInformerFactory.Certmanager().V1alpha1().Orders().Lister(),
		cmClientV:     ctx.CMClient.CertmanagerV1alpha1(),
		reporter:      crutil.NewReporter(ctx.Clock, ctx.Recorder),
	}
}

func (a *ACME) Sign(ctx context.Context, cr *v1alpha1.CertificateRequest, issuer v1alpha1.GenericIssuer) (*issuerpkg.IssueResponse, error) {
	log := logf.FromContext(ctx, "sign")
	resourceNamespace := a.issuerOptions.ResourceNamespace(issuer)

	// If we can't decode the CSR PEM we have to hard fail
	csr, err := pki.DecodeX509CertificateRequestBytes(cr.Spec.CSRPEM)
	if err != nil {
		message := "Failed to decode CSR in spec"

		a.reporter.Failed(cr, err, "CSRParsingError", message)
		log.Error(err, message)

		return nil, nil
	}

	// If we fail to build the order we have to hard fail.
	expectedOrder, err := buildOrder(cr, csr)
	if err != nil {
		message := "Failed to build order"

		a.reporter.Failed(cr, err, "OrderBuildingError", message)
		log.Error(err, message)

		return nil, nil
	}

	order, err := a.orderLister.Orders(expectedOrder.Namespace).Get(expectedOrder.Name)
	if k8sErrors.IsNotFound(err) {
		// Failing to create the order here is most likely network related.
		// We should backoff and keep trying.
		_, err = a.cmClientV.Orders(resourceNamespace).Create(expectedOrder)
		if err != nil {
			message := fmt.Sprintf("Failed create new order resource %s/%s", resourceNamespace, expectedOrder.Name)

			a.reporter.Pending(cr, err, "OrderCreatingError", message)
			log.Error(err, message)

			return nil, err
		}

		message := fmt.Sprintf("Created Order resource %s/%s",
			resourceNamespace, expectedOrder.Name)
		a.reporter.Pending(cr, nil, "OrderCreated", message)
		log.V(4).Info(message)

		return nil, nil
	}

	if err != nil {
		// We are probably in a network error here so we should backoff and retry
		message := fmt.Sprintf("Failed to get order resource %s/%s", resourceNamespace, expectedOrder.Name)

		a.reporter.Pending(cr, err, "OrderGetError", message)
		log.Error(err, message)

		return nil, err
	}

	log = logf.WithResource(log, order)

	// If the acme order has failed then so too does the CertificateRequest meet the same fate.
	if acme.IsFailureState(order.Status.State) {
		message := fmt.Sprintf("Failed to wait for order resource %s/%s to become ready",
			resourceNamespace, expectedOrder.Name)
		err := fmt.Errorf("order is in %q state", order.Status.State)

		a.reporter.Failed(cr, err, "OrderFailed", message)

		return nil, nil
	}

	// Order valid, return cert. The calling controller will update with ready if its happy with the cert.
	if order.Status.State == v1alpha1.Valid {
		log.Info("certificate issued")

		return &issuerpkg.IssueResponse{
			Certificate: order.Status.Certificate,
		}, nil
	}

	// We update here to just pending while we wait for the order to be resolved.
	a.reporter.Pending(cr, nil, "OrderPending",
		fmt.Sprintf("Waiting on certificate issuance from order %s/%s: %q",
			resourceNamespace, order.Name, order.Status.State))

	log.Info("acme Order resource is not in a ready state, waiting...")

	return nil, nil
}

// Build order. If we error here it is a terminating failure.
func buildOrder(cr *v1alpha1.CertificateRequest, csr *x509.CertificateRequest) (*v1alpha1.Order, error) {
	spec := v1alpha1.OrderSpec{
		CSR:        cr.Spec.CSRPEM,
		IssuerRef:  cr.Spec.IssuerRef,
		CommonName: csr.Subject.CommonName,
		DNSNames:   csr.DNSNames,
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
			Name:      fmt.Sprintf("%.52s-%d", cr.Name, hash),
			Namespace: cr.Namespace,
			Labels:    cr.Labels,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(cr, v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CertificateRequestKind)),
			},
		},
		Spec: spec,
	}, nil
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
