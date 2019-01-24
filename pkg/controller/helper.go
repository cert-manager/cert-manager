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

package controller

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/golang/glog"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
)

type Helper interface {
	GetGenericIssuer(ref cmapi.ObjectReference, ns string) (cmapi.GenericIssuer, error)
}

// Type Helper provides a set of commonly useful functions for use when building
// a cert-manager controller.
// An instance of Helper is made available as part of a controller's context.
type helperImpl struct {
	issuerLister        cmlisters.IssuerLister
	clusterIssuerLister cmlisters.ClusterIssuerLister
}

var _ Helper = &helperImpl{}

// NewHelper will construct a new instance of a Helper using values supplied on
// the provided controller context.
func NewHelper(issuerLister cmlisters.IssuerLister, clusterIssuerLister cmlisters.ClusterIssuerLister) Helper {
	return &helperImpl{
		issuerLister:        issuerLister,
		clusterIssuerLister: clusterIssuerLister,
	}
}

// GetGenericIssuer will return an Issuer for the given IssuerRef.
// The namespace parameter must be provided if an 'Issuer' is referenced.
// This namespace will be used to read the Issuer resource.
// In most cases, the ns parameter should be set to the namespace of the resource
// that defines the IssuerRef (i.e. the namespace of the Certificate resource).
func (h *helperImpl) GetGenericIssuer(ref cmapi.ObjectReference, ns string) (cmapi.GenericIssuer, error) {
	switch ref.Kind {
	case "", cmapi.IssuerKind:
		return h.issuerLister.Issuers(ns).Get(ref.Name)
	case cmapi.ClusterIssuerKind:
		// handle edge case where the ClusterIssuerLister is not set.
		// this isn't actually a supported operating mode right now, nor is it
		// exposed to users.
		// we include it here in case we do allow this mode of operation again
		// in future.
		if h.clusterIssuerLister == nil {
			return nil, fmt.Errorf("cannot get ClusterIssuer named %q as cert-manager is scoped to a single namespace", ref.Name)
		}
		return h.clusterIssuerLister.Get(ref.Name)
	default:
		return nil, fmt.Errorf(`invalid value %q for issuerRef.kind. Must be empty, %q or %q`, ref.Kind, cmapi.IssuerKind, cmapi.ClusterIssuerKind)
	}
}

func (o IssuerOptions) ResourceNamespace(iss cmapi.GenericIssuer) string {
	ns := iss.GetObjectMeta().Namespace
	if ns == "" {
		ns = o.ClusterResourceNamespace
	}
	return ns
}

func (o IssuerOptions) CanUseAmbientCredentials(iss cmapi.GenericIssuer) bool {
	switch iss.(type) {
	case *cmapi.ClusterIssuer:
		return o.ClusterIssuerAmbientCredentials
	case *cmapi.Issuer:
		return o.IssuerAmbientCredentials
	}
	return false
}

func (o IssuerOptions) CertificateNeedsRenew(cert *x509.Certificate, crt *cmapi.Certificate) bool {
	return o.CalculateDurationUntilRenew(cert, crt) <= 0
}

// to help testing
var now = time.Now

// CalculateDurationUntilRenew calculates how long cert-manager should wait to
// until attempting to renew this certificate resource.
func (o IssuerOptions) CalculateDurationUntilRenew(cert *x509.Certificate, crt *cmapi.Certificate) time.Duration {
	messageCertificateDuration := "Certificate received from server has a validity duration of %s. The requested certificate validity duration was %s"
	messageScheduleModified := "Certificate renewal duration was changed to fit inside the received certificate validity duration from issuer."

	// validate if the certificate received was with the issuer configured
	// duration. If not we generate an event to warn the user of that fact.
	certDuration := cert.NotAfter.Sub(cert.NotBefore)
	if crt.Spec.Duration != nil && certDuration < crt.Spec.Duration.Duration {
		s := fmt.Sprintf(messageCertificateDuration, certDuration, crt.Spec.Duration.Duration)
		glog.Info(s)
		// TODO Use the message as the reason in a 'renewal status' condition
	}

	// renew is the duration before the certificate expiration that cert-manager
	// will start to try renewing the certificate.
	renewBefore := cmapi.DefaultRenewBefore
	if crt.Spec.RenewBefore != nil {
		renewBefore = crt.Spec.RenewBefore.Duration
	}

	// Verify that the renewBefore duration is inside the certificate validity duration.
	// If not we notify with an event that we will renew the certificate
	// before (certificate duration / 3) of its expiration duration.
	if renewBefore > certDuration {
		glog.Info(messageScheduleModified)
		// TODO Use the message as the reason in a 'renewal status' condition
		// We will renew 1/3 before the expiration date.
		renewBefore = certDuration / 3
	}

	// calculate the amount of time until expiry
	durationUntilExpiry := cert.NotAfter.Sub(now())
	// calculate how long until we should start attempting to renew the certificate
	renewIn := durationUntilExpiry - renewBefore

	return renewIn
}
