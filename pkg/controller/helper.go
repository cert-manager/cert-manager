package controller

import (
	"fmt"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
)

// Type Helper provides a set of commonly useful functions for use when building
// a cert-manager controller.
// An instance of Helper is made available as part of a controller's context.
type Helper struct {
	issuerLister        cmlisters.IssuerLister
	clusterIssuerLister cmlisters.ClusterIssuerLister
}

// NewHelper will construct a new instance of a Helper using values supplied on
// the provided controller context.
func NewHelper(issuerLister cmlisters.IssuerLister, clusterIssuerLister cmlisters.ClusterIssuerLister) *Helper {
	return &Helper{
		issuerLister:        issuerLister,
		clusterIssuerLister: clusterIssuerLister,
	}
}

// GetGenericIssuer will return an Issuer for the given IssuerRef.
// The namespace parameter must be provided if an 'Issuer' is referenced.
// This namespace will be used to read the Issuer resource.
// In most cases, the ns parameter should be set to the namespace of the resource
// that defines the IssuerRef (i.e. the namespace of the Certificate resource).
func (h *Helper) GetGenericIssuer(ref cmapi.ObjectReference, ns string) (cmapi.GenericIssuer, error) {
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
