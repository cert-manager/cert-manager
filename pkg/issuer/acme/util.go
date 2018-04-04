package acme

import (
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/third_party/crypto/acme"
)

// This file includes some utility functions that can be used throughout the
// package. Functions in this file should not be members of structs, and
// instead should be package scoped members.

// buildOrder will construct an ACME Order structure for a given Certificate.
// This function should always be used to construct orders for Certificates.
func buildOrder(crt *v1alpha1.Certificate) (*acme.Order, error) {
	// DNSNamesForCertificate will automatically include the common name
	// for the certificate if not already included, so we don't need to
	// append the common name here.
	desiredDNSNames := pki.DNSNamesForCertificate(crt)
	return acme.NewOrder(desiredDNSNames...), nil
}
