package acme

import (
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/third_party/crypto/acme"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

// This file includes some utility functions that can be used throughout the
// package. Functions in this file should not be members of structs, and
// instead should be package scoped members.

// buildOrder will construct an ACME Order structure for a given Certificate.
// This function should always be used to construct orders for Certificates.
func buildOrder(crt *v1alpha1.Certificate) (*acme.Order, error) {
	desiredCN, err := pki.CommonNameForCertificate(crt)
	if err != nil {
		return nil, err
	}
	desiredDNSNames, err := pki.DNSNamesForCertificate(crt)
	if err != nil {
		return nil, err
	}
	desiredDomains := append([]string{desiredCN}, desiredDNSNames...)
	return acme.NewOrder(desiredDomains...), nil
}
