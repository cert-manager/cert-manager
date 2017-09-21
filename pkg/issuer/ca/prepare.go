package ca

import (
	"context"

	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
)

// Prepare does nothing for the CA issuer. In future, this may validate
// the certificate request against the issuer, or set fields in the Status
// block to be consumed in Issue and Renew
func (c *CA) Prepare(ctx context.Context, crt *v1alpha1.Certificate) (v1alpha1.CertificateStatus, error) {
	return crt.Status, nil
}
