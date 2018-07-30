package cfssl

import (
	"context"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

// Prepare does nothing for the CFSSL issuer. In future, this may validate
// the certificate request against the issuer, or set fields in the Status
// block to be consumed in Issue and Renew
func (c *CFSSL) Prepare(ctx context.Context, crt *v1alpha1.Certificate) error {
	return nil
}
