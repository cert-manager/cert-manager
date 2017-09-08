package issuers

import (
	"k8s.io/apimachinery/pkg/util/errors"

	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func (c *Controller) Sync(iss *v1alpha1.Issuer) (err error) {
	i, err := c.issuerFactory.IssuerFor(iss)

	if err != nil {
		return err
	}

	var status v1alpha1.IssuerStatus
	status, err = i.Setup()

	defer func() {
		if saveErr := c.updateIssuerStatus(iss, status); saveErr != nil {
			errs := []error{saveErr}
			if err != nil {
				errs = append(errs, err)
			}
			err = errors.NewAggregate(errs)
		}
	}()

	if err != nil {
		return err
	}

	return nil
}

func (c *Controller) updateIssuerStatus(iss *v1alpha1.Issuer, status v1alpha1.IssuerStatus) error {
	updateIssuer := iss.DeepCopy()
	updateIssuer.Status = status
	// TODO: replace Update call with UpdateStatus. This requires a custom API
	// server with the /status subresource enabled and/or subresource support
	// for CRDs (https://github.com/kubernetes/kubernetes/issues/38113)
	_, err := c.cmClient.CertmanagerV1alpha1().Issuers(iss.Namespace).Update(updateIssuer)
	return err
}
