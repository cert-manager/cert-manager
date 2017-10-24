package issuers

import (
	"context"

	"github.com/golang/glog"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/errors"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

const (
	errorInitIssuer = "ErrInitIssuer"

	messageErrorInitIssuer = "Error initializing issuer: "
)

func (c *Controller) Sync(ctx context.Context, iss *v1alpha1.Issuer) (err error) {
	issuerCopy := iss.DeepCopy()
	i, err := c.issuerFactory.IssuerFor(issuerCopy)

	if err != nil {
		return err
	}

	err = i.Setup(ctx)
	defer func() {
		if saveErr := c.updateIssuerStatus(issuerCopy); saveErr != nil {
			errs := []error{saveErr}
			if err != nil {
				errs = append(errs, err)
			}
			err = errors.NewAggregate(errs)
		}
	}()

	if err != nil {
		s := messageErrorInitIssuer + err.Error()
		glog.Info(s)
		c.recorder.Event(issuerCopy, v1.EventTypeWarning, errorInitIssuer, s)
		return err
	}

	return nil
}

func (c *Controller) updateIssuerStatus(iss *v1alpha1.Issuer) error {
	// TODO: replace Update call with UpdateStatus. This requires a custom API
	// server with the /status subresource enabled and/or subresource support
	// for CRDs (https://github.com/kubernetes/kubernetes/issues/38113)
	_, err := c.cmClient.CertmanagerV1alpha1().Issuers(iss.Namespace).Update(iss)
	return err
}
