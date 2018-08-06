package issuers

import (
	"context"
	"fmt"
	"reflect"

	"github.com/golang/glog"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/errors"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/validation"
)

const (
	errorInitIssuer = "ErrInitIssuer"
	errorConfig     = "ConfigError"

	messageErrorInitIssuer = "Error initializing issuer: "
)

func (c *Controller) Sync(ctx context.Context, iss *v1alpha1.Issuer) (err error) {
	issuerCopy := iss.DeepCopy()
	defer func() {
		if _, saveErr := c.updateIssuerStatus(iss, issuerCopy); saveErr != nil {
			err = errors.NewAggregate([]error{saveErr, err})
		}
	}()

	el := validation.ValidateIssuer(issuerCopy)
	if len(el) > 0 {
		msg := fmt.Sprintf("Resource validation failed: %v", el.ToAggregate())
		issuerCopy.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorConfig, msg)
		return
	} else {
		for i, c := range issuerCopy.Status.Conditions {
			if c.Type == v1alpha1.IssuerConditionReady {
				if c.Reason == errorConfig && c.Status == v1alpha1.ConditionFalse {
					issuerCopy.Status.Conditions = append(issuerCopy.Status.Conditions[:i], issuerCopy.Status.Conditions[i+1:]...)
					break
				}
			}
		}
	}

	i, err := c.IssuerFactory().IssuerFor(issuerCopy)

	if err != nil {
		return err
	}

	err = i.Setup(ctx)
	if err != nil {
		s := messageErrorInitIssuer + err.Error()
		glog.Info(s)
		c.Recorder.Event(issuerCopy, v1.EventTypeWarning, errorInitIssuer, s)
		return err
	}

	return nil
}

func (c *Controller) updateIssuerStatus(old, new *v1alpha1.Issuer) (*v1alpha1.Issuer, error) {
	if reflect.DeepEqual(old.Status, new.Status) {
		return nil, nil
	}
	// TODO: replace Update call with UpdateStatus. This requires a custom API
	// server with the /status subresource enabled and/or subresource support
	// for CRDs (https://github.com/kubernetes/kubernetes/issues/38113)
	return c.CMClient.CertmanagerV1alpha1().Issuers(new.Namespace).Update(new)
}
