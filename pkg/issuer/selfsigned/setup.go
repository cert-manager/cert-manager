package ca

import (
	"context"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

const (
	successReady = "IsReady"
)

func (c *SelfSigned) Setup(ctx context.Context) error {
	c.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionTrue, successReady, "")
	return nil
}
