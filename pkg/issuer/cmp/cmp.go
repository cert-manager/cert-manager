package cmp

import (
	"fmt"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/issuer"
)

type Cmp struct {
}

func New(ctx *controller.Context, issuer v1.GenericIssuer) (issuer.Interface, error) {
	fmt.Println("## CMP New called")
	return &Cmp{}, nil
}

// Register this Issuer with the issuer factory
func init() {
	issuer.RegisterIssuer(apiutil.IssuerCmp, New)
}
