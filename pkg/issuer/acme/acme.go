package acme

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/client/scheme"
	"github.com/jetstack/cert-manager/pkg/controller"
)

type Acme struct {
	ctx     *controller.Context
	issuer  *v1alpha1.Issuer
	account *account
}

func New(ctx *controller.Context, issuer *v1alpha1.Issuer) (*Acme, error) {
	if issuer.Spec.ACME == nil {
		return nil, fmt.Errorf("acme config is not set")
	}
	return &Acme{ctx, issuer, &account{ctx, issuer}}, nil
}

func (a *Acme) Setup() error {
	before, err := scheme.Scheme.DeepCopy(a.issuer)

	if err != nil {
		return fmt.Errorf("internal error creating deepcopy for issuer: %s", err.Error())
	}

	defer func() {
		if !reflect.DeepEqual(before, a.issuer) {
			a.saveIssuer()
		}
	}()

	err = a.ensureSetup()

	if err != nil {
		return err
	}

	return nil
}

// saveIssuer will save the contained issuer resource in the API server
func (a *Acme) saveIssuer() error {
	_, err := a.ctx.CertManagerClient.Issuers(a.issuer.Namespace).Update(a.issuer)
	return err
}

// ensureSetup will ensure that this issuer is ready to issue certificates.
// it
func (a *Acme) ensureSetup() error {
	err := a.account.verify()

	if err == nil {
		a.issuer.Status.Ready = true
		return nil
	}

	a.issuer.Status.Ready = false

	err = a.account.register()

	if err != nil {
		// don't write updated state as an actual error occurred
		return fmt.Errorf("error registering acme account: %s", err.Error())
	}

	a.issuer.Status.Ready = true

	return nil
}

func (a *Acme) Issue(crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	if crt.Spec.ACME == nil {
		return nil, nil, fmt.Errorf("acme config must be specified")
	}

	// TODO (@munnerz): tidy this weird horrible line up
	switch v1alpha1.ACMEChallengeType(strings.ToUpper(string(crt.Spec.ACME.Challenge))) {
	case v1alpha1.ACMEChallengeTypeHTTP01:
		a.ctx.Logger.Printf("Obtaining certificates for %+v", crt.Spec.Domains)
		// todo: use acme library to obtain challenge details and pass them to the solver
	case v1alpha1.ACMEChallengeTypeTLSSNI01:
	case v1alpha1.ACMEChallengeTypeDNS01:
	default:
		return nil, nil, fmt.Errorf("invalid acme challenge type '%s'", crt.Spec.ACME.Challenge)
	}

	return nil, nil, nil
}

func (a *Acme) Renew(crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	return nil, nil, nil
}
