package acme

import (
	"context"
	"errors"
	"fmt"

	"github.com/golang/glog"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/third_party/crypto/acme"
)

const (
	successObtainedAuthorization = "ObtainAuthorization"
	reasonPresentChallenge       = "PresentChallenge"
	reasonSelfCheck              = "SelfCheck"
	errorGetACMEAccount          = "ErrGetACMEAccount"
	errorCheckAuthorization      = "ErrCheckAuthorization"
	errorObtainAuthorization     = "ErrObtainAuthorization"
	errorInvalidConfig           = "ErrInvalidConfig"

	messageObtainedAuthorization    = "Obtained authorization for domain %s"
	messagePresentChallenge         = "Presenting %s challenge for domain %s"
	messageSelfCheck                = "Performing self-check for domain %s"
	messageErrorGetACMEAccount      = "Error getting ACME account: "
	messageErrorCheckAuthorization  = "Error checking ACME domain validation: "
	messageErrorObtainAuthorization = "Error obtaining ACME domain authorization: "
	messageErrorMissingConfig       = "certificate.spec.acme must be specified"
)

// Prepare will ensure the issuer has been initialised and is ready to issue
// certificates for the domains listed on the Certificate resource.
//
// It will send the appropriate Letsencrypt authorizations, and complete
// challenge requests if neccessary.
func (a *Acme) Prepare(ctx context.Context, crt *v1alpha1.Certificate) error {
	if crt.Spec.ACME == nil {
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorInvalidConfig, messageErrorMissingConfig)
		return fmt.Errorf(messageErrorMissingConfig)
	}
	// obtain an ACME client
	cl, err := a.acmeClient()
	if err != nil {
		s := messageErrorGetACMEAccount + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorGetACMEAccount, s)
		return errors.New(s)
	}

	orderURL := crt.Status.ACMEStatus().OrderURL
	var order *acme.Order
	// if the existing order URL is blank, create a new order
	if orderURL == "" {
		if order, err = createOrder(ctx, cl, crt); err != nil {
			return err
		}
	} else {
		// if we fail to get an existing order by URL, we should create a new
		// order to replace it.
		if order, err = cl.GetOrder(ctx, orderURL); err != nil {
			// TODO: review this - should we instead back-off and try again?
			// perhaps instead attempt to parse the URL first, and create a new
			// order if the URL is actually invalid. Not sure ??
			if order, err = createOrder(ctx, cl, crt); err != nil {
				return err
			}
		}
	}

	glog.V(4).Infof("Order %q status is %q", order.URL, order.Status)
	switch order.Status {
	// create a new order if the old one is invalid
	case acme.StatusDeactivated, acme.StatusInvalid, acme.StatusRevoked:
		if order, err = createOrder(ctx, cl, crt); err != nil {
			return err
		}
	case acme.StatusValid:
		glog.V(4).Infof("Order %q already valid", order.URL)
		return nil
	case acme.StatusPending, acme.StatusProcessing:
		// if the order is pending or processing, we will proceed.
		// TODO: should we return nil on processing? need to check acme spec
	default:
		return fmt.Errorf("order %q status is %q", order.URL, order.Status)
	}

	allAuthorizations, err := getAuthorizations(ctx, cl, order.Authorizations...)
	if err != nil {
		s := messageErrorCheckAuthorization + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorCheckAuthorization, s)
		return errors.New(s)
	}

	failed, pending, valid := partitionAuthorizations(allAuthorizations...)
	toCleanup := append(failed, valid...)
	for _, auth := range toCleanup {
		err := a.cleanupAuthorization(ctx, cl, crt, auth)
		if err != nil {
			// TODO: handle error properly
			return err
		}
	}

	if len(failed) > 0 {
		crt.Status.ACMEStatus().OrderURL = ""
		// TODO: pretty-print the list of failed authorizations
		s := fmt.Sprintf("Error obtaining validations for domains %v", failed)
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorCheckAuthorization, s)
		return errors.New(s)
	}

	// all validations have been obtained
	if len(pending) == 0 {
		return nil
	}

	var failingSelfChecks []string
	for _, auth := range pending {
		selfCheckPassed, challenge, err := a.presentAuthorization(ctx, cl, crt, auth)
		if err != nil {
			return err
		}
		if selfCheckPassed {
			err := a.acceptChallenge(ctx, cl, auth, challenge)
			if err != nil {
				return err
			}
		} else {
			failingSelfChecks = append(failingSelfChecks, auth.Identifier.Value)
		}
	}

	if len(failingSelfChecks) > 0 {
		return fmt.Errorf("self check failed for domains: %v", failingSelfChecks)
	}

	return nil
}

func (a *Acme) acceptChallenge(ctx context.Context, cl *acme.Client, auth *acme.Authorization, challenge *acme.Challenge) error {
	var err error
	challenge, err = cl.AcceptChallenge(ctx, challenge)
	if err != nil {
		return err
	}

	authorization, err := cl.WaitAuthorization(ctx, auth.URL)
	if err != nil {
		return err
	}

	if authorization.Status != acme.StatusValid {
		return fmt.Errorf("expected acme domain authorization status for %q to be valid, but it is %q", authorization.Identifier.Value, authorization.Status)
	}

	return nil
}

// presentAuthorization will present the challenge required for the given
// authorization using the supplied certificate configuration.
// If ths authorization is already presented, it will return no error.
// If the self-check for the authorization has passed, it will return true.
// Otherwise it will return false.
func (a *Acme) presentAuthorization(ctx context.Context, cl *acme.Client, crt *v1alpha1.Certificate, auth *acme.Authorization) (bool, *acme.Challenge, error) {
	challenge, err := a.challengeForAuthorization(cl, crt, auth)
	if err != nil {
		// TODO: handle error properly
		return false, nil, nil
	}
	domain := auth.Identifier.Value
	token := challenge.Token
	key, err := keyForChallenge(cl, challenge)
	if err != nil {
		return false, challenge, err
	}
	solver, err := a.solverFor(challenge.Type)
	if err != nil {
		// TODO: handle error properly
		return false, challenge, err
	}
	err = solver.Present(ctx, crt, domain, token, key)
	if err != nil {
		// TODO: handle error properly
		return false, challenge, err
	}
	ok, err := solver.Check(domain, token, key)
	if err != nil {
		return false, challenge, err
	}
	return ok, challenge, nil
}

func (a *Acme) cleanupAuthorization(ctx context.Context, cl *acme.Client, crt *v1alpha1.Certificate, auth *acme.Authorization) error {
	challenge, err := a.challengeForAuthorization(cl, crt, auth)
	if err != nil {
		// TODO: handle error properly
		return nil
	}
	domain := auth.Identifier.Value
	token := challenge.Token
	key, err := keyForChallenge(cl, challenge)
	if err != nil {
		return err
	}

	solver, err := a.solverFor(challenge.Type)
	if err != nil {
		// TODO: handle error properly
		return err
	}

	return solver.CleanUp(ctx, crt, domain, token, key)
}

// createOrder will create an order for the given certificate with the acme
// server. Once created, it will set the order URL on the status field of the
// certificate resource.
func createOrder(ctx context.Context, cl *acme.Client, crt *v1alpha1.Certificate) (*acme.Order, error) {
	desiredCN, err := pki.CommonNameForCertificate(crt)
	if err != nil {
		return nil, err
	}
	desiredDNSNames, err := pki.DNSNamesForCertificate(crt)
	if err != nil {
		return nil, err
	}
	desiredDomains := append([]string{desiredCN}, desiredDNSNames...)

	order, err := cl.CreateOrder(ctx, acme.NewOrder(desiredDomains...))
	if err != nil {
		return nil, err
	}
	crt.Status.ACMEStatus().OrderURL = order.URL
	return order, nil
}

func keyForChallenge(cl *acme.Client, challenge *acme.Challenge) (string, error) {
	var err error
	switch challenge.Type {
	case "http-01":
		return cl.HTTP01ChallengeResponse(challenge.Token)
	case "dns-01":
		return cl.DNS01ChallengeRecord(challenge.Token)
	default:
		err = fmt.Errorf("unsupported challenge type %s", challenge.Type)
	}
	return "", err
}

func getAuthorizations(ctx context.Context, cl *acme.Client, urls ...string) ([]*acme.Authorization, error) {
	var authzs []*acme.Authorization
	for _, url := range urls {
		a, err := cl.GetAuthorization(ctx, url)
		if err != nil {
			return nil, err
		}
		authzs = append(authzs, a)
	}
	return authzs, nil
}

func partitionAuthorizations(authzs ...*acme.Authorization) (failed, pending, valid []*acme.Authorization) {
	for _, a := range authzs {
		switch a.Status {
		case acme.StatusDeactivated, acme.StatusInvalid, acme.StatusRevoked, acme.StatusUnknown:
			failed = append(failed, a)
		case acme.StatusPending, acme.StatusProcessing:
			pending = append(pending, a)
		case acme.StatusValid:
			valid = append(valid, a)
		}
	}
	return failed, pending, valid
}

func (a *Acme) pickChallengeType(domain string, auth *acme.Authorization, cfg []v1alpha1.ACMECertificateDomainConfig) (string, error) {
	for _, d := range cfg {
		for _, dom := range d.Domains {
			if dom == domain {
				for _, challenge := range auth.Challenges {
					switch {
					case challenge.Type == "http-01" && d.HTTP01 != nil && a.issuer.GetSpec().ACME.HTTP01 != nil:
						return challenge.Type, nil
					case challenge.Type == "dns-01" && d.DNS01 != nil && a.issuer.GetSpec().ACME.DNS01 != nil:
						return challenge.Type, nil
					}
				}
			}
		}
	}
	return "", fmt.Errorf("no configured and supported challenge type found")
}

func (a *Acme) challengeForAuthorization(cl *acme.Client, crt *v1alpha1.Certificate, auth *acme.Authorization) (*acme.Challenge, error) {
	domain := auth.Identifier.Value
	glog.V(4).Infof("picking challenge type for domain %q", domain)
	challengeType, err := a.pickChallengeType(domain, auth, crt.Spec.ACME.Config)
	if err != nil {
		return nil, fmt.Errorf("error picking challenge type to use for domain '%s': %s", domain, err.Error())
	}

	for _, challenge := range auth.Challenges {
		if challenge.Type != challengeType {
			continue
		}
		return challenge, nil
	}
	return nil, fmt.Errorf("challenge mechanism '%s' not allowed for domain", challengeType)
}
