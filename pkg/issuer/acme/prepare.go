package acme

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/golang/glog"
	"golang.org/x/crypto/acme"
	"k8s.io/api/core/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	successObtainedAuthorization = "ObtainAuthorization"
	reasonPresentChallenge       = "PresentChallenge"
	reasonSelfCheck              = "SelfCheck"
	errorGetACMEAccount          = "ErrGetACMEAccount"
	errorCheckAuthorization      = "ErrCheckAuthorization"
	errorObtainAuthorization     = "ErrObtainAuthorization"

	messageObtainedAuthorization    = "Obtained authorization for domain %s"
	messagePresentChallenge         = "Presenting %s challenge for domain %s"
	messageSelfCheck                = "Performing self-check for domain %s"
	messageErrorGetACMEAccount      = "Error getting ACME account: "
	messageErrorCheckAuthorization  = "Error checking ACME domain validation: "
	messageErrorObtainAuthorization = "Error obtaining ACME domain authorization: "
)

// Prepare will ensure the issuer has been initialised and is ready to issue
// certificates for the domains listed on the Certificate resource.
//
// It will send the appropriate Letsencrypt authorizations, and complete
// challenge requests if neccessary.
func (a *Acme) Prepare(ctx context.Context, crt *v1alpha1.Certificate) error {
	// obtain an ACME client
	cl, err := a.acmeClient()
	if err != nil {
		s := messageErrorGetACMEAccount + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorGetACMEAccount, s)
		return errors.New(s)
	}

	// step one: check issuer to see if we already have authorizations
	toAuthorize, err := a.authorizationsToObtain(ctx, cl, crt)
	if err != nil {
		s := messageErrorCheckAuthorization + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorCheckAuthorization, s)
		return errors.New(s)
	}

	// if there are no more authorizations to obtain, we are done
	if len(toAuthorize) == 0 {
		// TODO: set a field in the status block to show authorizations have
		// been obtained so we can periodically update the auth status
		return nil
	}

	// request authorizations from the ACME server
	auths, err := getAuthorizations(ctx, cl, toAuthorize...)
	if err != nil {
		s := messageErrorCheckAuthorization + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorCheckAuthorization, s)
		return errors.New(s)
	}

	// TODO: move some of this logic into it's own function
	// attempt to authorize each domain. we do this in parallel to speed up
	// authorizations.
	var wg sync.WaitGroup
	resultChan := make(chan struct {
		authResponse
		*acme.Authorization
		error
	}, len(auths))
	for _, auth := range auths {
		wg.Add(1)
		go func(auth authResponse) {
			defer wg.Done()
			a, err := a.authorize(ctx, cl, crt, auth)
			resultChan <- struct {
				authResponse
				*acme.Authorization
				error
			}{authResponse: auth, Authorization: a, error: err}
		}(auth)
	}

	wg.Wait()
	close(resultChan)
	var errs []error
	for res := range resultChan {
		if res.error != nil {
			errs = append(errs, res.error)
			continue
		}
		if res.Authorization.Status != acme.StatusValid {
			errs = append(errs, fmt.Errorf("authorization in %s state is not ready", res.Authorization.Status))
		}
		crt.Status.ACMEStatus().SaveAuthorization(v1alpha1.ACMEDomainAuthorization{
			Domain:  res.authResponse.domain,
			URI:     res.Authorization.URI,
			Account: a.issuer.GetStatus().ACMEStatus().URI,
		})
	}

	if len(errs) > 0 {
		err = utilerrors.NewAggregate(errs)
		s := messageErrorCheckAuthorization + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorCheckAuthorization, s)
		return err
	}

	return nil
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

func (a *Acme) authorize(ctx context.Context, cl *acme.Client, crt *v1alpha1.Certificate, auth authResponse) (*acme.Authorization, error) {
	glog.V(4).Infof("picking challenge type for domain %q", auth.domain)
	challengeType, err := a.pickChallengeType(auth.domain, auth.auth, crt.Spec.ACME.Config)
	if err != nil {
		return nil, fmt.Errorf("error picking challenge type to use for domain '%s': %s", auth.domain, err.Error())
	}
	glog.V(4).Infof("using challenge type %q for domain %q", challengeType, auth.domain)
	challenge, err := challengeForAuthorization(cl, auth.auth, challengeType)
	if err != nil {
		return nil, fmt.Errorf("error getting challenge for domain '%s': %s", auth.domain, err.Error())
	}
	token := challenge.Token
	key, err := keyForChallenge(cl, challenge)
	if err != nil {
		return nil, err
	}
	solver, err := a.solverFor(challengeType)
	if err != nil {
		return nil, err
	}
	defer func() {
		err := solver.CleanUp(ctx, crt, auth.domain, token, key)
		if err != nil {
			glog.Errorf("Error cleaning up solver: %s", err.Error())
		}
	}()

	a.recorder.Eventf(crt, v1.EventTypeNormal, reasonPresentChallenge, messagePresentChallenge, challengeType, auth.domain)
	err = solver.Present(ctx, crt, auth.domain, token, key)
	if err != nil {
		return nil, fmt.Errorf("error presenting acme authorization for domain %q: %s", auth.domain, err.Error())
	}

	a.recorder.Eventf(crt, v1.EventTypeNormal, reasonSelfCheck, messageSelfCheck, auth.domain)
	err = solver.Wait(ctx, crt, auth.domain, token, key)
	if err != nil {
		return nil, fmt.Errorf("error waiting for key to be available for domain %q: %s", auth.domain, err.Error())
	}

	challenge, err = cl.Accept(ctx, challenge)
	if err != nil {
		return nil, fmt.Errorf("error accepting acme challenge for domain %q: %s", auth.domain, err.Error())
	}

	glog.V(4).Infof("waiting for authorization for domain %s (%s)...", auth.domain, challenge.URI)
	authorization, err := cl.WaitAuthorization(ctx, challenge.URI)
	if err != nil {
		return nil, fmt.Errorf("error waiting for authorization for domain %q: %s", auth.domain, err.Error())
	}

	if authorization.Status != acme.StatusValid {
		return nil, fmt.Errorf("expected acme domain authorization status for %q to be valid, but it is %q", auth.domain, authorization.Status)
	}

	a.recorder.Eventf(crt, v1.EventTypeNormal, successObtainedAuthorization, messageObtainedAuthorization, auth.domain)

	return authorization, nil
}

func checkAuthorization(ctx context.Context, cl *acme.Client, uri string) (bool, error) {
	a, err := cl.GetAuthorization(ctx, uri)

	if err != nil {
		return false, err
	}

	if a.Status == acme.StatusValid {
		return true, nil
	}

	return false, nil
}

func authorizationsMap(list []v1alpha1.ACMEDomainAuthorization) map[string]v1alpha1.ACMEDomainAuthorization {
	out := make(map[string]v1alpha1.ACMEDomainAuthorization, len(list))
	for _, a := range list {
		out[a.Domain] = a
	}
	return out
}

func removeDuplicates(in []string) []string {
	var found []string
Outer:
	for _, i := range in {
		for _, i2 := range found {
			if i2 == i {
				continue Outer
			}
		}
		found = append(found, i)
	}
	return found
}

func (a *Acme) authorizationsToObtain(ctx context.Context, cl *acme.Client, crt *v1alpha1.Certificate) ([]string, error) {
	authMap := authorizationsMap(crt.Status.ACMEStatus().Authorizations)
	expectedCN := pki.CommonNameForCertificate(crt)
	expectedDNSNames := pki.DNSNamesForCertificate(crt)
	check := removeDuplicates(append(expectedDNSNames, expectedCN))
	toAuthorize := util.StringFilter(func(domain string) (bool, error) {
		auth, ok := authMap[domain]
		glog.Infof("Compare %q with %q", auth.Account, a.issuer.GetStatus().ACMEStatus().URI)
		if !ok || auth.Account != a.issuer.GetStatus().ACMEStatus().URI {
			return false, nil
		}
		return checkAuthorization(ctx, cl, auth.URI)
	}, check...)

	domains := make([]string, len(toAuthorize))
	for i, v := range toAuthorize {
		if v.Err != nil {
			return nil, fmt.Errorf("error checking authorization status for %s: %s", v.String, v.Err)
		}
		domains[i] = v.String
	}

	return domains, nil
}

type authResponses []authResponse
type authResponse struct {
	domain string
	auth   *acme.Authorization
	err    error
}

// Error returns an error if any one of the authResponses contains an error
func (a authResponses) Error() error {
	var errs []error
	for _, r := range a {
		if r.err != nil {
			errs = append(errs, fmt.Errorf("'%s': %s", r.domain, r.err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("error getting authorization for domains: %v", errs)
	}
	return nil
}

func getAuthorizations(ctx context.Context, cl *acme.Client, domains ...string) ([]authResponse, error) {
	respCh := make(chan authResponse)
	defer close(respCh)
	for _, d := range domains {
		go func(domain string) {
			auth, err := cl.Authorize(ctx, domain)

			if err != nil {
				respCh <- authResponse{"", nil, fmt.Errorf("getting acme authorization failed: %s", err.Error())}
				return
			}

			respCh <- authResponse{domain, auth, nil}
		}(d)
	}

	responses := make([]authResponse, len(domains))
	for i := 0; i < len(domains); i++ {
		responses[i] = <-respCh
	}
	return responses, authResponses(responses).Error()
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

func challengeForAuthorization(cl *acme.Client, auth *acme.Authorization, challengeType string) (*acme.Challenge, error) {
	for _, challenge := range auth.Challenges {
		if challenge.Type != challengeType {
			continue
		}
		return challenge, nil
	}
	return nil, fmt.Errorf("challenge mechanism '%s' not allowed for domain", challengeType)
}
