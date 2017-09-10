package acme

import (
	"context"
	"fmt"
	"log"
	"sync"

	"golang.org/x/crypto/acme"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack-experimental/cert-manager/pkg/util"
	"github.com/jetstack-experimental/cert-manager/pkg/util/kube"
)

// Prepare will ensure the issuer has been initialised and is ready to issue
// certificates for the domains listed on the Certificate resource.
//
// It will send the appropriate Letsencrypt authorizations, and complete
// challenge requests if neccessary.
func (a *Acme) Prepare(crt *v1alpha1.Certificate) (v1alpha1.CertificateStatus, error) {
	updateStatus := *crt.Status.DeepCopy()

	if crt.Spec.ACME == nil {
		return updateStatus, fmt.Errorf("acme config must be specified")
	}

	log.Printf("getting private key for acme issuer %s/%s", a.issuer.Namespace, a.issuer.Name)
	_, accountPrivKey, err := kube.GetKeyPair(a.client, a.issuer.Namespace, a.issuer.Spec.ACME.PrivateKey)

	if accountPrivKey == nil {
		return updateStatus, fmt.Errorf("error getting acme account private key: %s", err.Error())
	}

	cl := &acme.Client{
		Key:          accountPrivKey,
		DirectoryURL: a.issuer.Spec.ACME.Server,
	}

	// step one: check issuer to see if we already have authorizations
	toAuthorize, err := authorizationsToObtain(cl, *crt)

	if err != nil {
		return updateStatus, err
	}

	log.Printf("need to get authorizations for %v", toAuthorize)

	// step two: if there are any domains that we don't have authorization for,
	// we should attempt to authorize those domains
	if len(toAuthorize) == 0 {
		return updateStatus, nil
	}

	auths, err := getAuthorizations(cl, toAuthorize...)

	if err != nil {
		return updateStatus, err
	}

	log.Printf("requested authorizations for %v", toAuthorize)

	var wg sync.WaitGroup
	resultChan := make(chan struct {
		authResponse
		*acme.Authorization
		error
	})
	for _, auth := range auths {
		wg.Add(1)
		go func(auth authResponse) {
			defer wg.Done()
			a, err := a.authorize(cl, crt, auth)
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
			Domain: res.authResponse.domain,
			URI:    res.Authorization.URI,
		})
	}

	if len(errs) > 0 {
		return updateStatus, utilerrors.NewAggregate(errs)
	}

	return updateStatus, nil
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

func (a *Acme) authorize(cl *acme.Client, crt *v1alpha1.Certificate, auth authResponse) (*acme.Authorization, error) {
	log.Printf("picking challenge type for domain '%s'", auth.domain)
	challengeType, err := pickChallengeType(auth.domain, auth.auth, crt.Spec.ACME.Config)
	if err != nil {
		return nil, fmt.Errorf("error picking challenge type to use for domain '%s': %s", auth.domain, err.Error())
	}
	log.Printf("using challenge type %s for domain '%s'", challengeType, auth.domain)
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

	defer solver.CleanUp(context.Background(), crt, auth.domain, token, key)

	log.Printf("presenting challenge for domain %s, token %s key %s", auth.domain, token, key)
	err = solver.Present(context.Background(), crt, auth.domain, token, key)
	if err != nil {
		return nil, fmt.Errorf("error presenting acme authorization for domain '%s': %s", auth.domain, err.Error())
	}

	log.Printf("waiting for key to be available to acme servers for domain %s", auth.domain)
	err = solver.Wait(context.Background(), crt, auth.domain, token, key)
	if err != nil {
		return nil, fmt.Errorf("error waiting for key to be available for domain '%s': %s", auth.domain, err.Error())
	}

	log.Printf("accepting %s challenge for domain %s", challengeType, auth.domain)
	challenge, err = cl.Accept(context.Background(), challenge)
	if err != nil {
		return nil, fmt.Errorf("error accepting acme challenge for domain '%s': %s", auth.domain, err.Error())
	}

	log.Printf("waiting for authorization for domain %s (%s)...", auth.domain, challenge.URI)
	authorization, err := cl.WaitAuthorization(context.Background(), challenge.URI)
	if err != nil {
		return nil, fmt.Errorf("error waiting for authorization for domain '%s': %s", auth.domain, err.Error())
	}

	if authorization.Status != acme.StatusValid {
		return nil, fmt.Errorf("expected acme domain authorization status for '%s' to be valid, but it's %s", auth.domain, authorization.Status)
	}
	log.Printf("got successful authorization for domain %s", auth.domain)

	return authorization, nil
}

func checkAuthorization(cl *acme.Client, uri string) (bool, error) {
	a, err := cl.GetAuthorization(context.Background(), uri)

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

func authorizationsToObtain(cl *acme.Client, crt v1alpha1.Certificate) ([]string, error) {
	authMap := authorizationsMap(crt.Status.ACMEStatus().Authorizations)
	toAuthorize := util.StringFilter(func(domain string) (bool, error) {
		auth, ok := authMap[domain]
		if !ok {
			return false, nil
		}
		return checkAuthorization(cl, auth.URI)
	}, crt.Spec.Domains...)

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

func getAuthorizations(cl *acme.Client, domains ...string) ([]authResponse, error) {
	respCh := make(chan authResponse)
	defer close(respCh)
	for _, d := range domains {
		go func(domain string) {
			auth, err := cl.Authorize(context.Background(), domain)

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

func pickChallengeType(domain string, auth *acme.Authorization, cfg []v1alpha1.ACMECertificateDomainConfig) (string, error) {
	for _, d := range cfg {
		for _, dom := range d.Domains {
			if dom == domain {
				for _, challenge := range auth.Challenges {
					switch {
					case challenge.Type == "http-01" && d.HTTP01 != nil:
						return challenge.Type, nil
					case challenge.Type == "dns-01" && d.DNS01 != nil:
						return challenge.Type, nil
					}
					log.Printf("cannot use %s challenge for domain %s", challenge.Type, domain)
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
