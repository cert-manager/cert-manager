/*
Copyright 2019 The Jetstack cert-manager contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	corev1listers "k8s.io/client-go/listers/core/v1"
	extv1beta1listers "k8s.io/client-go/listers/extensions/v1beta1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/http/solver"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

const (
	// HTTP01Timeout is the max amount of time to wait for an HTTP01 challenge
	// to succeed
	HTTP01Timeout = time.Minute * 15
	// acmeSolverListenPort is the port acmesolver should listen on
	acmeSolverListenPort = 8089

	domainLabelKey               = "certmanager.k8s.io/acme-http-domain"
	tokenLabelKey                = "certmanager.k8s.io/acme-http-token"
	solverIdentificationLabelKey = "certmanager.k8s.io/acme-http01-solver"
)

var (
	challengeGvk = v1alpha1.SchemeGroupVersion.WithKind("Challenge")
)

// Solver is an implementation of the acme http-01 challenge solver protocol
type Solver struct {
	*controller.Context

	podLister     corev1listers.PodLister
	serviceLister corev1listers.ServiceLister
	ingressLister extv1beta1listers.IngressLister

	testReachability reachabilityTest
	requiredPasses   int
}

type reachabilityTest func(ctx context.Context, url *url.URL, key string) error

// NewSolver returns a new ACME HTTP01 solver for the given Issuer and client.
// TODO: refactor this to have fewer args
func NewSolver(ctx *controller.Context) *Solver {
	return &Solver{
		Context:          ctx,
		podLister:        ctx.KubeSharedInformerFactory.Core().V1().Pods().Lister(),
		serviceLister:    ctx.KubeSharedInformerFactory.Core().V1().Services().Lister(),
		ingressLister:    ctx.KubeSharedInformerFactory.Extensions().V1beta1().Ingresses().Lister(),
		testReachability: testReachability,
		requiredPasses:   5,
	}
}

func http01LogCtx(ctx context.Context) context.Context {
	return logf.NewContext(ctx, nil, "http01")
}

func httpDomainCfgForChallenge(issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) (*v1alpha1.ACMEChallengeSolverHTTP01Ingress, error) {
	if ch.Spec.Solver != nil {
		if ch.Spec.Solver.HTTP01 == nil || ch.Spec.Solver.HTTP01.Ingress == nil {
			return nil, fmt.Errorf("challenge's 'solver' field is specified but no HTTP01 ingress config provided. " +
				"Ensure solvers[].http01.ingress is specified on your issuer resource")
		}
		return ch.Spec.Solver.HTTP01.Ingress, nil
	}
	if ch.Spec.Config != nil {
		if ch.Spec.Config.HTTP01 == nil {
			return nil, fmt.Errorf("challenge's 'config' field is specified but not HTTP01 ingress config provided")
		}
		if issuer.GetSpec().ACME.HTTP01 == nil {
			return nil, fmt.Errorf("issuer.spec.acme.http01 field is not specified, old format http01 issuer disabled")
		}
		return &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
			Name:        ch.Spec.Config.HTTP01.Ingress,
			Class:       ch.Spec.Config.HTTP01.IngressClass,
			ServiceType: issuer.GetSpec().ACME.HTTP01.ServiceType,
		}, nil
	}
	return nil, fmt.Errorf("no HTTP01 ingress configuration found on challenge")
}

// Present will realise the resources required to solve the given HTTP01
// challenge validation in the apiserver. If those resources already exist, it
// will return nil (i.e. this function is idempotent).
func (s *Solver) Present(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
	ctx = http01LogCtx(ctx)

	_, podErr := s.ensurePod(ctx, ch)
	svc, svcErr := s.ensureService(ctx, issuer, ch)
	if svcErr != nil {
		return utilerrors.NewAggregate([]error{podErr, svcErr})
	}
	_, ingressErr := s.ensureIngress(ctx, issuer, ch, svc.Name)
	return utilerrors.NewAggregate([]error{podErr, svcErr, ingressErr})
}

func (s *Solver) Check(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
	ctx = logf.NewContext(http01LogCtx(ctx), nil, "selfCheck")
	log := logf.FromContext(ctx)

	// HTTP Present is idempotent and the state of the system may have
	// changed since present was called by the controllers (killed pods, drained nodes)
	// Call present again to be certain.
	// if the listers are nil, that means we're in the present checks
	// test
	if s.podLister != nil && s.serviceLister != nil && s.ingressLister != nil {
		log.V(logf.DebugLevel).Info("calling Present function before running self check to ensure required resources exist")
		err := s.Present(ctx, issuer, ch)
		if err != nil {
			log.V(logf.DebugLevel).Info("failed to call Present function", "error", err)
			return err
		}
	}

	ctx, cancel := context.WithTimeout(ctx, HTTP01Timeout)
	defer cancel()
	url := s.buildChallengeUrl(ch)
	log = log.WithValues("url", url)
	ctx = logf.NewContext(ctx, log)

	log.V(logf.DebugLevel).Info("running self check multiple times to ensure challenge has propagated", "required_passes", s.requiredPasses)
	for i := 0; i < s.requiredPasses; i++ {
		err := s.testReachability(ctx, url, ch.Spec.Key)
		if err != nil {
			return err
		}
		log.V(logf.DebugLevel).Info("reachability test passed, re-checking in 2s time")
		time.Sleep(time.Second * 2)
	}

	log.V(logf.DebugLevel).Info("self check succeeded")

	return nil
}

// CleanUp will ensure the created service, ingress and pod are clean/deleted of any
// cert-manager created data.
func (s *Solver) CleanUp(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
	var errs []error
	errs = append(errs, s.cleanupPods(ctx, ch))
	errs = append(errs, s.cleanupServices(ctx, ch))
	errs = append(errs, s.cleanupIngresses(ctx, issuer, ch))
	return utilerrors.NewAggregate(errs)
}

func (s *Solver) buildChallengeUrl(ch *v1alpha1.Challenge) *url.URL {
	url := &url.URL{}
	url.Scheme = "http"
	url.Host = ch.Spec.DNSName
	url.Path = fmt.Sprintf("%s/%s", solver.HTTPChallengePath, ch.Spec.Token)

	return url
}

// testReachability will attempt to connect to the 'domain' with 'path' and
// check if the returned body equals 'key'
func testReachability(ctx context.Context, url *url.URL, key string) error {
	log := logf.FromContext(ctx)
	log.V(logf.DebugLevel).Info("performing HTTP01 reachability check")

	req := &http.Request{
		Method: http.MethodGet,
		URL:    url,
	}
	req = req.WithContext(ctx)

	// ACME spec says that a verifier should try
	// on http port 80 first, but follow any redirects may be thrown its way
	// The redirects may be HTTPS and its certificate may be invalid (they are trying to get a
	// certificate after all).
	// TODO(dmo): figure out if we need to add a more specific timeout for
	// individual checks
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		// we're only doing 1 request, make the code around this
		// simpler by disabling keepalives
		DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := http.Client{
		Transport: transport,
	}

	response, err := client.Do(req)
	if err != nil {
		log.V(logf.DebugLevel).Info("failed to perform self check GET request", "error", err)
		return fmt.Errorf("failed to perform self check GET request '%s': %v", url, err)
	}

	if response.StatusCode != http.StatusOK {
		log.V(logf.DebugLevel).Info("received HTTP status code was not StatusOK (200)", "code", response.StatusCode)
		return fmt.Errorf("wrong status code '%d', expected '%d'", response.StatusCode, http.StatusOK)
	}

	defer response.Body.Close()
	presentedKey, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.V(logf.DebugLevel).Info("failed to decode response body", "error", err)
		return fmt.Errorf("failed to read response body: %v", err)
	}

	if string(presentedKey) != key {
		log.V(logf.DebugLevel).Info("key returned by server did not match expected", "actual", presentedKey, "expected", key)
		return fmt.Errorf("presented key (%s) did not match expected (%s)", presentedKey, key)
	}

	log.V(logf.DebugLevel).Info("reachability test succeeded")

	return nil
}
