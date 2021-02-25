/*
Copyright 2020 The cert-manager Authors.

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
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	k8snet "k8s.io/utils/net"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	corev1listers "k8s.io/client-go/listers/core/v1"
	networkingv1beta1listers "k8s.io/client-go/listers/networking/v1beta1"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/http/solver"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	pkgutil "github.com/cert-manager/cert-manager/pkg/util"
)

const (
	// HTTP01Timeout is the max amount of time to wait for an HTTP01 challenge
	// to succeed
	HTTP01Timeout = time.Minute * 15
	// acmeSolverListenPort is the port acmesolver should listen on
	acmeSolverListenPort = 8089
)

var (
	challengeGvk = cmacme.SchemeGroupVersion.WithKind("Challenge")
)

// Solver is an implementation of the acme http-01 challenge solver protocol
type Solver struct {
	*controller.Context

	podLister     corev1listers.PodLister
	serviceLister corev1listers.ServiceLister
	ingressLister networkingv1beta1listers.IngressLister

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
		ingressLister:    ctx.KubeSharedInformerFactory.Networking().V1beta1().Ingresses().Lister(),
		testReachability: testReachability,
		requiredPasses:   5,
	}
}

func http01LogCtx(ctx context.Context) context.Context {
	return logf.NewContext(ctx, nil, "http01")
}

func httpDomainCfgForChallenge(ch *cmacme.Challenge) (*cmacme.ACMEChallengeSolverHTTP01Ingress, error) {
	if ch.Spec.Solver.HTTP01 == nil || ch.Spec.Solver.HTTP01.Ingress == nil {
		return nil, fmt.Errorf("challenge's 'solver' field is specified but no HTTP01 ingress config provided. " +
			"Ensure solvers[].http01.ingress is specified on your issuer resource")
	}
	return ch.Spec.Solver.HTTP01.Ingress, nil
}

// Present will realise the resources required to solve the given HTTP01
// challenge validation in the apiserver. If those resources already exist, it
// will return nil (i.e. this function is idempotent).
func (s *Solver) Present(ctx context.Context, issuer v1.GenericIssuer, ch *cmacme.Challenge) error {
	ctx = http01LogCtx(ctx)

	_, podErr := s.ensurePod(ctx, ch)
	svc, svcErr := s.ensureService(ctx, ch)
	if svcErr != nil {
		return utilerrors.NewAggregate([]error{podErr, svcErr})
	}
	_, ingressErr := s.ensureIngress(ctx, ch, svc.Name)
	return utilerrors.NewAggregate([]error{podErr, svcErr, ingressErr})
}

func (s *Solver) Check(ctx context.Context, issuer v1.GenericIssuer, ch *cmacme.Challenge) error {
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
func (s *Solver) CleanUp(ctx context.Context, issuer v1.GenericIssuer, ch *cmacme.Challenge) error {
	var errs []error
	errs = append(errs, s.cleanupPods(ctx, ch))
	errs = append(errs, s.cleanupServices(ctx, ch))
	errs = append(errs, s.cleanupIngresses(ctx, ch))
	return utilerrors.NewAggregate(errs)
}

func (s *Solver) buildChallengeUrl(ch *cmacme.Challenge) *url.URL {
	url := &url.URL{}
	url.Scheme = "http"
	url.Host = ch.Spec.DNSName

	// we need brackets for IPv6 addresses for the HTTP client to work
	if k8snet.IsIPv6(net.ParseIP(url.Host)) {
		url.Host = fmt.Sprintf("[%s]", url.Host)
	}
	url.Path = fmt.Sprintf("%s/%s", solver.HTTPChallengePath, ch.Spec.Token)

	return url
}

// testReachability will attempt to connect to the 'domain' with 'path' and
// check if the returned body equals 'key'
func testReachability(ctx context.Context, url *url.URL, key string) error {
	log := logf.FromContext(ctx)
	log.V(logf.DebugLevel).Info("performing HTTP01 reachability check")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", pkgutil.CertManagerUserAgent)

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
		// truncate the response before displaying it to avoid extra long strings
		// being displayed to users
		keyToPrint := string(presentedKey)
		if len(keyToPrint) > 24 {
			// trim spaces to make output look right if it ends with whitespace
			keyToPrint = strings.TrimSpace(keyToPrint[:24]) + "... (truncated)"
		}
		log.V(logf.DebugLevel).Info("key returned by server did not match expected", "actual", keyToPrint, "expected", key)
		return fmt.Errorf("did not get expected response when querying endpoint, expected %q but got: %s", key, keyToPrint)
	}

	log.V(logf.DebugLevel).Info("reachability test succeeded")

	return nil
}
