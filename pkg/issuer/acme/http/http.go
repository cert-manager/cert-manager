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
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	networkingv1listers "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/tools/cache"
	k8snet "k8s.io/utils/net"
	gwapilisters "sigs.k8s.io/gateway-api/pkg/client/listers/apis/v1"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/http/solver"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

const (
	// HTTP01Timeout is the max amount of time to wait for an HTTP01 challenge
	// to succeed
	HTTP01Timeout = time.Minute * 15
	// acmeSolverListenPort is the port acmesolver should listen on
	acmeSolverListenPort = 8089

	loggerName = "http01"

	// maxAcmeChallengeBodySize is the max size of a received response body for an
	// acme http challenge. The value is arbitrary and is chosen to be large enough
	// that any reasonable response would fit.
	maxAcmeChallengeBodySize = 1024 * 1024 // 1mb
)

var (
	challengeGvk = cmacme.SchemeGroupVersion.WithKind("Challenge")
)

// Solver is an implementation of the acme http-01 challenge solver protocol
type Solver struct {
	*controller.Context

	podLister       cache.GenericLister
	serviceLister   cache.GenericLister
	ingressLister   networkingv1listers.IngressLister
	httpRouteLister gwapilisters.HTTPRouteLister

	testReachability reachabilityTest
	requiredPasses   int
}

type reachabilityTest func(ctx context.Context, url *url.URL, key string, dnsServers []string, userAgent string) error

// NewSolver returns a new ACME HTTP01 solver for the given *controller.Context.
func NewSolver(ctx *controller.Context) (*Solver, error) {
	return &Solver{
		Context:          ctx,
		podLister:        ctx.HTTP01ResourceMetadataInformersFactory.ForResource(corev1.SchemeGroupVersion.WithResource("pods")).Lister(),
		serviceLister:    ctx.HTTP01ResourceMetadataInformersFactory.ForResource(corev1.SchemeGroupVersion.WithResource("services")).Lister(),
		ingressLister:    ctx.KubeSharedInformerFactory.Ingresses().Lister(),
		httpRouteLister:  ctx.GWShared.Gateway().V1().HTTPRoutes().Lister(),
		testReachability: testReachability,
		requiredPasses:   5,
	}, nil
}

func http01IngressCfgForChallenge(ch *cmacme.Challenge) (*cmacme.ACMEChallengeSolverHTTP01Ingress, error) {
	if ch.Spec.Solver.HTTP01 == nil || ch.Spec.Solver.HTTP01.Ingress == nil {
		return nil, fmt.Errorf("challenge's 'solver' field is specified but no HTTP01 ingress config provided. " +
			"Ensure solvers[].http01.ingress is specified on your issuer resource")
	}
	return ch.Spec.Solver.HTTP01.Ingress, nil
}

func getServiceType(ch *cmacme.Challenge) (corev1.ServiceType, error) {
	if ch.Spec.Solver.HTTP01 != nil && ch.Spec.Solver.HTTP01.Ingress != nil {
		return ch.Spec.Solver.HTTP01.Ingress.ServiceType, nil
	}
	if ch.Spec.Solver.HTTP01 != nil && ch.Spec.Solver.HTTP01.GatewayHTTPRoute != nil {
		return ch.Spec.Solver.HTTP01.GatewayHTTPRoute.ServiceType, nil
	}
	return "", fmt.Errorf("neither HTTP01 Ingress nor Gateway solvers were found")
}

// Present will realise the resources required to solve the given HTTP01
// challenge validation in the apiserver. If those resources already exist, it
// will return nil (i.e. this function is idempotent).
func (s *Solver) Present(ctx context.Context, issuer v1.GenericIssuer, ch *cmacme.Challenge) error {
	log := logf.FromContext(ctx).WithName(loggerName)
	ctx = logf.NewContext(ctx, log)

	podErr := s.ensurePod(ctx, ch)
	svcName, svcErr := s.ensureService(ctx, ch)
	if svcErr != nil {
		return utilerrors.NewAggregate([]error{podErr, svcErr})
	}
	var ingressErr, gatewayErr error
	if ch.Spec.Solver.HTTP01 != nil {
		if ch.Spec.Solver.HTTP01.Ingress != nil {
			_, ingressErr = s.ensureIngress(ctx, ch, svcName)
			return utilerrors.NewAggregate([]error{podErr, svcErr, ingressErr})
		}
		if ch.Spec.Solver.HTTP01.GatewayHTTPRoute != nil {
			if !s.GatewaySolverEnabled {
				return fmt.Errorf("couldn't Present challenge %s/%s: gateway api is not enabled", ch.Namespace, ch.Name)
			}
			_, gatewayErr = s.ensureGatewayHTTPRoute(ctx, ch, svcName)
			return utilerrors.NewAggregate([]error{podErr, svcErr, gatewayErr})
		}
	}
	return utilerrors.NewAggregate(
		[]error{
			podErr,
			svcErr,
			ingressErr,
			gatewayErr,
			fmt.Errorf("couldn't Present challenge %s/%s: no Ingress nor Gateway HTTP01 solvers were specified", ch.Namespace, ch.Name),
		},
	)
}

func (s *Solver) Check(ctx context.Context, issuer v1.GenericIssuer, ch *cmacme.Challenge) error {
	log := logf.FromContext(ctx, loggerName, "selfCheck")
	ctx = logf.NewContext(ctx, log)

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
		err := s.testReachability(ctx, url, ch.Spec.Key, s.HTTP01SolverNameservers, s.Context.RESTConfig.UserAgent)
		if err != nil {
			return err
		}
		log.V(logf.DebugLevel).Info("reachability test passed, re-checking in 2s time")

		if i != s.requiredPasses-1 {
			// sleep for 2s between checks
			time.Sleep(time.Second * 2)
		}
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
func testReachability(ctx context.Context, url *url.URL, key string, dnsServers []string, userAgent string) error {
	log := logf.FromContext(ctx)
	log.V(logf.DebugLevel).Info("performing HTTP01 reachability check")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)

	// The ACME spec says that a verifier should try on http port 80 first, but to follow any
	// redirects which may be returned. Let's Encrypt, in practice, follows redirects for HTTP
	// and HTTPS services on ports 80 and 443 respectively, but the spec doesn't seem to require
	// anything other than the initial connection being on port 80.

	// For further reading, the spec also discusses redirect following in section 10.2:
	// https://datatracker.ietf.org/doc/html/rfc8555#section-10.2

	// TODO: Since Let's Encrypt will only accept redirects to port 80 and port 443, and we follow
	// any redirect here, this could lead to a failure mode where we determine that the endpoint is reachable
	// but it'll certainly fail when tried by the actual verifier; it's an edge case, but we might be able
	// to handle this better.

	// The timeouts here are inspired by the timeouts used by Boulder - i.e., Let's Encrypt - when
	// validating HTTP01 challenges for real.
	// Boulder http.Transport: https://github.com/letsencrypt/boulder/blob/30a516737c9daa4c88c8c47070c25a5e7033cdcf/va/http.go#L146-L160
	// Boulder http.Client:    https://github.com/letsencrypt/boulder/blob/30a516737c9daa4c88c8c47070c25a5e7033cdcf/va/http.go#L567-L572

	// Boulder uses a much more complex timeout setup involving shaving time off the deadline to be able to differentiate
	// between timeouts at different stages of the connection and in turn provide for better error messages. We're a little
	// more blunt than that, and just use a static timeout of 10 seconds in http.Client.

	// That said, IdleConnTimeout is not covered by `Timeout` in http.Client, so we also set it in our Transport

	// See https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/#clienttimeouts for details on timeouts
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		// we're only doing 1 request, make the code around this
		// simpler by disabling keepalives
		DisableKeepAlives: true,

		// boulder sets this to 1 because "0" means "unlimited"
		MaxIdleConns: 1,

		// IdleConnTimeout's value is taken from Boulder
		IdleConnTimeout: time.Second,

		TLSClientConfig: &tls.Config{
			// If we're following a redirect, it's permissible for it to be HTTPS and
			// its certificate may be invalid (they are trying to get a certificate, after all!)
			// See: https://letsencrypt.org/docs/challenge-types/#http-01-challenge
			// > When redirected to an HTTPS URL, it does not validate certificates (since
			// > this challenge is intended to bootstrap valid certificates, it may encounter
			// > self-signed or expired certificates along the way).
			InsecureSkipVerify: true,
		},
	}

	if len(dnsServers) != 0 {
		transport.DialContext = func(ctx context.Context, network, addr string) (conn net.Conn, err error) {
			// we need to increment a counter to iterate through the dns servers as the dialer will not
			// return an error if the dns server is not responding.
			counter := 0
			dialer := &net.Dialer{
				Timeout: 3 * time.Second,
				Resolver: &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						d := net.Dialer{
							Timeout: 3 * time.Second,
						}
						s := dnsServers[counter%len(dnsServers)]
						counter++
						return d.DialContext(ctx, network, s)
					},
				},
			}
			return dialer.DialContext(ctx, network, addr)
		}
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Second * 10,
	}

	response, err := client.Do(req)
	if err != nil {
		log.V(logf.DebugLevel).Info("failed to perform self check GET request", "error", err)
		return fmt.Errorf("failed to perform self check GET request '%s': %v", url, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		log.V(logf.DebugLevel).Info("received HTTP status code was not StatusOK (200)", "code", response.StatusCode)
		return fmt.Errorf("wrong status code '%d', expected '%d'", response.StatusCode, http.StatusOK)
	}

	presentedKey, err := io.ReadAll(io.LimitReader(response.Body, maxAcmeChallengeBodySize))
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
