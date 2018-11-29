/*
Copyright 2018 The Jetstack cert-manager contributors.

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
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/golang/glog"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	corev1listers "k8s.io/client-go/listers/core/v1"
	extv1beta1listers "k8s.io/client-go/listers/extensions/v1beta1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/http/solver"
)

const (
	// HTTP01Timeout is the max amount of time to wait for an HTTP01 challenge
	// to succeed
	HTTP01Timeout = time.Minute * 15
	// acmeSolverListenPort is the port acmesolver should listen on
	acmeSolverListenPort = 8089

	domainLabelKey = "certmanager.k8s.io/acme-http-domain"
	tokenLabelKey  = "certmanager.k8s.io/acme-http-token"
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

type reachabilityTest func(ctx context.Context, url, key string) (bool, error)

// absorbErr wraps an error to mark it as absorbable (log and handle as nil)
type absorbErr struct {
	err error
}

func (ae *absorbErr) Error() string {
	return ae.err.Error()
}

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

// Present will realise the resources required to solve the given HTTP01
// challenge validation in the apiserver. If those resources already exist, it
// will return nil (i.e. this function is idempotent).
func (s *Solver) Present(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
	_, podErr := s.ensurePod(ch)
	svc, svcErr := s.ensureService(issuer, ch)
	if svcErr != nil {
		return utilerrors.NewAggregate([]error{podErr, svcErr})
	}
	_, ingressErr := s.ensureIngress(ch, svc.Name)
	return utilerrors.NewAggregate([]error{podErr, svcErr, ingressErr})
}

func (s *Solver) Check(ch *v1alpha1.Challenge) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), HTTP01Timeout)
	defer cancel()

	url := s.buildChallengeUrl(ch)

	for i := 0; i < s.requiredPasses; i++ {
		ok, err := s.testReachability(ctx, url, ch.Spec.Key)
		if absorbedErr, wasAbsorbed := err.(*absorbErr); wasAbsorbed {
			glog.Infof("could not reach '%s': %v", url, absorbedErr.err)
			return false, nil
		} else if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
		time.Sleep(time.Second * 2)
	}
	return true, nil
}

// CleanUp will ensure the created service, ingress and pod are clean/deleted of any
// cert-manager created data.
func (s *Solver) CleanUp(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
	var errs []error
	errs = append(errs, s.cleanupPods(ch))
	errs = append(errs, s.cleanupServices(ch))
	errs = append(errs, s.cleanupIngresses(ch))
	return utilerrors.NewAggregate(errs)
}

func (s *Solver) buildChallengeUrl(ch *v1alpha1.Challenge) string {
	url := &url.URL{}
	url.Scheme = "http"
	url.Host = ch.Spec.DNSName
	url.Path = fmt.Sprintf("%s/%s", solver.HTTPChallengePath, ch.Spec.Token)

	return url.String()
}

// testReachability will attempt to connect to the 'domain' with 'path' and
// check if the returned body equals 'key'
func testReachability(ctx context.Context, url string, key string) (bool, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("failed to build request: %v", err)
	}

	req = req.WithContext(ctx)

	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, &absorbErr{err: fmt.Errorf("failed to GET '%s': %v", url, err)}
	}

	if response.StatusCode != http.StatusOK {
		return false, &absorbErr{err: fmt.Errorf("wrong status code '%d', expected '%d'", response.StatusCode, http.StatusOK)}
	}

	defer response.Body.Close()
	presentedKey, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response body: %v", err)
	}

	if string(presentedKey) != key {
		return false, &absorbErr{err: fmt.Errorf("presented key (%s) did not match expected (%s)", presentedKey, key)}
	}

	return true, nil
}
