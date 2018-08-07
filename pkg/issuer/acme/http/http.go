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
	certificateGvk = v1alpha1.SchemeGroupVersion.WithKind("Certificate")
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

type reachabilityTest func(ctx context.Context, domain, path, key string) (bool, error)

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
func (s *Solver) Present(ctx context.Context, issuer v1alpha1.GenericIssuer, crt *v1alpha1.Certificate, ch v1alpha1.ACMEOrderChallenge) error {
	_, podErr := s.ensurePod(crt, ch)
	svc, svcErr := s.ensureService(crt, ch)
	if svcErr != nil {
		return utilerrors.NewAggregate([]error{podErr, svcErr})
	}
	_, ingressErr := s.ensureIngress(crt, svc.Name, ch)
	return utilerrors.NewAggregate([]error{podErr, svcErr, ingressErr})
}

func (s *Solver) Check(ch v1alpha1.ACMEOrderChallenge) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), HTTP01Timeout)
	defer cancel()
	for i := 0; i < s.requiredPasses; i++ {
		ok, err := s.testReachability(ctx, ch.Domain, fmt.Sprintf("%s/%s", solver.HTTPChallengePath, ch.Token), ch.Key)
		if err != nil {
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
func (s *Solver) CleanUp(ctx context.Context, issuer v1alpha1.GenericIssuer, crt *v1alpha1.Certificate, ch v1alpha1.ACMEOrderChallenge) error {
	var errs []error
	errs = append(errs, s.cleanupPods(crt, ch))
	errs = append(errs, s.cleanupServices(crt, ch))
	errs = append(errs, s.cleanupIngresses(crt, ch))
	return utilerrors.NewAggregate(errs)
}

// testReachability will attempt to connect to the 'domain' with 'path' and
// check if the returned body equals 'key'
func testReachability(ctx context.Context, domain, path, key string) (bool, error) {
	url := &url.URL{}
	url.Scheme = "http"
	url.Host = domain
	url.Path = path

	response, err := http.Get(url.String())
	if err != nil {
		// absorb http client errors
		return false, nil
	}

	if response.StatusCode != http.StatusOK {
		// TODO: log this elsewhere
		glog.Infof("wrong status code '%d'", response.StatusCode)
		return false, nil
	}

	defer response.Body.Close()
	presentedKey, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return false, err
	}

	if string(presentedKey) != key {
		glog.Infof("presented key (%s) did not match expected (%s)", presentedKey, key)
		return false, nil
	}

	return true, nil
}
