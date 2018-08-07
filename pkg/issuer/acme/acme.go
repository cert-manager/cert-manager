package acme

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/golang/glog"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	extlisters "k8s.io/client-go/listers/extensions/v1beta1"
	"k8s.io/client-go/tools/record"

	"github.com/jetstack/cert-manager/pkg/acme"
	"github.com/jetstack/cert-manager/pkg/acme/client"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/http"
	acmeapi "github.com/jetstack/cert-manager/third_party/crypto/acme"
)

// Acme is an issuer for an ACME server. It can be used to register and obtain
// certificates from any ACME server. It supports DNS01 and HTTP01 challenge
// mechanisms.
type Acme struct {
	helper *acme.Helper

	issuer v1alpha1.GenericIssuer

	client   kubernetes.Interface
	cmClient clientset.Interface
	recorder record.EventRecorder

	secretsLister  corelisters.SecretLister
	podsLister     corelisters.PodLister
	servicesLister corelisters.ServiceLister
	ingressLister  extlisters.IngressLister

	dnsSolver  solver
	httpSolver solver

	// issuerResourcesNamespace is a namespace to store resources in. This is
	// here so we can easily support ClusterIssuers with the same codepath. By
	// setting this field to either the namespace of the Issuer, or the
	// clusterResourceNamespace specified on the CLI, we can easily continue
	// to work with supplemental (e.g. secrets) resources without significant
	// refactoring.
	issuerResourcesNamespace string

	// ambientCredentials determines whether a given acme solver may draw
	// credentials ambiently, e.g. from metadata services or environment
	// variables.
	// Currently, only AWS ambient credential control is implemented.
	ambientCredentials bool

	dns01Nameservers []string
}

// solver solves ACME challenges by presenting the given token and key in an
// appropriate way given the config in the Issuer and Certificate.
type solver interface {
	// we pass the certificate to the Present function so that if the solver
	// needs to create any new resources, it can set the appropriate owner
	// reference
	Present(ctx context.Context, crt *v1alpha1.Certificate, ch v1alpha1.ACMEOrderChallenge) error

	// Check should return Error only if propagation check cannot be performed.
	// It MUST return `false, nil` if can contact all relevant services and all is
	// doing is waiting for propagation
	Check(ch v1alpha1.ACMEOrderChallenge) (bool, error)
	CleanUp(ctx context.Context, crt *v1alpha1.Certificate, ch v1alpha1.ACMEOrderChallenge) error
}

// New returns a new ACME issuer interface for the given issuer.
func New(issuer v1alpha1.GenericIssuer,
	client kubernetes.Interface,
	cmClient clientset.Interface,
	recorder record.EventRecorder,
	resourceNamespace string,
	acmeHTTP01SolverImage string,
	secretsLister corelisters.SecretLister,
	podsLister corelisters.PodLister,
	servicesLister corelisters.ServiceLister,
	ingressLister extlisters.IngressLister,
	ambientCreds bool,
	dns01Nameservers []string) (issuer.Interface, error) {
	if issuer.GetSpec().ACME == nil {
		return nil, fmt.Errorf("acme config may not be empty")
	}

	if issuer.GetSpec().ACME.Server == "" ||
		issuer.GetSpec().ACME.PrivateKey.Name == "" ||
		issuer.GetSpec().ACME.Email == "" {
		return nil, fmt.Errorf("acme server, private key and email are required fields")
	}

	if resourceNamespace == "" {
		return nil, fmt.Errorf("resource namespace cannot be empty")
	}

	a := &Acme{
		// TODO: helper *should* be instantiated with the ClusterResourceNamespace,
		// whereas here we are instantiating it with the actual namespace that should
		// be used to discover resources.
		// This is okay in this instance, as we construct a dedicated Helper per Issuer
		// and we also construct a dedicated 'Acme' per issuer too.
		// With the ACME order changes, this line will change appropriately.
		helper:         acme.NewHelper(secretsLister, resourceNamespace),
		issuer:         issuer,
		client:         client,
		cmClient:       cmClient,
		recorder:       recorder,
		secretsLister:  secretsLister,
		podsLister:     podsLister,
		servicesLister: servicesLister,
		ingressLister:  ingressLister,

		dnsSolver:                dns.NewSolver(issuer, client, secretsLister, resourceNamespace, ambientCreds, dns01Nameservers),
		httpSolver:               http.NewSolver(issuer, client, podsLister, servicesLister, ingressLister, acmeHTTP01SolverImage),
		issuerResourcesNamespace: resourceNamespace,
	}
	return a, nil
}

var timeout = time.Duration(5 * time.Second)

func dialTimeout(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, network, addr)
}

// createOrder will create an order for the given certificate with the acme
// server. Once created, it will set the order URL on the status field of the
// certificate resource.
func (a *Acme) createOrder(ctx context.Context, cl client.Interface, crt *v1alpha1.Certificate) (*acmeapi.Order, error) {
	order, err := buildOrder(crt)
	if err != nil {
		return nil, err
	}
	order, err = cl.CreateOrder(ctx, order)
	if err != nil {
		a.recorder.Eventf(crt, corev1.EventTypeWarning, "ErrCreateOrder", "Error creating order: %v", err)
		return nil, err
	}

	glog.Infof("Created order for domains: %v", order.Identifiers)
	crt.Status.ACMEStatus().Order.URL = order.URL
	return order, nil
}

func (a *Acme) solverFor(challengeType string) (solver, error) {
	switch challengeType {
	case "http-01":
		return a.httpSolver, nil
	case "dns-01":
		return a.dnsSolver, nil
	}
	return nil, fmt.Errorf("no solver for %q implemented", challengeType)
}

// Register this Issuer with the issuer factory
func init() {
	issuer.Register(issuer.IssuerACME, func(i v1alpha1.GenericIssuer, ctx *issuer.Context) (issuer.Interface, error) {
		issuerResourcesNamespace := i.GetObjectMeta().Namespace
		if issuerResourcesNamespace == "" {
			issuerResourcesNamespace = ctx.ClusterResourceNamespace
		}

		ambientCreds := false
		switch i.(type) {
		case *v1alpha1.ClusterIssuer:
			ambientCreds = ctx.ClusterIssuerAmbientCredentials
		case *v1alpha1.Issuer:
			ambientCreds = ctx.IssuerAmbientCredentials
		default:
			return nil, fmt.Errorf("issuer was neither an 'Issuer' nor 'ClusterIssuer'; was %T", i)
		}

		return New(
			i,
			ctx.Client,
			ctx.CMClient,
			ctx.Recorder,
			issuerResourcesNamespace,
			ctx.ACMEHTTP01SolverImage,
			ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
			ctx.KubeSharedInformerFactory.Core().V1().Pods().Lister(),
			ctx.KubeSharedInformerFactory.Core().V1().Services().Lister(),
			ctx.KubeSharedInformerFactory.Extensions().V1beta1().Ingresses().Lister(),
			ambientCreds,
			ctx.DNS01Nameservers,
		)
	})
}
