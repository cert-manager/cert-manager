package acme

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/glog"
	"golang.org/x/crypto/acme"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"

	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack-experimental/cert-manager/pkg/client/clientset"
	"github.com/jetstack-experimental/cert-manager/pkg/issuer"
	"github.com/jetstack-experimental/cert-manager/pkg/issuer/acme/dns"
	"github.com/jetstack-experimental/cert-manager/pkg/issuer/acme/http"
	"github.com/jetstack-experimental/cert-manager/pkg/util/kube"
)

// Acme is an issuer for an ACME server. It can be used to register and obtain
// certificates from any ACME server. It supports DNS01 and HTTP01 challenge
// mechanisms.
type Acme struct {
	issuer v1alpha1.GenericIssuer

	client   kubernetes.Interface
	cmClient clientset.Interface
	recorder record.EventRecorder

	secretsLister corelisters.SecretLister

	dnsSolver  solver
	httpSolver solver

	// resourceNamespace is a namespace to store resources in. This is here so
	// we can easily support ClusterIssuers with the same codepath. By setting
	// this field to either the namespace of the Issuer, or the
	// clusterResourceNamespace specified on the CLI, we can easily continue
	// to work with supplemental resources without significant refactoring.
	resourceNamespace string
}

// solver solves ACME challenges by presenting the given token and key in an
// appropriate way given the config in the Issuer and Certificate.
type solver interface {
	Present(ctx context.Context, crt *v1alpha1.Certificate, domain, token, key string) error
	Wait(ctx context.Context, crt *v1alpha1.Certificate, domain, token, key string) error
	CleanUp(ctx context.Context, crt *v1alpha1.Certificate, domain, token, key string) error
}

// New returns a new ACME issuer interface for the given issuer.
func New(issuer v1alpha1.GenericIssuer,
	client kubernetes.Interface,
	cmClient clientset.Interface,
	recorder record.EventRecorder,
	resourceNamespace string,
	acmeHTTP01SolverImage string,
	secretsInformer cache.SharedIndexInformer) (issuer.Interface, error) {
	if issuer.GetSpec().ACME == nil {
		return nil, fmt.Errorf("acme config may not be empty")
	}

	secretsLister := corelisters.NewSecretLister(secretsInformer.GetIndexer())

	return &Acme{
		issuer:            issuer,
		client:            client,
		cmClient:          cmClient,
		recorder:          recorder,
		secretsLister:     secretsLister,
		dnsSolver:         dns.NewSolver(issuer, client, secretsLister, resourceNamespace),
		httpSolver:        http.NewSolver(issuer, client, secretsLister, acmeHTTP01SolverImage),
		resourceNamespace: resourceNamespace,
	}, nil
}

func (a *Acme) acmeClient() (*acme.Client, error) {
	secretName, secretKey := a.acmeAccountPrivateKeyMeta()
	glog.V(4).Infof("getting private key (%s->%s) for acme issuer %s/%s", secretName, secretKey, a.resourceNamespace, a.issuer.GetObjectMeta().Name)
	accountPrivKey, err := kube.SecretTLSKeyRef(a.secretsLister, a.resourceNamespace, secretName, secretKey)
	if err != nil {
		return nil, err
	}

	cl := &acme.Client{
		Key:          accountPrivKey,
		DirectoryURL: a.issuer.GetSpec().ACME.Server,
	}
	return cl, nil
}

// acmeAccountPrivateKeyMeta returns the name and the secret 'key' that stores
// the ACME account private key.
func (a *Acme) acmeAccountPrivateKeyMeta() (name string, key string) {
	secretName := a.issuer.GetSpec().ACME.PrivateKey.Name
	secretKey := a.issuer.GetSpec().ACME.PrivateKey.Key
	if len(secretKey) == 0 {
		secretKey = corev1.TLSPrivateKeyKey
	}
	return secretName, secretKey
}

func (a *Acme) solverFor(challengeType string) (solver, error) {
	switch challengeType {
	case "http-01":
		return a.httpSolver, nil
	case "dns-01":
		return a.dnsSolver, nil
	}
	return nil, fmt.Errorf("no solver implemented")
}

// Register this Issuer with the issuer factory
func init() {
	// TODO: This constructor function below is called to create instances of
	// the Issuer from a GenericIssuer and Context. However, we currently
	// construct a new SharedInformer for every single item processed. This
	// will be the same SharedInformer as other loops use, thanks to the
	// SharedInformerFactory, however it seems a bit unnatural to create a
	// lister per-request, even if that lister does share the same underlying
	// indexer.
	issuer.Register(issuer.IssuerACME, func(i v1alpha1.GenericIssuer, ctx *issuer.Context) (issuer.Interface, error) {
		// We do this little dance because of the way our SharedInformerFactory is
		// written. It'd be great if this weren't necessary.
		resourceNamespace := i.GetObjectMeta().Namespace
		informerNS := ctx.Namespace
		if resourceNamespace == "" {
			resourceNamespace = ctx.ClusterResourceNamespace
			informerNS = ctx.ClusterResourceNamespace
		}
		return New(
			i,
			ctx.Client,
			ctx.CMClient,
			ctx.Recorder,
			resourceNamespace,
			ctx.ACMEHTTP01SolverImage,
			ctx.SharedInformerFactory.InformerFor(
				informerNS,
				metav1.GroupVersionKind{Version: "v1", Kind: "Secret"},
				coreinformers.NewSecretInformer(ctx.Client, resourceNamespace, time.Second*30, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})),
		)
	})
}
