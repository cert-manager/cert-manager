package vault

import (
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/record"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"github.com/jetstack/cert-manager/pkg/issuer"
)

type Vault struct {
	issuer v1alpha1.GenericIssuer

	client   kubernetes.Interface
	cmclient clientset.Interface
	recorder record.EventRecorder

	secretsLister corelisters.SecretLister

	// issuerResourcesNamespace is a namespace to store resources in. This is
	// here so we can easily support ClusterIssuers with the same codepath. By
	// setting this field to either the namespace of the Issuer, or the
	// clusterResourceNamespace specified on the CLI, we can easily continue
	// to work with supplemental (e.g. secrets) resources without significant
	// refactoring.
	issuerResourcesNamespace string
}

func NewVault(issuerObj v1alpha1.GenericIssuer,
	cl kubernetes.Interface,
	cmclient clientset.Interface,
	recorder record.EventRecorder,
	resourceNamespace string,
	secretsLister corelisters.SecretLister) (issuer.Interface, error) {

	return &Vault{
		issuer:                   issuerObj,
		client:                   cl,
		cmclient:                 cmclient,
		recorder:                 recorder,
		issuerResourcesNamespace: resourceNamespace,
		secretsLister:            secretsLister,
	}, nil
}

// Register this Issuer with the issuer factory
func init() {
	issuer.Register(issuer.IssuerVault, func(issuer v1alpha1.GenericIssuer, ctx *issuer.Context) (issuer.Interface, error) {
		issuerResourcesNamespace := issuer.GetObjectMeta().Namespace
		if issuerResourcesNamespace == "" {
			issuerResourcesNamespace = ctx.ClusterResourceNamespace
		}
		return NewVault(
			issuer,
			ctx.Client,
			ctx.CMClient,
			ctx.Recorder,
			issuerResourcesNamespace,
			ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
		)
	})
}
