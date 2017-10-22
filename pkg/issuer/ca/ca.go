package ca

import (
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/record"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"github.com/jetstack/cert-manager/pkg/issuer"
)

// CA is a simple CA implementation backed by the Kubernetes API server.
// A secret resource is used to store a CA public and private key that is then
// used to sign certificates.
type CA struct {
	issuer                   v1alpha1.GenericIssuer
	cl                       kubernetes.Interface
	cmclient                 clientset.Interface
	recorder                 record.EventRecorder
	issuerResourcesNamespace string
	secretsLister            corelisters.SecretLister
}

func NewCA(issuer v1alpha1.GenericIssuer,
	cl kubernetes.Interface,
	cmclient clientset.Interface,
	recorder record.EventRecorder,
	issuerResourcesNamespace string,
	secretsLister corelisters.SecretLister) (issuer.Interface, error) {
	return &CA{
		issuer:                   issuer,
		cl:                       cl,
		cmclient:                 cmclient,
		recorder:                 recorder,
		issuerResourcesNamespace: issuerResourcesNamespace,
		secretsLister:            secretsLister,
	}, nil
}

const (
	ControllerName = "ca"
)

func init() {
	issuer.Register(ControllerName, func(issuer v1alpha1.GenericIssuer, ctx *issuer.Context) (issuer.Interface, error) {
		issuerResourcesNamespace := issuer.GetObjectMeta().Namespace
		if issuerResourcesNamespace == "" {
			issuerResourcesNamespace = ctx.ClusterResourceNamespace
		}
		return NewCA(
			issuer,
			ctx.Client,
			ctx.CMClient,
			ctx.Recorder,
			issuerResourcesNamespace,
			ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
		)
	})
}
