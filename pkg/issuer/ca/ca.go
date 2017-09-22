package ca

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"

	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack-experimental/cert-manager/pkg/client/clientset"
	"github.com/jetstack-experimental/cert-manager/pkg/issuer"
)

// CA is a simple CA implementation backed by the Kubernetes API server.
// A secret resource is used to store a CA public and private key that is then
// used to sign certificates.
type CA struct {
	issuer        v1alpha1.GenericIssuer
	cl            kubernetes.Interface
	cmclient      clientset.Interface
	recorder      record.EventRecorder
	secretsLister corelisters.SecretLister
}

func NewCA(issuer v1alpha1.GenericIssuer,
	cl kubernetes.Interface,
	cmclient clientset.Interface,
	recorder record.EventRecorder,
	secretInformer cache.SharedIndexInformer) (issuer.Interface, error) {
	secretsLister := corelisters.NewSecretLister(secretInformer.GetIndexer())
	return &CA{
		issuer:        issuer,
		cl:            cl,
		cmclient:      cmclient,
		recorder:      recorder,
		secretsLister: secretsLister,
	}, nil
}

const (
	ControllerName = "ca"
)

func init() {
	issuer.Register(ControllerName, func(issuer v1alpha1.GenericIssuer, ctx *issuer.Context) (issuer.Interface, error) {
		// We do this little dance because of the way our SharedInformerFactory is
		// written. It'd be great if this weren't necessary.
		resourceNamespace := issuer.GetObjectMeta().Namespace
		informerNS := ctx.Namespace
		if resourceNamespace == "" {
			resourceNamespace = ctx.ClusterResourceNamespace
			informerNS = ctx.ClusterResourceNamespace
		}
		return NewCA(
			issuer,
			ctx.Client,
			ctx.CMClient,
			ctx.Recorder,
			ctx.SharedInformerFactory.InformerFor(
				informerNS,
				metav1.GroupVersionKind{Version: "v1", Kind: "Secret"},
				coreinformers.NewSecretInformer(ctx.Client, resourceNamespace, time.Second*30, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})),
		)
	})
}
