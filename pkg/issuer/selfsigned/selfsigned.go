package ca

import (
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/record"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"github.com/jetstack/cert-manager/pkg/issuer"
)

// SelfSigned is an Issuer implementation the simply self-signs Certificates.
type SelfSigned struct {
	issuer        v1alpha1.GenericIssuer
	cl            kubernetes.Interface
	cmclient      clientset.Interface
	recorder      record.EventRecorder
	secretsLister corelisters.SecretLister
}

func NewSelfSigned(issuer v1alpha1.GenericIssuer,
	cl kubernetes.Interface,
	cmclient clientset.Interface,
	recorder record.EventRecorder,
	secretsLister corelisters.SecretLister) (issuer.Interface, error) {
	return &SelfSigned{
		issuer:        issuer,
		cl:            cl,
		cmclient:      cmclient,
		recorder:      recorder,
		secretsLister: secretsLister,
	}, nil
}

const (
	ControllerName = "selfsigned"
)

func init() {
	issuer.Register(ControllerName, func(issuer v1alpha1.GenericIssuer, ctx *issuer.Context) (issuer.Interface, error) {
		return NewSelfSigned(
			issuer,
			ctx.Client,
			ctx.CMClient,
			ctx.Recorder,
			ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
		)
	})
}
