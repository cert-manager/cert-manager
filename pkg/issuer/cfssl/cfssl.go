package cfssl

import (
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/record"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"github.com/jetstack/cert-manager/pkg/issuer"
)

// CFSSL allows communicating with a remote cfssl based certificate authority.
// A secret resource is used to store the authkey that is used to make authenticated requests to the remote CA server.
type CFSSL struct {
	issuer                   v1alpha1.GenericIssuer
	client                   kubernetes.Interface
	cmclient                 clientset.Interface
	recorder                 record.EventRecorder
	issuerResourcesNamespace string
	secretsLister            corelisters.SecretLister
}

// Request defines the body of an unauthenticated request to send to a remote cfssl ca server
type Request struct {
	Profile            string `json:"profile,omitempty"`
	CertificateRequest string `json:"certificate_request"`
}

// Response defines the response body received from a remote cfssl ca server
type Response struct {
	Success bool                     `json:"success"`
	Result  map[string]interface{}   `json:"result"`
	Errors  []map[string]interface{} `json:"errors"`
}

// AuthenticatedRequest defines the body of an authenticated request to send to a remote cfssl ca server
type AuthenticatedRequest struct {
	Token   string `json:"token"`
	Request string `json:"request"`
}

// NewCFSSL initializes a new CFSSL struct and returns a pointer to it
func NewCFSSL(issuer v1alpha1.GenericIssuer,
	cl kubernetes.Interface,
	cmclient clientset.Interface,
	recorder record.EventRecorder,
	issuerResourcesNamespace string,
	secretsLister corelisters.SecretLister) (issuer.Interface, error) {
	return &CFSSL{
		issuer:                   issuer,
		client:                   cl,
		cmclient:                 cmclient,
		recorder:                 recorder,
		issuerResourcesNamespace: issuerResourcesNamespace,
		secretsLister:            secretsLister,
	}, nil
}

// Register CFSSL Issuer with the issuer factory
func init() {
	issuer.Register(issuer.IssuerCFSSL, func(issuer v1alpha1.GenericIssuer, ctx *issuer.Context) (issuer.Interface, error) {
		issuerResourcesNamespace := issuer.GetObjectMeta().Namespace
		if issuerResourcesNamespace == "" {
			issuerResourcesNamespace = ctx.ClusterResourceNamespace
		}
		return NewCFSSL(
			issuer,
			ctx.Client,
			ctx.CMClient,
			ctx.Recorder,
			issuerResourcesNamespace,
			ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
		)
	})
}
