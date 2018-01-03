package issuer

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"

	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	informers "github.com/jetstack/cert-manager/pkg/client/informers/externalversions"
	kubeinformers "github.com/jetstack/cert-manager/third_party/k8s.io/client-go/informers"
)

// Context contains various types that are used by Issuer implementations.
// We purposely don't have specific informers/listers here, and instead keep
// a reference to a SharedInformerFactory so that issuer constructors can
// choose themselves which listers are required.
type Context struct {
	// Client is a Kubernetes clientset
	Client kubernetes.Interface
	// CMClient is a cert-manager clientset
	CMClient clientset.Interface
	// Recorder is an EventRecorder to log events to
	Recorder record.EventRecorder

	// KubeSharedInformerFactory can be used to obtain shared
	// SharedIndexInformer instances for Kubernetes types
	KubeSharedInformerFactory kubeinformers.SharedInformerFactory
	// SharedInformerFactory can be used to obtain shared SharedIndexInformer
	// instances
	SharedInformerFactory informers.SharedInformerFactory

	// Namespace is a namespace to operate within. This should be used when
	// constructing SharedIndexInformers for the informer factory.
	Namespace string
	// ClusterResourceNamespace is the namespace to store resources created by
	// non-namespaced resources (e.g. ClusterIssuer) in.
	ClusterResourceNamespace string
	// ACMEHTTP01SolverImage is the image to use for solving ACME HTTP01
	// challenges
	ACMEHTTP01SolverImage string
	// acmeDNS01ResolvConfFile is an optional custom resolv.conf file for
	// solve ACME DNS01 challenges
	ACMEDNS01ResolvConfFile string
}
