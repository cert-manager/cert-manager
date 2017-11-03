package controller

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"

	clientset "github.com/jetstack-experimental/cert-manager/pkg/client/clientset/versioned"
	"github.com/jetstack-experimental/cert-manager/pkg/issuer"
	"github.com/jetstack-experimental/cert-manager/pkg/util/kube"
)

// Context contains various types that are used by controller implementations.
// We purposely don't have specific informers/listers here, and instead keep
// a reference to a SharedInformerFactory so that controllers can choose
// themselves which listers are required.
type Context struct {
	// Client is a Kubernetes clientset
	Client kubernetes.Interface
	// CMClient is a cert-manager clientset
	CMClient clientset.Interface
	// Recorder to record events to
	Recorder record.EventRecorder

	// SharedInformerFactory can be used to obtain shared SharedIndexInformer
	// instances
	SharedInformerFactory kube.SharedInformerFactory
	// IssuerFactory is a factory that can be used to obtain issuer.Interface
	// instances
	IssuerFactory issuer.Factory

	// Namespace is a namespace to operate within. This should be used when
	// constructing SharedIndexInformers for the informer factory.
	Namespace string
	// ClusterResourceNamespace is the namespace to store resources created by
	// non-namespaced resources (e.g. ClusterIssuer) in.
	ClusterResourceNamespace string
}
