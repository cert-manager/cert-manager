package issuer

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"

	"github.com/jetstack-experimental/cert-manager/pkg/client/clientset"
	"github.com/jetstack-experimental/cert-manager/pkg/util/kube"
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
	// SharedInformerFactory can be used to obtain shared SharedIndexInformer
	// instances
	SharedInformerFactory kube.SharedInformerFactory

	// Namespace is a namespace to operate within. This should be used when
	// constructing SharedIndexInformers for the informer factory.
	Namespace string
}
