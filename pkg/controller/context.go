package controller

import (
	"crypto/x509"
	"time"

	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"

	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	informers "github.com/jetstack/cert-manager/pkg/client/informers/externalversions"
	"github.com/jetstack/cert-manager/pkg/issuer"
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

	// KubeSharedInformerFactory can be used to obtain shared
	// SharedIndexInformer instances for Kubernetes types
	KubeSharedInformerFactory kubeinformers.SharedInformerFactory
	// SharedInformerFactory can be used to obtain shared SharedIndexInformer
	// instances
	SharedInformerFactory informers.SharedInformerFactory
	// IssuerFactory is a factory that can be used to obtain issuer.Interface
	// instances
	IssuerFactory issuer.Factory

	// ClusterResourceNamespace is the namespace to store resources created by
	// non-namespaced resources (e.g. ClusterIssuer) in.
	ClusterResourceNamespace string

	// Default issuer/certificates details consumed by ingress-shim
	DefaultIssuerName                  string
	DefaultIssuerKind                  string
	DefaultACMEIssuerChallengeType     string
	DefaultACMEIssuerDNS01ProviderName string

	// RenewBeforeExpiryDuration is the default 'renew before expiry' time for Certificates.
	// Once a certificate is within this duration until expiry, a new Certificate
	// will be attempted to be issued.
	RenewBeforeExpiryDuration time.Duration
}

func CertificateNeedsRenew(cert *x509.Certificate, renewBeforeDuration time.Duration) bool {
	// calculate the amount of time until expiry
	durationUntilExpiry := cert.NotAfter.Sub(time.Now())
	// calculate how long until we should start attempting to renew the
	// certificate
	renewIn := durationUntilExpiry - renewBeforeDuration
	// if we should being attempting to renew now, then trigger a renewal
	if renewIn <= 0 {
		return true
	}
	return false
}
