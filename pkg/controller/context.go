/*
Copyright 2018 The Jetstack cert-manager contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"time"

	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"

	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	informers "github.com/jetstack/cert-manager/pkg/client/informers/externalversions"
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

	IssuerOptions
	ACMEOptions
	IngressShimOptions
}

func (c *Context) IssuerFactory() IssuerFactory {
	return NewIssuerFactory(c)
}

type IssuerOptions struct {
	// ClusterResourceNamespace is the namespace to store resources created by
	// non-namespaced resources (e.g. ClusterIssuer) in.
	ClusterResourceNamespace string

	// ClusterIssuerAmbientCredentials controls whether a cluster issuer should
	// pick up ambient credentials, such as those from metadata services, to
	// construct clients.
	ClusterIssuerAmbientCredentials bool

	// IssuerAmbientCredentials controls whether an issuer should pick up ambient
	// credentials, such as those from metadata services, to construct clients.
	IssuerAmbientCredentials bool

	// RenewBeforeExpiryDuration is the default 'renew before expiry' time for Certificates.
	// Once a certificate is within this duration until expiry, a new Certificate
	// will be attempted to be issued.
	RenewBeforeExpiryDuration time.Duration
}

type ACMEOptions struct {
	// ACMEHTTP01SolverImage is the image to use for solving ACME HTTP01
	// challenges
	HTTP01SolverImage string

	// DNS01Nameservers is a list of nameservers to use when performing self-checks
	// for ACME DNS01 validations.
	DNS01Nameservers []string
}

type IngressShimOptions struct {
	// Default issuer/certificates details consumed by ingress-shim
	DefaultIssuerName                  string
	DefaultIssuerKind                  string
	DefaultACMEIssuerChallengeType     string
	DefaultACMEIssuerDNS01ProviderName string
}
