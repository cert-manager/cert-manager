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

package v1alpha1

import (
	internalinterfaces "github.com/jetstack/cert-manager/pkg/client/informers/externalversions/internalinterfaces"
)

// Interface provides access to all the informers in this group version.
type Interface interface {
	// Certificates returns a CertificateInformer.
	Certificates() CertificateInformer
	// ClusterIssuers returns a ClusterIssuerInformer.
	ClusterIssuers() ClusterIssuerInformer
	// Issuers returns a IssuerInformer.
	Issuers() IssuerInformer
}

type version struct {
	factory          internalinterfaces.SharedInformerFactory
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// New returns a new Interface.
func New(f internalinterfaces.SharedInformerFactory, namespace string, tweakListOptions internalinterfaces.TweakListOptionsFunc) Interface {
	return &version{factory: f, namespace: namespace, tweakListOptions: tweakListOptions}
}

// Certificates returns a CertificateInformer.
func (v *version) Certificates() CertificateInformer {
	return &certificateInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// ClusterIssuers returns a ClusterIssuerInformer.
func (v *version) ClusterIssuers() ClusterIssuerInformer {
	return &clusterIssuerInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// Issuers returns a IssuerInformer.
func (v *version) Issuers() IssuerInformer {
	return &issuerInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}
