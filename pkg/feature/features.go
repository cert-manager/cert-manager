/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package feature

import (
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/component-base/featuregate"

	utilfeature "github.com/jetstack/cert-manager/pkg/util/feature"
)

const (
	// alpha: v0.7.2
	//
	// ValidateCAA enables CAA checking when issuing certificates
	ValidateCAA featuregate.Feature = "ValidateCAA"

	// beta: v0.8.1
	//
	// IssueTemporaryCertificate enables issuing temporary certificates
	IssueTemporaryCertificate featuregate.Feature = "IssueTemporaryCertificate"

	// alpha: v0.8.1
	//
	// Enables cert-manager to resolve certificate requests using its
	// CertificateRequest issuer controllers.
	CertificateRequestControllers = "CertificateRequestControllers"
)

func init() {
	runtime.Must(utilfeature.DefaultMutableFeatureGate.Add(defaultKubernetesFeatureGates))
}

// defaultKubernetesFeatureGates consists of all known Kubernetes-specific feature keys.
// To add a new feature, define a key for it above and add it here. The features will be
// available throughout Kubernetes binaries.
var defaultKubernetesFeatureGates = map[featuregate.Feature]featuregate.FeatureSpec{
	ValidateCAA:                   {Default: false, PreRelease: featuregate.Alpha},
	IssueTemporaryCertificate:     {Default: true, PreRelease: featuregate.Beta},
	CertificateRequestControllers: {Default: false, PreRelease: featuregate.Alpha},
}
