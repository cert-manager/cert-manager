/*
Copyright 2022 The cert-manager Authors.

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
	"k8s.io/component-base/featuregate"

	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
)

const (
	// FeatureName will enable XYZ feature.
	// Fill this section out with additional details about the feature.
	//
	// Owner (responsible for graduating feature through to GA): @username
	// Alpha: vX.Y
	// Beta: ...
	//FeatureName featuregate.Feature = "FeatureName"

	// Owner: @joshvanl
	// alpha: v1.7.1
	//
	// AdditionalCertificateOutputFormats enable output additional format
	AdditionalCertificateOutputFormats featuregate.Feature = "AdditionalCertificateOutputFormats"

	// Owner (responsible for graduating feature through to GA): @spockz , @irbekrm
	// Alpha: v1.9
	// LiteralCertificateSubject will enable providing a subject in the Certificate that will be used literally in the CertificateSigningRequest. The subject can be provided via `LiteralSubject` field on `Certificate`'s spec.
	// This feature gate must be used together with LiteralCertificateSubject webhook feature gate.
	// See https://github.com/cert-manager/cert-manager/issues/3203 and https://github.com/cert-manager/cert-manager/issues/4424 for context.
	LiteralCertificateSubject featuregate.Feature = "LiteralCertificateSubject"
)

func init() {
	utilfeature.DefaultMutableFeatureGate.Add(webhookFeatureGates)
}

// webhookFeatureGates defines all feature gates for the webhook component.
// To add a new feature, define a key for it above and add it here.
// To check whether a feature is enabled, use:
//
//	utilfeature.DefaultFeatureGate.Enabled(feature.FeatureName)
//
// Where utilfeature is github.com/cert-manager/cert-manager/pkg/util/feature.
var webhookFeatureGates = map[featuregate.Feature]featuregate.FeatureSpec{
	AdditionalCertificateOutputFormats: {Default: false, PreRelease: featuregate.Alpha},
	LiteralCertificateSubject:          {Default: false, PreRelease: featuregate.Alpha},
}
