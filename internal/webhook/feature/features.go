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

// feature contains webhook's feature gate setup functionality. Do not import
// this package into any code that's shared with other components to prevent
// overwriting other component's feature gates, see i.e
// https://github.com/cert-manager/cert-manager/issues/6011
package feature

import (
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/component-base/featuregate"

	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
)

// see https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/#feature-stages

const (
	// Copy & paste the following template when you add a new feature gate:
	// ========================== START TEMPLATE ==========================
	// Owner: @username
	// Alpha: vX.Y
	// Beta: ...
	//
	// FeatureName will enable XYZ feature.
	// Fill this section out with additional details about the feature.
	// FeatureName featuregate.Feature = "FeatureName"
	// =========================== END TEMPLATE ===========================

	// Owner: @joshvanl
	// Alpha: v1.7.1
	// Beta: v1.15
	//
	// AdditionalCertificateOutputFormats enable output additional format
	AdditionalCertificateOutputFormats featuregate.Feature = "AdditionalCertificateOutputFormats"

	// Owner: @spockz, @irbekrm
	// Alpha: v1.9
	//
	// LiteralCertificateSubject will enable providing a subject in the Certificate that will be used literally in the CertificateSigningRequest. The subject can be provided via `LiteralSubject` field on `Certificate`'s spec.
	// This feature gate must be used together with LiteralCertificateSubject webhook feature gate.
	// See https://github.com/cert-manager/cert-manager/issues/3203 and https://github.com/cert-manager/cert-manager/issues/4424 for context.
	LiteralCertificateSubject featuregate.Feature = "LiteralCertificateSubject"

	// Owner: @inteon
	// Beta: v1.13
	// GA: v1.15
	//
	// DisallowInsecureCSRUsageDefinition will prevent the webhook from allowing
	// CertificateRequest's usages to be only defined in the CSR, while leaving
	// the usages field empty.
	DisallowInsecureCSRUsageDefinition featuregate.Feature = "DisallowInsecureCSRUsageDefinition"

	// Owner: @tanujd11
	// Alpha: v1.14
	//
	// NameConstraints adds support for Name Constraints in Certificate resources
	// with IsCA=true.
	// Github Issue: https://github.com/cert-manager/cert-manager/issues/3655
	NameConstraints featuregate.Feature = "NameConstraints"

	// Owner: @SpectralHiss
	// Alpha: v1.14
	//
	// OtherNames adds support for OtherName Subject Alternative Name values in
	// Certificate resources.
	// Github Issue: https://github.com/cert-manager/cert-manager/issues/6393
	OtherNames featuregate.Feature = "OtherNames"
)

func init() {
	utilruntime.Must(utilfeature.DefaultMutableFeatureGate.Add(webhookFeatureGates))
}

// webhookFeatureGates defines all feature gates for the webhook component.
// To add a new feature, define a key for it above and add it here.
// To check whether a feature is enabled, use:
//
//	utilfeature.DefaultFeatureGate.Enabled(feature.FeatureName)
//
// Where utilfeature is github.com/cert-manager/cert-manager/pkg/util/feature.
var webhookFeatureGates = map[featuregate.Feature]featuregate.FeatureSpec{
	DisallowInsecureCSRUsageDefinition: {Default: true, PreRelease: featuregate.GA},

	AdditionalCertificateOutputFormats: {Default: true, PreRelease: featuregate.Beta},
	LiteralCertificateSubject:          {Default: true, PreRelease: featuregate.Beta},
	NameConstraints:                    {Default: false, PreRelease: featuregate.Alpha},
	OtherNames:                         {Default: false, PreRelease: featuregate.Alpha},
}
