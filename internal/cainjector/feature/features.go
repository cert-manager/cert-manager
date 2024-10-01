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

// feature contains cainjector feature gate setup code. Do not import this
// package into any code that's shared with other components to prevent
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

	// Owner: @inteon
	// Alpha: v1.12
	//
	// ServerSideApply enables the use of ServerSideApply in all API calls.
	ServerSideApply featuregate.Feature = "ServerSideApply"
)

func init() {
	utilruntime.Must(utilfeature.DefaultMutableFeatureGate.Add(cainjectorFeatureGates))
}

// cainjectorFeatureGates defines all feature gates for the cainjector component.
// To add a new feature, define a key for it above and add it here.
// To check whether a feature is enabled, use:
//
//	utilfeature.DefaultFeatureGate.Enabled(feature.FeatureName)
//
// Where utilfeature is github.com/cert-manager/cert-manager/pkg/util/feature.
var cainjectorFeatureGates = map[featuregate.Feature]featuregate.FeatureSpec{
	ServerSideApply: {Default: false, PreRelease: featuregate.Alpha},
}
