/*
Copyright 2023 The cert-manager Authors.

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

// This file contains code that initializes cainjector feature gates. It is
// important that this code is never imported in a shared library as the feature
// gate setup for all binary components involves modifying a global variable
// from an upstream package

package features

import (
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/component-base/featuregate"

	cainjectorfeatures "github.com/cert-manager/cert-manager/internal/cainjector/feature"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
)

func init() {
	runtime.Must(utilfeature.DefaultMutableFeatureGate.Add(cainjectorFeatureGates))
}

// cainjectorFeatureGates defines all feature gates for the cainjector component.
// To add a new feature, define a key for it above and add it here.
// To check whether a feature is enabled, use:
//
//	utilfeature.DefaultFeatureGate.Enabled(feature.FeatureName)
//
// Where utilfeature is github.com/cert-manager/cert-manager/pkg/util/feature.
var cainjectorFeatureGates = map[featuregate.Feature]featuregate.FeatureSpec{
	cainjectorfeatures.ServerSideApply: {Default: false, PreRelease: featuregate.Alpha},
}
