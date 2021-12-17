package feature

import (
	utilfeature "github.com/jetstack/cert-manager/pkg/util/feature"
	"k8s.io/component-base/featuregate"
)

const (
// FeatureName will enable XYZ feature.
// Fill this section out with additional details about the feature.
//
// Owner (responsible for graduating feature through to GA): @username
// Alpha: vX.Y
// Beta: ...
//FeatureName featuregate.Feature = "FeatureName"

// Insert features below this line to maintain the template above.
)

func init() {
	utilfeature.DefaultMutableFeatureGate.Add(webhookFeatureGates)
}

// webhookFeatureGates defines all feature gates for the webhook component.
// To add a new feature, define a key for it above and add it here.
// To check whether a feature is enabled, use:
//   utilfeature.DefaultFeatureGate.Enabled(feature.FeatureName)
// Where utilfeature is github.com/jetstack/cert-manager/pkg/util/feature.
var webhookFeatureGates = map[featuregate.Feature]featuregate.FeatureSpec{
	//FeatureName: {Default: false, PreRelease: featuregate.Alpha},
}
