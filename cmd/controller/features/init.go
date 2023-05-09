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

	controllerfeatures "github.com/cert-manager/cert-manager/internal/controller/feature"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
)

func init() {
	runtime.Must(utilfeature.DefaultMutableFeatureGate.Add(defaultCertManagerFeatureGates))
}

// defaultCertManagerFeatureGates consists of all known cert-manager feature keys.
// To add a new feature, define a key for it above and add it here. The features will be
// available on the cert-manager controller binary.
var defaultCertManagerFeatureGates = map[featuregate.Feature]featuregate.FeatureSpec{
	controllerfeatures.ValidateCAA:                                      {Default: false, PreRelease: featuregate.Alpha},
	controllerfeatures.ExperimentalCertificateSigningRequestControllers: {Default: false, PreRelease: featuregate.Alpha},
	controllerfeatures.ExperimentalGatewayAPISupport:                    {Default: false, PreRelease: featuregate.Alpha},
	controllerfeatures.AdditionalCertificateOutputFormats:               {Default: false, PreRelease: featuregate.Alpha},
	controllerfeatures.ServerSideApply:                                  {Default: false, PreRelease: featuregate.Alpha},
	controllerfeatures.LiteralCertificateSubject:                        {Default: false, PreRelease: featuregate.Alpha},
	controllerfeatures.StableCertificateRequestName:                     {Default: false, PreRelease: featuregate.Alpha},
	controllerfeatures.UseCertificateRequestBasicConstraints:            {Default: false, PreRelease: featuregate.Alpha},
	controllerfeatures.SecretsFilteredCaching:                           {Default: false, PreRelease: featuregate.Alpha},
}
