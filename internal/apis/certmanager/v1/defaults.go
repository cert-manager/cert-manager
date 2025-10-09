/*
Copyright 2020 The cert-manager Authors.

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

package v1

import (
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/cert-manager/cert-manager/internal/controller/feature"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
)

func addDefaultingFuncs(scheme *runtime.Scheme) error {
	return RegisterDefaults(scheme)
}

// SetObjectDefaults_CertificateSpec mutates the supplied Certificate object,
// setting defaults for certain missing fields:
// - Sets the default  private key rotation policy to:
//   - Always, if the DefaultPrivateKeyRotationPolicyAlways feature is enabled
//   - Never, if the DefaultPrivateKeyRotationPolicyAlways feature is disabled.
//
// TODO(wallrj): When DefaultPrivateKeyRotationPolicyAlways is GA, the default
// value can probably be added as an API default by adding:
//
//	`// +default="Always"`
//
// ... to the API struct.
func SetObjectDefaults_CertificateSpec(in *cmapi.CertificateSpec) {
	if in.PrivateKey == nil {
		in.PrivateKey = &cmapi.CertificatePrivateKey{}
	}

	if in.PrivateKey.RotationPolicy == "" {
		defaultRotationPolicy := cmapi.RotationPolicyNever
		if utilfeature.DefaultFeatureGate.Enabled(feature.DefaultPrivateKeyRotationPolicyAlways) {
			defaultRotationPolicy = cmapi.RotationPolicyAlways
		}
		in.PrivateKey.RotationPolicy = defaultRotationPolicy
	}
}
