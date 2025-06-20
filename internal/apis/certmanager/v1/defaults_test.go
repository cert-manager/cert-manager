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
	"testing"

	"github.com/stretchr/testify/assert"
	featuregatetesting "k8s.io/component-base/featuregate/testing"

	"github.com/cert-manager/cert-manager/internal/controller/feature"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
)

// Test_SetRuntimeDefaults_Certificate_PrivateKey_RotationPolicy demonstrates that
// the default rotation policy is set by the defaulting function and that the
// old default (`Never`) can be re-instated by disabling the
// DefaultPrivateKeyRotationPolicyAlways feature gate.
func Test_SetRuntimeDefaults_Certificate_PrivateKey_RotationPolicy(t *testing.T) {
	t.Run("feature-enabled", func(t *testing.T) {
		featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, feature.DefaultPrivateKeyRotationPolicyAlways, true)
		in := &cmapi.Certificate{}
		SetRuntimeDefaults_Certificate(in)
		assert.Equal(t, cmapi.RotationPolicyAlways, in.Spec.PrivateKey.RotationPolicy)
	})
	t.Run("feature-disabled", func(t *testing.T) {
		featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, feature.DefaultPrivateKeyRotationPolicyAlways, false)
		in := &cmapi.Certificate{}
		SetRuntimeDefaults_Certificate(in)
		assert.Equal(t, cmapi.RotationPolicyNever, in.Spec.PrivateKey.RotationPolicy)
	})
	t.Run("explicit-rotation-policy", func(t *testing.T) {
		const expectedRotationPolicy = cmapi.PrivateKeyRotationPolicy("neither-always-nor-never")
		featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, feature.DefaultPrivateKeyRotationPolicyAlways, false)
		in := &cmapi.Certificate{
			Spec: cmapi.CertificateSpec{
				PrivateKey: &cmapi.CertificatePrivateKey{
					RotationPolicy: expectedRotationPolicy,
				},
			},
		}
		SetRuntimeDefaults_Certificate(in)
		assert.Equal(t, expectedRotationPolicy, in.Spec.PrivateKey.RotationPolicy)
	})
}
