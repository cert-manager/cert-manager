/*
Copyright 2021 The cert-manager Authors.

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

package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
	certificatesv1 "k8s.io/api/certificates/v1"
)

func Test_certificateSigningRequestGetCondition(t *testing.T) {
	tests := map[string]struct {
		conditions   []certificatesv1.CertificateSigningRequestCondition
		condType     certificatesv1.RequestConditionType
		expCondition *certificatesv1.CertificateSigningRequestCondition
	}{
		"if no conditions exist, return nil": {
			conditions:   []certificatesv1.CertificateSigningRequestCondition{},
			condType:     certificatesv1.RequestConditionType("a"),
			expCondition: nil,
		},
		"if conditions exist but type doesn't match, return nil": {
			conditions: []certificatesv1.CertificateSigningRequestCondition{
				{Type: certificatesv1.RequestConditionType("a")},
				{Type: certificatesv1.RequestConditionType("b")},
			},
			condType:     certificatesv1.RequestConditionType("c"),
			expCondition: nil,
		},
		"if conditions exist and type matches, return condition": {
			conditions: []certificatesv1.CertificateSigningRequestCondition{
				{Type: certificatesv1.RequestConditionType("a")},
				{Type: certificatesv1.RequestConditionType("b")},
				{Type: certificatesv1.RequestConditionType("c")},
			},
			condType:     certificatesv1.RequestConditionType("c"),
			expCondition: &certificatesv1.CertificateSigningRequestCondition{Type: certificatesv1.RequestConditionType("c")},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gotCondition := certificateSigningRequestGetCondition(&certificatesv1.CertificateSigningRequest{
				Status: certificatesv1.CertificateSigningRequestStatus{
					Conditions: test.conditions,
				},
			}, test.condType)
			assert.Equal(t, test.expCondition, gotCondition)
		})
	}
}
