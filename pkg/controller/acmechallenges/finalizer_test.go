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

package acmechallenges

import (
	"testing"

	"github.com/stretchr/testify/assert"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func Test_finalizerRequired(t *testing.T) {
	tests := []struct {
		name       string
		finalizers []string
		want       bool
	}{
		{
			name:       "no-finalizers",
			finalizers: nil,
			want:       true,
		},
		{
			name:       "only-native-legacy-finalizer",
			finalizers: []string{cmacme.ACMELegacyFinalizer},
			want:       false,
		},
		{
			name:       "only-native-domain-qualified-finalizer",
			finalizers: []string{cmacme.ACMEDomainQualifiedFinalizer},
			want:       false,
		},
		{
			name:       "both-native-finalizers",
			finalizers: []string{cmacme.ACMELegacyFinalizer, cmacme.ACMEDomainQualifiedFinalizer},
			want:       false,
		},
		{
			name:       "some-foreign-and-legacy-finalizer",
			finalizers: []string{"f1", "f2", cmacme.ACMELegacyFinalizer, "f3"},
			want:       false,
		},
		{
			name:       "some-foreign-and-domain-qualified-finalizer",
			finalizers: []string{"f1", "f2", cmacme.ACMEDomainQualifiedFinalizer, "f3"},
			want:       false,
		},
		{
			name:       "some-foreign-and-legacy-finalizer-and-domain-qualified-finalizer",
			finalizers: []string{"f1", "f2", cmacme.ACMELegacyFinalizer, cmacme.ACMEDomainQualifiedFinalizer, "f3"},
			want:       false,
		},
		{
			name:       "only-foreign-finalizers",
			finalizers: []string{"f1", "f2", "f3"},
			want:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(
				t,
				tt.want,
				finalizerRequired(
					gen.Challenge("example", gen.SetChallengeFinalizers(tt.finalizers)),
				),
			)
		})
	}
}
