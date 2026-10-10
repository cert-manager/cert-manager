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

package validation

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	cmacme "github.com/cert-manager/cert-manager/internal/apis/acme"
)

func TestValidateChallengeUpdate(t *testing.T) {
	someAdmissionRequest := &admissionv1.AdmissionRequest{
		RequestKind: &metav1.GroupVersionKind{
			Group:   "test",
			Kind:    "test",
			Version: "test",
		},
	}

	scenarios := map[string]struct {
		old, new *cmacme.Challenge
		a        *admissionv1.AdmissionRequest
		errs     []*field.Error
		warnings []string
	}{
		"allows setting challenge spec for the first time": {
			new: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					URL: "testurl",
				},
			},
			a: someAdmissionRequest,
		},
		"disallow updating challenge spec": {
			old: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					URL: "testurl",
				},
			},
			new: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					URL: "newtesturl",
				},
			},
			a: someAdmissionRequest,
			errs: []*field.Error{
				field.Forbidden(field.NewPath("spec"), "challenge spec is immutable after creation"),
			},
		},
		"allow updating challenge spec if no changes are made": {
			old: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					URL: "testurl",
				},
			},
			new: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					URL: "testurl",
				},
			},
			a: someAdmissionRequest,
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs, warnings := ValidateChallengeUpdate(s.a, s.old, s.new)
			field.ErrorMatcher{}.ByType().ByField().ByDetailExact().Test(t, s.errs, errs)
			assert.Equal(t, s.warnings, warnings)
		})
	}
}

func TestValidateChallenge(t *testing.T) {
	scenarios := map[string]struct {
		chal     *cmacme.Challenge
		a        *admissionv1.AdmissionRequest
		errs     []*field.Error
		warnings []string
	}{
		"allows challenge without delay options": {
			chal: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					URL: "testurl",
				},
			},
		},
		"allows challenge with a valid delayBeforeAccept": {
			chal: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					URL: "testurl",
					Solver: cmacme.ACMEChallengeSolver{
						DelayBeforeAccept: &metav1.Duration{Duration: 30 * time.Second},
					},
				},
			},
		},
		"rejects challenge with a negative delayBeforeAccept": {
			chal: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					URL: "testurl",
					Solver: cmacme.ACMEChallengeSolver{
						DelayBeforeAccept: &metav1.Duration{Duration: -5 * time.Second},
					},
				},
			},
			errs: []*field.Error{
				field.Invalid(field.NewPath("spec", "solver").Child("delayBeforeAccept"), -5*time.Second, "delayBeforeAccept must not be negative"),
			},
		},
		"rejects challenge with a negative waitInsteadOfSelfCheck": {
			chal: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					URL: "testurl",
					Solver: cmacme.ACMEChallengeSolver{
						WaitInsteadOfSelfCheck: &metav1.Duration{Duration: -5 * time.Second},
					},
				},
			},
			errs: []*field.Error{
				field.Invalid(field.NewPath("spec", "solver").Child("waitInsteadOfSelfCheck"), -5*time.Second, "waitInsteadOfSelfCheck must not be negative"),
			},
		},
		"rejects challenge with both waitInsteadOfSelfCheck and delayBeforeAccept": {
			chal: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					URL: "testurl",
					Solver: cmacme.ACMEChallengeSolver{
						WaitInsteadOfSelfCheck: &metav1.Duration{Duration: 30 * time.Second},
						DelayBeforeAccept:      &metav1.Duration{Duration: 30 * time.Second},
					},
				},
			},
			errs: []*field.Error{
				field.Forbidden(field.NewPath("spec", "solver"), "may not specify both waitInsteadOfSelfCheck and delayBeforeAccept"),
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs, warnings := ValidateChallenge(s.a, s.chal)
			field.ErrorMatcher{}.ByType().ByField().ByDetailExact().Test(t, s.errs, errs)
			assert.Equal(t, s.warnings, warnings)
		})
	}
}
