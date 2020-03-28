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

package v1beta1

import (
	"k8s.io/apimachinery/pkg/conversion"

	"github.com/cert-manager/cert-manager/internal/apis/acme"
)

// Convert_acme_ACMEIssuer_To_v1beta1_ACMEIssuer is explicitly defined to avoid issues in conversion-gen
// when referencing types in other API groups.
func Convert_acme_ACMEIssuer_To_v1beta1_ACMEIssuer(in *acme.ACMEIssuer, out *ACMEIssuer, s conversion.Scope) error {
	return autoConvert_acme_ACMEIssuer_To_v1beta1_ACMEIssuer(in, out, s)
}

// Convert_v1beta1_ACMEIssuer_To_acme_ACMEIssuer is explicitly defined to avoid issues in conversion-gen
// when referencing types in other API groups.
func Convert_v1beta1_ACMEIssuer_To_acme_ACMEIssuer(in *ACMEIssuer, out *acme.ACMEIssuer, s conversion.Scope) error {
	return autoConvert_v1beta1_ACMEIssuer_To_acme_ACMEIssuer(in, out, s)
}

// Drop fields which have only been added to v1 since we stopped serving this
// deprecated API
func Convert_acme_ACMEChallengeSolver_To_v1beta1_ACMEChallengeSolver(in *acme.ACMEChallengeSolver, out *ACMEChallengeSolver, s conversion.Scope) error {
	return autoConvert_acme_ACMEChallengeSolver_To_v1beta1_ACMEChallengeSolver(in, out, s)
}

func Convert_acme_ChallengeStatus_To_v1beta1_ChallengeStatus(in *acme.ChallengeStatus, out *ChallengeStatus, s conversion.Scope) error {
	return autoConvert_acme_ChallengeStatus_To_v1beta1_ChallengeStatus(in, out, s)
}
