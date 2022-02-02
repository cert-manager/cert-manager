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

package v1alpha2

import (
	"k8s.io/apimachinery/pkg/conversion"

	"github.com/cert-manager/cert-manager/internal/apis/acme"
)

func Convert_v1alpha2_ChallengeSpec_To_acme_ChallengeSpec(in *ChallengeSpec, out *acme.ChallengeSpec, s conversion.Scope) error {
	if err := autoConvert_v1alpha2_ChallengeSpec_To_acme_ChallengeSpec(in, out, s); err != nil {
		return err
	}

	out.AuthorizationURL = in.AuthzURL

	switch in.Type {
	case ACMEChallengeTypeHTTP01:
		out.Type = acme.ACMEChallengeTypeHTTP01
	case ACMEChallengeTypeDNS01:
		out.Type = acme.ACMEChallengeTypeDNS01
	default:
		// this case should never be hit due to validation
		out.Type = acme.ACMEChallengeType(in.Type)
	}

	return nil
}

func Convert_acme_ChallengeSpec_To_v1alpha2_ChallengeSpec(in *acme.ChallengeSpec, out *ChallengeSpec, s conversion.Scope) error {
	if err := autoConvert_acme_ChallengeSpec_To_v1alpha2_ChallengeSpec(in, out, s); err != nil {
		return err
	}

	out.AuthzURL = in.AuthorizationURL

	switch in.Type {
	case acme.ACMEChallengeTypeHTTP01:
		out.Type = ACMEChallengeTypeHTTP01
	case acme.ACMEChallengeTypeDNS01:
		out.Type = ACMEChallengeTypeDNS01
	default:
		// this case should never be hit due to validation
		out.Type = ACMEChallengeType(in.Type)
	}

	return nil
}

func Convert_v1alpha2_OrderSpec_To_acme_OrderSpec(in *OrderSpec, out *acme.OrderSpec, s conversion.Scope) error {
	if err := autoConvert_v1alpha2_OrderSpec_To_acme_OrderSpec(in, out, s); err != nil {
		return err
	}

	out.Request = in.CSR

	return nil
}

func Convert_acme_OrderSpec_To_v1alpha2_OrderSpec(in *acme.OrderSpec, out *OrderSpec, s conversion.Scope) error {
	if err := autoConvert_acme_OrderSpec_To_v1alpha2_OrderSpec(in, out, s); err != nil {
		return err
	}

	out.CSR = in.Request

	return nil
}

// Convert_acme_ACMEIssuer_To_v1alpha2_ACMEIssuer is explicitly defined to avoid issues in conversion-gen
// when referencing types in other API groups.
func Convert_acme_ACMEIssuer_To_v1alpha2_ACMEIssuer(in *acme.ACMEIssuer, out *ACMEIssuer, s conversion.Scope) error {
	return autoConvert_acme_ACMEIssuer_To_v1alpha2_ACMEIssuer(in, out, s)
}

// Convert_v1alpha2_ACMEIssuer_To_acme_ACMEIssuer is explicitly defined to avoid issues in conversion-gen
// when referencing types in other API groups.
func Convert_v1alpha2_ACMEIssuer_To_acme_ACMEIssuer(in *ACMEIssuer, out *acme.ACMEIssuer, s conversion.Scope) error {
	return autoConvert_v1alpha2_ACMEIssuer_To_acme_ACMEIssuer(in, out, s)
}
