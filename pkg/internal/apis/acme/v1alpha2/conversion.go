/*
Copyright 2020 The Jetstack cert-manager contributors.

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

	"github.com/jetstack/cert-manager/pkg/apis/acme/v1alpha2"
	"github.com/jetstack/cert-manager/pkg/internal/apis/acme"
)

func Convert_v1alpha2_ChallengeSpec_To_acme_ChallengeSpec(in *v1alpha2.ChallengeSpec, out *acme.ChallengeSpec, s conversion.Scope) error {
	if err := autoConvert_v1alpha2_ChallengeSpec_To_acme_ChallengeSpec(in, out, s); err != nil {
		return err
	}

	out.AuthorizationURL = in.AuthzURL

	return nil
}

func Convert_acme_ChallengeSpec_To_v1alpha2_ChallengeSpec(in *acme.ChallengeSpec, out *v1alpha2.ChallengeSpec, s conversion.Scope) error {
	if err := autoConvert_acme_ChallengeSpec_To_v1alpha2_ChallengeSpec(in, out, s); err != nil {
		return err
	}

	out.AuthzURL = in.AuthorizationURL

	return nil
}
