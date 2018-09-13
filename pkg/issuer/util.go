/*
Copyright 2018 The Jetstack cert-manager contributors.

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

package issuer

import (
	"fmt"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func ValidateDuration(issuer v1alpha1.GenericIssuer) error {
	duration := issuer.GetSpec().Duration.Duration
	if duration == 0 {
		duration = v1alpha1.DefaultCertificateDuration
	}
	renewBefore := issuer.GetSpec().RenewBefore.Duration
	if renewBefore == 0 {
		renewBefore = v1alpha1.DefaultRenewBefore
	}
	if duration <= v1alpha1.MinimumCertificateDuration {
		return fmt.Errorf("certificate duration must be greater than %s", v1alpha1.MinimumCertificateDuration)
	}
	if renewBefore < v1alpha1.MinimumRenewBefore {
		return fmt.Errorf("certificate renewBefore %s value must be greater than %s", renewBefore, v1alpha1.MinimumRenewBefore)
	}
	if duration <= renewBefore {
		return fmt.Errorf("certificate duration %s must be greater than renewBefore %s ", duration, renewBefore)
	}
	return nil
}
