/*
Copyright 2026 The cert-manager Authors.

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

package acme

import (
	"fmt"

	"k8s.io/apimachinery/pkg/util/validation/field"

	cmacme "github.com/cert-manager/cert-manager/internal/apis/acme"
	"github.com/cert-manager/cert-manager/internal/apis/certmanager/validation"
	"github.com/cert-manager/cert-manager/internal/apis/meta"
	"github.com/cert-manager/cert-manager/pkg/api"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// RequiredDNS01SolverSecrets returns the Kubernetes Secret references required
// by the ACME DNS-01 solvers configured on the given issuer. It is the single
// source of truth for which Secrets an ACME issuer's DNS-01 solvers depend on,
// shared by the code that validates those Secrets exist (pkg/issuer/acme) and
// the code that decides whether a Secret event is relevant to a given
// Issuer/ClusterIssuer (pkg/controller/issuers, pkg/controller/clusterissuers).
func RequiredDNS01SolverSecrets(issuer v1.GenericIssuer) ([]*meta.SecretKeySelector, error) {
	var secrets []*meta.SecretKeySelector
	spec := issuer.GetSpec()
	if spec.ACME == nil {
		return secrets, nil
	}

	solvers := spec.ACME.Solvers
	for i := range solvers {
		sol := solvers[i]
		if sol.DNS01 == nil {
			continue
		}

		var out cmacme.ACMEChallengeSolver
		if err := api.Scheme.Convert(&sol, &out, nil); err != nil {
			return nil, fmt.Errorf("unable to convert ACME challenge solver to internal challenge type: %w", err)
		}

		_, requiredSecrets := validation.ValidateACMEChallengeSolverDNS01(out.DNS01, field.NewPath("spec"))
		if len(requiredSecrets) == 0 {
			continue
		}
		secrets = append(secrets, requiredSecrets...)
	}

	return secrets, nil
}
