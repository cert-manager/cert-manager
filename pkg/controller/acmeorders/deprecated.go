/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package acmeorders

import (
	"context"
	"fmt"

	acmecl "github.com/jetstack/cert-manager/pkg/acme/client"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func deprecatedChallengeSpecForAuthorization(ctx context.Context, cl acmecl.Interface, issuer cmapi.GenericIssuer, o *cmapi.Order, authz cmapi.ACMEAuthorization) (*cmapi.ChallengeSpec, error) {
	cfg, err := solverConfigurationForAuthorization(o.Spec.Config, &authz)
	if err != nil {
		return nil, err
	}

	acmeSpec := issuer.GetSpec().ACME
	if acmeSpec == nil {
		return nil, fmt.Errorf("issuer %q is not configured as an ACME Issuer. Cannot be used for creating ACME orders", issuer.GetObjectMeta().Name)
	}

	challenge := func() *cmapi.ACMEChallenge {
		for _, ch := range authz.Challenges {
			switch {
			case ch.Type == cmapi.ACMEChallengeTypeHTTP01 && cfg.HTTP01 != nil && acmeSpec.HTTP01 != nil:
				return &ch
			case ch.Type == cmapi.ACMEChallengeTypeDNS01 && cfg.DNS01 != nil && acmeSpec.DNS01 != nil:
				return &ch
			}
		}
		return nil
	}()

	domain := authz.Identifier
	if challenge == nil {
		return nil, fmt.Errorf("ACME server does not allow selected challenge type or no provider is configured for domain %q", domain)
	}

	key, err := keyForChallenge(cl, challenge)
	if err != nil {
		return nil, err
	}

	return &cmapi.ChallengeSpec{
		AuthzURL:  authz.URL,
		Type:      challenge.Type,
		URL:       challenge.URL,
		DNSName:   domain,
		Token:     challenge.Token,
		Key:       key,
		Config:    cfg,
		Wildcard:  authz.Wildcard,
		IssuerRef: o.Spec.IssuerRef,
	}, nil
}
