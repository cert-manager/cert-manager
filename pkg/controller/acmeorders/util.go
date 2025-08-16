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

package acmeorders

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/pkg/acme"
	acmecl "github.com/cert-manager/cert-manager/pkg/acme/client"
	"github.com/cert-manager/cert-manager/pkg/api/util"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util/solverpicker"
)

var (
	orderGvk = cmacme.SchemeGroupVersion.WithKind("Order")
)

// buildPartialRequiredChallenges builds partial required ACME challenges by
// looking at authorization on order spec and related issuer. It does not call
// ACME. ensureKeysForChallenge must be called before creating the Challenge.
func buildPartialRequiredChallenges(ctx context.Context, issuer cmapi.GenericIssuer, o *cmacme.Order) ([]*cmacme.Challenge, error) {
	chs := make([]*cmacme.Challenge, 0)
	for _, a := range o.Status.Authorizations {
		if a.InitialState == cmacme.Valid {
			wc := false
			if a.Wildcard != nil {
				wc = *a.Wildcard
			}
			logf.FromContext(ctx).V(logf.DebugLevel).Info("Authorization already valid, not creating Challenge resource", "identifier", a.Identifier, "is_wildcard", wc)
			continue
		}
		ch, err := buildPartialChallenge(ctx, issuer, o, a)
		if err != nil {
			return nil, err
		}
		chs = append(chs, ch)
	}
	return chs, nil
}

// buildPartialChallenge builds a challenge for the required ACME Authorization.
// The spec will be populated with fields that can be determined by looking at
// the ACME Authorization object returned in Order.
func buildPartialChallenge(ctx context.Context, issuer cmapi.GenericIssuer, o *cmacme.Order, authz cmacme.ACMEAuthorization) (*cmacme.Challenge, error) {
	chSpec, err := partialChallengeSpecForAuthorization(ctx, issuer, o, authz)
	if err != nil {
		// TODO: in this case, we should probably not return the error as it's
		//  unlikely we can make it succeed by retrying.
		return nil, err
	}

	chName, err := util.ComputeName(o.Name, chSpec)
	if err != nil {
		return nil, err
	}

	return &cmacme.Challenge{
		ObjectMeta: metav1.ObjectMeta{
			Name:            chName,
			Namespace:       o.Namespace,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(o, orderGvk)},
		},
		Spec: *chSpec,
	}, nil
}

// partialChallengeSpecForAuthorization builds a partial challenge spec by
// looking at the ACME authorization object and issuer. It does not make any
// ACME calls.
func partialChallengeSpecForAuthorization(ctx context.Context, issuer cmapi.GenericIssuer, o *cmacme.Order, authz cmacme.ACMEAuthorization) (*cmacme.ChallengeSpec, error) {
	// 1. fetch solvers from issuer
	solvers := issuer.GetSpec().ACME.Solvers

	wc := false
	if authz.Wildcard != nil {
		wc = *authz.Wildcard
	}
	domainToFind := authz.Identifier
	if wc {
		domainToFind = "*." + domainToFind
	}

	selectedSolver, selectedChallenge := solverpicker.Pick(ctx, domainToFind, authz.Challenges, solvers, o)
	if selectedSolver == nil || selectedChallenge == nil {
		return nil, fmt.Errorf("no configured challenge solvers can be used for this challenge")
	}

	// It should never be possible for this case to be hit as earlier in this
	// method we already assert that the challenge type is one of 'http-01'
	// or 'dns-01'.
	chType, err := challengeType(selectedChallenge.Type)
	if err != nil {
		return nil, err
	}

	// 4. handle overriding the HTTP01 ingress class and name fields using the
	//    ACMECertificateHTTP01IngressNameOverride & Class annotations
	if err := applyIngressParameterAnnotationOverrides(o, selectedSolver); err != nil {
		return nil, err
	}

	// 5. construct Challenge resource with spec.solver field set
	return &cmacme.ChallengeSpec{
		AuthorizationURL: authz.URL,
		Type:             chType,
		URL:              selectedChallenge.URL,
		DNSName:          authz.Identifier,
		Token:            selectedChallenge.Token,
		// selectedSolver cannot be nil due to the check above.
		Solver:    *selectedSolver,
		Wildcard:  wc,
		IssuerRef: o.Spec.IssuerRef,
	}, nil
}

func challengeType(t string) (cmacme.ACMEChallengeType, error) {
	switch t {
	case "http-01":
		return cmacme.ACMEChallengeTypeHTTP01, nil
	case "dns-01":
		return cmacme.ACMEChallengeTypeDNS01, nil
	default:
		return "", fmt.Errorf("unsupported challenge type: %v", t)
	}
}

func applyIngressParameterAnnotationOverrides(o *cmacme.Order, s *cmacme.ACMEChallengeSolver) error {
	if s.HTTP01 == nil || s.HTTP01.Ingress == nil || o.Annotations == nil {
		return nil
	}

	manualIngressName, hasManualIngressName := o.Annotations[cmacme.ACMECertificateHTTP01IngressNameOverride]
	manualIngressClass, hasManualIngressClass := o.Annotations[cmacme.ACMECertificateHTTP01IngressClassOverride]
	// don't allow both override annotations to be specified at once
	if hasManualIngressName && hasManualIngressClass {
		return fmt.Errorf("both ingress name and ingress class overrides specified - only one may be specified at a time")
	}
	// if an override annotation is specified, clear out the existing solver
	// config
	if hasManualIngressClass || hasManualIngressName {
		s.HTTP01.Ingress.Class = nil
		s.HTTP01.Ingress.Name = ""
	}
	if hasManualIngressName {
		s.HTTP01.Ingress.Name = manualIngressName
	}
	if hasManualIngressClass {
		s.HTTP01.Ingress.Class = &manualIngressClass
	}
	return nil
}

func ensureKeysForChallenges(cl acmecl.Interface, challenges []*cmacme.Challenge) ([]*cmacme.Challenge, error) {
	for _, ch := range challenges {
		var (
			key string
			err error
		)
		switch ch.Spec.Type {
		case cmacme.ACMEChallengeTypeHTTP01:
			key, err = cl.HTTP01ChallengeResponse(ch.Spec.Token)
		case cmacme.ACMEChallengeTypeDNS01:
			key, err = cl.DNS01ChallengeRecord(ch.Spec.Token)
		default:
			return nil, fmt.Errorf("challenge %s has unsupported challenge type: %s", ch.Name, ch.Spec.Type)
		}
		if err != nil {
			return nil, err
		}
		ch.Spec.Key = key
	}
	return challenges, nil
}

func anyChallengesFailed(chs []*cmacme.Challenge) bool {
	for _, ch := range chs {
		if acme.IsFailureState(ch.Status.State) {
			return true
		}
	}
	return false
}

func allChallengesFinal(chs []*cmacme.Challenge) bool {
	for _, ch := range chs {
		if !acme.IsFinalState(ch.Status.State) {
			return false
		}
	}
	return true
}
