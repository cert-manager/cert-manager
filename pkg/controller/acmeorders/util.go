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
	"encoding/json"
	"fmt"
	"github.com/jetstack/cert-manager/pkg/acme"
	"hash/fnv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	acmecl "github.com/jetstack/cert-manager/pkg/acme/client"
	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1alpha2"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	"github.com/jetstack/cert-manager/pkg/controller/acmeorders/selectors"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

var (
	orderGvk = cmapi.SchemeGroupVersion.WithKind("Order")
)

func buildRequiredChallenges(ctx context.Context, cl acmecl.Interface, issuer cmapi.GenericIssuer, o *cmacme.Order) ([]cmacme.Challenge, error) {
	chs := make([]cmacme.Challenge, len(o.Status.Authorizations))
	for i, a := range o.Status.Authorizations {
		ch, err := buildChallenge(ctx, cl, issuer, o, a)
		if err != nil {
			return nil, err
		}
		chs[i] = *ch
	}
	return chs, nil
}

func buildChallenge(ctx context.Context, cl acmecl.Interface, issuer cmapi.GenericIssuer, o *cmacme.Order, authz cmacme.ACMEAuthorization) (*cmacme.Challenge, error) {
	chSpec, err := challengeSpecForAuthorization(ctx, cl, issuer, o, authz)
	if err != nil {
		// TODO: in this case, we should probably not return the error as it's
		//  unlikely we can make it succeed by retrying.
		return nil, err
	}

	chName, err := buildChallengeName(o.Name, *chSpec)
	if err != nil {
		return nil, err
	}

	return &cmacme.Challenge{
		ObjectMeta: metav1.ObjectMeta{
			Name:            chName,
			Namespace:       o.Namespace,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(o, orderGvk)},
			Finalizers:      []string{cmacme.ACMEFinalizer},
		},
		Spec: *chSpec,
	}, nil
}

func buildChallengeName(orderName string, chSpec cmacme.ChallengeSpec) (string, error) {
	hash, err := hashChallenge(chSpec)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s-%d", orderName, hash), nil
}

func hashChallenge(spec cmacme.ChallengeSpec) (uint32, error) {
	specBytes, err := json.Marshal(spec)
	if err != nil {
		return 0, err
	}

	hashF := fnv.New32()
	_, err = hashF.Write(specBytes)
	if err != nil {
		return 0, err
	}

	return hashF.Sum32(), nil
}

func challengeSpecForAuthorization(ctx context.Context, cl acmecl.Interface, issuer cmapi.GenericIssuer, o *cmacme.Order, authz cmacme.ACMEAuthorization) (*cmacme.ChallengeSpec, error) {
	log := logf.FromContext(ctx, "challengeSpecForAuthorization")
	dbg := log.V(logf.DebugLevel)

	// 1. fetch solvers from issuer
	solvers := issuer.GetSpec().ACME.Solvers

	domainToFind := authz.Identifier
	if authz.Wildcard {
		domainToFind = "*." + domainToFind
	}

	var selectedSolver *cmacme.ACMEChallengeSolver
	var selectedChallenge *cmacme.ACMEChallenge
	selectedNumLabelsMatch := 0
	selectedNumDNSNamesMatch := 0
	selectedNumDNSZonesMatch := 0

	challengeForSolver := func(solver *cmacme.ACMEChallengeSolver) *cmacme.ACMEChallenge {
		for _, ch := range authz.Challenges {
			switch {
			case ch.Type == "http-01" && solver.HTTP01 != nil:
				return &ch
			case ch.Type == "dns-01" && solver.DNS01 != nil:
				return &ch
			}
		}
		return nil
	}

	// 2. filter solvers to only those that matchLabels
	for _, cfg := range solvers {
		acmech := challengeForSolver(&cfg)
		if acmech == nil {
			dbg.Info("cannot use solver as the ACME authorization does not allow solvers of this type")
			continue
		}

		if cfg.Selector == nil {
			if selectedSolver != nil {
				dbg.Info("not selecting solver as previously selected solver has a just as or more specific selector")
				continue
			}
			dbg.Info("selecting solver due to match all selector and no previously selected solver")
			selectedSolver = cfg.DeepCopy()
			selectedChallenge = acmech
			continue
		}

		labelsMatch, numLabelsMatch := selectors.Labels(*cfg.Selector).Matches(o.ObjectMeta, domainToFind)
		dnsNamesMatch, numDNSNamesMatch := selectors.DNSNames(*cfg.Selector).Matches(o.ObjectMeta, domainToFind)
		dnsZonesMatch, numDNSZonesMatch := selectors.DNSZones(*cfg.Selector).Matches(o.ObjectMeta, domainToFind)

		if !labelsMatch || !dnsNamesMatch || !dnsZonesMatch {
			dbg.Info("not selecting solver", "labels_match", labelsMatch, "dnsnames_match", dnsNamesMatch, "dnszones_match", dnsZonesMatch)
			continue
		}

		dbg.Info("selector matches")

		selectSolver := func() {
			selectedSolver = cfg.DeepCopy()
			selectedChallenge = acmech
			selectedNumLabelsMatch = numLabelsMatch
			selectedNumDNSNamesMatch = numDNSNamesMatch
			selectedNumDNSZonesMatch = numDNSZonesMatch
		}

		if selectedSolver == nil {
			dbg.Info("selecting solver as there is no previously selected solver")
			selectSolver()
			continue
		}

		dbg.Info("determining whether this match is more significant than last")

		// because we don't count multiple dnsName matches as extra 'weight'
		// in the selection process, we normalise the numDNSNamesMatch vars
		// to be either 1 or 0 (i.e. true or false)
		selectedHasMatchingDNSNames := selectedNumDNSNamesMatch > 0
		hasMatchingDNSNames := numDNSNamesMatch > 0

		// dnsName selectors have the highest precedence, so check them first
		switch {
		case !selectedHasMatchingDNSNames && hasMatchingDNSNames:
			dbg.Info("selecting solver as this solver has matching DNS names and the previous one does not")
			selectSolver()
			continue
		case selectedHasMatchingDNSNames && !hasMatchingDNSNames:
			dbg.Info("not selecting solver as the previous one has matching DNS names and this one does not")
			continue
		case !selectedHasMatchingDNSNames && !hasMatchingDNSNames:
			dbg.Info("solver does not have any matching DNS names, checking dnsZones")
			// check zones
		case selectedHasMatchingDNSNames && hasMatchingDNSNames:
			dbg.Info("both this solver and the previously selected one matches dnsNames, comparing zones")
			if numDNSZonesMatch > selectedNumDNSZonesMatch {
				dbg.Info("selecting solver as this one has a more specific dnsZone match than the previously selected one")
				selectSolver()
				continue
			}
			if selectedNumDNSZonesMatch > numDNSZonesMatch {
				dbg.Info("not selecting this solver as the previously selected one has a more specific dnsZone match")
				continue
			}
			dbg.Info("both this solver and the previously selected one match dnsZones, comparing labels")
			// choose the one with the most labels
			if numLabelsMatch > selectedNumLabelsMatch {
				dbg.Info("selecting solver as this one has more labels than the previously selected one")
				selectSolver()
				continue
			}
			dbg.Info("not selecting this solver as previous one has either the same number of or more labels")
			continue
		}

		selectedHasMatchingDNSZones := selectedNumDNSZonesMatch > 0
		hasMatchingDNSZones := numDNSZonesMatch > 0

		switch {
		case !selectedHasMatchingDNSZones && hasMatchingDNSZones:
			dbg.Info("selecting solver as this solver has matching DNS zones and the previous one does not")
			selectSolver()
			continue
		case selectedHasMatchingDNSZones && !hasMatchingDNSZones:
			dbg.Info("not selecting solver as the previous one has matching DNS zones and this one does not")
			continue
		case !selectedHasMatchingDNSZones && !hasMatchingDNSZones:
			dbg.Info("solver does not have any matching DNS zones, checking labels")
			// check labels
		case selectedHasMatchingDNSZones && hasMatchingDNSZones:
			dbg.Info("both this solver and the previously selected one matches dnsZones")
			dbg.Info("comparing number of matching domain segments")
			// choose the one with the most matching DNS zone segments
			if numDNSZonesMatch > selectedNumDNSZonesMatch {
				dbg.Info("selecting solver because this one has more matching DNS zone segments")
				selectSolver()
				continue
			}
			if selectedNumDNSZonesMatch > numDNSZonesMatch {
				dbg.Info("not selecting solver because previous one has more matching DNS zone segments")
				continue
			}
			// choose the one with the most labels
			if numLabelsMatch > selectedNumLabelsMatch {
				dbg.Info("selecting solver because this one has more labels than the previous one")
				selectSolver()
				continue
			}
			dbg.Info("not selecting solver as this one's number of matching labels is equal to or less than the last one")
			continue
		}

		if numLabelsMatch > selectedNumLabelsMatch {
			dbg.Info("selecting solver as this one has more labels than the last one")
			selectSolver()
			continue
		}

		dbg.Info("not selecting solver as this one's number of matching labels is equal to or less than the last one (reached end of loop)")
		// if we get here, the number of matches is less than or equal so we
		// fallback to choosing the first in the list
	}

	if selectedSolver == nil || selectedChallenge == nil {
		return nil, fmt.Errorf("no configured challenge solvers can be used for this challenge")
	}

	key, err := keyForChallenge(cl, selectedChallenge)
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
		AuthzURL:  authz.URL,
		Type:      selectedChallenge.Type,
		URL:       selectedChallenge.URL,
		DNSName:   authz.Identifier,
		Token:     selectedChallenge.Token,
		Key:       key,
		Solver:    selectedSolver,
		Wildcard:  authz.Wildcard,
		IssuerRef: o.Spec.IssuerRef,
	}, nil
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

func keyForChallenge(cl acmecl.Interface, challenge *cmacme.ACMEChallenge) (string, error) {
	var err error
	switch challenge.Type {
	case cmacme.ACMEChallengeTypeHTTP01:
		return cl.HTTP01ChallengeResponse(challenge.Token)
	case cmacme.ACMEChallengeTypeDNS01:
		return cl.DNS01ChallengeRecord(challenge.Token)
	default:
		err = fmt.Errorf("unsupported challenge type %s", challenge.Type)
	}
	return "", err
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
