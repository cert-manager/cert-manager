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

package solverpicker

import (
	"context"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	"github.com/cert-manager/cert-manager/pkg/controller/acmeorders/selectors"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// Pick will select a solver based on the type of challenge, labels, dns names and dns zones
func Pick(ctx context.Context, domainToFind string, challenges []cmacme.ACMEChallenge, solvers []cmacme.ACMEChallengeSolver, o *cmacme.Order) (*cmacme.ACMEChallengeSolver, *cmacme.ACMEChallenge) {
	log := logf.FromContext(ctx, "selectSolver")
	dbg := log.V(logf.DebugLevel)

	var selectedSolver *cmacme.ACMEChallengeSolver
	var selectedChallenge *cmacme.ACMEChallenge
	selectedNumLabelsMatch := 0
	selectedNumDNSNamesMatch := 0
	selectedNumDNSZonesMatch := 0

	challengeForSolver := func(solver *cmacme.ACMEChallengeSolver) *cmacme.ACMEChallenge {
		for _, ch := range challenges {
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
		acmech := challengeForSolver(&cfg) // #nosec G601 -- False positive. See https://github.com/golang/go/discussions/56010
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
		// in the selection process, we normalize the numDNSNamesMatch vars
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

	return selectedSolver, selectedChallenge
}
