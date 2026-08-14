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

package solverpicker

import (
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	"github.com/cert-manager/cert-manager/pkg/controller/acmeorders/selectors"

	"hegel.dev/go/hegel"
)

// score is the specificity of an eligible solver for a given order and
// domain, ordered lexicographically: solvers with matching dnsNames beat
// solvers with matching dnsZones, which beat label-only matches; within a
// tier more matching zone segments win, then more matching labels. Ties go
// to the earlier solver in the list. This ordering is nowhere written down
// except in Pick's branch structure; these properties pin it.
type score struct {
	tier   int // 2: dnsNames match, 1: dnsZones match, 0: labels only
	zones  int
	labels int
}

func (a score) beats(b score) bool {
	if a.tier != b.tier {
		return a.tier > b.tier
	}
	if a.zones != b.zones {
		return a.zones > b.zones
	}
	return a.labels > b.labels
}

// TestPickProperties generates orders, challenges and solver lists and
// checks Pick against a specification independent of its loop structure:
//
//   - a solver is returned iff some solver is eligible (its challenge type
//     is offered and its selector, if any, fully matches)
//   - the returned solver is eligible, no eligible solver strictly beats
//     it, and it is the first solver with its exact score
//   - the returned challenge is the first offered challenge compatible
//     with the returned solver
func TestPickProperties(t *testing.T) {
	domains := []string{"www.example.com", "*.example.com", "www.prod.example.com", "foo.bar.example.com", "other.org", "notexample.com"}
	zonePool := []string{"example.com", "bar.example.com", "prod.example.com", "com", "org", "www.example.com"}
	labelKeys := []string{"a", "b", "x"}

	solverGen := hegel.Composite(func(tc hegel.TestCase) cmacme.ACMEChallengeSolver {
		var s cmacme.ACMEChallengeSolver
		if hegel.Draw(tc, hegel.Booleans()) {
			s.HTTP01 = &cmacme.ACMEChallengeSolverHTTP01{}
		} else {
			s.DNS01 = &cmacme.ACMEChallengeSolverDNS01{}
		}
		if hegel.Draw(tc, hegel.Booleans()) {
			s.Selector = &cmacme.CertificateDNSNameSelector{
				MatchLabels: hegel.Draw(tc, hegel.Maps(hegel.SampledFrom(labelKeys), hegel.SampledFrom([]string{"1", "2"})).MaxSize(2)),
				DNSNames:    hegel.Draw(tc, hegel.Lists(hegel.SampledFrom(domains)).MaxSize(2)),
				DNSZones:    hegel.Draw(tc, hegel.Lists(hegel.SampledFrom(zonePool)).MaxSize(2)),
			}
		}
		return s
	})

	hegel.Test(t, func(ht *hegel.T) {
		domain := hegel.Draw(ht, hegel.SampledFrom(domains))
		order := &cmacme.Order{ObjectMeta: metav1.ObjectMeta{
			Labels: hegel.Draw(ht, hegel.Maps(hegel.SampledFrom(labelKeys), hegel.SampledFrom([]string{"1", "2"})).MaxSize(3)),
		}}
		var challenges []cmacme.ACMEChallenge
		for _, typ := range drawShuffle(ht, []string{"http-01", "dns-01"}) {
			if hegel.Draw(ht, hegel.Booleans()) {
				challenges = append(challenges, cmacme.ACMEChallenge{Type: typ, Token: typ + "-token"})
			}
		}
		solvers := hegel.Draw(ht, hegel.Lists(solverGen).MaxSize(5))

		challengeFor := func(s *cmacme.ACMEChallengeSolver) *cmacme.ACMEChallenge {
			for _, ch := range challenges {
				if (ch.Type == "http-01" && s.HTTP01 != nil) || (ch.Type == "dns-01" && s.DNS01 != nil) {
					return &ch
				}
			}
			return nil
		}
		// eligibility and score, using the selectors package as the scoring
		// oracle; nil selectors are eligible with the lowest score.
		eligible := func(s *cmacme.ACMEChallengeSolver) (score, bool) {
			if challengeFor(s) == nil {
				return score{}, false
			}
			if s.Selector == nil {
				return score{}, true
			}
			labelsMatch, numLabels := selectors.Labels(*s.Selector).Matches(order.ObjectMeta, domain)
			namesMatch, numNames := selectors.DNSNames(*s.Selector).Matches(order.ObjectMeta, domain)
			zonesMatch, numZones := selectors.DNSZones(*s.Selector).Matches(order.ObjectMeta, domain)
			if !labelsMatch || !namesMatch || !zonesMatch {
				return score{}, false
			}
			tier := 0
			if numZones > 0 {
				tier = 1
			}
			if numNames > 0 {
				tier = 2
			}
			return score{tier: tier, zones: numZones, labels: numLabels}, true
		}

		gotSolver, gotChallenge := Pick(t.Context(), domain, challenges, solvers, order)

		anyEligible := false
		for i := range solvers {
			if _, ok := eligible(&solvers[i]); ok {
				anyEligible = true
			}
		}
		if gotSolver == nil {
			if anyEligible {
				ht.Fatalf("Pick returned nil but an eligible solver exists (domain=%s, challenges=%v, solvers=%+v)", domain, challenges, solvers)
			}
			return
		}
		if !anyEligible {
			ht.Fatalf("Pick returned %+v but no solver is eligible", gotSolver)
		}

		winnerIdx := -1
		for i := range solvers {
			if reflect.DeepEqual(&solvers[i], gotSolver) {
				winnerIdx = i
				break
			}
		}
		if winnerIdx == -1 {
			ht.Fatalf("Pick returned a solver not in the input list: %+v", gotSolver)
		}
		winnerScore, ok := eligible(gotSolver)
		if !ok {
			ht.Fatalf("Pick returned ineligible solver %+v (domain=%s, challenges=%v)", gotSolver, domain, challenges)
		}
		for i := range solvers {
			sc, ok := eligible(&solvers[i])
			if !ok {
				continue
			}
			if sc.beats(winnerScore) {
				ht.Fatalf("solver %d %+v (score %+v) beats returned solver %d (score %+v)", i, solvers[i], sc, winnerIdx, winnerScore)
			}
			if i < winnerIdx && sc == winnerScore {
				ht.Fatalf("solver %d has the same score %+v as returned solver %d; the first should win", i, winnerScore, winnerIdx)
			}
		}

		wantChallenge := challengeFor(gotSolver)
		if gotChallenge == nil || wantChallenge == nil || gotChallenge.Type != wantChallenge.Type {
			ht.Fatalf("returned challenge %+v, want %+v", gotChallenge, wantChallenge)
		}
	}, hegel.WithTestCases(2000))
}

func drawShuffle[T any](ht *hegel.T, xs []T) []T {
	out := append([]T(nil), xs...)
	for i := len(out) - 1; i > 0; i-- {
		j := hegel.Draw(ht, hegel.Integers(0, i))
		out[i], out[j] = out[j], out[i]
	}
	return out
}
