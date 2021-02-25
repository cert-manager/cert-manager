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

package scheduler

import (
	"context"
	"sort"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/cert-manager/cert-manager/pkg/acme"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmacmelisters "github.com/cert-manager/cert-manager/pkg/client/listers/acme/v1"
	"github.com/cert-manager/cert-manager/pkg/logs"
)

// Scheduler implements an ACME challenge scheduler that applies heuristics
// to challenge resources in order to determine which challenges should be
// processing at a given time.
type Scheduler struct {
	log                     logr.Logger
	challengeLister         cmacmelisters.ChallengeLister
	maxConcurrentChallenges int
}

// New will construct a new instance of a scheduler
func New(ctx context.Context, l cmacmelisters.ChallengeLister, maxConcurrentChallenges int) *Scheduler {
	log := logs.FromContext(ctx, "challenge-scheduler")
	return &Scheduler{log: log, challengeLister: l, maxConcurrentChallenges: maxConcurrentChallenges}
}

// ScheduleN will return a maximum of N challenge resources that should be
// scheduled for processing.
// It may return an empty list if there are no challenges that can/should be
// scheduled.
func (s *Scheduler) ScheduleN(n int) ([]*cmacme.Challenge, error) {
	// Get a list of all challenges from the cache
	allChallenges, err := s.challengeLister.List(labels.Everything())
	if err != nil {
		return nil, err
	}

	return s.scheduleN(n, allChallenges)
}

func (s *Scheduler) scheduleN(n int, allChallenges []*cmacme.Challenge) ([]*cmacme.Challenge, error) {
	// Determine the list of challenges that could feasibly be scheduled on
	// this pass of the scheduler.
	// This function returns a list of candidates sorted by creation timestamp.
	candidates, inProgressChallengeCount, err := s.determineChallengeCandidates(allChallenges)
	if err != nil {
		return nil, err
	}

	numberToSelect := n
	remainingNumberAllowedChallenges := s.maxConcurrentChallenges - inProgressChallengeCount
	if remainingNumberAllowedChallenges < 0 {
		remainingNumberAllowedChallenges = 0
	}
	if numberToSelect > remainingNumberAllowedChallenges {
		numberToSelect = remainingNumberAllowedChallenges
	}

	candidates, err = s.selectChallengesToSchedule(candidates, numberToSelect)
	if err != nil {
		return nil, err
	}

	return candidates, nil
}

// selectChallengesToSchedule will apply some sorting heuristic to the allowed
// challenge candidates and return a maximum of N challenges that should be
// scheduled for processing.
func (s *Scheduler) selectChallengesToSchedule(candidates []*cmacme.Challenge, n int) ([]*cmacme.Challenge, error) {
	// Trim the candidates returned to 'n'
	if len(candidates) > n {
		candidates = candidates[:n]
	}
	return candidates, nil
}

// determineChallengeCandidates will determine which, if any, challenges can
// be scheduled given the current state of items to be scheduled and currently
// processing.
// The returned challenges will be sorted in ascending order based on timestamp
// (i.e. the oldest challenge will be element zero).
func (s *Scheduler) determineChallengeCandidates(allChallenges []*cmacme.Challenge) ([]*cmacme.Challenge, int, error) {
	// consider the entire set of challenges for 'in progress', in case a challenge
	// has processing=true whilst still being in a 'final' state
	inProgress := processingChallenges(allChallenges)
	inProgressChallengeCount := len(inProgress)

	// Ensure we only run a max of MaxConcurrentChallenges at a time
	// We perform this check here to avoid extra processing if we've already
	// hit the maximum number of challenges.
	if inProgressChallengeCount >= s.maxConcurrentChallenges {
		s.log.V(logs.DebugLevel).Info("hit maximum concurrent challenge limit. refusing to schedule more challenges.", "in_progress", len(inProgress), "max_concurrent", s.maxConcurrentChallenges)
		return []*cmacme.Challenge{}, inProgressChallengeCount, nil
	}

	// Calculate incomplete challenges
	incomplete := incompleteChallenges(allChallenges)
	// This is the list that we will be filtering/scheduling from
	unfilteredCandidates := notProcessingChallenges(incomplete)

	// Never process multiple challenges for the same domain and solver type
	// at any one time
	// In-place deduplication: https://github.com/golang/go/wiki/SliceTricks
	dedupedCandidates := dedupeChallenges(unfilteredCandidates)

	// If there are any already in-progress challenges for a domain and type,
	// filter them out.
	candidates := filterChallenges(dedupedCandidates, func(ch *cmacme.Challenge) bool {
		for _, inPCh := range inProgress {
			if compareChallenges(ch, inPCh) == 0 {
				s.log.V(logs.DebugLevel).Info("there is already a challenge processing with this domain", "domain", ch.Spec.DNSName, "type", ch.Spec.Type)
				return false
			}
		}
		return true
	})

	// Finally, sorted the challenges by timestamp to ensure a stable output
	sortChallengesByTimestamp(candidates)

	return candidates, inProgressChallengeCount, nil
}

func sortChallengesByTimestamp(chs []*cmacme.Challenge) {
	sort.Slice(chs, func(i, j int) bool {
		return chs[i].CreationTimestamp.Before(&chs[j].CreationTimestamp)
	})
}

// notProcessingChallenges will filter out challenges from the given slice
// that have status.processing set to true.
func notProcessingChallenges(chs []*cmacme.Challenge) []*cmacme.Challenge {
	return filterChallenges(chs, func(ch *cmacme.Challenge) bool {
		return !ch.Status.Processing
	})
}

// processingChallenges will filter out challenges from the given slice
// that have status.processing set to false.
func processingChallenges(chs []*cmacme.Challenge) []*cmacme.Challenge {
	return filterChallenges(chs, func(ch *cmacme.Challenge) bool {
		return ch.Status.Processing
	})
}

// incompleteChallenges will filter out challenges from the given slice
// that are in a 'final' state
func incompleteChallenges(chs []*cmacme.Challenge) []*cmacme.Challenge {
	return filterChallenges(chs, func(ch *cmacme.Challenge) bool {
		return !acme.IsFinalState(ch.Status.State)
	})
}

func filterChallenges(chs []*cmacme.Challenge, fn func(ch *cmacme.Challenge) bool) []*cmacme.Challenge {
	ret := []*cmacme.Challenge{}
	for _, ch := range chs {
		if fn(ch) {
			ret = append(ret, ch)
		}
	}
	return ret
}

// compareChallenges is used to compare two challenge resources.
// If two resources are 'equal', they will not be scheduled at the same time
// as they could cause a conflict.
func compareChallenges(l, r *cmacme.Challenge) int {
	if l.Spec.DNSName < r.Spec.DNSName {
		return -1
	}
	if l.Spec.DNSName > r.Spec.DNSName {
		return 1
	}

	if l.Spec.Type < r.Spec.Type {
		return -1
	}
	if l.Spec.Type > r.Spec.Type {
		return 1
	}

	// TODO: check the http01.ingressClass attribute and allow two challenges
	// with different ingress classes specified to be scheduled at once

	// TODO: check the dns01.provider attribute and allow two challenges with
	// different providers to be scheduled at once

	return 0
}

// sortChallenges will sort the provided list of challenges according to the
// schedulers sorting heuristics.
// This is used to make deduplication of list items efficient (see dedupeChallenges)
func sortChallenges(chs []*cmacme.Challenge) {
	sort.Slice(chs, func(i, j int) bool {
		cmp := compareChallenges(chs[i], chs[j])
		if cmp != 0 {
			return cmp == -1
		}

		// we have to take the creation timestamp into account when sorting if
		// the other fields already match
		if chs[i].CreationTimestamp.Time.UnixNano() < chs[j].CreationTimestamp.Time.UnixNano() {
			return true
		}
		if chs[i].CreationTimestamp.Time.UnixNano() > chs[j].CreationTimestamp.Time.UnixNano() {
			return false
		}

		return false
	})
}

// https://github.com/golang/go/wiki/SliceTricks#In-place-deduplicate-comparable
func dedupeChallenges(in []*cmacme.Challenge) []*cmacme.Challenge {
	sortChallenges(in)
	j := 0
	for i := 1; i < len(in); i++ {
		if compareChallenges(in[j], in[i]) == 0 {
			continue
		}
		j++
		in[i], in[j] = in[j], in[i]
	}
	if len(in) == 0 {
		return in
	}
	return in[:j+1]
}
