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

package scheduler

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/diff"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/client/clientset/versioned/fake"
	cminformers "github.com/jetstack/cert-manager/pkg/client/informers/externalversions"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

const maxConcurrentChallenges = 60

func randomChallenge(rand int) *cmapi.Challenge {
	if rand == 0 {
		rand = 10
	}
	return gen.Challenge("test-"+util.RandStringRunes(10),
		gen.SetChallengeDNSName(util.RandStringRunes(rand)),
		gen.SetChallengeType("http-01"))
}

func randomChallengeN(n int, rand int) []*cmapi.Challenge {
	chs := make([]*cmapi.Challenge, n)
	for i := range chs {
		chs[i] = randomChallenge(rand)
	}
	return chs
}

func ascendingChallengeN(n int, mods ...gen.ChallengeModifier) []*cmapi.Challenge {
	chs := make([]*cmapi.Challenge, n)
	for i := range chs {
		name := fmt.Sprintf("test-%d", i)
		chs[i] = gen.Challenge(name,
			gen.SetChallengeDNSName(name),
			gen.SetChallengeType("http-01"))
		chs[i].CreationTimestamp = metav1.NewTime(time.Unix(int64(i), 0))
		for _, m := range mods {
			m(chs[i])
		}
	}
	return chs
}

func withCreationTimestamp(i int64) func(*cmapi.Challenge) {
	return func(ch *cmapi.Challenge) {
		ch.CreationTimestamp.Time = time.Unix(i, 0)
	}
}

func BenchmarkScheduleAscending(b *testing.B) {
	counts := []int{10, 100, 1000, 10000, 100000, 1000000}
	for _, c := range counts {
		b.Run(fmt.Sprintf("With %d challenges to schedule", c), func(b *testing.B) {
			chs := ascendingChallengeN(c)
			s := &Scheduler{}
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				s.scheduleN(30, chs)
			}
		})
	}
}

func BenchmarkScheduleRandom(b *testing.B) {
	counts := []int{10, 100, 1000, 10000, 100000, 1000000}
	for _, c := range counts {
		b.Run(fmt.Sprintf("With %d random challenges to schedule", c), func(b *testing.B) {
			chs := randomChallengeN(c, 0)
			s := &Scheduler{}
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				s.scheduleN(30, chs)
			}
		})
	}
}

func BenchmarkScheduleDuplicates(b *testing.B) {
	counts := []int{10, 100, 1000, 10000, 100000, 1000000}
	for _, c := range counts {
		b.Run(fmt.Sprintf("With %d random but likely duplicate challenges to schedule", c), func(b *testing.B) {
			chs := randomChallengeN(c, 3)
			s := &Scheduler{}
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				s.scheduleN(30, chs)
			}
		})
	}
}

func TestScheduleN(t *testing.T) {
	tests := []struct {
		name       string
		n          int
		challenges []*cmapi.Challenge
		expected   []*cmapi.Challenge
		err        bool
	}{
		{
			name:       "schedule a single challenge",
			n:          5,
			challenges: ascendingChallengeN(1),
			expected:   ascendingChallengeN(1),
		},
		{
			name:       "schedule a maximum of N challenges",
			n:          5,
			challenges: ascendingChallengeN(10),
			expected:   ascendingChallengeN(5),
		},
		{
			name:       "schedule a maximum of MaxConcurrentChallenges",
			n:          maxConcurrentChallenges * 2,
			challenges: ascendingChallengeN(maxConcurrentChallenges * 2),
			expected:   ascendingChallengeN(maxConcurrentChallenges),
		},
		{
			name: "schedule duplicate challenge if second challenge is in a final state",
			n:    5,
			challenges: []*cmapi.Challenge{
				gen.Challenge("test",
					gen.SetChallengeDNSName("example.com")),
				gen.Challenge("test2",
					gen.SetChallengeDNSName("example.com"),
					gen.SetChallengeState(cmapi.Valid)),
			},
			expected: []*cmapi.Challenge{
				gen.Challenge("test",
					gen.SetChallengeDNSName("example.com")),
			},
		},
		{
			name: "schedule a single duplicate in CreationTimestamp order",
			n:    5,
			challenges: []*cmapi.Challenge{
				gen.Challenge("test",
					gen.SetChallengeDNSName("example.com"),
					withCreationTimestamp(2)),
				gen.Challenge("test2",
					gen.SetChallengeDNSName("example.com"),
					withCreationTimestamp(1)),
			},
			expected: []*cmapi.Challenge{
				gen.Challenge("test2",
					gen.SetChallengeDNSName("example.com"),
					withCreationTimestamp(1)),
			},
		},
		{
			name: "schedule duplicate in CreationTimestamp order (inverted input)",
			n:    5,
			challenges: []*cmapi.Challenge{
				gen.Challenge("test2",
					gen.SetChallengeDNSName("example.com"),
					withCreationTimestamp(1)),
				gen.Challenge("test",
					gen.SetChallengeDNSName("example.com"),
					withCreationTimestamp(2)),
			},
			expected: []*cmapi.Challenge{
				gen.Challenge("test2",
					gen.SetChallengeDNSName("example.com"),
					withCreationTimestamp(1)),
			},
		},
		{
			name: "schedule duplicate challenges for the same domain if they have a different type",
			n:    5,
			challenges: []*cmapi.Challenge{
				gen.Challenge("test1",
					gen.SetChallengeDNSName("example.com"),
					gen.SetChallengeType("dns01")),
				gen.Challenge("test2",
					gen.SetChallengeDNSName("example.com"),
					gen.SetChallengeType("http01")),
			},
			expected: []*cmapi.Challenge{
				gen.Challenge("test1",
					gen.SetChallengeDNSName("example.com"),
					gen.SetChallengeType("dns01")),
				gen.Challenge("test2",
					gen.SetChallengeDNSName("example.com"),
					gen.SetChallengeType("http01")),
			},
		},
		{
			name: "schedule duplicate challenges for the same domain if they have a different type (inverted input)",
			n:    5,
			challenges: []*cmapi.Challenge{
				gen.Challenge("test2",
					gen.SetChallengeDNSName("example.com"),
					gen.SetChallengeType("http01")),
				gen.Challenge("test1",
					gen.SetChallengeDNSName("example.com"),
					gen.SetChallengeType("dns01")),
			},
			expected: []*cmapi.Challenge{
				gen.Challenge("test1",
					gen.SetChallengeDNSName("example.com"),
					gen.SetChallengeType("dns01")),
				gen.Challenge("test2",
					gen.SetChallengeDNSName("example.com"),
					gen.SetChallengeType("http01")),
			},
		},
		// this test case replicates a failure seen in CI
		{
			name: "schedule a challenge when other challenges are already in progress",
			n:    5,
			challenges: []*cmapi.Challenge{
				gen.Challenge("test1-0",
					gen.SetChallengeDNSName("rvrko.certmanager.kubernetes.network"),
					gen.SetChallengeType("dns-01"),
					gen.SetChallengeWildcard(true)),
				gen.Challenge("test1-1",
					gen.SetChallengeDNSName("rvrko.certmanager.kubernetes.network"),
					gen.SetChallengeType("dns-01"),
					gen.SetChallengeWildcard(false),
					// the non-wildcard version *is* processing
					gen.SetChallengeProcessing(true)),
				gen.Challenge("should-schedule",
					gen.SetChallengeDNSName("aodob.certmanager.kubernetes.network"),
					gen.SetChallengeType("dns-01"),
					gen.SetChallengeWildcard(true)),
			},
			expected: []*cmapi.Challenge{
				gen.Challenge("should-schedule",
					gen.SetChallengeDNSName("aodob.certmanager.kubernetes.network"),
					gen.SetChallengeType("dns-01"),
					gen.SetChallengeWildcard(true)),
			},
		},
		{
			name: "don't schedule when total number of scheduled challenges exceeds global maximum",
			n:    5,
			challenges: append(
				ascendingChallengeN(maxConcurrentChallenges, gen.SetChallengeProcessing(true)),
				randomChallengeN(5, 0)...,
			),
		},
		{
			name: "don't schedule challenge if another one with the same dnsName exists",
			n:    5,
			challenges: []*cmapi.Challenge{
				gen.Challenge("test",
					gen.SetChallengeDNSName("example.com")),
				gen.Challenge("test2",
					gen.SetChallengeDNSName("example.com"),
					gen.SetChallengeProcessing(true)),
			},
		},
		{
			name: "don't schedule anything if all challenges are processing",
			n:    5,
			challenges: []*cmapi.Challenge{
				gen.Challenge("test",
					gen.SetChallengeDNSName("example.com"),
					gen.SetChallengeProcessing(true)),
				gen.Challenge("test2",
					gen.SetChallengeDNSName("example.com"),
					gen.SetChallengeProcessing(true)),
			},
		},
		{
			name: "don't schedule anything if all challenges are in a final state",
			n:    5,
			challenges: []*cmapi.Challenge{
				gen.Challenge("test2",
					gen.SetChallengeDNSName("example.com"),
					gen.SetChallengeState(cmapi.Valid)),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cl := fake.NewSimpleClientset()
			factory := cminformers.NewSharedInformerFactory(cl, 0)
			challengesInformer := factory.Certmanager().V1alpha1().Challenges()
			for _, ch := range test.challenges {
				challengesInformer.Informer().GetIndexer().Add(ch)
			}

			s := New(context.Background(), challengesInformer.Lister(), maxConcurrentChallenges)

			if test.expected == nil {
				test.expected = []*cmapi.Challenge{}
			}
			chs, err := s.ScheduleN(test.n)
			if err != nil && !test.err {
				t.Errorf("expected no error, but got: %v", err)
			}
			if err == nil && test.err {
				t.Errorf("expected to get an error, but got none")
			}
			if !reflect.DeepEqual(chs, test.expected) {
				t.Errorf("expected did not match actual: %v", diff.ObjectDiff(test.expected, chs))
			}
		})
	}
}
