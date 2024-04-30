/*
Copyright 2022 The cert-manager Authors.

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

package acmechallenges

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func TestRunScheduler(t *testing.T) {
	tests := map[string]struct {
		maxConcurrentChallenges int
		builder                 *testpkg.Builder
	}{
		"unscheduled challenges are scheduled": {
			maxConcurrentChallenges: 2,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.Challenge("ch1",
						gen.SetChallengeDNSName("host1.example.com"),
						gen.SetChallengeProcessing(false),
					),
					gen.Challenge("ch2",
						gen.SetChallengeDNSName("host2.example.com"),
						gen.SetChallengeProcessing(false),
					),
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(
						coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("challenges"),
							"status",
							gen.DefaultTestNamespace,
							gen.Challenge("ch1",
								gen.SetChallengeDNSName("host1.example.com"),
								gen.SetChallengeProcessing(true),
							))),
					testpkg.NewAction(
						coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("challenges"),
							"status",
							gen.DefaultTestNamespace,
							gen.Challenge("ch2",
								gen.SetChallengeDNSName("host2.example.com"),
								gen.SetChallengeProcessing(true),
							))),
				},
				ExpectedEvents: []string{
					"Normal Started Challenge scheduled for processing",
					"Normal Started Challenge scheduled for processing",
				},
			},
		},
		"maxConcurrentChallenges limits the number of challenges that are scheduled": {
			maxConcurrentChallenges: 1,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.Challenge("ch1",
						gen.SetChallengeDNSName("host1.example.com"),
						gen.SetChallengeProcessing(true),
					),
					gen.Challenge("ch2",
						gen.SetChallengeDNSName("host2.example.com"),
						gen.SetChallengeProcessing(false),
					),
				},
				ExpectedActions: nil,
				ExpectedEvents:  nil,
			},
		},
		"challenges with the same domain are never scheduled together": {
			maxConcurrentChallenges: 2,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.Challenge("ch1",
						gen.SetChallengeDNSName("host1.example.com"),
						gen.SetChallengeProcessing(true),
					),
					gen.Challenge("ch2",
						gen.SetChallengeDNSName("host1.example.com"),
						gen.SetChallengeProcessing(false),
					),
				},
				ExpectedActions: nil,
				ExpectedEvents:  nil,
			},
		},
		"scheduled challenges are ignored": {
			maxConcurrentChallenges: 2,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.Challenge("ch1",
						gen.SetChallengeProcessing(true),
					),
					gen.Challenge("ch2",
						gen.SetChallengeProcessing(true),
					),
				},
				ExpectedActions: nil,
				ExpectedEvents:  nil,
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.builder.T = t
			test.builder.Init()
			test.builder.Context.SchedulerOptions.MaxConcurrentChallenges = test.maxConcurrentChallenges

			defer test.builder.Stop()
			c := &controller{}
			_, _, err := c.Register(test.builder.Context)
			require.NoError(t, err)
			test.builder.Start()
			c.runScheduler(context.Background())
			test.builder.CheckAndFinish()
		})
	}
}
