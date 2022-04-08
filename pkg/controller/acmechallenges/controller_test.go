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
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/fake"
	cminformers "github.com/cert-manager/cert-manager/pkg/client/informers/externalversions"
	"github.com/cert-manager/cert-manager/pkg/controller/acmechallenges/scheduler"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

const (
	randomFinalizer         = "random.acme.cert-manager.io"
	maxConcurrentChallenges = 60
)

func TestRunScheduler(t *testing.T) {
	baseChallenge := gen.Challenge("testchal",
		gen.SetChallengeIssuer(cmmeta.ObjectReference{
			Name: "testissuer",
		}),
	)

	tests := map[string]struct {
		challenge *cmacme.Challenge
		builder   *testpkg.Builder
	}{
		"A finalizer gets added and status gets set to processing in for a challenge that doesn't have any finalizers yet, an event gets throw": {
			challenge: gen.ChallengeFrom(baseChallenge,
				gen.SetChallengeProcessing(false),
				gen.SetChallengeURL("testurl"),
			),

			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.ChallengeFrom(baseChallenge,
					gen.SetChallengeProcessing(false),
					gen.SetChallengeURL("testurl"),
				)},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(
						coretesting.NewUpdateAction(cmacme.SchemeGroupVersion.WithResource("challenges"),
							gen.DefaultTestNamespace,
							gen.ChallengeFrom(baseChallenge,
								gen.SetChallengeProcessing(false),
								gen.SetChallengeURL("testurl"),
								gen.SetChallengeFinalizers([]string{cmacme.ACMEFinalizer}),
							))),
					testpkg.NewAction(
						coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("challenges"),
							"status",
							gen.DefaultTestNamespace,
							gen.ChallengeFrom(baseChallenge,
								gen.SetChallengeProcessing(true),
								gen.SetChallengeURL("testurl"),
								gen.SetChallengeFinalizers([]string{cmacme.ACMEFinalizer}),
							))),
				},
				ExpectedEvents: []string{"Normal Started Challenge scheduled for processing"},
			},
		},
		"A finalizer gets added and status gets set to processing in for a challenge that has a random finalizer, an event gets throw": {
			challenge: gen.ChallengeFrom(baseChallenge,
				gen.SetChallengeProcessing(false),
				gen.SetChallengeURL("testurl"),
				gen.SetChallengeFinalizers([]string{randomFinalizer}),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.ChallengeFrom(baseChallenge,
					gen.SetChallengeProcessing(false),
					gen.SetChallengeURL("testurl"),
					gen.SetChallengeFinalizers([]string{randomFinalizer}),
				)},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(
						coretesting.NewUpdateAction(cmacme.SchemeGroupVersion.WithResource("challenges"),
							gen.DefaultTestNamespace,
							gen.ChallengeFrom(baseChallenge,
								gen.SetChallengeProcessing(false),
								gen.SetChallengeURL("testurl"),
								gen.SetChallengeFinalizers([]string{randomFinalizer, cmacme.ACMEFinalizer}),
							))),
					testpkg.NewAction(
						coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("challenges"),
							"status",
							gen.DefaultTestNamespace,
							gen.ChallengeFrom(baseChallenge,
								gen.SetChallengeProcessing(true),
								gen.SetChallengeURL("testurl"),
								gen.SetChallengeFinalizers([]string{randomFinalizer, cmacme.ACMEFinalizer}),
							))),
				},
				ExpectedEvents: []string{"Normal Started Challenge scheduled for processing"},
			},
		},
		"Status gets set to processing, but no finalizer if there already is the ACME finalizer, an event gets thrown": {
			challenge: gen.ChallengeFrom(baseChallenge,
				gen.SetChallengeProcessing(false),
				gen.SetChallengeURL("testurl"),
				gen.SetChallengeFinalizers([]string{cmacme.ACMEFinalizer}),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.ChallengeFrom(baseChallenge,
					gen.SetChallengeProcessing(false),
					gen.SetChallengeURL("testurl"),
					gen.SetChallengeFinalizers([]string{cmacme.ACMEFinalizer}),
				)},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(
						coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("challenges"),
							"status",
							gen.DefaultTestNamespace,
							gen.ChallengeFrom(baseChallenge,
								gen.SetChallengeProcessing(true),
								gen.SetChallengeURL("testurl"),
								gen.SetChallengeFinalizers([]string{cmacme.ACMEFinalizer}),
							))),
				},
				ExpectedEvents: []string{"Normal Started Challenge scheduled for processing"},
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.builder.T = t
			test.builder.Init()
			defer test.builder.Stop()

			cl := fake.NewSimpleClientset()
			factory := cminformers.NewSharedInformerFactory(cl, 0)
			challengesInformer := factory.Acme().V1().Challenges()

			err := challengesInformer.Informer().GetIndexer().Add(test.challenge)
			require.NoError(t, err)

			controller := &controller{}
			_, _, err = controller.Register(test.builder.Context)
			if err != nil {
				t.Fatal(err)
			}
			controller.scheduler = scheduler.New(context.Background(), challengesInformer.Lister(), maxConcurrentChallenges)
			controller.challengeLister = challengesInformer.Lister()

			test.builder.Start()

			controller.runScheduler(context.Background())

			test.builder.CheckAndFinish()
		})
	}
}
