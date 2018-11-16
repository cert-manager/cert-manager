/*
Copyright 2018 The Jetstack cert-manager contributors.

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
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller/test"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

type fixture struct {
	Controller *Controller
	*test.Builder

	Challenge *v1alpha1.Challenge

	PreFn   func(*testing.T, *fixture)
	CheckFn func(*testing.T, *fixture, ...interface{})
	Err     bool

	Ctx context.Context
}

func TestSync(t *testing.T) {
	tests := map[string]fixture{
		"with one challenge in api, mark processing=true": {
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.Challenge("test",
						gen.SetChallengeDNSName("example.com"))},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(v1alpha1.SchemeGroupVersion.WithResource("challenges"), gen.DefaultTestNamespace,
						gen.Challenge("test",
							gen.SetChallengeDNSName("example.com"),
							gen.SetChallengeProcessing(true)))),
				},
			},
			Challenge: gen.Challenge("test", gen.SetChallengeDNSName("example.com")),
		},
		"when a duplicate challenge exists in the API, and is processing, don't mark next one as processing": {
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.Challenge("test",
						gen.SetChallengeDNSName("example.com")),
					gen.Challenge("test2",
						gen.SetChallengeDNSName("example.com"),
						gen.SetChallengeProcessing(true)),
				},
			},
			Challenge: gen.Challenge("test", gen.SetChallengeDNSName("example.com")),
			Err:       true,
		},
		"skip elements that are already marked as processing=true": {
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.Challenge("test",
						gen.SetChallengeDNSName("example.com"),
						gen.SetChallengeProcessing(true)),
				},
			},
			Challenge: gen.Challenge("test",
				gen.SetChallengeDNSName("example.com"),
				gen.SetChallengeProcessing(true)),
		},
		"skip elements that are already in a final state": {
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.Challenge("test",
						gen.SetChallengeDNSName("example.com"),
						gen.SetChallengeState(v1alpha1.Invalid)),
					gen.Challenge("test2",
						gen.SetChallengeDNSName("example.com"),
						gen.SetChallengeProcessing(true)),
				},
			},
			Challenge: gen.Challenge("test",
				gen.SetChallengeDNSName("example.com"),
				gen.SetChallengeState(v1alpha1.Invalid)),
		},
	}

	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			if test.Builder == nil {
				test.Builder = &testpkg.Builder{}
			}
			test.Setup(t)
			chalCopy := test.Challenge.DeepCopy()
			err := test.Controller.Sync(test.Ctx, chalCopy)
			if err != nil && !test.Err {
				t.Errorf("Expected function to not error, but got: %v", err)
			}
			if err == nil && test.Err {
				t.Errorf("Expected function to get an error, but got: %v", err)
			}
			test.Finish(t, chalCopy, err)
		})
	}
}
