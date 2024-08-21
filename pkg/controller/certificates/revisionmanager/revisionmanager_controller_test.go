/*
Copyright 2021 The cert-manager Authors.

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

package revisionmanager

import (
	"context"
	"reflect"
	"testing"

	logtesting "github.com/go-logr/logr/testing"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	coretesting "k8s.io/client-go/testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func TestProcessItem(t *testing.T) {
	baseCrt := gen.Certificate("test-cert",
		gen.SetCertificateNamespace("testns"),
		gen.SetCertificateUID("uid-1"),
	)
	baseCRNoOwner := gen.CertificateRequest("test-cr",
		gen.SetCertificateRequestNamespace("testns"),
	)
	baseCR := gen.CertificateRequestFrom(baseCRNoOwner,
		gen.AddCertificateRequestOwnerReferences(*metav1.NewControllerRef(
			baseCrt, cmapi.SchemeGroupVersion.WithKind("Certificate")),
		),
	)

	tests := map[string]struct {
		// key that should be passed to ProcessItem.
		// if not set, the 'namespace/name' of the 'Certificate' field will be used.
		// if neither is set, the key will be ""
		key types.NamespacedName

		// Certificate to be synced for the test.
		// if not set, the 'key' will be passed to ProcessItem instead.
		certificate *cmapi.Certificate

		// Request, if set, will exist in the apiserver before the test is run.
		requests []runtime.Object

		expectedActions []testpkg.Action

		// err is the expected error text returned by the controller, if any.
		err string
	}{
		"do nothing if an empty 'key' is used": {},
		"do nothing if an invalid 'key' is used": {
			key: types.NamespacedName{
				Namespace: "abc",
				Name:      "def/ghi",
			},
		},
		"do nothing if a key references a Certificate that does not exist": {
			key: types.NamespacedName{
				Namespace: "namespace",
				Name:      "name",
			},
		},
		"do nothing if Certificate is not in a Ready=True state": {
			certificate: gen.CertificateFrom(baseCrt,
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionFalse}),
				gen.SetCertificateRevisionHistoryLimit(1),
			),
			requests: []runtime.Object{
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-1"),
					gen.SetCertificateRequestRevision("1"),
				),
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("2"),
				),
			},
		},
		"do nothing if no requests exist": {
			certificate: gen.CertificateFrom(baseCrt,
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionReady, Status: cmmeta.ConditionTrue}),
				gen.SetCertificateRevisionHistoryLimit(1),
			),
		},
		"do nothing if requests don't have or bad revisions set": {
			certificate: gen.CertificateFrom(baseCrt,
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionReady, Status: cmmeta.ConditionTrue}),
				gen.SetCertificateRevisionHistoryLimit(1),
			),
			requests: []runtime.Object{
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-1"),
					gen.SetCertificateRequestRevision("abc"),
				),
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-2"),
				),
			},
		},
		"do nothing if requests aren't owned by this Certificate": {
			certificate: gen.CertificateFrom(baseCrt,
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionReady, Status: cmmeta.ConditionTrue}),
				gen.SetCertificateRevisionHistoryLimit(1),
			),
			requests: []runtime.Object{
				gen.CertificateRequestFrom(baseCRNoOwner,
					gen.SetCertificateRequestName("cr-1"),
					gen.SetCertificateRequestRevision("1"),
				),
				gen.CertificateRequestFrom(baseCRNoOwner,
					gen.SetCertificateRequestName("cr-2"),
					gen.SetCertificateRequestRevision("2"),
				),
			},
		},
		"do nothing if number of revisions matches that of the limit": {
			certificate: gen.CertificateFrom(baseCrt,
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionReady, Status: cmmeta.ConditionTrue}),
				gen.SetCertificateRevisionHistoryLimit(2),
			),
			requests: []runtime.Object{
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-1"),
					gen.SetCertificateRequestRevision("1"),
				),
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-2"),
					gen.SetCertificateRequestRevision("2"),
				),
			},
		},
		"do nothing if revision limit is not set": {
			certificate: gen.CertificateFrom(baseCrt,
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionReady, Status: cmmeta.ConditionTrue}),
			),
			requests: []runtime.Object{
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-1"),
					gen.SetCertificateRequestRevision("1"),
				),
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-2"),
					gen.SetCertificateRequestRevision("2"),
				),
			},
		},
		"delete 1 request if limit is 1 and 2 requests exist": {
			certificate: gen.CertificateFrom(baseCrt,
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionReady, Status: cmmeta.ConditionTrue}),
				gen.SetCertificateRevisionHistoryLimit(1),
			),
			requests: []runtime.Object{
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-2"),
					gen.SetCertificateRequestRevision("2"),
				),
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-1"),
					gen.SetCertificateRequestRevision("1"),
				),
			},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewDeleteAction(cmapi.SchemeGroupVersion.WithResource("certificaterequests"), "testns", "cr-1")),
			},
		},
		"delete 3 requests if limit is 3 and 6 requests exist": {
			certificate: gen.CertificateFrom(baseCrt,
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionReady, Status: cmmeta.ConditionTrue}),
				gen.SetCertificateRevisionHistoryLimit(3),
			),
			requests: []runtime.Object{
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-2"),
					gen.SetCertificateRequestRevision("2"),
				),
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-3"),
					gen.SetCertificateRequestRevision("3"),
				),
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-1"),
					gen.SetCertificateRequestRevision("1"),
				),
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-4"),
					gen.SetCertificateRequestRevision("11"),
				),
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-5"),
					gen.SetCertificateRequestRevision("11"),
				),
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-6"),
					gen.SetCertificateRequestRevision("2"),
				),
			},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewDeleteAction(cmapi.SchemeGroupVersion.WithResource("certificaterequests"), "testns", "cr-1")),
				testpkg.NewAction(coretesting.NewDeleteAction(cmapi.SchemeGroupVersion.WithResource("certificaterequests"), "testns", "cr-2")),
				testpkg.NewAction(coretesting.NewDeleteAction(cmapi.SchemeGroupVersion.WithResource("certificaterequests"), "testns", "cr-6")),
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Create and initialise a new unit test builder
			builder := &testpkg.Builder{
				T:               t,
				ExpectedEvents:  nil,
				ExpectedActions: test.expectedActions,
				StringGenerator: func(i int) string { return "notrandom" },
			}
			if test.certificate != nil {
				builder.CertManagerObjects = append(builder.CertManagerObjects, test.certificate)
			}
			builder.CertManagerObjects = append(builder.CertManagerObjects, test.requests...)
			builder.Init()

			// Register informers used by the controller using the registration wrapper
			w := &controllerWrapper{}
			_, _, err := w.Register(builder.Context)
			if err != nil {
				t.Fatal(err)
			}
			// Start the informers and begin processing updates
			builder.Start()
			defer builder.Stop()

			key := test.key
			if key == (types.NamespacedName{}) && test.certificate != nil {
				key = types.NamespacedName{
					Name:      test.certificate.Name,
					Namespace: test.certificate.Namespace,
				}
			}

			// Call ProcessItem
			err = w.controller.ProcessItem(context.Background(), key)
			switch {
			case err != nil:
				if test.err != err.Error() {
					t.Errorf("error text did not match, got=%s, exp=%s", err.Error(), test.err)
				}
			default:
				if test.err != "" {
					t.Errorf("got no error but expected: %s", test.err)
				}
			}

			if err := builder.AllEventsCalled(); err != nil {
				builder.T.Error(err)
			}
			if err := builder.AllActionsExecuted(); err != nil {
				builder.T.Error(err)
			}
		})
	}
}

func TestCertificateRequestsToDelete(t *testing.T) {
	baseCR := gen.CertificateRequest("test")

	tests := map[string]struct {
		input []*cmapi.CertificateRequest
		limit int
		exp   []revision
	}{
		"an empty list of request should return empty": {
			input: nil,
			limit: 3,
			exp:   nil,
		},
		"a single request with no revision set should return empty": {
			input: []*cmapi.CertificateRequest{
				baseCR,
			},
			limit: 3,
			exp:   nil,
		},
		"a single request with revision set but higher limit should return no requests": {
			input: []*cmapi.CertificateRequest{
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestRevision("123"),
				),
			},
			limit: 3,
			exp:   nil,
		},
		"two requests with one badly formed revision but limit set to 1 should return no requests": {
			input: []*cmapi.CertificateRequest{
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-1"),
					gen.SetCertificateRequestRevision("123"),
				),
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-2"),
					gen.SetCertificateRequestRevision("hello"),
				),
			},
			limit: 1,
			exp:   []revision{},
		},
		"multiple requests with some with good revsions should return list in order": {
			input: []*cmapi.CertificateRequest{
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-1"),
					gen.SetCertificateRequestRevision("123"),
				),
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-2"),
					gen.SetCertificateRequestRevision("hello"),
				),
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-3"),
					gen.SetCertificateRequestRevision("3"),
				),
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-4"),
					gen.SetCertificateRequestRevision("cert-manager"),
				),
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-5"),
					gen.SetCertificateRequestRevision("900"),
				),
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-6"),
					gen.SetCertificateRequestRevision("1"),
				),
			},
			limit: 1,
			exp: []revision{
				{
					1,
					types.NamespacedName{
						Namespace: gen.DefaultTestNamespace,
						Name:      "cr-6",
					},
				},
				{
					3,
					types.NamespacedName{
						Namespace: gen.DefaultTestNamespace,
						Name:      "cr-3",
					},
				},
				{
					123,
					types.NamespacedName{
						Namespace: gen.DefaultTestNamespace,
						Name:      "cr-1",
					},
				},
			},
		},
		"multiple requests with some with good revsions but less than the limit, should return list in order under limit": {
			input: []*cmapi.CertificateRequest{
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-1"),
					gen.SetCertificateRequestRevision("123"),
				),
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-2"),
					gen.SetCertificateRequestRevision("hello"),
				),
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-3"),
					gen.SetCertificateRequestRevision("3"),
				),
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-4"),
					gen.SetCertificateRequestRevision("cert-manager"),
				),
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-5"),
					gen.SetCertificateRequestRevision("900"),
				),
				gen.CertificateRequestFrom(baseCR,
					gen.SetCertificateRequestName("cr-6"),
					gen.SetCertificateRequestRevision("1"),
				),
			},
			limit: 3,
			exp: []revision{
				{
					1,
					types.NamespacedName{
						Namespace: gen.DefaultTestNamespace,
						Name:      "cr-6",
					},
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			log := logtesting.NewTestLogger(t)
			output := certificateRequestsToDelete(log, test.limit, test.input)
			if !reflect.DeepEqual(test.exp, output) {
				t.Errorf("unexpected prune sort response, exp=%v got=%v",
					test.exp, output)
			}
		})
	}
}
