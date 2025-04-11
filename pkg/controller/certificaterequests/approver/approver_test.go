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

package approver

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
)

func TestProcessItem(t *testing.T) {
	// now time is the current time at the start of the test (the clock is fixed)
	now := time.Now()
	metaNow := metav1.NewTime(now)
	tests := map[string]struct {
		// key that should be passed to ProcessItem.
		// if not set, the 'namespace/name' of the 'CertificateRequest' field will be used.
		// if neither is set, the key will be ""
		key types.NamespacedName

		// CertificateRequest to be synced for the test.
		// if not set, the 'key' will be passed to ProcessItem instead.
		request *cmapi.CertificateRequest

		// expectedEvent, if set, is an 'event string' that is expected to be fired.
		expectedEvent string

		// expectedConditions is the expected set of conditions on the
		// CertificateRequest resource if an Update is made.
		// If nil, no update is expected.
		// If empty, an update to the empty set/nil is expected.
		expectedConditions []cmapi.CertificateRequestCondition

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
		"do nothing if CertificateRequest already has 'Approved' True condition": {
			request: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"},
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{
							Type:   cmapi.CertificateRequestConditionApproved,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
		},
		"do nothing if CertificateRequest already has 'Denied' True condition": {
			request: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"},
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{
							Type:   cmapi.CertificateRequestConditionDenied,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
		},
		"do nothing if CertificateRequest already has 'Ready' Failed condition": {
			request: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"},
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{
							Type:   cmapi.CertificateRequestConditionReady,
							Status: cmmeta.ConditionFalse,
							Reason: cmapi.CertificateRequestReasonFailed,
						},
					},
				},
			},
		},
		"do nothing if CertificateRequest already has 'Ready' Issued condition": {
			request: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"},
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{
							Type:   cmapi.CertificateRequestConditionReady,
							Status: cmmeta.ConditionTrue,
							Reason: cmapi.CertificateRequestReasonIssued,
						},
					},
				},
			},
		},
		"approve CertificateRequest if no condition": {
			request: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"},
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{},
				},
			},
			expectedConditions: []cmapi.CertificateRequestCondition{
				{
					Type:               cmapi.CertificateRequestConditionApproved,
					Status:             cmmeta.ConditionTrue,
					Reason:             "cert-manager.io",
					Message:            ApprovedMessage,
					LastTransitionTime: &metaNow,
				},
			},
			expectedEvent: "Normal cert-manager.io Certificate request has been approved by cert-manager.io",
		},
		"approve CertificateRequest has 'Ready' Pending condition": {
			request: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"},
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{
							Type:   cmapi.CertificateRequestConditionReady,
							Status: cmmeta.ConditionFalse,
							Reason: cmapi.CertificateRequestReasonPending,
						},
					},
				},
			},
			expectedConditions: []cmapi.CertificateRequestCondition{
				{
					Type:   cmapi.CertificateRequestConditionReady,
					Status: cmmeta.ConditionFalse,
					Reason: cmapi.CertificateRequestReasonPending,
				},
				{
					Type:               cmapi.CertificateRequestConditionApproved,
					Status:             cmmeta.ConditionTrue,
					Reason:             "cert-manager.io",
					Message:            ApprovedMessage,
					LastTransitionTime: &metaNow,
				},
			},
			expectedEvent: "Normal cert-manager.io Certificate request has been approved by cert-manager.io",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Create and initialise a new unit test builder
			builder := &testpkg.Builder{
				T:     t,
				Clock: fakeclock.NewFakeClock(now),
			}
			if test.request != nil {
				builder.CertManagerObjects = append(builder.CertManagerObjects, test.request)
			}
			builder.Init()

			c := new(Controller)
			_, _, err := c.Register(builder.Context)
			if err != nil {
				t.Fatal(err)
			}
			if test.expectedConditions != nil {
				if test.request == nil {
					t.Fatal("cannot expect an Update operation if test.request is nil")
				}
				expectedRequest := test.request.DeepCopy()
				expectedRequest.Status.Conditions = test.expectedConditions
				builder.ExpectedActions = append(builder.ExpectedActions,
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						test.request.Namespace,
						expectedRequest,
					)),
				)
			}
			if test.expectedEvent != "" {
				builder.ExpectedEvents = []string{test.expectedEvent}
			}
			// Start the informers and begin processing updates
			builder.Start()
			defer builder.Stop()

			key := test.key
			if key == (types.NamespacedName{}) && test.request != nil {
				key = types.NamespacedName{
					Name:      test.request.Name,
					Namespace: test.request.Namespace,
				}
			}

			// Call ProcessItem
			err = c.ProcessItem(context.Background(), key)
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
