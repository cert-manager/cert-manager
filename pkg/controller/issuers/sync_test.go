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

package issuers

import (
	"context"
	"errors"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/issuers/fake"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

var (
	fixedClockStart = time.Now()
	fixedClock      = fakeclock.NewFakeClock(fixedClockStart)
)

func TestProcessItem(t *testing.T) {
	metaFixedClockStart := metav1.NewTime(fixedClockStart)

	tests := map[string]struct {
		// key that should be passed to ProcessItem.
		// if not set, the 'namespace/name' of the '[Cluster]Issuer' field will be
		// used.  if neither is set, the key will be ""
		key string

		// The issuer kind (Issuer or ClusterIssuer) this controller is configured
		// for.
		issuerKind string

		// Issuer implementation
		issuerBackend Issuer

		// [Cluster]Issuer to be synced for the test.
		// if not set, the 'key' will be passed to ProcessItem instead.
		issuer cmapi.GenericIssuer

		expectedActions []testpkg.Action

		// err is the expected error text returned by the controller, if any.
		err string
	}{
		// Issuer Kind controller
		"issuer: do nothing if an empty 'key' is used": {
			issuerKind: cmapi.IssuerKind,
		},
		"issuer: do nothing if an invalid 'key' is used": {
			issuerKind: cmapi.IssuerKind,
			key:        "abc/def/ghi",
		},
		"issuer: do nothing if a key references a Issuer that does not exist": {
			issuerKind: cmapi.IssuerKind,
			key:        "namespace/name",
		},
		"issuer: do nothing if a key references a ClusterIssuer": {
			issuerKind: cmapi.IssuerKind,
			key:        "test",
			issuer:     gen.ClusterIssuer("test"),
			issuerBackend: fake.New().WithImplements(func(cmapi.GenericIssuer) bool {
				t.Fatal("unexpected implements call")
				return false
			}),
		},
		"issuer: do nothing if controller doesn't implement issuer type": {
			issuerKind: cmapi.IssuerKind,
			issuer:     gen.Issuer("test"),
			issuerBackend: fake.New().WithImplements(func(cmapi.GenericIssuer) bool {
				return false
			}),
		},
		"issuer: if setup fails, should update issuer with Failed condition and return error": {
			issuerKind: cmapi.IssuerKind,
			issuer:     gen.Issuer("test"),
			issuerBackend: fake.New().WithImplements(func(cmapi.GenericIssuer) bool {
				return true
			}).WithSetup(func(ctx context.Context, iss cmapi.GenericIssuer) error {
				apiutil.SetIssuerCondition(iss, cmapi.IssuerConditionReady, cmmeta.ConditionFalse, "SetupFailed", "Failed to setup")
				return errors.New("setup error")
			}),
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
					cmapi.SchemeGroupVersion.WithResource("issuers"),
					"status",
					gen.DefaultTestNamespace,
					gen.Issuer("test",
						gen.AddIssuerCondition(cmapi.IssuerCondition{
							Type:               cmapi.IssuerConditionReady,
							Status:             cmmeta.ConditionFalse,
							Reason:             "SetupFailed",
							Message:            "Failed to setup",
							LastTransitionTime: &metaFixedClockStart,
						}),
					),
				)),
			},
			err: "setup error",
		},
		"issuer: if setup succeeds, should update issuer with Ready condition and return nil": {
			issuerKind: cmapi.IssuerKind,
			issuer:     gen.Issuer("test"),
			issuerBackend: fake.New().WithImplements(func(cmapi.GenericIssuer) bool {
				return true
			}).WithSetup(func(ctx context.Context, iss cmapi.GenericIssuer) error {
				apiutil.SetIssuerCondition(iss, cmapi.IssuerConditionReady, cmmeta.ConditionTrue, "Ready", "Issuer ready")
				return nil
			}),
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
					cmapi.SchemeGroupVersion.WithResource("issuers"),
					"status",
					gen.DefaultTestNamespace,
					gen.Issuer("test",
						gen.AddIssuerCondition(cmapi.IssuerCondition{
							Type:               cmapi.IssuerConditionReady,
							Status:             cmmeta.ConditionTrue,
							Reason:             "Ready",
							Message:            "Issuer ready",
							LastTransitionTime: &metaFixedClockStart,
						}),
					),
				)),
			},
			err: "",
		},
		"issuer: if setup succeeds, should remove old failed condition and return nil": {
			issuerKind: cmapi.IssuerKind,
			issuer: gen.Issuer("test",
				gen.AddIssuerCondition(cmapi.IssuerCondition{
					Type:               "RandomType",
					Status:             cmmeta.ConditionTrue,
					Reason:             "Random",
					Message:            "random condition",
					LastTransitionTime: &metaFixedClockStart,
				}),
				gen.AddIssuerCondition(cmapi.IssuerCondition{
					Type:               cmapi.IssuerConditionReady,
					Status:             cmmeta.ConditionFalse,
					Reason:             "SetupFailed",
					Message:            "Setup failed",
					LastTransitionTime: &metaFixedClockStart,
				}),
			),
			issuerBackend: fake.New().WithImplements(func(cmapi.GenericIssuer) bool {
				return true
			}).WithSetup(func(ctx context.Context, iss cmapi.GenericIssuer) error {
				apiutil.SetIssuerCondition(iss, cmapi.IssuerConditionReady, cmmeta.ConditionTrue, "Ready", "Issuer ready")
				return nil
			}),
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
					cmapi.SchemeGroupVersion.WithResource("issuers"),
					"status",
					gen.DefaultTestNamespace,
					gen.Issuer("test",
						gen.AddIssuerCondition(cmapi.IssuerCondition{
							Type:               "RandomType",
							Status:             cmmeta.ConditionTrue,
							Reason:             "Random",
							Message:            "random condition",
							LastTransitionTime: &metaFixedClockStart,
						}),
						gen.AddIssuerCondition(cmapi.IssuerCondition{
							Type:               cmapi.IssuerConditionReady,
							Status:             cmmeta.ConditionTrue,
							Reason:             "Ready",
							Message:            "Issuer ready",
							LastTransitionTime: &metaFixedClockStart,
						}),
					),
				)),
			},
			err: "",
		},
		"issuer: if setup fails, should remove old ready condition and return error": {
			issuerKind: cmapi.IssuerKind,
			issuer: gen.Issuer("test",
				gen.AddIssuerCondition(cmapi.IssuerCondition{
					Type:               "RandomType",
					Status:             cmmeta.ConditionTrue,
					Reason:             "Random",
					Message:            "random condition",
					LastTransitionTime: &metaFixedClockStart,
				}),
				gen.AddIssuerCondition(cmapi.IssuerCondition{
					Type:               cmapi.IssuerConditionReady,
					Status:             cmmeta.ConditionTrue,
					Reason:             "Ready",
					Message:            "Issuer ready",
					LastTransitionTime: &metaFixedClockStart,
				}),
			),
			issuerBackend: fake.New().WithImplements(func(cmapi.GenericIssuer) bool {
				return true
			}).WithSetup(func(ctx context.Context, iss cmapi.GenericIssuer) error {
				apiutil.SetIssuerCondition(iss, cmapi.IssuerConditionReady, cmmeta.ConditionFalse, "SetupFailed", "Failed to setup")
				return errors.New("setup error")
			}),
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
					cmapi.SchemeGroupVersion.WithResource("issuers"),
					"status",
					gen.DefaultTestNamespace,
					gen.Issuer("test",
						gen.AddIssuerCondition(cmapi.IssuerCondition{
							Type:               "RandomType",
							Status:             cmmeta.ConditionTrue,
							Reason:             "Random",
							Message:            "random condition",
							LastTransitionTime: &metaFixedClockStart,
						}),
						gen.AddIssuerCondition(cmapi.IssuerCondition{
							Type:               cmapi.IssuerConditionReady,
							Status:             cmmeta.ConditionFalse,
							Reason:             "SetupFailed",
							Message:            "Failed to setup",
							LastTransitionTime: &metaFixedClockStart,
						}),
					),
				)),
			},
			err: "setup error",
		},

		// ClusterIssuer Kind controller
		"cluster issuer: do nothing if an empty 'key' is used": {
			issuerKind: cmapi.ClusterIssuerKind,
		},
		"cluster issuer: do nothing if an invalid 'key' is used": {
			issuerKind: cmapi.ClusterIssuerKind,
			key:        "abc/def/ghi",
		},
		"cluster issuer: do nothing if a key references a Issuer that does not exist": {
			issuerKind: cmapi.ClusterIssuerKind,
			key:        "name",
		},
		"cluster issuer: do nothing if a key references an Issuer": {
			issuerKind: cmapi.ClusterIssuerKind,
			key:        "test",
			issuer:     gen.Issuer("test"),
			issuerBackend: fake.New().WithImplements(func(cmapi.GenericIssuer) bool {
				t.Fatal("unexpected implements call")
				return false
			}),
		},
		"cluster issuer: do nothing if controller doesn't implement issuer type": {
			issuerKind: cmapi.ClusterIssuerKind,
			issuer:     gen.ClusterIssuer("test"),
			issuerBackend: fake.New().WithImplements(func(cmapi.GenericIssuer) bool {
				return false
			}),
		},
		"cluster issuer: if setup fails, should update cluster issuer with Failed condition and return error": {
			issuerKind: cmapi.ClusterIssuerKind,
			issuer:     gen.ClusterIssuer("test"),
			issuerBackend: fake.New().WithImplements(func(cmapi.GenericIssuer) bool {
				return true
			}).WithSetup(func(ctx context.Context, iss cmapi.GenericIssuer) error {
				apiutil.SetIssuerCondition(iss, cmapi.IssuerConditionReady, cmmeta.ConditionFalse, "SetupFailed", "Failed to setup")
				return errors.New("setup error")
			}),
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
					cmapi.SchemeGroupVersion.WithResource("clusterissuers"),
					"status",
					"",
					gen.ClusterIssuer("test",
						gen.AddIssuerCondition(cmapi.IssuerCondition{
							Type:               cmapi.IssuerConditionReady,
							Status:             cmmeta.ConditionFalse,
							Reason:             "SetupFailed",
							Message:            "Failed to setup",
							LastTransitionTime: &metaFixedClockStart,
						}),
					),
				)),
			},
			err: "setup error",
		},
		"cluster issuer: if setup succeeds, should update cluster issuer with Ready condition and return nil": {
			issuerKind: cmapi.ClusterIssuerKind,
			issuer:     gen.ClusterIssuer("test"),
			issuerBackend: fake.New().WithImplements(func(cmapi.GenericIssuer) bool {
				return true
			}).WithSetup(func(ctx context.Context, iss cmapi.GenericIssuer) error {
				apiutil.SetIssuerCondition(iss, cmapi.IssuerConditionReady, cmmeta.ConditionTrue, "Ready", "Issuer ready")
				return nil
			}),
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
					cmapi.SchemeGroupVersion.WithResource("clusterissuers"),
					"status",
					"",
					gen.ClusterIssuer("test",
						gen.AddIssuerCondition(cmapi.IssuerCondition{
							Type:               cmapi.IssuerConditionReady,
							Status:             cmmeta.ConditionTrue,
							Reason:             "Ready",
							Message:            "Issuer ready",
							LastTransitionTime: &metaFixedClockStart,
						}),
					),
				)),
			},
			err: "",
		},
		"cluster issuer: if setup succeeds, should remove old failed condition and return nil": {
			issuerKind: cmapi.ClusterIssuerKind,
			issuer: gen.ClusterIssuer("test",
				gen.AddIssuerCondition(cmapi.IssuerCondition{
					Type:               "RandomType",
					Status:             cmmeta.ConditionTrue,
					Reason:             "Random",
					Message:            "random condition",
					LastTransitionTime: &metaFixedClockStart,
				}),
				gen.AddIssuerCondition(cmapi.IssuerCondition{
					Type:               cmapi.IssuerConditionReady,
					Status:             cmmeta.ConditionFalse,
					Reason:             "SetupFailed",
					Message:            "Setup failed",
					LastTransitionTime: &metaFixedClockStart,
				}),
			),
			issuerBackend: fake.New().WithImplements(func(cmapi.GenericIssuer) bool {
				return true
			}).WithSetup(func(ctx context.Context, iss cmapi.GenericIssuer) error {
				apiutil.SetIssuerCondition(iss, cmapi.IssuerConditionReady, cmmeta.ConditionTrue, "Ready", "Issuer ready")
				return nil
			}),
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
					cmapi.SchemeGroupVersion.WithResource("clusterissuers"),
					"status",
					"",
					gen.ClusterIssuer("test",
						gen.AddIssuerCondition(cmapi.IssuerCondition{
							Type:               "RandomType",
							Status:             cmmeta.ConditionTrue,
							Reason:             "Random",
							Message:            "random condition",
							LastTransitionTime: &metaFixedClockStart,
						}),
						gen.AddIssuerCondition(cmapi.IssuerCondition{
							Type:               cmapi.IssuerConditionReady,
							Status:             cmmeta.ConditionTrue,
							Reason:             "Ready",
							Message:            "Issuer ready",
							LastTransitionTime: &metaFixedClockStart,
						}),
					),
				)),
			},
			err: "",
		},
		"cluster issuer: if setup fails, should remove old ready condition and return error": {
			issuerKind: cmapi.ClusterIssuerKind,
			issuer: gen.ClusterIssuer("test",
				gen.AddIssuerCondition(cmapi.IssuerCondition{
					Type:               "RandomType",
					Status:             cmmeta.ConditionTrue,
					Reason:             "Random",
					Message:            "random condition",
					LastTransitionTime: &metaFixedClockStart,
				}),
				gen.AddIssuerCondition(cmapi.IssuerCondition{
					Type:               cmapi.IssuerConditionReady,
					Status:             cmmeta.ConditionTrue,
					Reason:             "Ready",
					Message:            "Issuer ready",
					LastTransitionTime: &metaFixedClockStart,
				}),
			),
			issuerBackend: fake.New().WithImplements(func(cmapi.GenericIssuer) bool {
				return true
			}).WithSetup(func(ctx context.Context, iss cmapi.GenericIssuer) error {
				apiutil.SetIssuerCondition(iss, cmapi.IssuerConditionReady, cmmeta.ConditionFalse, "SetupFailed", "Failed to setup")
				return errors.New("setup error")
			}),
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
					cmapi.SchemeGroupVersion.WithResource("clusterissuers"),
					"status",
					"",
					gen.ClusterIssuer("test",
						gen.AddIssuerCondition(cmapi.IssuerCondition{
							Type:               "RandomType",
							Status:             cmmeta.ConditionTrue,
							Reason:             "Random",
							Message:            "random condition",
							LastTransitionTime: &metaFixedClockStart,
						}),
						gen.AddIssuerCondition(cmapi.IssuerCondition{
							Type:               cmapi.IssuerConditionReady,
							Status:             cmmeta.ConditionFalse,
							Reason:             "SetupFailed",
							Message:            "Failed to setup",
							LastTransitionTime: &metaFixedClockStart,
						}),
					),
				)),
			},
			err: "setup error",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Create and initialise a new unit test builder
			builder := &testpkg.Builder{
				Clock:           fixedClock,
				T:               t,
				ExpectedActions: test.expectedActions,
			}
			if test.issuer != nil {
				builder.CertManagerObjects = append(builder.CertManagerObjects, test.issuer)
			}
			builder.Init()

			// Register informers used by the controller using the registration wrapper
			c := New("test-controller", test.issuerKind, test.issuerBackend)
			if _, _, err := c.Register(builder.Context); err != nil {
				t.Fatal(err)
			}

			// Start the informers and begin processing updates
			builder.Start()
			defer builder.Stop()

			var (
				key = test.key
				err error
			)
			if key == "" && test.issuer != nil {
				key, err = controllerpkg.KeyFunc(test.issuer)
				if err != nil {
					t.Fatal(err)
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

			if err := builder.AllActionsExecuted(); err != nil {
				builder.T.Error(err)
			}
			if err := builder.AllReactorsCalled(); err != nil {
				builder.T.Error(err)
			}
		})
	}
}
