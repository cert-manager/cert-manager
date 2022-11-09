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

package duplicatesecrets

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"
	"k8s.io/client-go/util/workqueue"
	fakeclock "k8s.io/utils/clock/testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func Test_ProcessItem(t *testing.T) {
	// now time is the current UTC time at the start of the test
	now := time.Now().UTC()
	metaNow := metav1.NewTime(now)
	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"},
		Spec: cmapi.CertificateSpec{
			SecretName: "test-secret",
			DNSNames:   []string{"example.com"},
		},
	}
	tests := map[string]struct {
		// key that should be passed to ProcessItem.
		// if not set, the 'namespace/name' of the 'Certificate' field will be used.
		// if neither is set, the key will be "".
		key string

		// cert to be loaded to fake clientset
		cert *cmapi.Certificate

		existingCerts []runtime.Object

		// whether we expect an update action against the Certificate
		certShouldUpdate bool

		// Certificate's DuplicateSecretName condition to be applied with the
		// update
		condition *cmapi.CertificateCondition

		wantsErr bool

		expQueue []string
	}{
		"do nothing if an empty 'key' is used": {},
		"do nothing if an invalid 'key' is used": {
			key: "abc/def/ghi",
		},
		"do nothing if a key references a Certificate that does not exist": {
			key: "namespace/name",
		},
		"do nothing if there is a single Certificate and no duplicate": {
			cert:             gen.CertificateFrom(cert),
			certShouldUpdate: false,
		},
		"if existing cert in the same Namespace has the same SecretName, expect condition created": {
			cert: gen.CertificateFrom(cert),
			existingCerts: []runtime.Object{gen.CertificateFrom(cert,
				gen.SetCertificateName("test2"),
			)},
			certShouldUpdate: true,
			condition: &cmapi.CertificateCondition{
				Type:               "DuplicateSecretName",
				Status:             "True",
				Reason:             "test2",
				Message:            "Certificate shares the same Secret name as the following Certificates in the same Namespace: [ test2 ]. Issuance will block until this is resolved to prevent CertificateRequest creation runaway.",
				LastTransitionTime: &metaNow,
			},
			expQueue: []string{"testns/test2"},
		},
		"if existing cert in different Namespace has the same SecretName, expect no condition": {
			cert: gen.CertificateFrom(cert),
			existingCerts: []runtime.Object{gen.CertificateFrom(cert,
				gen.SetCertificateName("test2"),
				gen.SetCertificateNamespace("not-the-same-namespace"),
			)},
			certShouldUpdate: false,
		},
		"if 2 existing cert in the same Namespace has the same SecretName, expect condition created": {
			cert: gen.CertificateFrom(cert),
			existingCerts: []runtime.Object{
				gen.CertificateFrom(cert, gen.SetCertificateName("test3")),
				gen.CertificateFrom(cert, gen.SetCertificateName("test2")),
			},
			certShouldUpdate: true,
			condition: &cmapi.CertificateCondition{
				Type:               "DuplicateSecretName",
				Status:             "True",
				Reason:             "test2,test3",
				Message:            "Certificate shares the same Secret name as the following Certificates in the same Namespace: [ test2, test3 ]. Issuance will block until this is resolved to prevent CertificateRequest creation runaway.",
				LastTransitionTime: &metaNow,
			},
			expQueue: []string{"testns/test2", "testns/test3"},
		},
		"if existing condition does not cover all duplicate existing Certificates, expect condtion to be updated": {
			cert: gen.CertificateFrom(cert,
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
					Type:               "DuplicateSecretName",
					Status:             "True",
					Reason:             "test2",
					Message:            "Certificate shares the same Secret name as the following Certificates in the same Namespace: [ test2 ]. Issuance will block until this is resolved to prevent CertificateRequest creation runaway.",
					LastTransitionTime: &metaNow,
				}),
			),
			existingCerts: []runtime.Object{
				gen.CertificateFrom(cert, gen.SetCertificateName("test3")),
				gen.CertificateFrom(cert, gen.SetCertificateName("test2")),
			},
			certShouldUpdate: true,
			condition: &cmapi.CertificateCondition{
				Type:               "DuplicateSecretName",
				Status:             "True",
				Reason:             "test2,test3",
				Message:            "Certificate shares the same Secret name as the following Certificates in the same Namespace: [ test2, test3 ]. Issuance will block until this is resolved to prevent CertificateRequest creation runaway.",
				LastTransitionTime: &metaNow,
			},
			expQueue: []string{"testns/test2", "testns/test3"},
		},
		"if existing condition is still valid for the current state, expect no update": {
			cert: gen.CertificateFrom(cert,
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
					Type:               "DuplicateSecretName",
					Status:             "True",
					Reason:             "test2,test3",
					Message:            "Certificate shares the same Secret name as the following Certificates in the same Namespace: [ test2, test3 ]. Issuance will block until this is resolved to prevent CertificateRequest creation runaway.",
					LastTransitionTime: &metaNow,
				}),
			),
			existingCerts: []runtime.Object{
				gen.CertificateFrom(cert, gen.SetCertificateName("test3")),
				gen.CertificateFrom(cert, gen.SetCertificateName("test2")),
			},
			certShouldUpdate: false,
		},
		"if existing condition is no longer correct, expect condition to be removed": {
			cert: gen.CertificateFrom(cert,
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
					Type:               "DuplicateSecretName",
					Status:             "True",
					Reason:             "test2,test3",
					Message:            "Certificate shares the same Secret name as the following Certificates in the same Namespace: [ test2, test3]. Issuance will block until this is resolved to prevent CertificateRequest creation runaway.",
					LastTransitionTime: &metaNow,
				}),
			),
			existingCerts:    []runtime.Object{},
			certShouldUpdate: true,
			condition:        nil,
			expQueue:         []string{},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Create and initialise a new unit test builder.
			builder := &testpkg.Builder{
				T: t,
				// Fix the clock to be able to set lastTransitionTime on Certificate's Ready condition.
				Clock: fakeclock.NewFakeClock(now),
			}
			if test.cert != nil {
				// Ensures cert is loaded into the builder's fake clientset.
				builder.CertManagerObjects = append(builder.CertManagerObjects, test.cert)
			}
			if len(test.existingCerts) > 0 {
				builder.CertManagerObjects = append(builder.CertManagerObjects, test.existingCerts...)
			}

			builder.Init()

			// Register informers used by the controller using the registration wrapper.
			w := &controllerWrapper{}
			_, _, err := w.Register(builder.Context)
			if err != nil {
				t.Fatal(err)
			}

			// Custom queue we can measure.
			w.controller.queue = workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
			queue := w.controller.queue

			// If Certificate's status should be updated,
			// build the expected Certificate and use it to set the expected update action on builder.
			if test.certShouldUpdate {
				c := gen.CertificateFrom(test.cert)
				if test.condition != nil {
					c.Status.Conditions = []cmapi.CertificateCondition{*test.condition}
				} else {
					c.Status.Conditions = []cmapi.CertificateCondition{}
				}

				builder.ExpectedActions = append(builder.ExpectedActions,
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						"status",
						c.Namespace,
						c)))
			}

			// Start the informers and begin processing updates.
			builder.Start()
			defer builder.Stop()

			key := test.key
			if key == "" && cert != nil {
				key, err = controllerpkg.KeyFunc(cert)
				if err != nil {
					t.Fatal(err)
				}
			}

			// Call ProcessItem
			err = w.controller.ProcessItem(context.Background(), key)
			if test.wantsErr != (err != nil) {
				t.Errorf("expected error: %v, got : %v", test.wantsErr, err)
			}

			for i, expKey := range test.expQueue {
				if key, _ := queue.Get(); key != expKey {
					t.Errorf("expected queue item %d to be %q, got %q", i, expKey, key)
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
