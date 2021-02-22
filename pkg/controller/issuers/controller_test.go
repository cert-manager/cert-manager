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

package issuers_test

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclock "k8s.io/utils/clock/testing"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/jetstack/cert-manager/pkg/controller/issuers"
	"github.com/jetstack/cert-manager/pkg/controller/issuers/ca"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

var (
	fixedClockStart = time.Now()
	fixedClock      = fakeclock.NewFakeClock(fixedClockStart)
)

func TestAffectedSecret(t *testing.T) {
	const (
		clusterResourceNamespace = "cert-manager"
	)

	tests := map[string]struct {
		controllerKind string
		issuers        []runtime.Object
		secret         *corev1.Secret
		expectedKeys   []string
	}{
		// Issuer Kind
		"issuer: if no issuers exist, expect no keys": {
			controllerKind: cmapi.IssuerKind,
			issuers:        []runtime.Object{},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: gen.DefaultTestNamespace,
				},
			},
		},
		"issuer: if cluster issuers exist but no issuers, expect no keys": {
			controllerKind: cmapi.IssuerKind,
			issuers: []runtime.Object{
				gen.ClusterIssuer("cluster-issuer-1",
					gen.SetIssuerCA(cmapi.CAIssuer{
						SecretName: "test-secret",
					}),
				),
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: gen.DefaultTestNamespace,
				},
			},
		},
		"issuer: if issuer exist but different secret, expect no keys": {
			controllerKind: cmapi.IssuerKind,
			issuers: []runtime.Object{
				gen.Issuer("issuer-1",
					gen.SetIssuerCA(cmapi.CAIssuer{
						SecretName: "test-secret-2",
					}),
				),
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: gen.DefaultTestNamespace,
				},
			},
		},
		"issuer: if issuer exist which references secret, expect key": {
			controllerKind: cmapi.IssuerKind,
			issuers: []runtime.Object{
				gen.Issuer("issuer-1",
					gen.SetIssuerCA(cmapi.CAIssuer{
						SecretName: "test-secret",
					}),
				),
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: gen.DefaultTestNamespace,
				},
			},
			expectedKeys: []string{gen.DefaultTestNamespace + "/issuer-1"},
		},
		"issuer: if issuer exist which references secret but wrong namespace, expect no keys": {
			controllerKind: cmapi.IssuerKind,
			issuers: []runtime.Object{
				gen.Issuer("issuer-1",
					gen.SetIssuerCA(cmapi.CAIssuer{
						SecretName: "test-secret",
					}),
				),
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "foo",
				},
			},
			expectedKeys: nil,
		},
		"issuer: if multiple issuers exist which references the same secret, expect multiple keys": {
			controllerKind: cmapi.IssuerKind,
			issuers: []runtime.Object{
				gen.Issuer("issuer-1",
					gen.SetIssuerCA(cmapi.CAIssuer{
						SecretName: "test-secret",
					}),
				),
				gen.Issuer("issuer-2",
					gen.SetIssuerCA(cmapi.CAIssuer{
						SecretName: "test-secret",
					}),
				),
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: gen.DefaultTestNamespace,
				},
			},
			expectedKeys: []string{
				gen.DefaultTestNamespace + "/issuer-1",
				gen.DefaultTestNamespace + "/issuer-2",
			},
		},

		// ClusterIssuer Kind
		"cluster issuer: if no cluster issuers exist, expect no keys": {
			controllerKind: cmapi.ClusterIssuerKind,
			issuers:        []runtime.Object{},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: clusterResourceNamespace,
				},
			},
		},
		"cluster issuer: if issuers exist but no cluster issuers, expect no keys": {
			controllerKind: cmapi.ClusterIssuerKind,
			issuers: []runtime.Object{
				gen.Issuer("cluster-issuer-1",
					gen.SetIssuerCA(cmapi.CAIssuer{
						SecretName: "test-secret",
					}),
				),
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: clusterResourceNamespace,
				},
			},
		},
		"cluster issuer: if cluster issuer exists but different secret, expect no keys": {
			controllerKind: cmapi.ClusterIssuerKind,
			issuers: []runtime.Object{
				gen.ClusterIssuer("issuer-1",
					gen.SetIssuerCA(cmapi.CAIssuer{
						SecretName: "test-secret-2",
					}),
				),
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: clusterResourceNamespace,
				},
			},
		},
		"cluster issuer: if cluster issuer exists which references secret, expect key": {
			controllerKind: cmapi.ClusterIssuerKind,
			issuers: []runtime.Object{
				gen.ClusterIssuer("issuer-1",
					gen.SetIssuerCA(cmapi.CAIssuer{
						SecretName: "test-secret",
					}),
				),
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: clusterResourceNamespace,
				},
			},
			expectedKeys: []string{"issuer-1"},
		},
		"cluster issuer: if cluster issuer exist which references secret but wrong namespace, expect no keys": {
			controllerKind: cmapi.ClusterIssuerKind,
			issuers: []runtime.Object{
				gen.ClusterIssuer("issuer-1",
					gen.SetIssuerCA(cmapi.CAIssuer{
						SecretName: "test-secret",
					}),
				),
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "foo",
				},
			},
			expectedKeys: nil,
		},
		"cluster issuer: if multiple cluster issuers exist which references the same secret, expect multiple keys": {
			controllerKind: cmapi.ClusterIssuerKind,
			issuers: []runtime.Object{
				gen.ClusterIssuer("issuer-1",
					gen.SetIssuerCA(cmapi.CAIssuer{
						SecretName: "test-secret",
					}),
				),
				gen.ClusterIssuer("issuer-2",
					gen.SetIssuerCA(cmapi.CAIssuer{
						SecretName: "test-secret",
					}),
				),
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: clusterResourceNamespace,
				},
			},
			expectedKeys: []string{
				"issuer-1",
				"issuer-2",
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixedClock.SetTime(fixedClockStart)
			builder := &testpkg.Builder{
				Clock:              fixedClock,
				T:                  t,
				CertManagerObjects: test.issuers,
			}

			builder.Init()
			defer builder.Stop()

			// Set cluster resource namespace
			builder.Context.IssuerOptions.ClusterResourceNamespace = clusterResourceNamespace

			issuerBackend := ca.New(builder.Context)
			c := issuers.New(name, test.controllerKind, issuerBackend)
			if _, _, err := c.Register(builder.Context); err != nil {
				t.Fatal(err)
			}

			builder.Start()

			keys := c.AffectedSecret(test.secret)
			if !util.EqualUnsorted(keys, test.expectedKeys) {
				t.Errorf("unepected issuer keys affected by secret, exp=%v got=%v",
					test.expectedKeys, keys)
			}
		})
	}
}
