/*
Copyright 2020 The Jetstack cert-manager contributors.

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

package genericissuer

import (
	"context"
	"errors"
	"testing"

	logrtesting "github.com/go-logr/logr/testing"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

type fakeSyncer struct {
	errSync error
}

var _ syncer = &fakeSyncer{}

func (o *fakeSyncer) Sync(_ context.Context, issuer cmapi.GenericIssuer) error {
	return o.errSync
}

func TestControllerProcessItem(t *testing.T) {

	type testCase struct {
		ctx           context.Context
		key           string
		builder       *testpkg.Builder
		issuerGetter  issuerGetter
		syncer        syncer
		expectRequeue bool
		err           error
	}

	tests := map[string]testCase{
		"success": {
			key: "ns1/issuer-1",
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.Issuer(
						"issuer-1",
						gen.SetIssuerNamespace("ns1"),
						gen.SetIssuerVenafi(cmapi.VenafiIssuer{
							Zone: `foo\bar`,
						}),
					),
				},
			},
			syncer:        &fakeSyncer{},
			expectRequeue: true,
		},
		"ignore empty key": {},
		"ignore bad key": {
			key: "three/segment/key",
		},
		"ignore not-found issuer": {
			key: "ns1/issuer-1",
		},
		"failing issuer getter": {
			key:     "ns1/issuer-1",
			builder: &testpkg.Builder{},
			issuerGetter: func(_ context.Context, namespace, name string) (cmapi.GenericIssuer, error) {
				return nil, errors.New("simulated issuerGetter error")
			},
			err: errIssuerGetter,
		},
		"ignore non-venafi issuer": {
			key: "ns1/issuer-1",
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.Issuer(
						"issuer-1",
						gen.SetIssuerNamespace("ns1"),
					),
				},
			},
		},
		"failing sync": {
			key: "ns1/issuer-1",
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.Issuer(
						"issuer-1",
						gen.SetIssuerNamespace("ns1"),
						gen.SetIssuerVenafi(cmapi.VenafiIssuer{
							Zone: `foo\bar`,
						}),
					),
				},
			},
			syncer: &fakeSyncer{errSync: errors.New("simulated sync error")},
			err:    errSync,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			builder := tc.builder
			if builder == nil {
				builder = &testpkg.Builder{}
			}
			builder.T = t
			builder.Init()
			defer builder.Stop()

			syncer := tc.syncer
			if syncer == nil {
				syncer = &fakeSyncer{}
			}
			issuerGetter := tc.issuerGetter
			if issuerGetter == nil {
				issuerGetter = issuerGetterFromIssuerLister(builder.FakeCMInformerFactory().Certmanager().V1().Issuers().Lister())
			}

			didRequeue := false

			c := &Controller{
				issuerGetter: issuerGetter,
				syncer:       syncer,
				requeue: func(key string) {
					didRequeue = true
					assert.Equal(t, tc.key, key, "requeue was called with a different key than was supplied to ProcessItem")
				},
			}
			ctx := tc.ctx
			if ctx == nil {
				ctx = context.TODO()
			}
			log := logrtesting.TestLogger{T: t}
			ctx = logf.NewContext(ctx, log)

			builder.Start()
			defer builder.CheckAndFinish()

			err := c.ProcessItem(ctx, tc.key)

			if tc.err == nil {
				assert.NoError(t, err)
			} else {
				assertErrorIs(t, err, tc.err)
			}
			assert.Equal(t, tc.expectRequeue, didRequeue, "unexpected requeue. expected: %v, actual: %v", tc.expectRequeue, didRequeue)
		})
	}
}
