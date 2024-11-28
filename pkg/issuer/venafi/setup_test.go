/*
Copyright 2020 The cert-manager Authors.

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

package venafi

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	controllertest "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/pkg/issuer/venafi/client"
	internalvenafifake "github.com/cert-manager/cert-manager/pkg/issuer/venafi/client/fake"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/metrics"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func TestSetup(t *testing.T) {
	baseIssuer := gen.Issuer("test-issuer")

	failingClientBuilder := func(string, internalinformers.SecretLister,
		cmapi.GenericIssuer, *metrics.Metrics, logr.Logger, string) (client.Interface, error) {
		return nil, errors.New("this is an error")
	}

	failingPingClient := func(string, internalinformers.SecretLister,
		cmapi.GenericIssuer, *metrics.Metrics, logr.Logger, string) (client.Interface, error) {
		return &internalvenafifake.Venafi{
			PingFn: func() error {
				return errors.New("this is a ping error")
			},
		}, nil
	}

	pingClient := func(string, internalinformers.SecretLister,
		cmapi.GenericIssuer, *metrics.Metrics, logr.Logger, string) (client.Interface, error) {
		return &internalvenafifake.Venafi{
			PingFn: func() error {
				return nil
			},
		}, nil
	}

	verifyCredentialsClient := func(string, internalinformers.SecretLister, cmapi.GenericIssuer, *metrics.Metrics, logr.Logger, string) (client.Interface, error) {
		return &internalvenafifake.Venafi{
			PingFn: func() error {
				return nil
			},
			VerifyCredentialsFn: func() error {
				return nil
			},
		}, nil
	}

	failingVerifyCredentialsClient := func(string, internalinformers.SecretLister, cmapi.GenericIssuer, *metrics.Metrics, logr.Logger, string) (client.Interface, error) {
		return &internalvenafifake.Venafi{
			PingFn: func() error {
				return nil
			},
			VerifyCredentialsFn: func() error {
				return fmt.Errorf("401 Unauthorized")
			},
		}, nil
	}

	tests := map[string]testSetupT{
		"if client builder fails then should error": {
			clientBuilder: failingClientBuilder,
			iss:           baseIssuer.DeepCopy(),
			expectErr:     "error building Venafi client: this is an error",
		},

		"if ping fails then should error": {
			clientBuilder: failingPingClient,
			iss:           baseIssuer.DeepCopy(),
			expectErr:     "error pinging Venafi API: this is a ping error",
		},

		"if ready then should set condition": {
			clientBuilder: pingClient,
			iss:           baseIssuer.DeepCopy(),
		},
		"verifyCredentials happy path": {
			clientBuilder: verifyCredentialsClient,
			iss:           baseIssuer.DeepCopy(),
		},

		"if verifyCredentials returns an error we should set condition to False": {
			clientBuilder: failingVerifyCredentialsClient,
			iss:           baseIssuer.DeepCopy(),
			expectErr:     "error verifying Venafi credentials: 401 Unauthorized",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.runTest(t)
		})
	}
}

type testSetupT struct {
	clientBuilder client.VenafiClientBuilder
	iss           cmapi.GenericIssuer

	expectErr string
}

func (s *testSetupT) runTest(t *testing.T) {
	rec := &controllertest.FakeRecorder{}

	v := &Venafi{
		resourceNamespace: "test-namespace",
		Context: &controllerpkg.Context{
			Recorder: rec,
		},
		clientBuilder: s.clientBuilder,
		log:           logf.Log.WithName("venafi"),
	}

	err := v.Setup(context.TODO(), s.iss)
	if s.expectErr != "" {
		assert.EqualError(t, err, s.expectErr)
		return
	}
	assert.NoError(t, err)

	if len(rec.Events) > 0 {
		t.Errorf("got unexpected events, got='%s'", rec.Events)
	}
}
