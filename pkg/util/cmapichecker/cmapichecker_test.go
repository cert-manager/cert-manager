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

package cmapichecker

import (
	"context"
	"errors"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
)

type fakeErrorClient struct {
	client.Client

	newError    error
	createError error
}

func (cl *fakeErrorClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if cl.createError != nil {
		return cl.createError
	}

	return cl.Client.Create(ctx, obj, opts...)
}

func newFakeCmapiChecker() (*fakeErrorClient, Interface, error) {
	scheme := runtime.NewScheme()
	if err := cmapi.AddToScheme(scheme); err != nil {
		return nil, nil, err
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	errorClient := &fakeErrorClient{
		Client:      cl,
		newError:    nil,
		createError: nil,
	}

	return errorClient, &cmapiChecker{
		clientBuilder: func() (client.Client, error) {
			if errorClient.newError != nil {
				return nil, errorClient.newError
			}
			return errorClient, nil
		},
	}, nil
}

func TestCmapiChecker(t *testing.T) {
	tests := map[string]testT{
		"check API without errors": {
			newError:    nil,
			createError: nil,

			expectedError: "",
		},
		"check API server unreachable": {
			newError:    errors.New("while creating client: Get \"http://localhost:8080/api?timeout=32s\": dial tcp 127.0.0.1:8080: connect: connection refused"),
			createError: nil,

			expectedError: ErrAPIServerUnreachable.Error(),
		},
		"check API without CRDs installed": {
			newError:    nil,
			createError: errors.New("error finding the scope of the object: failed to get restmapping: no matches for kind \"Certificate\" in group \"cert-manager.io\""),

			expectedError: ErrCertManagerCRDsNotFound.Error(),
		},
		"check API with webhook service not ready": {
			newError:    nil,
			createError: errors.New("Internal error occurred: failed calling webhook \"webhook.cert-manager.io\": Post \"https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s\": service \"cert-manager-webhook\" not found"),

			expectedError: ErrCertManagerAPIEndpointsNotEstablished.Error(),
		},
		"check API with webhook pod not accepting connections": {
			newError:    nil,
			createError: errors.New("Internal error occurred: failed calling webhook \"webhook.cert-manager.io\": Post \"https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s\": dial tcp 10.96.38.90:443: connect: connection refused"),

			expectedError: ErrWebhookConnectionFailure.Error(),
		},
		"check API with webhook certificate not updated in mutation webhook resource definitions": {
			newError:    nil,
			createError: errors.New("Internal error occurred: failed calling webhook \"webhook.cert-manager.io\": Post \"https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s\": x509: certificate signed by unknown authority (possibly because of \"x509: ECDSA verification failure\" while trying to verify candidate authority certificate \"cert-manager-webhook-ca\""),

			expectedError: ErrWebhookCertificateFailure.Error(),
		},
		"check API with webhook certificate not updated in conversion webhook resource definitions": {
			newError:    nil,
			createError: errors.New("conversion webhook for cert-manager.io/v1alpha2, Kind=Certificate failed: Post \"https://cert-manager-webhook.cert-manager.svc:443/convert?timeout=30s\": x509: certificate signed by unknown authority"),

			expectedError: ErrWebhookCertificateFailure.Error(),
		},
	}

	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			runTest(t, test)
		})
	}
}

type testT struct {
	newError    error
	createError error

	expectedError string
}

func runTest(t *testing.T, test testT) {
	errorClient, checker, _ := newFakeCmapiChecker()

	errorClient.newError = test.newError
	errorClient.createError = test.createError

	err := checker.Check(context.TODO())
	if err != nil {
		if err.Error() != test.expectedError {
			t.Errorf("error differs from expected error:\n%s\n vs \n%s", err.Error(), test.expectedError)
		}
	} else {
		if test.expectedError != "" {
			t.Errorf("expected error did not occure:\n%s", test.expectedError)
		}
	}
}
