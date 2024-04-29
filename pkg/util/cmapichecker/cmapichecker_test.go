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

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

type fakeErrorClient struct {
	client.Client

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
		createError: nil,
	}

	return errorClient, &cmapiChecker{
		client: errorClient,
	}, nil
}

const (
	errCertManagerCRDsMapping  = `error finding the scope of the object: failed to get restmapping: no matches for kind "Certificate" in group "cert-manager.io"`
	errCertManagerCRDsNotFound = `the server could not find the requested resource (post certificates.cert-manager.io)`

	errMutatingWebhookServiceFailure     = `Internal error occurred: failed calling webhook "webhook.cert-manager.io": Post "https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s": service "cert-manager-webhook" not found`
	errMutatingWebhookDeploymentFailure  = `Internal error occurred: failed calling webhook "webhook.cert-manager.io": Post "https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s": dial tcp 10.96.38.90:443: connect: connection refused`
	errMutatingWebhookCertificateFailure = `Internal error occurred: failed calling webhook "webhook.cert-manager.io": Post "https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s": x509: certificate signed by unknown authority (possibly because of "x509: ECDSA verification failure" while trying to verify candidate authority certificate "cert-manager-webhook-ca"`

	// These /convert error examples test that we can correctly parse errors
	// while connecting to the conversion webhook,
	// but as of cert-manager 1.6 the conversion webhook will no-longer be used
	// because legacy CRD versions will no longer be "served"
	// and in 1.7 the conversion webhook may be removed at which point these can
	// be removed too.
	// TODO: Add tests for errors when connecting to the /validate
	// ValidatingWebhook endpoint.
	errConversionWebhookServiceFailure     = `conversion webhook for cert-manager.io/v1alpha2, Kind=Certificate failed: Post "https://cert-manager-webhook.cert-manager.svc:443/convert?timeout=30s": service "cert-manager-webhook" not found`
	errConversionWebhookDeploymentFailure  = `conversion webhook for cert-manager.io/v1alpha2, Kind=Certificate failed: Post "https://cert-manager-webhook.cert-manager.svc:443/convert?timeout=30s": dial tcp 10.96.38.90:443: connect: connection refused`
	errConversionWebhookCertificateFailure = `conversion webhook for cert-manager.io/v1alpha2, Kind=Certificate failed: Post "https://cert-manager-webhook.cert-manager.svc:443/convert?timeout=30s": x509: certificate signed by unknown authority`
)

func TestCmapiChecker(t *testing.T) {
	tests := map[string]testT{
		"check API without errors": {
			createError: nil,

			expectedSimpleError:  "",
			expectedVerboseError: "",
		},
		"check API without CRDs installed 1": {
			createError: errors.New(errCertManagerCRDsMapping),

			expectedSimpleError:  ErrCertManagerCRDsNotFound.Error(),
			expectedVerboseError: errCertManagerCRDsMapping,
		},
		"check API without CRDs installed 2": {
			createError: errors.New(errCertManagerCRDsNotFound),

			expectedSimpleError:  ErrCertManagerCRDsNotFound.Error(),
			expectedVerboseError: errCertManagerCRDsNotFound,
		},

		"check API with mutating webhook service not ready": {
			createError: errors.New(errMutatingWebhookServiceFailure),

			expectedSimpleError:  ErrWebhookServiceFailure.Error(),
			expectedVerboseError: errMutatingWebhookServiceFailure,
		},
		"check API with conversion webhook service not ready": {
			createError: errors.New(errConversionWebhookServiceFailure),

			expectedSimpleError:  ErrWebhookServiceFailure.Error(),
			expectedVerboseError: errConversionWebhookServiceFailure,
		},

		"check API with mutating webhook pod not accepting connections": {
			createError: errors.New(errMutatingWebhookDeploymentFailure),

			expectedSimpleError:  ErrWebhookDeploymentFailure.Error(),
			expectedVerboseError: errMutatingWebhookDeploymentFailure,
		},
		"check API with conversion webhook pod not accepting connections": {
			createError: errors.New(errConversionWebhookDeploymentFailure),

			expectedSimpleError:  ErrWebhookDeploymentFailure.Error(),
			expectedVerboseError: errConversionWebhookDeploymentFailure,
		},

		"check API with webhook certificate not updated in mutation webhook resource definitions": {
			createError: errors.New(errMutatingWebhookCertificateFailure),

			expectedSimpleError:  ErrWebhookCertificateFailure.Error(),
			expectedVerboseError: errMutatingWebhookCertificateFailure,
		},
		"check API with webhook certificate not updated in conversion webhook resource definitions": {
			createError: errors.New(errConversionWebhookCertificateFailure),

			expectedSimpleError:  ErrWebhookCertificateFailure.Error(),
			expectedVerboseError: errConversionWebhookCertificateFailure,
		},
		"unexpected error": {
			createError: errors.New("unexpected error"),

			expectedSimpleError:  "",
			expectedVerboseError: "unexpected error",
		},
	}

	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			runTest(t, test)
		})
	}
}

type testT struct {
	createError error

	expectedSimpleError  string
	expectedVerboseError string
}

func runTest(t *testing.T, test testT) {
	errorClient, checker, err := newFakeCmapiChecker()
	if err != nil {
		t.Error(err)
	}

	errorClient.createError = test.createError

	var simpleError error
	err = checker.Check(context.TODO())
	if err != nil {
		if err.Error() != test.expectedVerboseError {
			t.Errorf("error differs from expected error:\n%s\n vs \n%s", err.Error(), test.expectedVerboseError)
		}

		simpleError = TranslateToSimpleError(err)
	} else if test.expectedVerboseError != "" {
		t.Errorf("expected error did not occure:\n%s", test.expectedVerboseError)
	}

	if simpleError != nil {
		if simpleError.Error() != test.expectedSimpleError {
			t.Errorf("simple error differs from expected error:\n%s\n vs \n%s", simpleError.Error(), test.expectedSimpleError)
		}
	} else {
		if test.expectedSimpleError != "" {
			t.Errorf("expected simple error did not occure:\n%s", test.expectedSimpleError)
		}
	}
}
