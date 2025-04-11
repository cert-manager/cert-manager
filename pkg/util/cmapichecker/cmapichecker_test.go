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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

const (
	crNoMutation = `{
		"kind":"CertificateRequest",
		"apiVersion":"cert-manager.io/v1",
		"metadata":{
			"name":"cmapichecker-0001",
			"namespace":"test-namespace"
		},
		"spec":{
			"issuerRef":{"name":"cmapichecker"},
			"request":"PENTUi1WQUxVRT4="
		}
	}`
	crAfterMutation = `{
		"kind":"CertificateRequest",
		"apiVersion":"cert-manager.io/v1",
		"metadata":{
			"name":"cmapichecker-0001",
			"namespace":"test-namespace"
		},
		"spec":{
			"issuerRef":{"name":"cmapichecker"},
			"request":"PENTUi1WQUxVRT4=",
			"username":"test-user",
			"uid":"test-uid"
		},
		"status":{}
	}`
)

func TestCheck(t *testing.T) {
	type testT struct {
		discoveryResponse     func(t *testing.T, r *http.Request) (int, []byte)
		createValidResponse   func(t *testing.T, r *http.Request) (int, []byte)
		createInvalidResponse func(t *testing.T, r *http.Request) (int, []byte)

		expectedError       string
		expectedSimpleError string
	}

	tests := map[string]testT{
		"no errors": {},
		"without any cert-manager CRDs installed (404)": {
			discoveryResponse: func(t *testing.T, r *http.Request) (int, []byte) {
				return http.StatusNotFound, nil
			},
			expectedError:       `error finding the scope of the object: failed to get restmapping: no matches for kind "CertificateRequest" in version "cert-manager.io/v1"`,
			expectedSimpleError: ErrCertManagerCRDsNotFound.Error(),
		},
		"without any cert-manager CRDs installed (empty list)": {
			discoveryResponse: func(t *testing.T, r *http.Request) (int, []byte) {
				return http.StatusOK, []byte(`{
					"kind":"APIResourceList",
					"apiVersion":"v1",
					"groupVersion":"cert-manager.io/v1",
					"resources":[]
				}`)
			},
			expectedError:       `error finding the scope of the object: failed to get restmapping: no matches for kind "CertificateRequest" in version "cert-manager.io/v1"`,
			expectedSimpleError: ErrCertManagerCRDsNotFound.Error(),
		},
		"without certificate request CRD installed": {
			discoveryResponse: func(t *testing.T, r *http.Request) (int, []byte) {
				return http.StatusOK, []byte(`{
					"kind":"APIResourceList",
					"apiVersion":"v1",
					"groupVersion":"cert-manager.io/v1",
					"resources":[
						{
							"name":"test",
							"singularName":"",
							"namespaced":true,
							"kind":"Test",
							"verbs":["get","patch","update"]
						}
					]
				}`)
			},
			expectedError:       `error finding the scope of the object: failed to get restmapping: no matches for kind "CertificateRequest" in version "cert-manager.io/v1"`,
			expectedSimpleError: ErrCertManagerCRDsNotFound.Error(),
		},
		"with missing certificate request endpoint": {
			discoveryResponse: func(t *testing.T, r *http.Request) (int, []byte) {
				return http.StatusNotFound, nil
			},
			expectedError:       `error finding the scope of the object: failed to get restmapping: no matches for kind "CertificateRequest" in version "cert-manager.io/v1"`,
			expectedSimpleError: ErrCertManagerCRDsNotFound.Error(),
		},
		"dry-run certificate request was not mutated": {
			createValidResponse: func(t *testing.T, r *http.Request) (int, []byte) {
				return http.StatusOK, []byte(crNoMutation)
			},
			expectedError: ErrMutationWebhookMissing.Error(),
		},
		"cr was denied by 3rd party webhook": {
			createInvalidResponse: func(t *testing.T, r *http.Request) (int, []byte) {
				return http.StatusNotAcceptable, []byte(`{
					"kind":"Status",
					"apiVersion":"v1",
					"metadata":{},
					"status":"Failure",
					"message":"admission webhook \"other-webhook.io\" denied the request: [ERROR MESSAGE]",
					"reason":"NotAcceptable",
					"code":406
				}`)
			},
			expectedError:       "admission webhook \"other-webhook.io\" denied the request: [ERROR MESSAGE]",
			expectedSimpleError: ErrFailedToCheckAPI.Error(),
		},
		"missing validation error": {
			createInvalidResponse: func(t *testing.T, r *http.Request) (int, []byte) {
				return http.StatusOK, []byte(crAfterMutation)
			},
			expectedError: ErrValidatingWebhookMissing.Error(),
		},
	}

	type testFailure struct {
		message     string
		reason      string
		code        int
		simpleError string
	}

	for name, test := range map[string]testFailure{
		"no permission": {
			message: `certificaterequests.cert-manager.io is forbidden: User "test" cannot create resource "certificaterequests" in API group "cert-manager.io" in the namespace "test-namespace"`,
			reason:  "Forbidden",
			code:    http.StatusForbidden,

			simpleError: ErrFailedToCheckAPI.Error(),
		},

		"service not found": {
			message: `failed calling webhook "webhook.cert-manager.io": Post "https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s": service "cert-manager-webhook" not found`,
			reason:  "InternalError",
			code:    500,

			simpleError: ErrWebhookServiceFailure.Error(),
		},
		"connection refused": {
			message: `failed calling webhook "webhook.cert-manager.io": failed to call webhook: Post "https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=30s": dial tcp 10.96.19.42:443: connect: connection refused`,
			reason:  "InternalError",
			code:    500,

			simpleError: ErrWebhookDeploymentFailure.Error(),
		},

		"certificate signed by unknown authority": {
			message: `failed calling webhook "webhook.cert-manager.io": failed to call webhook: Post "https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=30s": x509: certificate signed by unknown authority`,
			reason:  "NotAcceptable",
			code:    406,

			simpleError: ErrWebhookCertificateFailure.Error(),
		},
		"certificate signed by unknown authority (ECDSA verification failure)": {
			message: `failed calling webhook "webhook.cert-manager.io": Post "https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s": x509: certificate signed by unknown authority (possibly because of "x509: ECDSA verification failure" while trying to verify candidate authority certificate "cert-manager-webhook-ca"`,
			reason:  "NotAcceptable",
			code:    406,

			simpleError: ErrWebhookCertificateFailure.Error(),
		},

		"validating webhook error (3rd party)": {
			message: `admission webhook "other-webhook.io" denied the request: [ERROR MESSAGE]`,
			reason:  "NotAcceptable",
			code:    406,

			simpleError: ErrFailedToCheckAPI.Error(),
		},
		"missing mutating webhook": {
			message: `admission webhook "webhook.cert-manager.io" denied the request: [spec.username: Forbidden: username identity must be that of the requester, spec.groups: Forbidden: groups identity must be that of the requester]`,
			reason:  "NotAcceptable",
			code:    406,

			simpleError: ErrMutationWebhookIncorrect.Error(),
		},
		"validating webhook error": {
			message: `admission webhook "webhook.cert-manager.io" denied the request: spec.request: Invalid value: []byte{0x00}: error decoding certificate request PEM block`,
			reason:  "NotAcceptable",
			code:    406,

			simpleError: ErrMutationWebhookIncorrect.Error(),
		},

		"unknown error": {
			message: `UNKNOWN ERROR`,
			reason:  "InternalError",
			code:    500,
		},
	} {
		tests["valid_failure_"+name] = testT{
			createValidResponse: func(t *testing.T, r *http.Request) (int, []byte) {
				byteResponse, err := json.Marshal(map[string]interface{}{
					"kind":       "Status",
					"apiVersion": "v1",
					"metadata":   map[string]interface{}{},
					"status":     "Failure",
					"message":    test.message,
					"reason":     test.reason,
					"code":       test.code,
				})
				if err != nil {
					t.Error(err)
				}
				return test.code, byteResponse
			},
			expectedError:       test.message,
			expectedSimpleError: test.simpleError,
		}
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// fake https server to simulate the Kubernetes API server responses
			mockKubernetesAPI := func(t *testing.T, r *http.Request) (int, []byte) {
				switch r.URL.Path {
				case "/apis/cert-manager.io/v1":
					if test.discoveryResponse != nil {
						return test.discoveryResponse(t, r)
					}

					return http.StatusOK, []byte(`{
						"kind":"APIResourceList",
						"apiVersion":"v1",
						"groupVersion":"cert-manager.io/v1",
						"resources":[
							{
								"name":"certificaterequests",
								"singularName":"certificaterequest",
								"namespaced":true,
								"kind":"CertificateRequest",
								"verbs":["delete","deletecollection","get","list","patch","create","update","watch"],
								"shortNames":["cr","crs"],
								"categories":["cert-manager"],
								"storageVersionHash":"tuxiikMaACg="
							},
							{
								"name":"certificaterequests/status",
								"singularName":"",
								"namespaced":true,
								"kind":"CertificateRequest",
								"verbs":["get","patch","update"]
							}
						]
					}`)
				case "/apis/cert-manager.io/v1/namespaces/test-namespace/certificaterequests":
					obj := metav1.PartialObjectMetadata{}
					if err := json.NewDecoder(r.Body).Decode(&obj); err != nil {
						t.Errorf("failed to decode request body: %v", err)
					}

					switch obj.GenerateName {
					case "cmapichecker-valid-":
						if test.createValidResponse != nil {
							return test.createValidResponse(t, r)
						}

						return http.StatusOK, []byte(crAfterMutation)
					case "cmapichecker-invalid-":
						if test.createInvalidResponse != nil {
							return test.createInvalidResponse(t, r)
						}

						return http.StatusNotAcceptable, []byte(`{
							"kind":"Status",
							"apiVersion":"v1",
							"metadata":{},
							"status":"Failure",
							"message":"admission webhook \"webhook.cert-manager.io\" denied the request: [ERROR MESSAGE]",
							"reason":"NotAcceptable",
							"code":406
						}`)
					}
				default:
				}

				return http.StatusNotFound, nil
			}
			testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				statusCode, content := mockKubernetesAPI(t, r)
				w.WriteHeader(statusCode)
				if content == nil {
					return
				}

				if _, err := w.Write(content); err != nil {
					t.Errorf("failed to write response: %v", err)
				}
			}))
			t.Cleanup(testServer.Close)

			restConfig := &rest.Config{
				Host: testServer.URL,
			}
			checker, err := NewForConfigAndClient(restConfig, testServer.Client(), "test-namespace")
			if err != nil {
				t.Fatalf("failed to create checker: %v", err)
			}

			for i := 0; i < 10; i++ {
				t.Logf("# check %d", i)

				err = checker.Check(context.Background())
				switch {
				case err == nil && test.expectedError == "":
				case err == nil && test.expectedError != "":
					t.Errorf("expected error %q, got nil", test.expectedError)
				case err.Error() != test.expectedError:
					t.Errorf("expected error %q, got %q", test.expectedError, err.Error())
				}

				simpleErr := TranslateToSimpleError(err)
				switch {
				case simpleErr == nil && test.expectedSimpleError == "":
				case simpleErr == nil && test.expectedSimpleError != "":
					t.Errorf("expected error %q, got nil", test.expectedSimpleError)
				case simpleErr.Error() != test.expectedSimpleError:
					t.Errorf("expected error %q, got %q", test.expectedSimpleError, simpleErr.Error())
				}
			}
		})
	}
}
