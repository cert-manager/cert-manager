/*
Copyright 2026 The cert-manager Authors.

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

package webhook

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
)

func TestDecodeStatusResponse(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		want *metav1.Status
	}{
		{
			name: "Kubernetes Status response",
			body: []byte(`{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"BadRequest","message":"invalid request"}`),
			want: &metav1.Status{
				TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"},
				Status:   metav1.StatusFailure,
				Reason:   metav1.StatusReasonBadRequest,
				Message:  "invalid request",
			},
		},
		{
			name: "failure without type metadata",
			body: []byte(`{"status":"Failure","message":"solver failed"}`),
			want: &metav1.Status{Status: metav1.StatusFailure, Message: "solver failed"},
		},
		{
			name: "challenge payload is not a Status response",
			body: []byte(`{"response":{"success":true}}`),
		},
		{
			name: "success marker without Status kind is not a failure",
			body: []byte(`{"status":"Success","message":"ok"}`),
		},
		{
			name: "malformed JSON",
			body: []byte(`{"kind":`),
		},
		{
			name: "empty body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, decodeStatusResponse(tt.body)); diff != "" {
				t.Errorf("decodeStatusResponse() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFormatStatusError(t *testing.T) {
	tests := []struct {
		name   string
		status *metav1.Status
		want   string
	}{
		{
			name:   "reason and message",
			status: &metav1.Status{Reason: metav1.StatusReasonBadRequest, Message: "invalid request"},
			want:   "BadRequest: invalid request",
		},
		{
			name:   "reason only",
			status: &metav1.Status{Reason: metav1.StatusReasonBadRequest},
			want:   "BadRequest",
		},
		{
			name:   "message only",
			status: &metav1.Status{Message: "invalid request"},
			want:   "invalid request",
		},
		{
			name:   "no details",
			status: &metav1.Status{},
		},
		{
			name: "nil status",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatStatusError(tt.status)
			if tt.want == "" {
				if got != nil {
					t.Fatalf("formatStatusError() = %v, want nil", got)
				}
				return
			}
			if got == nil || got.Error() != tt.want {
				t.Fatalf("formatStatusError() = %v, want %q", got, tt.want)
			}
		})
	}
}

func TestStatusResponseError(t *testing.T) {
	status := &metav1.Status{
		Reason:  metav1.StatusReasonBadRequest,
		Message: "invalid request",
	}

	t.Run("avoids duplicating the status message", func(t *testing.T) {
		got := statusResponseError(status, errors.New(status.Message))
		if got == nil || got.Error() != "BadRequest: invalid request" {
			t.Fatalf("statusResponseError() = %v, want %q", got, "BadRequest: invalid request")
		}
	})

	t.Run("includes a distinct request error", func(t *testing.T) {
		got := statusResponseError(status, errors.New("request failed"))
		if got == nil || !strings.Contains(got.Error(), "BadRequest: invalid request") || !strings.Contains(got.Error(), "request failed") {
			t.Fatalf("statusResponseError() = %v, want status details and request error", got)
		}
	})

	t.Run("reports Status without details", func(t *testing.T) {
		got := statusResponseError(&metav1.Status{}, nil)
		if got == nil || got.Error() != "webhook returned a Status response without a reason or message" {
			t.Fatalf("statusResponseError() = %v, want generic Status error", got)
		}
	})
}

func TestWebhookResponseHandling(t *testing.T) {
	tests := []struct {
		name           string
		action         v1alpha1.ChallengeAction
		statusCode     int
		responseBody   string
		wantErrorParts []string
	}{
		{
			name:         "Present accepts a successful ChallengePayload",
			action:       v1alpha1.ChallengeActionPresent,
			statusCode:   http.StatusOK,
			responseBody: `{"apiVersion":"webhook.acme.cert-manager.io/v1alpha1","kind":"ChallengePayload","response":{"success":true}}`,
		},
		{
			name:         "CleanUp accepts a successful ChallengePayload",
			action:       v1alpha1.ChallengeActionCleanUp,
			statusCode:   http.StatusOK,
			responseBody: `{"apiVersion":"webhook.acme.cert-manager.io/v1alpha1","kind":"ChallengePayload","response":{"success":true}}`,
		},
		{
			name:       "Present reports an HTTP Status response",
			action:     v1alpha1.ChallengeActionPresent,
			statusCode: http.StatusInternalServerError,
			responseBody: `{"apiVersion":"v1","kind":"Status","status":"Failure",` +
				`"reason":"InternalError","message":"provider failed"}`,
			wantErrorParts: []string{"InternalError", "provider failed"},
		},
		{
			name:       "CleanUp reports a Status response with HTTP 200",
			action:     v1alpha1.ChallengeActionCleanUp,
			statusCode: http.StatusOK,
			responseBody: `{"apiVersion":"v1","kind":"Status","status":"Failure",` +
				`"reason":"Forbidden","message":"cleanup denied"}`,
			wantErrorParts: []string{"Forbidden", "cleanup denied"},
		},
		{
			name:           "reports a Status nested in a ChallengePayload",
			action:         v1alpha1.ChallengeActionPresent,
			statusCode:     http.StatusOK,
			responseBody:   `{"apiVersion":"webhook.acme.cert-manager.io/v1alpha1","kind":"ChallengePayload","response":{"success":false,"status":{"status":"Failure","reason":"Invalid","message":"record rejected"}}}`,
			wantErrorParts: []string{"Invalid", "record rejected"},
		},
		{
			name:           "malformed response returns an error",
			action:         v1alpha1.ChallengeActionPresent,
			statusCode:     http.StatusOK,
			responseBody:   `{"kind":`,
			wantErrorParts: []string{"json parse error"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("request method = %q, want POST", r.Method)
				}

				var request v1alpha1.ChallengePayload
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Errorf("decoding request payload: %v", err)
				} else if request.Request == nil || request.Request.Action != tt.action {
					t.Errorf("request action = %v, want %q", request.Request, tt.action)
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			solver := &Webhook{}
			if err := solver.Initialize(&rest.Config{Host: server.URL}, nil); err != nil {
				t.Fatalf("initializing webhook client: %v", err)
			}

			challenge := &v1alpha1.ChallengeRequest{
				Config: &apiextensionsv1.JSON{Raw: []byte(`{"groupName":"webhook.acme.cert-manager.io","solverName":"test","config":{}}`)},
			}

			var err error
			switch tt.action {
			case v1alpha1.ChallengeActionPresent:
				err = solver.Present(challenge)
			case v1alpha1.ChallengeActionCleanUp:
				err = solver.CleanUp(challenge)
			default:
				t.Fatalf("unexpected action %q", tt.action)
			}

			if len(tt.wantErrorParts) == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected an error")
			}
			for _, part := range tt.wantErrorParts {
				if !strings.Contains(err.Error(), part) {
					t.Errorf("error %q does not contain %q", err, part)
				}
			}
		})
	}
}
