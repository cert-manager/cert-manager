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

package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	flowcontrolapi "k8s.io/api/flowcontrol/v1"
	"k8s.io/client-go/rest"
)

func Test_NewContextFactory(t *testing.T) {
	ctxFactory, err := NewContextFactory(t.Context(), ContextOptions{
		APIServerHost:      "localhost:8443",
		KubernetesAPIQPS:   10,
		KubernetesAPIBurst: 10,
	})
	assert.NoError(t, err)

	// Ensure a single RateLimiter is preserved across Contexts.
	ctx1, err := ctxFactory.Build("test-1")
	assert.NoError(t, err)
	ctx2, err := ctxFactory.Build("test-2")
	assert.NoError(t, err)

	assert.NotNil(t, ctx1.RESTConfig.RateLimiter)
	assert.Same(t, ctx1.RESTConfig.RateLimiter, ctx2.RESTConfig.RateLimiter)
}

func Test_isAPFEnabled(t *testing.T) {
	testCases := []struct {
		name            string
		responseHeaders map[string]string
		statusCode      int
		expectedEnabled bool
	}{
		{
			name: "APF header present indicates enabled",
			responseHeaders: map[string]string{
				flowcontrolapi.ResponseHeaderMatchedFlowSchemaUID: "unused-uuid",
			},
			statusCode:      http.StatusOK,
			expectedEnabled: true,
		},
		{
			name:            "no APF header indicates disabled",
			statusCode:      http.StatusOK,
			expectedEnabled: false,
		},
		{
			name: "APF header present with non-200 status still indicates enabled",
			responseHeaders: map[string]string{
				flowcontrolapi.ResponseHeaderMatchedFlowSchemaUID: "unused-uuid",
			},
			statusCode:      http.StatusInternalServerError,
			expectedEnabled: true,
		},
		{
			name:            "no APF header with non-200 status indicates disabled",
			statusCode:      http.StatusNotFound,
			expectedEnabled: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				assert.Equal(t, "/livez/ping", req.URL.Path)
				assert.Equal(t, http.MethodHead, req.Method)
				for k, v := range tc.responseHeaders {
					w.Header().Set(k, v)
				}
				w.WriteHeader(tc.statusCode)
			}))
			defer server.Close()

			enabled, err := isAPFEnabled(ctx, &rest.Config{Host: server.URL})
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedEnabled, enabled)
		})
	}
}

func Test_isAPFEnabled_invalidHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	enabled, err := isAPFEnabled(ctx, &rest.Config{Host: "://invalid"})
	assert.Error(t, err)
	assert.False(t, enabled)
}
