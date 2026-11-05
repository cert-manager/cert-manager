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
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	flowcontrolapi "k8s.io/api/flowcontrol/v1"
)

func Test_NewContextFactory(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set(flowcontrolapi.ResponseHeaderMatchedFlowSchemaUID, "unused-uuid")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	testCases := map[string]struct {
		qps                 float32
		burst               int
		expectedQPS         float32
		expectedBurst       int
		expectedRateLimiter bool
	}{
		"configured QPS and burst": {
			qps:                 10,
			burst:               20,
			expectedQPS:         10,
			expectedBurst:       20,
			expectedRateLimiter: true,
		},
		"client-go defaults": {
			qps:                 0,
			burst:               0,
			expectedQPS:         5,
			expectedBurst:       10,
			expectedRateLimiter: true,
		},
		"disabled rate limiting": {
			qps:                 -1,
			burst:               -1,
			expectedQPS:         -1,
			expectedBurst:       -1,
			expectedRateLimiter: false,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctxFactory, err := NewContextFactory(t.Context(), ContextOptions{
				APIServerHost:      server.URL,
				KubernetesAPIQPS:   tc.qps,
				KubernetesAPIBurst: tc.burst,
			})
			assert.NoError(t, err)

			// Ensure a single RateLimiter is preserved across Contexts.
			ctx1, err := ctxFactory.Build("test-1")
			assert.NoError(t, err)
			ctx2, err := ctxFactory.Build("test-2")
			assert.NoError(t, err)

			assert.Equal(t, tc.expectedQPS, ctx1.RESTConfig.QPS)
			assert.Equal(t, tc.expectedBurst, ctx1.RESTConfig.Burst)
			if tc.expectedRateLimiter {
				assert.NotNil(t, ctx1.RESTConfig.RateLimiter)
				assert.Same(t, ctx1.RESTConfig.RateLimiter, ctx2.RESTConfig.RateLimiter)
			} else {
				assert.Nil(t, ctx1.RESTConfig.RateLimiter)
				assert.Nil(t, ctx2.RESTConfig.RateLimiter)
			}
		})
	}

	assert.Zero(t, requests.Load())
}
