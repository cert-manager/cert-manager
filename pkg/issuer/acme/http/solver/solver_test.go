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

package solver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
)

func TestSolver(t *testing.T) {
	cases := map[string]struct {
		solverPort           int
		solverDomain         string
		solverToken          string
		solverKey            string
		requestTarget        string
		expectedResponseCode int
	}{
		"return ok if healthcheck url - /": {
			requestTarget:        "/",
			expectedResponseCode: http.StatusOK,
		},
		"return ok if healthcheck url - /healthz": {
			requestTarget:        "/",
			expectedResponseCode: http.StatusOK,
		},
		"return not found if not-challenge url reached": {
			requestTarget:        "/test",
			expectedResponseCode: http.StatusNotFound,
		},
		"return not found if tokens do not match": {
			solverDomain:         "www.example.com",
			solverToken:          "not-secret",
			requestTarget:        "http://www.example.com" + HTTPChallengePath + "/secret",
			expectedResponseCode: http.StatusNotFound,
		},
		"return not found if domains do not match": {
			solverDomain:         "www.example2.com",
			solverToken:          "secret",
			requestTarget:        "http://www.example.com" + HTTPChallengePath + "/secret",
			expectedResponseCode: http.StatusNotFound,
		},
		"return ok if domain and token match": {
			solverDomain:         "www.example.com",
			solverToken:          "secret",
			solverKey:            "test-key",
			requestTarget:        "http://www.example.com" + HTTPChallengePath + "/secret",
			expectedResponseCode: http.StatusOK,
		},
		"return ok with ipv4": {
			solverPort:           8080,
			solverDomain:         "192.168.1.1",
			solverToken:          "secret",
			solverKey:            "test-key",
			requestTarget:        "http://192.168.1.1:8080" + HTTPChallengePath + "/secret",
			expectedResponseCode: http.StatusOK,
		},
		"return ok with ipv4 when request goes through proxy": {
			solverPort:           8080,
			solverDomain:         "192.168.1.1",
			solverToken:          "secret",
			solverKey:            "test-key",
			requestTarget:        "http://192.168.1.1:80" + HTTPChallengePath + "/secret",
			expectedResponseCode: http.StatusOK,
		},
		"return ok with ipv4 without specified port in the request": {
			solverPort:           80,
			solverDomain:         "192.168.1.1",
			solverToken:          "secret",
			solverKey:            "test-key",
			requestTarget:        "http://192.168.1.1" + HTTPChallengePath + "/secret",
			expectedResponseCode: http.StatusOK,
		},
		"return ok with ipv6": {
			solverPort:           1234,
			solverDomain:         "2001:db8:3333:4444:5555:6666:7777:8888",
			solverToken:          "secret",
			solverKey:            "test-key",
			requestTarget:        "http://[2001:db8:3333:4444:5555:6666:7777:8888]:1234" + HTTPChallengePath + "/secret",
			expectedResponseCode: http.StatusOK,
		},
		"return ok with ipv6 - 2": {
			solverPort:           1234,
			solverDomain:         "2a00:8a00:4000:435::13a",
			solverToken:          "secret",
			solverKey:            "test-key",
			requestTarget:        "http://[2a00:8a00:4000:435::13a]:1234" + HTTPChallengePath + "/secret",
			expectedResponseCode: http.StatusOK,
		},
		"return ok with ipv6 without specified port in the request": {
			solverPort:           80,
			solverDomain:         "2001:db8:3333:4444:5555:6666:7777:8888",
			solverToken:          "secret",
			solverKey:            "test-key",
			requestTarget:        "http://2001:db8:3333:4444:5555:6666:7777:8888" + HTTPChallengePath + "/secret",
			expectedResponseCode: http.StatusOK,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			solver := HTTP01Solver{
				ListenPort: tc.solverPort,
				Domain:     tc.solverDomain,
				Token:      tc.solverToken,
				Key:        tc.solverKey,
			}

			r := httptest.NewRequest(http.MethodGet, tc.requestTarget, nil)
			w := httptest.NewRecorder()

			solver.challengeHandler(logr.Discard()).ServeHTTP(w, r)

			if w.Code != tc.expectedResponseCode {
				t.Errorf("Expected response code %d, got %d", tc.expectedResponseCode, w.Code)
			}
			response := w.Body.String()
			if tc.solverKey != "" && response != tc.solverKey {
				t.Errorf("Expected response body %q, got %q", tc.solverKey, response)
			}
		})
	}
}

func Test_parseHost(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    string
		expected string
	}{
		"FQDN with port": {
			input:    "example.com:8080",
			expected: "example.com",
		},
		"FQDN without port": {
			input:    "example.com",
			expected: "example.com",
		},
		"IPv4 address with port": {
			input:    "192.168.1.1:8080",
			expected: "192.168.1.1",
		},
		"IPv4 address without port": {
			input:    "192.168.1.1",
			expected: "192.168.1.1",
		},
		"IPv6 address with port": {
			input:    "[2001:db8:3333:4444:5555:6666:7777:8888]:1234",
			expected: "2001:db8:3333:4444:5555:6666:7777:8888",
		},
		"IPv6 address with port - 2": {
			input:    "[2a00:8a00:4000:435::13a]:1234",
			expected: "2a00:8a00:4000:435::13a",
		},
		"IPv6 address without port": {
			input:    "[2001:db8:3333:4444:5555:6666:7777:8888]",
			expected: "2001:db8:3333:4444:5555:6666:7777:8888",
		},
		"IPv6 address without bracket": {
			input:    "2001:db8:3333:4444:5555:6666:7777:8888",
			expected: "2001:db8:3333:4444:5555:6666:7777:8888",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			actual := parseHost(tc.input)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
