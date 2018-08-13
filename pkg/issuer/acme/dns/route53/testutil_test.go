/*
Copyright 2018 The Jetstack cert-manager contributors.

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

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

package route53

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// MockResponse represents a predefined response used by a mock server
type MockResponse struct {
	StatusCode int
	Body       string
}

// MockResponseMap maps request paths to responses
type MockResponseMap map[string]MockResponse

func newMockServer(t *testing.T, responses MockResponseMap) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		resp, ok := responses[path]
		if !ok {
			msg := fmt.Sprintf("Requested path not found in response map: %s", path)
			require.FailNow(t, msg)
		}

		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(resp.StatusCode)
		w.Write([]byte(resp.Body))
	}))

	time.Sleep(100 * time.Millisecond)
	return ts
}
