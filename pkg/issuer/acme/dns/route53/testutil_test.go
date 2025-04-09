// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

package route53

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// MockResponse represents a predefined response used by a mock server
type MockResponse struct {
	StatusCode int
	Body       string
}

// MockResponseMap maps request paths to responses
type MockResponseMap map[string]MockResponse

func newMockServer(t *testing.T, responses MockResponseMap) *httptest.Server {
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("%s: %s", r.Method, r.URL)
		path := r.URL.Path
		resp, ok := responses[path]
		if !ok {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("X-Amzn-Requestid", "SOMEREQUESTID")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write([]byte(resp.Body))
	}))
	time.Sleep(100 * time.Millisecond)
	return ts
}
