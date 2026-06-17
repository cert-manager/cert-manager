// +skip_license_check

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
		w.Header().Set("X-Amzn-Requestid", "SOMEREQUESTID")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write([]byte(resp.Body))
	}))

	time.Sleep(100 * time.Millisecond)
	return ts
}
