package lightsail

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

func newMockServer(t *testing.T, responses map[string]MockResponse) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		resp, ok := responses[path]
		if !ok {
			msg := fmt.Sprintf("Requested path not found in response map: %s", path)
			require.FailNow(t, msg)
		}

		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(resp.StatusCode)
		_, err := w.Write([]byte(resp.Body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))

	time.Sleep(100 * time.Millisecond)
	return ts
}
