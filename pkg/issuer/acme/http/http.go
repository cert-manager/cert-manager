package http

import (
	"fmt"
	"net/http"
	"path"
	"strings"
	"sync"
)

// Challenge is a Host/Token pair that is used for verify ownership of domains
type challenge struct {
	host, token string
}

// httpSolver is an ACME HTTP-01 challenge solver. It will listen on a given
// port and respond with the appropriate response given the listen of valid
// Challenge structures registered with it.
type httpSolver struct {
	// challenges is a list of challenge resources to validate
	challenges []challenge
	// challengeMutex is used to guarantee sync between different goroutines
	// accessing the list of valid challenges
	challengeMutex sync.Mutex
	// ListenPort is the port cert-manager should listen on for ACME HTTP-01
	// challenge requests
	ListenPort int
}

// AddChallenge will add a challenge structure to the list of valid challenges
func (h *httpSolver) addChallenge(c challenge) {
	h.challengeMutex.Lock()
	defer h.challengeMutex.Unlock()
	h.challenges = append(h.challenges, c)
}

// Listen will begin listening for connections on the given port, and
// validating requests that contain a valid domain, path & token
func (h *httpSolver) listen() error {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.challengeMutex.Lock()
		defer h.challengeMutex.Unlock()

		// extract vars from the request
		host := strings.Split(r.Host, ":")[0]
		basePath := path.Dir(r.URL.EscapedPath())
		token := path.Base(r.URL.EscapedPath())

		// verify the base path is correct
		if basePath != HTTPChallengePath {
			http.NotFound(w, r)
			return
		}

		for i, c := range h.challenges {
			// if either the host or the token don't match what is expected,
			// we should continue to the next loop iteration
			if c.host != host || c.token != token {
				continue
			}

			// otherwise, this is a valid request and we're going to approve it
			w.WriteHeader(http.StatusOK)
			// remove this challenge from the list so we don't store indefinitely
			h.challenges = append(h.challenges[:i], h.challenges[i+1:]...)
			return
		}

		// if nothing else, we return a 404 here
		http.NotFound(w, r)
	})
	return http.ListenAndServe(fmt.Sprintf(":%d", h.ListenPort), handler)
}
