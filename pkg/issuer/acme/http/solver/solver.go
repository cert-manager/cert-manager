package solver

import (
	"fmt"
	"log"
	"net/http"
	"path"
	"strings"
)

type HTTP01Solver struct {
	ListenPort int

	Domain string
	Token  string
	Key    string
}

func (h *HTTP01Solver) Listen() error {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// extract vars from the request
		host := strings.Split(r.Host, ":")[0]
		basePath := path.Dir(r.URL.EscapedPath())
		token := path.Base(r.URL.EscapedPath())

		if r.URL.EscapedPath() == "/" || r.URL.EscapedPath() == "/healthz" {
			log.Printf("[%s] Responding OK to health check '%s'", h.Domain, r.URL.EscapedPath())
			w.WriteHeader(http.StatusOK)
			return
		}

		log.Printf("[%s] Validating request. basePath=%s, token=%s", h.Domain, basePath, token)
		// verify the base path is correct
		if basePath != HTTPChallengePath {
			log.Printf("[%s] Invalid basePath, got '%s' but expected '%s'", h.Domain, basePath, HTTPChallengePath)
			http.NotFound(w, r)
			return
		}

		log.Printf("[%s] Comparing actual host '%s' against expected '%s'", host, host, h.Domain)

		if h.Domain != host {
			log.Printf("[%s] Invalid host '%s'", h.Domain, host)
			http.NotFound(w, r)
			return
		}

		if h.Token != token {
			// if nothing else, we return a 404 here
			log.Printf("[%s] Invalid token '%s', expected: '%s'", h.Domain, token, h.Token)
			http.NotFound(w, r)
			return
		}

		log.Printf("[%s] Got successful challenge request, writing key...", h.Domain)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, h.Key)
	})
	return http.ListenAndServe(fmt.Sprintf(":%d", h.ListenPort), handler)
}
