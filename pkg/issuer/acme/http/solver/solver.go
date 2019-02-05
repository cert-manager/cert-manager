/*
Copyright 2019 The Jetstack cert-manager contributors.

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
