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
	"fmt"
	"net/http"
	"path"
	"strings"

	"github.com/go-logr/logr"
)

// HTTP01Solver is the HTTP server used to solve the ACME challenge
type HTTP01Solver struct {
	ListenPort int

	Domain string
	Token  string
	Key    string

	http.Server
}

// Listen performs all validations and serves a http Server based on values present
func (h *HTTP01Solver) Listen(log logr.Logger) error {
	log.Info("starting listener",
		"expected_domain", h.Domain,
		"expected_token", h.Token,
		"expected_key", h.Key,
		"listen_port", h.ListenPort,
	)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// extract vars from the request
		host := strings.Split(r.Host, ":")[0]
		basePath := path.Dir(r.URL.EscapedPath())
		token := path.Base(r.URL.EscapedPath())

		log := log.WithValues(
			"host", host,
			"path", r.URL.EscapedPath(),
			"base_path", basePath,
			"token", token,
		)
		if r.URL.EscapedPath() == "/" || r.URL.EscapedPath() == "/healthz" {
			log.Info("responding OK to health check")
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.WriteHeader(http.StatusOK)
			return
		}
		log.Info("validating request")
		// verify the base path is correct
		if basePath != HTTPChallengePath {
			log.Info("invalid base_path", "expected_base_path", HTTPChallengePath)
			http.NotFound(w, r)
			return
		}

		log.Info("comparing host", "expected_host", h.Domain)
		if h.Domain != host {
			log.Info("invalid host", "expected_host", h.Domain)
			http.NotFound(w, r)
			return
		}

		log.Info("comparing token", "expected_token", h.Token)
		if h.Token != token {
			// if nothing else, we return a 404 here
			log.Info("invalid token", "expected_token", h.Token)
			http.NotFound(w, r)
			return
		}

		log.Info("got successful challenge request, writing key")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, h.Key)
	})

	h.Server = http.Server{
		Addr:    fmt.Sprintf(":%d", h.ListenPort),
		Handler: handler,
	}

	return h.Server.ListenAndServe()
}
