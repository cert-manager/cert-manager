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
	"net/netip"
	"path"
	"strings"
	"time"

	"github.com/go-logr/logr"
)

const (
	// This is intended to mitigate "slowloris" attacks by limiting the time a
	// deliberately slow client can spend sending HTTP headers.
	// This default value is copied from:
	// * kubernetes api-server:
	//   https://github.com/kubernetes/kubernetes/blob/9e028b40b9e970142191259effe796b3dab39828/staging/src/k8s.io/apiserver/pkg/server/secure_serving.go#L165-L173
	// * controller-runtime:
	//   https://github.com/kubernetes-sigs/controller-runtime/blob/1ea2be573f7887a9fbd766e9a921c5af344da6eb/pkg/internal/httpserver/server.go#L14
	defaultReadHeaderTimeout = 32 * time.Second
)

type HTTP01Solver struct {
	ListenPort int

	Domain string
	Token  string
	Key    string

	http.Server
}

func (h *HTTP01Solver) Listen(log logr.Logger) error {
	log.Info("starting listener",
		"expected_domain", h.Domain,
		"expected_token", h.Token,
		"expected_key", h.Key,
		"listen_port", h.ListenPort,
	)

	h.Server = http.Server{
		Addr:              fmt.Sprintf(":%d", h.ListenPort),
		Handler:           h.challengeHandler(log),
		ReadHeaderTimeout: defaultReadHeaderTimeout, // Mitigation for G112: Potential slowloris attack
	}

	return h.Server.ListenAndServe()
}

func (h *HTTP01Solver) challengeHandler(log logr.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// extract vars from the request
		host := parseHost(r.Host)
		basePath := path.Dir(r.URL.EscapedPath())
		token := path.Base(r.URL.EscapedPath())

		log := log.WithValues(
			"host", host,
			"path", r.URL.EscapedPath(),
			"base_path", basePath,
			"token", token,
			"headers", r.Header,
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
	}
}

func parseHost(s string) string {
	// ip v4/v6 with port
	addrPort, err := netip.ParseAddrPort(s)
	if err == nil {
		return addrPort.Addr().String()
	}

	// ip v4/v6 without port
	addr, err := netip.ParseAddr(s)
	if err == nil {
		return addr.String()
	}

	host := strings.Split(s, ":")
	return host[0]
}
