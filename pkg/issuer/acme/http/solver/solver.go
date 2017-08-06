package solver

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
)

const (
	CertManagerSelfTestParam = "selftest"
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

		log.Printf("got request for host %s, basePath %s, token %s", host, basePath, token)
		// verify the base path is correct
		if basePath != HTTPChallengePath {
			log.Printf("invalid basePath - expected %s", HTTPChallengePath)
			http.NotFound(w, r)
			return
		}

		log.Printf("comparing host %s against %s", host, h.Domain)
		// if either the host or the token don't match what is expected,
		// we should continue to the next loop iteration
		if h.Domain != host || h.Token != token {
			// if nothing else, we return a 404 here
			http.NotFound(w, r)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, h.Key)

		if r.URL.Query().Get(CertManagerSelfTestParam) == "" {
			os.Exit(0)
		}
	})
	return http.ListenAndServe(fmt.Sprintf(":%d", h.ListenPort), handler)
}
