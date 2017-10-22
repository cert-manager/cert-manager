package main

import (
	"flag"
	"log"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/http/solver"
)

// acmesolver solves ACME http-01 challenges. This is intended to run as a pod
// in the target kubernetes cluster in order to solve challenges for
// cert-manager.

var (
	listenPort = flag.Int("listen-port", 8089, "the port number to listen on for connections")
	domain     = flag.String("domain", "", "the domain name to verify")
	token      = flag.String("token", "", "the challenge token to verify against")
	key        = flag.String("key", "", "the challenge key to respond with")
)

func main() {
	flag.Parse()

	s := &solver.HTTP01Solver{
		ListenPort: *listenPort,
		Domain:     *domain,
		Token:      *token,
		Key:        *key,
	}

	if err := s.Listen(); err != nil {
		log.Fatalf("error listening for connections: %s", err.Error())
	}
}
