package main

import (
	"flag"
	"fmt"

	"github.com/jetstack/cert-manager/test/conformance"
)

var (
	provider = flag.String("provider", "", "the provider to test")
	domain   = flag.String("domain", "", "the domain to use for tests")

	serviceAccountFilePath = flag.String("sa-account-file", "", "service account file")
	project                = flag.String("project", "", "project")
)

func main() {
	flag.Parse()

	conf := conformance.Config{
		Domain:             *domain,
		ServiceAccountFile: *serviceAccountFilePath,
		Project:            *project,
	}

	solver, err := conformance.SolverForIssuerProvider(*provider, conf)
	if err != nil {
		panic(err)
	}

	key := "toot"

	fmt.Printf("Presenting key '%s' on %s\n", key, *domain)

	err = solver.Present(*domain, "testingtoken", key)
	if err != nil {
		panic(err)
	}

	err = conformance.CheckDNS(*domain, key)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Checking '%s' on %s\n", key, *domain)

	err = solver.Present(*domain, "testingtoken", key)
	if err != nil {
		panic(err)
	}

}
