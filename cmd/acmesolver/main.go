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

package main

import (
	"flag"
	"log"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/http/solver"
	"github.com/jetstack/cert-manager/pkg/logs"
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
	logs.InitLogs()
	defer logs.FlushLogs()

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
