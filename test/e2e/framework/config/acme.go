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

package config

import (
	"flag"
)

type ACMEServer struct {
	URL                         string
	DNSServer                   string
	IngressIP                   string
	GatewayIP                   string
	InvalidACMEURL              string
	TestingACMEEmail            string
	TestingACMEEmailAlternative string
	TestingACMEPrivateKey       string
}

func (p *ACMEServer) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&p.URL, "acme-server-url", "https://pebble.pebble.svc.cluster.local/dir", "URL for the ACME server used during end-to-end tests")
	fs.StringVar(&p.DNSServer, "acme-dns-server", "10.0.0.16", "DNS server for ACME DNS01 tests to run against using RFC2136")
	fs.StringVar(&p.IngressIP, "acme-ingress-ip", "10.0.0.15", "IP of the ingress server that solves HTTP01 ACME challenges")
	fs.StringVar(&p.GatewayIP, "acme-gateway-ip", "10.0.0.14", "IP of the Gateway listener that solves HTTP01 ACME challenges")
	fs.StringVar(&p.InvalidACMEURL, "invalid-acme-url", "http://not-a-real-acme-url.com", "An invalid URL to be used during end-to-end tests")
	fs.StringVar(&p.TestingACMEEmail, "testing-acme-email", "test@example.com", "Email to be used for the tests")
	fs.StringVar(&p.TestingACMEEmailAlternative, "testing-acme-email-alternative", "another-test@example.com", "Alternate email to be used for the tests")
	fs.StringVar(&p.TestingACMEPrivateKey, "testing-acme-private-key", "test-acme-private-key", "Private key for the ACME tests")
}

func (p *ACMEServer) Validate() []error {
	return nil
}
