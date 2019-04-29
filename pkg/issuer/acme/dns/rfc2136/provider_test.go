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

package rfc2136

import (
	"testing"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/test/acme/dns"
	testserver "github.com/jetstack/cert-manager/test/acme/dns/server"
)

func TestRunSuiteWithTSIG(t *testing.T) {
	ctx := logf.NewContext(nil, nil, t.Name())
	server := &testserver.BasicServer{
		Zones:         []string{rfc2136TestZone},
		EnableTSIG:    true,
		TSIGZone:      rfc2136TestZone,
		TSIGKeyName:   rfc2136TestTsigKeyName,
		TSIGKeySecret: rfc2136TestTsigSecret,
	}
	if err := server.Run(ctx); err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer server.Shutdown()

	var validConfig = cmapi.ACMEIssuerDNS01ProviderRFC2136{
		Nameserver: server.ListenAddr(),
		TSIGSecret: cmapi.SecretKeySelector{
			LocalObjectReference: cmapi.LocalObjectReference{
				Name: "testkey",
			},
			Key: "value",
		},
		TSIGKeyName: rfc2136TestTsigKeyName,
	}

	fixture := dns.NewFixture(&Solver{},
		dns.SetResolvedZone(rfc2136TestZone),
		dns.SetResolvedFQDN(rfc2136TestFqdn),
		dns.SetAllowAmbientCredentials(false),
		dns.SetConfig(validConfig),
		dns.SetDNSServer(server.ListenAddr()),
		dns.SetManifestPath("testdata"),
		// Disable recursive NS lookups as we run a single authoritative NS per test
		dns.SetUseAuthoritative(false),
	)

	fixture.RunConformance(t)
}

func TestRunSuiteNoTSIG(t *testing.T) {
	ctx := logf.NewContext(nil, nil, t.Name())
	server := &testserver.BasicServer{
		Zones: []string{rfc2136TestZone},
	}
	if err := server.Run(ctx); err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer server.Shutdown()

	var validConfig = cmapi.ACMEIssuerDNS01ProviderRFC2136{
		Nameserver: server.ListenAddr(),
	}

	fixture := dns.NewFixture(&Solver{},
		dns.SetResolvedZone(rfc2136TestZone),
		dns.SetResolvedFQDN(rfc2136TestFqdn),
		dns.SetAllowAmbientCredentials(false),
		dns.SetConfig(validConfig),
		dns.SetDNSServer(server.ListenAddr()),
		dns.SetManifestPath("testdata"),
		// Disable recursive NS lookups as we run a single authoritative NS per test
		dns.SetUseAuthoritative(false),
	)

	fixture.RunConformance(t)
}
