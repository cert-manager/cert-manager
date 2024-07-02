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

package rfc2136

import (
	"context"
	"testing"

	logtesting "github.com/go-logr/logr/testing"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/rfc2136"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	dns "github.com/cert-manager/cert-manager/test/acme"
	testserver "github.com/cert-manager/cert-manager/test/acme/server"
)

func TestRunSuiteWithTSIG(t *testing.T) {
	ctx := logf.NewContext(context.TODO(), logtesting.NewTestLogger(t), t.Name())
	server := &testserver.BasicServer{
		T:             t,
		Zones:         []string{rfc2136TestZone},
		EnableTSIG:    true,
		TSIGZone:      rfc2136TestZone,
		TSIGKeyName:   rfc2136TestTsigKeyName,
		TSIGKeySecret: rfc2136TestTsigSecret,
	}
	if err := server.Run(ctx); err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer func() {
		if err := server.Shutdown(); err != nil {
			t.Errorf("failed to gracefully shut down test server: %v", err)
		}
	}()

	var validConfig = cmacme.ACMEIssuerDNS01ProviderRFC2136{
		Nameserver: server.ListenAddr(),
		TSIGSecret: cmmeta.SecretKeySelector{
			LocalObjectReference: cmmeta.LocalObjectReference{
				Name: "testkey",
			},
			Key: "value",
		},
		TSIGKeyName: rfc2136TestTsigKeyName,
	}

	fixture := dns.NewFixture(rfc2136.New(rfc2136.InitializeResetLister()),
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
	ctx := logf.NewContext(context.TODO(), logtesting.NewTestLogger(t), t.Name())
	server := &testserver.BasicServer{
		T:     t,
		Zones: []string{rfc2136TestZone},
	}
	if err := server.Run(ctx); err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer func() {
		if err := server.Shutdown(); err != nil {
			t.Errorf("failed to gracefully shut down test server: %v", err)
		}
	}()

	var validConfig = cmacme.ACMEIssuerDNS01ProviderRFC2136{
		Nameserver: server.ListenAddr(),
	}

	fixture := dns.NewFixture(rfc2136.New(rfc2136.InitializeResetLister()),
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
