package rfc2136

import (
	"testing"

	dnslib "github.com/miekg/dns"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/acme/dns"
)

func TestRunSuiteWithTSIG(t *testing.T) {
	dnslib.HandleFunc(rfc2136TestZone, (&basicStatefulServer{}).serverHandlerPassBackRequest)
	defer dnslib.HandleRemove(rfc2136TestZone)

	server, addrstr, err := runLocalDNSTestServer("127.0.0.1:0", true)
	if err != nil {
		t.Errorf("error starting test dns server: %v", err)
		t.FailNow()
	}
	defer server.Shutdown()

	var validConfig = cmapi.ACMEIssuerDNS01ProviderRFC2136{
		Nameserver: addrstr,
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
		dns.SetDNSServer(addrstr),
		dns.SetManifestPath("testdata"),
		// Disable recursive NS lookups as we run a single authoritative NS per test
		dns.SetUseAuthoritative(false),
	)

	fixture.RunConformance(t)
}

func TestRunSuiteNoTSIG(t *testing.T) {
	dnslib.HandleFunc(rfc2136TestZone, (&basicStatefulServer{}).serverHandlerPassBackRequest)
	defer dnslib.HandleRemove(rfc2136TestZone)

	server, addrstr, err := runLocalDNSTestServer("127.0.0.1:0", false)
	if err != nil {
		t.Errorf("error starting test dns server: %v", err)
		t.FailNow()
	}
	defer server.Shutdown()

	var validConfig = cmapi.ACMEIssuerDNS01ProviderRFC2136{
		Nameserver: addrstr,
	}

	fixture := dns.NewFixture(&Solver{},
		dns.SetResolvedZone(rfc2136TestZone),
		dns.SetResolvedFQDN(rfc2136TestFqdn),
		dns.SetAllowAmbientCredentials(false),
		dns.SetConfig(validConfig),
		dns.SetDNSServer(addrstr),
		dns.SetManifestPath("testdata"),
		// Disable recursive NS lookups as we run a single authoritative NS per test
		dns.SetUseAuthoritative(false),
	)

	fixture.RunConformance(t)
}
