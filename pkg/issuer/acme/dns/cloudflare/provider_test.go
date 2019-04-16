package cloudflare

import (
	"testing"

	"github.com/jetstack/cert-manager/test/acme/dns"
)

func TestRunsSuite(t *testing.T) {
	fixture := dns.NewFixture(&Solver{},
		dns.SetResolvedZone("k8s.co"),
		dns.SetAllowAmbientCredentials(false),
	)

	fixture.RunConformance(t)
}
