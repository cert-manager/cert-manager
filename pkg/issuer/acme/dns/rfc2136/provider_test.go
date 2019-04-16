package rfc2136

import (
	"testing"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/acme/dns"
)

//var apiKeySecret = &v1.Secret{
//	ObjectMeta: metav1.ObjectMeta{
//		Name: "testing-api-key",
//	},
//	Data: map[string][]byte{
//		"apikey": []byte(apiKey),
//	},
//}

func TestRunSuiteNoTSIG(t *testing.T) {
	//if apiKey == "" {
	//	t.Skip("skipping running test suite as api key is not provided")
	//}
	//if email == "" {
	//	t.Skip("skipping running test suite as email is not provided")
	//}

	_, addrstr, err := runLocalDNSTestServer("127.0.0.1:0", false)
	if err != nil {
		t.Errorf("error starting test dns server: %v", err)
		t.FailNow()
	}

	var validConfig = cmapi.ACMEIssuerDNS01ProviderRFC2136{
		Nameserver: addrstr,
	}

	fixture := dns.NewFixture(&Solver{},
		dns.SetResolvedZone("example.com"),
		dns.SetAllowAmbientCredentials(false),
		dns.SetConfig(validConfig),
		//dns.AddSecretFixture(apiKeySecret),
	)

	fixture.RunConformance(t)
}
