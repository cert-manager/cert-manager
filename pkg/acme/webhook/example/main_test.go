package main

import (
	"os"
	"testing"

	"github.com/jetstack/cert-manager/test/acme/dns"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
	// If your DNS provider requires credentials to authenticate, you can use
	// environment variables to obtain credentials and then utilise them in the
	// secret definition and validConfig structure below.
	//email = os.Getenv("CLOUDFLARE_EMAIL")
	//apiKey = os.Getenv("CLOUDFLARE_API_KEY")
)

// validConfig is a snippet of valid configuration that should be included on
// the ChallengeRequest passed as part of the test cases.
var validConfig = customDNSProviderConfig{
	//Email: email,
	//APIKey: cmapi.SecretKeySelector{
	//	LocalObjectReference: cmapi.LocalObjectReference{
	//		Name: "testing-api-key",
	//	},
	//	Key: "apikey",
	//},
}

//var apiKeySecret = &v1.Secret{
//	ObjectMeta: metav1.ObjectMeta{
//		Name: "testing-api-key",
//	},
//	Data: map[string][]byte{
//		"apikey": []byte(apiKey),
//	},
//}

func TestRunsSuite(t *testing.T) {
	//if apiKey == "" {
	//	t.Skip("skipping running test suite as api key is not provided")
	//}
	//if email == "" {
	//	t.Skip("skipping running test suite as email is not provided")
	//}

	fixture := dns.NewFixture(&customDNSProviderSolver{},
		dns.SetResolvedZone(zone),
		dns.SetAllowAmbientCredentials(false),
		dns.SetConfig(validConfig),
		//dns.AddSecretFixture(apiKeySecret),
	)

	fixture.RunConformance(t)
}
