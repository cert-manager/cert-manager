package cloudflare

import (
	"os"
	"testing"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/acme/dns"
)

var (
	zone = os.Getenv("CLOUDFLARE_ZONE")
	email = os.Getenv("CLOUDFLARE_EMAIL")
	apiKey = os.Getenv("CLOUDFLARE_API_KEY")
)

var validConfig = cmapi.ACMEIssuerDNS01ProviderCloudflare{
	Email: email,
	APIKey: cmapi.SecretKeySelector{
		LocalObjectReference: cmapi.LocalObjectReference{
			Name: "testing-api-key",
		},
		Key: "apikey",
	},
}

var apiKeySecret = &v1.Secret{
	ObjectMeta: metav1.ObjectMeta{
		Name: "testing-api-key",
	},
	Data: map[string][]byte{
		"apikey": []byte(apiKey),
	},
}

func TestRunsSuite(t *testing.T) {
	if apiKey == "" {
		t.Skip("skipping running test suite as api key is not provided")
	}
	if email == "" {
		t.Skip("skipping running test suite as email is not provided")
	}

	fixture := dns.NewFixture(&Solver{},
		dns.SetResolvedZone(zone),
		dns.SetAllowAmbientCredentials(false),
		dns.SetConfig(validConfig),
		dns.AddSecretFixture(apiKeySecret),
	)

	fixture.RunConformance(t)
}
