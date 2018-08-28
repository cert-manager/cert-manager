package conformance

import (
	"fmt"
	"time"

	"github.com/pkg/errors"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/acmedns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/akamai"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/azuredns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/clouddns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/cloudflare"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/route53"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

type solver interface {
	Present(domain, token, key string) error
	CleanUp(domain, token, key string) error
	Timeout() (timeout, interval time.Duration)
}

var DNS01Nameservers = []string{"8.8.8.8:53"}

type Config struct {
	Domain             string
	ServiceAccountFile string
	Project            string
}

func CheckDNS(domain, key string) error {

	for {
		fqdn, value, ttl, err := util.DNS01Record(domain, key, DNS01Nameservers)
		if err != nil {
			panic(err)
		}

		fmt.Printf("Checking DNS propagation for %q using name servers: %v\n", domain, DNS01Nameservers)

		ok, err := util.PreCheckDNS(fqdn, value, DNS01Nameservers)
		if err != nil {
			panic(err)
		}
		if !ok {
			fmt.Printf("DNS record for %q not yet propagated\n", domain)
			time.Sleep(time.Second * time.Duration(ttl))
			continue
		}
		break
	}
	return nil
}

func SolverForIssuerProvider(provider string, config Config) (solver, error) {
	var impl solver
	var err error

	switch provider {
	case "akamai":
		clientToken := ""

		clientSecret := ""

		accessToken := ""

		serviceConsumerDomain := ""

		impl, err = akamai.NewDNSProvider(
			string(serviceConsumerDomain),
			string(clientToken),
			string(clientSecret),
			string(accessToken),
			DNS01Nameservers)
		if err != nil {
			return nil, errors.Wrap(err, "error instantiating akamai challenge solver")
		}
	case "clouddns":
		impl, err = clouddns.NewDNSProviderServiceAccount(config.Project, config.ServiceAccountFile, DNS01Nameservers)
		if err != nil {
			return nil, fmt.Errorf("error instantiating google clouddns challenge solver: %s", err)
		}
	case "cloudflare":
		email := ""
		apiKey := ""

		impl, err = cloudflare.NewDNSProviderCredentials(email, apiKey, DNS01Nameservers)
		if err != nil {
			return nil, fmt.Errorf("error instantiating cloudflare challenge solver: %s", err)
		}
	case "route53":
		accessKeyID := ""
		secretAccessKey := ""
		hostedZoneID := ""
		region := ""

		impl, err = route53.NewDNSProvider(
			accessKeyID,
			secretAccessKey,
			hostedZoneID,
			region,
			false,
			DNS01Nameservers,
		)
		if err != nil {
			return nil, fmt.Errorf("error instantiating route53 challenge solver: %s", err)
		}
	case "azuredns":
		clientSecret := ""
		clientID := ""

		subscriptionID := ""
		tenantID := ""
		resourceGroupName := ""
		hostedZoneName := ""

		impl, err = azuredns.NewDNSProviderCredentials(
			clientID,
			clientSecret,
			subscriptionID,
			tenantID,
			resourceGroupName,
			hostedZoneName,
			DNS01Nameservers,
		)
	case "acmedns":
		host := ""
		accountSecret := ""

		impl, err = acmedns.NewDNSProviderHostBytes(
			host,
			[]byte(accountSecret),
			DNS01Nameservers,
		)
	default:
		return nil, fmt.Errorf("no dns provider config specified for provider %q", provider)
	}

	return impl, nil
}
