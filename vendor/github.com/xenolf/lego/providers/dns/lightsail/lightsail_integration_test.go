package lightsail

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lightsail"
	"github.com/stretchr/testify/require"
)

func TestLiveTTL(t *testing.T) {
	if !envTest.IsLiveTest() {
		t.Skip("skipping live test")
	}

	envTest.RestoreEnv()

	provider, err := NewDNSProvider()
	require.NoError(t, err)

	domain := envTest.GetDomain()

	err = provider.Present(domain, "foo", "bar")
	require.NoError(t, err)

	// we need a separate Lightsail client here as the one in the DNS provider is
	// unexported.
	fqdn := "_acme-challenge." + domain
	sess, err := session.NewSession()
	require.NoError(t, err)

	svc := lightsail.New(sess)
	require.NoError(t, err)

	defer func() {
		errC := provider.CleanUp(domain, "foo", "bar")
		if errC != nil {
			t.Log(errC)
		}
	}()

	params := &lightsail.GetDomainInput{
		DomainName: aws.String(domain),
	}

	resp, err := svc.GetDomain(params)
	require.NoError(t, err)

	entries := resp.Domain.DomainEntries
	for _, entry := range entries {
		if aws.StringValue(entry.Type) == "TXT" && aws.StringValue(entry.Name) == fqdn {
			return
		}
	}

	t.Fatalf("Could not find a TXT record for _acme-challenge.%s", domain)
}
