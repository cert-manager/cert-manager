package lightsail

import (
	"net/http/httptest"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lightsail"
	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/platform/tester"
)

var envTest = tester.NewEnvTest(
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_REGION",
	"AWS_HOSTED_ZONE_ID").
	WithDomain("DNS_ZONE").
	WithLiveTestRequirements("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "DNS_ZONE")

func makeProvider(ts *httptest.Server) (*DNSProvider, error) {
	config := &aws.Config{
		Credentials: credentials.NewStaticCredentials("abc", "123", " "),
		Endpoint:    aws.String(ts.URL),
		Region:      aws.String("mock-region"),
		MaxRetries:  aws.Int(1),
	}

	sess, err := session.NewSession(config)
	if err != nil {
		return nil, err
	}

	conf := NewDefaultConfig()

	client := lightsail.New(sess)
	return &DNSProvider{client: client, config: conf}, nil
}

func TestCredentialsFromEnv(t *testing.T) {
	defer envTest.RestoreEnv()
	envTest.ClearEnv()

	os.Setenv("AWS_ACCESS_KEY_ID", "123")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "123")
	os.Setenv("AWS_REGION", "us-east-1")

	config := &aws.Config{
		CredentialsChainVerboseErrors: aws.Bool(true),
	}

	sess, err := session.NewSession(config)
	require.NoError(t, err)

	_, err = sess.Config.Credentials.Get()
	require.NoError(t, err, "Expected credentials to be set from environment")
}

func TestDNSProvider_Present(t *testing.T) {
	mockResponses := map[string]MockResponse{
		"/": {StatusCode: 200, Body: ""},
	}

	ts := newMockServer(t, mockResponses)
	defer ts.Close()

	provider, err := makeProvider(ts)
	require.NoError(t, err)

	domain := "example.com"
	keyAuth := "123456d=="

	err = provider.Present(domain, "", keyAuth)
	require.NoError(t, err, "Expected Present to return no error")
}
