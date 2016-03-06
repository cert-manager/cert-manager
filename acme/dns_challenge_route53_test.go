package acme

import (
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/mitchellh/goamz/aws"
	"github.com/mitchellh/goamz/route53"
	"github.com/mitchellh/goamz/testutil"
	"github.com/stretchr/testify/assert"
)

var (
	route53Secret     string
	route53Key        string
	awsCredentialFile string
	homeDir           string
	testServer        *testutil.HTTPServer
)

var ChangeResourceRecordSetsAnswer = `<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
   <ChangeInfo>
      <Id>/change/asdf</Id>
      <Status>PENDING</Status>
      <SubmittedAt>2014</SubmittedAt>
   </ChangeInfo>
</ChangeResourceRecordSetsResponse>`

var ListHostedZonesAnswer = `<?xml version="1.0" encoding="utf-8"?>
<ListHostedZonesResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
    <HostedZones>
        <HostedZone>
            <Id>/hostedzone/Z2K123214213123</Id>
            <Name>example.com.</Name>
            <CallerReference>D2224C5B-684A-DB4A-BB9A-E09E3BAFEA7A</CallerReference>
            <Config>
                <Comment>Test comment</Comment>
            </Config>
            <ResourceRecordSetCount>10</ResourceRecordSetCount>
        </HostedZone>
        <HostedZone>
            <Id>/hostedzone/ZLT12321321124</Id>
            <Name>sub.example.com.</Name>
            <CallerReference>A970F076-FCB1-D959-B395-96474CC84EB8</CallerReference>
            <Config>
                <Comment>Test comment for subdomain host</Comment>
            </Config>
            <ResourceRecordSetCount>4</ResourceRecordSetCount>
        </HostedZone>
    </HostedZones>
    <IsTruncated>false</IsTruncated>
    <MaxItems>100</MaxItems>
</ListHostedZonesResponse>`

var GetChangeAnswer = `<?xml version="1.0" encoding="UTF-8"?>
<GetChangeResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
   <ChangeInfo>
      <Id>/change/asdf</Id>
      <Status>INSYNC</Status>
      <SubmittedAt>2016-02-03T01:36:41.958Z</SubmittedAt>
   </ChangeInfo>
</GetChangeResponse>`

var serverResponseMap = testutil.ResponseMap{
	"/2013-04-01/hostedzone/":                      testutil.Response{Status: 200, Headers: nil, Body: ListHostedZonesAnswer},
	"/2013-04-01/hostedzone/Z2K123214213123/rrset": testutil.Response{Status: 200, Headers: nil, Body: ChangeResourceRecordSetsAnswer},
	"/2013-04-01/change/asdf":                      testutil.Response{Status: 200, Headers: nil, Body: GetChangeAnswer},
}

func init() {
	route53Key = os.Getenv("AWS_ACCESS_KEY_ID")
	route53Secret = os.Getenv("AWS_SECRET_ACCESS_KEY")
	awsCredentialFile = os.Getenv("AWS_CREDENTIAL_FILE")
	homeDir = os.Getenv("HOME")
	testServer = testutil.NewHTTPServer()
	testServer.Start()
}

func restoreRoute53Env() {
	os.Setenv("AWS_ACCESS_KEY_ID", route53Key)
	os.Setenv("AWS_SECRET_ACCESS_KEY", route53Secret)
	os.Setenv("AWS_CREDENTIAL_FILE", awsCredentialFile)
	os.Setenv("HOME", homeDir)
}

func makeRoute53TestServer() *testutil.HTTPServer {
	testServer.Flush()
	return testServer
}

func makeRoute53Provider(server *testutil.HTTPServer) *DNSProviderRoute53 {
	auth := aws.Auth{AccessKey: "abc", SecretKey: "123", Token: ""}
	client := route53.NewWithClient(auth, aws.Region{Route53Endpoint: server.URL}, testutil.DefaultClient)
	return &DNSProviderRoute53{client: client}
}

func TestNewDNSProviderRoute53Valid(t *testing.T) {
	os.Setenv("AWS_ACCESS_KEY_ID", "")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "")
	_, err := NewDNSProviderRoute53("123", "123", "us-east-1")
	assert.NoError(t, err)
	restoreRoute53Env()
}

func TestNewDNSProviderRoute53ValidEnv(t *testing.T) {
	os.Setenv("AWS_ACCESS_KEY_ID", "123")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "123")
	_, err := NewDNSProviderRoute53("", "", "us-east-1")
	assert.NoError(t, err)
	restoreRoute53Env()
}

func TestNewDNSProviderRoute53MissingAuthErr(t *testing.T) {
	os.Setenv("AWS_ACCESS_KEY_ID", "")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "")
	os.Setenv("AWS_CREDENTIAL_FILE", "") // in case test machine has this variable set
	os.Setenv("HOME", "/")               // in case test machine has ~/.aws/credentials

	// The default AWS HTTP client retries three times with a deadline of 10 seconds.
	// Replace the default HTTP client with one that does not retry and has a low timeout.
	awsClient := aws.RetryingClient
	aws.RetryingClient = &http.Client{Timeout: time.Millisecond}

	_, err := NewDNSProviderRoute53("", "", "us-east-1")
	assert.EqualError(t, err, "No valid AWS authentication found")
	restoreRoute53Env()

	// restore default AWS HTTP client
	aws.RetryingClient = awsClient
}

func TestNewDNSProviderRoute53InvalidRegionErr(t *testing.T) {
	_, err := NewDNSProviderRoute53("123", "123", "us-east-3")
	assert.EqualError(t, err, "Invalid AWS region name us-east-3")
}

func TestRoute53Present(t *testing.T) {
	assert := assert.New(t)
	testServer := makeRoute53TestServer()
	provider := makeRoute53Provider(testServer)
	testServer.ResponseMap(3, serverResponseMap)

	domain := "example.com"
	keyAuth := "123456d=="

	err := provider.Present(domain, "", keyAuth)
	assert.NoError(err, "Expected Present to return no error")

	httpReqs := testServer.WaitRequests(3)
	httpReq := httpReqs[1]

	assert.Equal("/2013-04-01/hostedzone/Z2K123214213123/rrset", httpReq.URL.Path,
		"Expected Present to select the correct hostedzone")

}
