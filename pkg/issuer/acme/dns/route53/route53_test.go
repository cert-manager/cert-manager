// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

package route53

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

var (
	route53Secret string
	route53Key    string
	route53Region string
)

func init() {
	route53Key = os.Getenv("AWS_ACCESS_KEY_ID")
	route53Secret = os.Getenv("AWS_SECRET_ACCESS_KEY")
	route53Region = os.Getenv("AWS_REGION")
}

func restoreRoute53Env() {
	os.Setenv("AWS_ACCESS_KEY_ID", route53Key)
	os.Setenv("AWS_SECRET_ACCESS_KEY", route53Secret)
	os.Setenv("AWS_REGION", route53Region)
}

func makeRoute53Provider(ts *httptest.Server) (*DNSProvider, error) {
	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("abc", "123", " ")),
		config.WithEndpointResolverWithOptions(aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				URL: ts.URL,
			}, nil
		})),
		config.WithRegion("mock-region"),
		config.WithRetryMaxAttempts(1),
		config.WithHTTPClient(ts.Client()),
	)
	if err != nil {
		return nil, err
	}

	client := route53.NewFromConfig(cfg)
	return &DNSProvider{client: client, dns01Nameservers: util.RecursiveNameservers}, nil
}

func TestAmbientCredentialsFromEnv(t *testing.T) {
	os.Setenv("AWS_ACCESS_KEY_ID", "123")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "123")
	os.Setenv("AWS_REGION", "us-east-1")
	defer restoreRoute53Env()

	provider, err := NewDNSProvider("", "", "", "", "", true, util.RecursiveNameservers, "cert-manager-test")
	assert.NoError(t, err, "Expected no error constructing DNSProvider")

	_, err = provider.client.Options().Credentials.Retrieve(context.TODO())
	assert.NoError(t, err, "Expected credentials to be set from environment")

	assert.Equal(t, provider.client.Options().Region, "us-east-1")
}

func TestNoCredentialsFromEnv(t *testing.T) {
	os.Setenv("AWS_ACCESS_KEY_ID", "123")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "123")
	os.Setenv("AWS_REGION", "us-east-1")
	defer restoreRoute53Env()

	_, err := NewDNSProvider("", "", "", "", "", false, util.RecursiveNameservers, "cert-manager-test")
	assert.Error(t, err, "Expected error constructing DNSProvider with no credentials and not ambient")
}

func TestAmbientRegionFromEnv(t *testing.T) {
	os.Setenv("AWS_REGION", "us-east-1")
	defer restoreRoute53Env()

	provider, err := NewDNSProvider("", "", "", "", "", true, util.RecursiveNameservers, "cert-manager-test")
	assert.NoError(t, err, "Expected no error constructing DNSProvider")

	assert.Equal(t, "us-east-1", provider.client.Options().Region, "Expected Region to be set from environment")
}

func TestNoRegionFromEnv(t *testing.T) {
	os.Setenv("AWS_REGION", "us-east-1")
	defer restoreRoute53Env()

	provider, err := NewDNSProvider("marx", "swordfish", "", "", "", false, util.RecursiveNameservers, "cert-manager-test")
	assert.NoError(t, err, "Expected no error constructing DNSProvider")

	assert.Equal(t, "", provider.client.Options().Region, "Expected Region to not be set from environment")
}

func TestRoute53Present(t *testing.T) {
	mockResponses := MockResponseMap{
		"/2013-04-01/hostedzonesbyname":        MockResponse{StatusCode: 200, Body: ListHostedZonesByNameResponse},
		"/2013-04-01/hostedzone/ABCDEFG/rrset": MockResponse{StatusCode: 200, Body: ChangeResourceRecordSetsResponse},
		"/2013-04-01/hostedzone/HIJKLMN/rrset": MockResponse{StatusCode: 200, Body: ChangeResourceRecordSetsResponse},
		"/2013-04-01/change/123456":            MockResponse{StatusCode: 200, Body: GetChangeResponse},
		"/2013-04-01/hostedzone/OPQRSTU/rrset": MockResponse{StatusCode: 403, Body: ChangeResourceRecordSets403Response},
	}

	ts := newMockServer(t, mockResponses)
	defer ts.Close()

	provider, err := makeRoute53Provider(ts)
	assert.NoError(t, err, "Expected to make a Route 53 provider without error")

	domain := "example.com"
	keyAuth := "123456d=="

	err = provider.Present(domain, "_acme-challenge."+domain+".", keyAuth)
	assert.NoError(t, err, "Expected Present to return no error")

	subDomain := "foo.example.com"
	err = provider.Present(subDomain, "_acme-challenge."+subDomain+".", keyAuth)
	assert.NoError(t, err, "Expected Present to return no error")

	nonExistentSubDomain := "bar.foo.example.com"
	err = provider.Present(nonExistentSubDomain, nonExistentSubDomain+".", keyAuth)
	assert.NoError(t, err, "Expected Present to return no error")

	nonExistentDomain := "baz.com"
	err = provider.Present(nonExistentDomain, nonExistentDomain+".", keyAuth)
	assert.Error(t, err, "Expected Present to return an error")

	// This test case makes sure that the request id has been properly
	// stripped off. It has to be stripped because it changes on every
	// request which causes spurious challenge updates.
	err = provider.Present("bar.example.com", "bar.example.com.", keyAuth)
	require.Error(t, err, "Expected Present to return an error")
	assert.Equal(t, `failed to change Route 53 record set: operation error Route 53: ChangeResourceRecordSets, https response error StatusCode: 403, RequestID: <REDACTED>, api error AccessDenied: User: arn:aws:iam::0123456789:user/test-cert-manager is not authorized to perform: route53:ChangeResourceRecordSets on resource: arn:aws:route53:::hostedzone/OPQRSTU`, err.Error())
}

func TestAssumeRole(t *testing.T) {
	creds := &ststypes.Credentials{
		AccessKeyId:     aws.String("foo"),
		SecretAccessKey: aws.String("bar"),
		SessionToken:    aws.String("my-token"),
	}
	cases := []struct {
		name      string
		ambient   bool
		role      string
		expErr    bool
		expCreds  *ststypes.Credentials
		expRegion string
		key       string
		secret    string
		region    string
		mockSTS   *mockSTS
	}{
		{
			name:      "should assume role w/ ambient creds",
			role:      "my-role",
			key:       "key",
			secret:    "secret",
			region:    "",
			ambient:   true,
			expErr:    false,
			expCreds:  creds,
			expRegion: "",
			mockSTS: &mockSTS{
				AssumeRoleFn: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
					return &sts.AssumeRoleOutput{
						Credentials: creds,
					}, nil
				},
			},
		},
		{
			name:     "should assume role w/o ambient",
			ambient:  false,
			role:     "my-role",
			key:      "key",
			secret:   "secret",
			region:   "eu-central-1",
			expErr:   false,
			expCreds: creds,
			mockSTS: &mockSTS{
				AssumeRoleFn: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
					return &sts.AssumeRoleOutput{
						Credentials: creds,
					}, nil
				},
			},
		},
		{
			name:    "no role set: do NOT assume role and use provided credentials",
			ambient: true,
			role:    "",
			key:     "my-explicit-key",
			secret:  "my-explicit-secret",
			region:  "eu-central-1",
			expErr:  false,
			expCreds: &ststypes.Credentials{
				AccessKeyId:     aws.String("my-explicit-key"),    // from <key> above
				SecretAccessKey: aws.String("my-explicit-secret"), // from <secret> above
			},
			mockSTS: &mockSTS{
				AssumeRoleFn: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
					return &sts.AssumeRoleOutput{
						Credentials: creds,
					}, nil
				},
			},
		},
		{
			// AssumeRole() error should be forwarded by provider
			name:     "error assuming role w/ ambient",
			ambient:  true,
			role:     "my-role",
			key:      "key",
			secret:   "secret",
			region:   "eu-central-1",
			expErr:   true,
			expCreds: nil,
			mockSTS: &mockSTS{
				AssumeRoleFn: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
					return nil, fmt.Errorf("error assuming mock role")
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			provider, err := makeMockSessionProvider(func(aws.Config) StsClient {
				return c.mockSTS
			}, c.key, c.secret, c.region, c.role, c.ambient)
			assert.NoError(t, err)
			cfg, err := provider.GetSession()
			if c.expErr {
				assert.NotNil(t, err)
			} else {
				sessCreds, _ := cfg.Credentials.Retrieve(context.TODO())
				assert.Equal(t, c.mockSTS.assumedRole, c.role)
				assert.Equal(t, *c.expCreds.SecretAccessKey, sessCreds.SecretAccessKey)
				assert.Equal(t, *c.expCreds.AccessKeyId, sessCreds.AccessKeyID)
				assert.Equal(t, c.region, cfg.Region)
			}
		})
	}
}

type mockSTS struct {
	AssumeRoleFn func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
	assumedRole  string
}

func (m *mockSTS) AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	if m.AssumeRoleFn != nil {
		m.assumedRole = *params.RoleArn
		return m.AssumeRoleFn(ctx, params, optFns...)
	}

	return nil, nil
}

func makeMockSessionProvider(
	defaultSTSProvider func(aws.Config) StsClient,
	accessKeyID, secretAccessKey, region, role string,
	ambient bool,
) (*sessionProvider, error) {
	return &sessionProvider{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		Ambient:         ambient,
		Region:          region,
		Role:            role,
		StsProvider:     defaultSTSProvider,
		log:             logf.Log.WithName("route53-session"),
	}, nil
}

func Test_removeReqID(t *testing.T) {
	newResponseError := func() *smithyhttp.ResponseError {
		return &smithyhttp.ResponseError{
			Err: errors.New("foo"),
			Response: &smithyhttp.Response{
				Response: &http.Response{},
			},
		}
	}

	tests := []struct {
		name    string
		err     error
		wantErr error
	}{
		{
			name:    "should replace the request id in a nested error with a static value to keep the message stable",
			err:     &smithy.OperationError{OperationName: "test", Err: &awshttp.ResponseError{RequestID: "SOMEREQUESTID", ResponseError: newResponseError()}},
			wantErr: &smithy.OperationError{OperationName: "test", Err: &awshttp.ResponseError{RequestID: "<REDACTED>", ResponseError: newResponseError()}},
		},
		{
			name:    "should replace the request id with a static value to keep the message stable",
			err:     &awshttp.ResponseError{RequestID: "SOMEREQUESTID", ResponseError: newResponseError()},
			wantErr: &awshttp.ResponseError{RequestID: "<REDACTED>", ResponseError: newResponseError()},
		},
		{
			name:    "should do nothing if no request id is set",
			err:     newResponseError(),
			wantErr: newResponseError(),
		},
		{
			name:    "should do nothing if the error is not an aws error",
			err:     errors.New("foo"),
			wantErr: errors.New("foo"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := removeReqID(tt.err)
			if tt.wantErr != nil {
				require.Error(t, err)
				assert.Equal(t, tt.wantErr.Error(), err.Error())
				return
			}
			require.NoError(t, err)
		})
	}
}
