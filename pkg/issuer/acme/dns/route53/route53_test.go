/*
Copyright 2020 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/klog/v2"
	"k8s.io/klog/v2/ktesting"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

func makeRoute53Provider(ts *httptest.Server) (*DNSProvider, error) {
	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("abc", "123", " ")),
		config.WithRegion("mock-region"),
		config.WithRetryMaxAttempts(1),
		config.WithHTTPClient(ts.Client()),
	)
	if err != nil {
		return nil, err
	}

	cfg.BaseEndpoint = aws.String(ts.URL)

	client := route53.NewFromConfig(cfg)
	return &DNSProvider{client: client, dns01Nameservers: util.RecursiveNameservers}, nil
}

func TestAmbientCredentialsFromEnv(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "123")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "123")
	t.Setenv("AWS_REGION", "us-east-1")

	_, ctx := ktesting.NewTestContext(t)
	provider, err := NewDNSProvider(ctx, "", "", "", "", "", nil, true, util.RecursiveNameservers, "cert-manager-test")
	assert.NoError(t, err, "Expected no error constructing DNSProvider")

	_, err = provider.client.Options().Credentials.Retrieve(ctx)
	assert.NoError(t, err, "Expected credentials to be set from environment")

	assert.Equal(t, provider.client.Options().Region, "us-east-1")
}

func TestNoCredentialsFromEnv(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "123")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "123")
	t.Setenv("AWS_REGION", "us-east-1")

	_, ctx := ktesting.NewTestContext(t)
	_, err := NewDNSProvider(ctx, "", "", "", "", "", nil, false, util.RecursiveNameservers, "cert-manager-test")
	assert.Error(t, err, "Expected error constructing DNSProvider with no credentials and not ambient")
}

type bitmask byte

func (haystack bitmask) Has(needle bitmask) bool {
	return haystack&needle != 0
}

type fakeIdentityTokenRetriever struct{}

func (o *fakeIdentityTokenRetriever) GetIdentityToken() ([]byte, error) {
	return []byte("fake-web-identity-token"), nil
}

// TestSessionProviderGetSessionRegion calls sessionProvider.GetSession with all
// permutations of those inputs that influence how it selects an AWS region.
// The desired region selection properties are documented alongside each
// assertion.
func TestSessionProviderGetSessionRegion(t *testing.T) {
	const (
		fakeAmbientRegion = "ambient-region-1"
		fakeIssuerRegion  = "issuer-region-1"
	)

	testFunc := func(t *testing.T, allowAmbientCredentials, setAmbientRegion, supplyAccessKey, supplyWebIdentity, supplyIssuerRegion bool) {
		t.Log(
			"ambient-credentials-allowed", allowAmbientCredentials,
			"ambient-region-set", setAmbientRegion,
			"access-key-supplied", supplyAccessKey,
			"web-identity-supplied", supplyWebIdentity,
			"issuer-region-supplied", supplyIssuerRegion,
		)
		var (
			accessKeyID               string
			secretAccessKey           string
			region                    string
			role                      string
			webIdentityTokenRetriever stscreds.IdentityTokenRetriever
			userAgent                 string
		)
		if supplyAccessKey {
			accessKeyID = "fake-access-key-id"
			secretAccessKey = "fake-secret-access-key"
		}
		if supplyWebIdentity {
			webIdentityTokenRetriever = &fakeIdentityTokenRetriever{}
			role = "fake-web-identity-role"
		}
		if setAmbientRegion {
			t.Setenv("AWS_REGION", fakeAmbientRegion)
		}
		if supplyIssuerRegion {
			region = fakeIssuerRegion
		}

		p := newSessionProvider(accessKeyID, secretAccessKey, region, role, webIdentityTokenRetriever, allowAmbientCredentials, userAgent)

		logger := ktesting.NewLogger(t, ktesting.NewConfig(ktesting.BufferLogs(true)))
		ctx := klog.NewContext(context.Background(), logger)

		cfg, err := p.GetSession(ctx)

		testingLogger, ok := logger.GetSink().(ktesting.Underlier)
		require.True(t, ok)
		logMessages := testingLogger.GetBuffer().String()

		if !supplyAccessKey && !supplyWebIdentity && !allowAmbientCredentials {
			assert.EqualError(t, err, "unable to construct route53 provider: empty credentials; perhaps you meant to enable ambient credentials?")
			return
		} else {
			require.NoError(t, err)
		}

		// IRSA and Pod Identity are the most widely used "ambient credential"
		// mechanisms and both use webhooks to inject the AWS_REGION environment
		// variable into the cert-manager Pod.
		// When ambient credentials are in use and an environment region is detected,
		// cert-manager will use the environment region and ignore any Issuer region.
		// This if for backwards compatibility with cert-manager < 1.16 where
		// the Issuer region was a required field, but ignored.
		if !supplyAccessKey && !supplyWebIdentity && setAmbientRegion {
			assert.Equal(t, fakeAmbientRegion, cfg.Region,
				"If using ambient credentials, and there is a region in the environment, "+
					"use the region from the environment. Ignore the region in the Issuer region.")
		}

		// If the Issuer region has been ignored (see above), log an info
		// message to alert the user that the Issuer region is no longer a
		// required field and can be omitted in this situation.
		if !supplyAccessKey && !supplyWebIdentity && setAmbientRegion && supplyIssuerRegion {
			assert.Contains(t, logMessages, "Ignoring Issuer region",
				"If using ambient credentials, and there is a region in the environment and in the Issuer resource, "+
					"log a warning to say the Issuer region will be ignored.")
		}

		// In the case of ambient credentials from EC2 instance metadata service
		// (IMDS), the AWS_REGION environment variable is not necessarily set
		// and the Issuer region **should** be used.
		if !supplyAccessKey && !supplyWebIdentity && !setAmbientRegion && supplyIssuerRegion {
			assert.Equal(t, fakeIssuerRegion, cfg.Region,
				"If using ambient credentials but no environment region, "+
					"use the Issuer region.")
		}

		// In the general case, the environment region should always be used
		// if it is set and if the Issuer region is omitted.
		if setAmbientRegion && !supplyIssuerRegion {
			assert.Equal(t, fakeAmbientRegion, cfg.Region,
				"If there is a region in the environment and not in the Issuer resource, "+
					"the region in the environment should always be used.")
		}

		// In the general case, the Issuer region should always be used if it is set.
		// and if the environment region is not detected.
		if !setAmbientRegion && supplyIssuerRegion {
			assert.Equal(t, fakeIssuerRegion, cfg.Region,
				"If there is an Issuer region but no environment region, "+
					"the Issuer region in the environment should always be used.")
		}

		// And if no region is detected, log an info message to alert the user
		// to the mis-configuration
		if !setAmbientRegion && !supplyIssuerRegion {
			assert.Contains(t, logMessages, "Region not found",
				"If no region was detected, "+
					"log a warning to explain how to set the region.")
		}
	}

	const (
		allowAmbientCredentials bitmask = 1 << iota
		setAmbientRegion
		supplyAccessKey
		supplyWebIdentity
		supplyIssuerRegion
	)
	allFalse := bitmask(0)
	allTrue := allowAmbientCredentials | setAmbientRegion | supplyAccessKey | supplyWebIdentity | supplyIssuerRegion

	for input := allFalse; input <= allTrue; input++ {
		t.Run(
			fmt.Sprintf("%v", input),
			func(t *testing.T) {
				testFunc(
					t,
					input.Has(allowAmbientCredentials),
					input.Has(setAmbientRegion),
					input.Has(supplyAccessKey),
					input.Has(supplyWebIdentity),
					input.Has(supplyIssuerRegion),
				)
			},
		)
	}
}

func TestRoute53Present(t *testing.T) {
	_, ctx := ktesting.NewTestContext(t)
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

	err = provider.Present(ctx, domain, "_acme-challenge."+domain+".", keyAuth)
	assert.NoError(t, err, "Expected Present to return no error")

	subDomain := "foo.example.com"
	err = provider.Present(ctx, subDomain, "_acme-challenge."+subDomain+".", keyAuth)
	assert.NoError(t, err, "Expected Present to return no error")

	nonExistentSubDomain := "bar.foo.example.com"
	err = provider.Present(ctx, nonExistentSubDomain, nonExistentSubDomain+".", keyAuth)
	assert.NoError(t, err, "Expected Present to return no error")

	nonExistentDomain := "baz.com"
	err = provider.Present(ctx, nonExistentDomain, nonExistentDomain+".", keyAuth)
	assert.Error(t, err, "Expected Present to return an error")

	// This test case makes sure that the request id has been properly
	// stripped off. It has to be stripped because it changes on every
	// request which causes spurious challenge updates.
	err = provider.Present(ctx, "bar.example.com", "bar.example.com.", keyAuth)
	require.Error(t, err, "Expected Present to return an error")
	assert.Equal(t, `failed to change Route 53 record set: operation error Route 53: ChangeResourceRecordSets, https response error StatusCode: 403, RequestID: <REDACTED>, api error AccessDenied: User: arn:aws:iam::0123456789:user/test-cert-manager is not authorized to perform: route53:ChangeResourceRecordSets on resource: arn:aws:route53:::hostedzone/OPQRSTU`, err.Error())
}

func TestAssumeRole(t *testing.T) {
	cases := []struct {
		name                      string
		ambient                   bool
		role                      string
		webIdentityTokenRetriever stscreds.IdentityTokenRetriever
		expErr                    bool
		expErrMessage             string
		expCreds                  *ststypes.Credentials
		key                       string
		secret                    string
		region                    string
		mockAPIResponse           *MockResponse
	}{
		{
			name:            "should remove request ID for assumeRole",
			role:            "arn:aws:sts::123456789012:assumed-role/demo/TestAR",
			key:             "key",
			secret:          "secret",
			region:          "eu-central-1",
			ambient:         true,
			expErr:          true,
			expErrMessage:   "failed to refresh cached credentials, operation error STS: AssumeRole, https response error StatusCode: 403, RequestID: <REDACTED>, api error InvalidClientTokenId: The security token included in the request is invalid.",
			mockAPIResponse: &MockResponse{StatusCode: 403, Body: AssumeRole403Response},
		},
		{
			name:                      "should remove request ID for assumeRoleWithWebIdentity",
			role:                      "arn:aws:sts::123456789012:assumed-role/FederatedWebIdentityRole/app1",
			webIdentityTokenRetriever: &fakeIdentityTokenRetriever{},
			region:                    "eu-central-1",
			ambient:                   true,
			expErr:                    true,
			expErrMessage:             "failed to refresh cached credentials, failed to retrieve credentials, operation error STS: AssumeRoleWithWebIdentity, https response error StatusCode: 400, RequestID: <REDACTED>, api error ValidationError: Request ARN is invalid",
			mockAPIResponse:           &MockResponse{StatusCode: 400, Body: AssumeRoleWithWebIdentity400Response},
		},
		{
			name:    "should assume role with ambient creds",
			role:    "arn:aws:sts::123456789012:assumed-role/demo/TestAR",
			region:  "eu-central-1",
			ambient: true,
			expErr:  false,
			expCreds: &ststypes.Credentials{
				AccessKeyId:     aws.String("ASIAIOSFODNN7EXAMPLE"),
				SecretAccessKey: aws.String("wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY"),
			},
			mockAPIResponse: &MockResponse{StatusCode: 200, Body: AssumeRoleResponse},
		},
		{
			name:    "should assume role without ambient creds",
			ambient: false,
			role:    "arn:aws:sts::123456789012:assumed-role/demo/TestAR",
			key:     "key",
			secret:  "secret",
			region:  "eu-central-1",
			expErr:  false,
			expCreds: &ststypes.Credentials{
				AccessKeyId:     aws.String("ASIAIOSFODNN7EXAMPLE"),
				SecretAccessKey: aws.String("wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY"),
			},
			mockAPIResponse: &MockResponse{StatusCode: 200, Body: AssumeRoleResponse},
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
		},
		{
			// AssumeRole() error should be forwarded by provider
			name:            "error assuming role with ambient",
			ambient:         true,
			role:            "arn:aws:sts::123456789012:assumed-role/demo/TestAR",
			key:             "key",
			secret:          "secret",
			region:          "eu-central-1",
			expErr:          true,
			expErrMessage:   "failed to refresh cached credentials, operation error STS: AssumeRole, https response error StatusCode: 403, RequestID: <REDACTED>, api error InvalidClientTokenId: The security token included in the request is invalid.",
			expCreds:        nil,
			mockAPIResponse: &MockResponse{StatusCode: 403, Body: AssumeRole403Response},
		},
		{
			name:                      "should assume role with web identity",
			role:                      "arn:aws:sts::123456789012:assumed-role/FederatedWebIdentityRole/app1",
			webIdentityTokenRetriever: &fakeIdentityTokenRetriever{},
			region:                    "eu-central-1",
			expErr:                    false,
			expCreds: &ststypes.Credentials{
				AccessKeyId:     aws.String("ASgeIAIOSFODNN7EXAMPLE"),
				SecretAccessKey: aws.String("wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY"),
			},
			mockAPIResponse: &MockResponse{StatusCode: 200, Body: AssumeRoleWithWebIdentityResponse},
		},
		{
			name:                      "require role when using assume role with web identity",
			webIdentityTokenRetriever: &fakeIdentityTokenRetriever{},
			region:                    "eu-central-1",
			expErr:                    true,
			expErrMessage:             "unable to construct route53 provider: role must be set when web identity token is set",
			expCreds:                  nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// The following environment variables are standard in all AWS SDKs:
			// https://docs.aws.amazon.com/sdkref/latest/guide/settings-reference.html#EVarSettings

			// Provide "ambient" credentials for those tests that expect them
			t.Setenv("AWS_ACCESS_KEY_ID", "key")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
			// Disable AWS metadata service connections
			t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
			// Prevent looking in the users `.aws/config` and `aws/credentials`
			t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
			// Avoid slow retries in tests
			t.Setenv("AWS_MAX_ATTEMPTS", "1")

			// Simulate the AWS STS server using a local HTTP server.
			// But allow tests to be run against real AWS endpoints
			// to help judge the accuracy of our fake responses.
			// Only error tests will succeed in this case.
			if os.Getenv("USE_REAL_AWS") != "true" {
				mockResponses := MockResponseMap{}
				if c.mockAPIResponse != nil {
					mockResponses["/"] = *c.mockAPIResponse
				}
				s := newMockServer(t, mockResponses)
				t.Setenv("AWS_ENDPOINT_URL", s.URL)
			}

			_, ctx := ktesting.NewTestContext(t)
			provider := makeMockSessionProvider(c.key, c.secret, c.region, c.role, c.webIdentityTokenRetriever, c.ambient)
			cfg, err := provider.GetSession(ctx)

			var sessCreds aws.Credentials
			if err == nil {
				assert.Equal(t, c.region, cfg.Region)
				sessCreds, err = cfg.Credentials.Retrieve(ctx)
			}

			if c.expErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if c.expErrMessage != "" {
				assert.EqualError(t, err, c.expErrMessage)
			}
			if c.expCreds != nil {
				assert.Equal(t, *c.expCreds.SecretAccessKey, sessCreds.SecretAccessKey)
				assert.Equal(t, *c.expCreds.AccessKeyId, sessCreds.AccessKeyID)
			}
		})
	}
}

func makeMockSessionProvider(
	accessKeyID, secretAccessKey, region, role string, webIdentityTokenRetriever stscreds.IdentityTokenRetriever,
	ambient bool,
) *sessionProvider {
	return &sessionProvider{
		AccessKeyID:               accessKeyID,
		SecretAccessKey:           secretAccessKey,
		Ambient:                   ambient,
		Region:                    region,
		Role:                      role,
		webIdentityTokenRetriever: webIdentityTokenRetriever,
		userAgent:                 "fake-user-agent-for-tests",
	}
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
			name:    "should replace the request id in a %w wrapped error",
			err:     fmt.Errorf("failed to refresh cached credentials, %w", &awshttp.ResponseError{RequestID: "SOMEREQUESTID", ResponseError: newResponseError()}),
			wantErr: fmt.Errorf("failed to refresh cached credentials, %w", &awshttp.ResponseError{RequestID: "<REDACTED>", ResponseError: newResponseError()}),
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
		{
			name:    "should ignore nil errors",
			err:     nil,
			wantErr: nil,
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
