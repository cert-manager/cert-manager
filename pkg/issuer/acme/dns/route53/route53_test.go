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
	"k8s.io/klog/v2"
	"k8s.io/klog/v2/ktesting"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

const jwt string = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJzdHMuYW1hem9uYXdzLmNvbSIsImV4cCI6MTc0MTg4NzYwOCwiaWF0IjoxNzEwMzUxNjM4LCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoiMTIzNDU2Nzg5MCJ9.SfuV3SW-vEdV-tLFIr2PK2DnN6QYmozygav5OeoH36Q"

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
	provider, err := NewDNSProvider(ctx, "", "", "", "", "", "", true, util.RecursiveNameservers, "cert-manager-test")
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
	_, err := NewDNSProvider(ctx, "", "", "", "", "", "", false, util.RecursiveNameservers, "cert-manager-test")
	assert.Error(t, err, "Expected error constructing DNSProvider with no credentials and not ambient")
}

type bitmask byte

func (haystack bitmask) Has(needle bitmask) bool {
	return haystack&needle != 0
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
			accessKeyID      string
			secretAccessKey  string
			region           string
			role             string
			webIdentityToken string
			userAgent        string
		)
		if supplyAccessKey {
			accessKeyID = "fake-access-key-id"
			secretAccessKey = "fake-secret-access-key"
		}
		if supplyWebIdentity {
			webIdentityToken = "fake-web-identity-token"
			role = "fake-web-identity-role"
		}
		if setAmbientRegion {
			t.Setenv("AWS_REGION", fakeAmbientRegion)
		}
		if supplyIssuerRegion {
			region = fakeIssuerRegion
		}

		p := newSessionProvider(accessKeyID, secretAccessKey, region, role, webIdentityToken, allowAmbientCredentials, userAgent)
		p.StsProvider = func(cfg aws.Config) StsClient {
			return &mockSTS{
				AssumeRoleWithWebIdentityFn: func(
					ctx context.Context,
					params *sts.AssumeRoleWithWebIdentityInput,
					optFns ...func(*sts.Options),
				) (*sts.AssumeRoleWithWebIdentityOutput, error) {
					return &sts.AssumeRoleWithWebIdentityOutput{
						Credentials: &ststypes.Credentials{
							AccessKeyId:     aws.String("fake-sts-access-key-id"),
							SecretAccessKey: aws.String("fake-sts-secret-access-key"),
							SessionToken:    aws.String("fake-sts-session-token"),
						},
					}, nil
				},
			}
		}

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
	creds := &ststypes.Credentials{
		AccessKeyId:     aws.String("foo"),
		SecretAccessKey: aws.String("bar"),
		SessionToken:    aws.String("my-token"),
	}
	cases := []struct {
		name             string
		ambient          bool
		role             string
		webIdentityToken string
		expErr           bool
		expErrMessage    string
		expCreds         *ststypes.Credentials
		expRegion        string
		key              string
		secret           string
		region           string
		mockSTS          *mockSTS
	}{
		{
			name:          "should remove request ID for assumeRole",
			role:          "my-role",
			ambient:       true,
			expErr:        true,
			expErrMessage: "unable to assume role: https response error StatusCode: 0, RequestID: <REDACTED>, foo",
			expCreds:      creds,
			expRegion:     "",
			mockSTS: &mockSTS{
				AssumeRoleFn: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
					return nil, &awshttp.ResponseError{
						RequestID: "fake-request-id",
						ResponseError: &smithyhttp.ResponseError{
							Err: errors.New("foo"),
							Response: &smithyhttp.Response{
								Response: &http.Response{},
							},
						},
					}
				},
			},
		},
		{
			name:             "should remove request ID for assumeRoleWithWebIdentity",
			role:             "my-role",
			webIdentityToken: jwt,
			ambient:          true,
			expErr:           true,
			expErrMessage:    "unable to assume role with web identity: https response error StatusCode: 0, RequestID: <REDACTED>, foo",
			expCreds:         creds,
			expRegion:        "",
			mockSTS: &mockSTS{
				AssumeRoleWithWebIdentityFn: func(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
					return nil, &awshttp.ResponseError{
						RequestID: "fake-request-id",
						ResponseError: &smithyhttp.ResponseError{
							Err: errors.New("foo"),
							Response: &smithyhttp.Response{
								Response: &http.Response{},
							},
						},
					}
				},
			},
		},
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
		{
			name:             "should assume role with web identity",
			role:             "my-role",
			webIdentityToken: jwt,
			expErr:           false,
			expCreds:         creds,
			mockSTS: &mockSTS{
				AssumeRoleWithWebIdentityFn: func(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
					return &sts.AssumeRoleWithWebIdentityOutput{
						Credentials: creds,
					}, nil
				},
			},
		},
		{
			name:             "require role when using assume role with web identity",
			webIdentityToken: jwt,
			expErr:           true,
			expCreds:         nil,
			mockSTS: &mockSTS{
				AssumeRoleWithWebIdentityFn: func(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
					return nil, fmt.Errorf("error assuming mock role with web identity")
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			provider := makeMockSessionProvider(func(cfg aws.Config) StsClient {
				return c.mockSTS
			}, c.key, c.secret, c.region, c.role, c.webIdentityToken, c.ambient)
			_, ctx := ktesting.NewTestContext(t)
			cfg, err := provider.GetSession(ctx)
			if c.expErr {
				assert.NotNil(t, err)
				if c.expErrMessage != "" {
					assert.EqualError(t, err, c.expErrMessage)
				}
			} else {
				assert.Nil(t, err)
				sessCreds, _ := cfg.Credentials.Retrieve(ctx)
				assert.Equal(t, c.mockSTS.assumedRole, c.role)
				assert.Equal(t, *c.expCreds.SecretAccessKey, sessCreds.SecretAccessKey)
				assert.Equal(t, *c.expCreds.AccessKeyId, sessCreds.AccessKeyID)
				assert.Equal(t, c.region, cfg.Region)
			}
		})
	}
}

type mockSTS struct {
	AssumeRoleFn                func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
	AssumeRoleWithWebIdentityFn func(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
	assumedRole                 string
}

func (m *mockSTS) AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	if m.AssumeRoleFn != nil {
		m.assumedRole = *params.RoleArn
		return m.AssumeRoleFn(ctx, params, optFns...)
	}

	return nil, nil
}

func (m *mockSTS) AssumeRoleWithWebIdentity(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	if m.AssumeRoleWithWebIdentityFn != nil {
		m.assumedRole = *params.RoleArn
		return m.AssumeRoleWithWebIdentityFn(ctx, params, optFns...)
	}

	return nil, nil
}

func makeMockSessionProvider(
	defaultSTSProvider func(aws.Config) StsClient,
	accessKeyID, secretAccessKey, region, role, webIdentityToken string,
	ambient bool,
) *sessionProvider {
	return &sessionProvider{
		AccessKeyID:      accessKeyID,
		SecretAccessKey:  secretAccessKey,
		Ambient:          ambient,
		Region:           region,
		Role:             role,
		WebIdentityToken: webIdentityToken,
		StsProvider:      defaultSTSProvider,
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
