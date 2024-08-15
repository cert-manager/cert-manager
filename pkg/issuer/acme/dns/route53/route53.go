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

// Package route53 implements a DNS provider for solving the DNS-01 challenge
// using AWS Route 53 DNS.
package route53

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/logging"
	"github.com/aws/smithy-go/middleware"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

const (
	route53TTL = 10
)

// DNSProvider implements the util.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers []string
	client           *route53.Client
	hostedZoneID     string
	userAgent        string
}

type sessionProvider struct {
	AccessKeyID               string
	SecretAccessKey           string
	Ambient                   bool
	Region                    string
	Role                      string
	webIdentityTokenRetriever stscreds.IdentityTokenRetriever
	userAgent                 string
}

func NewWrappedSTSClient(ctx context.Context, optFns ...func(*config.LoadOptions) error) (*stsWrapper, error) {
	stsCfg, err := config.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return nil, err
	}
	return &stsWrapper{
		wrapped: sts.NewFromConfig(stsCfg),
	}, nil
}

type stsWrapper struct {
	wrapped *sts.Client
}

func (o *stsWrapper) AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	out, err := o.wrapped.AssumeRole(ctx, params, optFns...)
	if err != nil {
		err = removeReqID(err)
	}
	return out, err
}

func (o *stsWrapper) AssumeRoleWithWebIdentity(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	out, err := o.wrapped.AssumeRoleWithWebIdentity(ctx, params, optFns...)
	if err != nil {
		err = removeReqID(err)
	}
	return out, err
}

var _ stscreds.AssumeRoleAPIClient = &stsWrapper{}
var _ stscreds.AssumeRoleWithWebIdentityAPIClient = &stsWrapper{}

// GetSession loads an AWS SDK for Go V2 configuration which is used for the
// Route53 client.
//
// It uses the [standardized credential chain](https://docs.aws.amazon.com/sdkref/latest/guide/standardized-credentials.html),
// so that cert-manager can be compatible with AWS authentication mechanisms
// such as:
// - [IAM for Service Accounts (IRSA)](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html), and
// - [Pod Identities](https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html).
//
// To support bespoke OIDC authentication using a non-mounted ServiceAccount
// token, we instantiate an stscreds WebIdentityTokenRetriever, if the user has
// supplied a ServiceAccount reference. This allows AWS SDK for Go to request a
// ServiceAccountToken when ever it needs to re-authenticate to AWS.
// In this case, the supplied Role is used.
//
// We also support Assuming a different role for other credential sources,
// such as ambient credentials or static credentials.
// If a Role is supplied an AssumeRole credential provider is instantiated.
//
// Note: We deliberately do not use config.WithAssumeRoleCredentialOptions.
// That option is misleading. See:
// - https://github.com/aws/aws-sdk-go-v2/issues/1382
func (d *sessionProvider) GetSession(ctx context.Context) (aws.Config, error) {
	useAmbientCredentials := d.Ambient && (d.AccessKeyID == "" && d.SecretAccessKey == "") && d.webIdentityTokenRetriever == nil

	log := logf.FromContext(ctx)
	optFns := []func(*config.LoadOptions) error{
		// Print AWS API requests but only at cert-manager debug level
		config.WithLogger(logging.LoggerFunc(func(classification logging.Classification, format string, v ...interface{}) {
			log := log.WithValues("aws-classification", classification)
			if classification == logging.Debug {
				log = log.V(logf.DebugLevel)
			}
			log.Info(fmt.Sprintf(format, v...))
		})),
		config.WithClientLogMode(aws.LogDeprecatedUsage | aws.LogRequest | aws.LogResponseWithBody),
		config.WithLogConfigurationWarnings(true),
		// Append cert-manager user-agent string to all AWS API requests
		config.WithAPIOptions(
			[]func(*middleware.Stack) error{
				func(stack *middleware.Stack) error {
					return awsmiddleware.AddUserAgentKeyValue("cert-manager", d.userAgent)(stack)
				},
			},
		),
	}

	var envRegionFound bool
	{
		envConfig, err := config.NewEnvConfig()
		if err != nil {
			return aws.Config{}, err
		}
		envRegionFound = envConfig.Region != ""
	}

	if !envRegionFound && d.Region == "" {
		log.Info(
			"Region not found",
			"reason", "The AWS_REGION or AWS_DEFAULT_REGION environment variables were not set and the Issuer region field was empty",
		)
	}

	if d.Region != "" {
		if envRegionFound && useAmbientCredentials {
			log.Info(
				"Ignoring Issuer region",
				"reason", "Issuer is configured to use ambient credentials and AWS_REGION or AWS_DEFAULT_REGION environment variables were found",
				"suggestion", "Since cert-manager 1.16, the Issuer region field is optional and can be removed from your Issuer or ClusterIssuer",
				"issuer-region", d.Region,
			)
		} else {
			optFns = append(optFns,
				config.WithRegion(d.Region),
			)
		}
	}

	switch {
	case d.AccessKeyID != "" && d.SecretAccessKey != "":
		log.V(logf.DebugLevel).Info("Using static credentials provider. Ambient credentials will be ignored.")
		optFns = append(
			optFns,
			config.WithCredentialsProvider(
				credentials.NewStaticCredentialsProvider(d.AccessKeyID, d.SecretAccessKey, ""),
			),
		)
	case d.webIdentityTokenRetriever != nil:
		log.V(logf.DebugLevel).Info("Using AssumeRoleWithWebIdentity (OIDC) credentials provider. Ambient credentials will be ignored.")
		if d.Role == "" {
			return aws.Config{}, errors.New("unable to construct route53 provider: role must be set when web identity token is set")
		}
		stsClient, err := NewWrappedSTSClient(ctx, optFns...)
		if err != nil {
			return aws.Config{}, err
		}
		optFns = append(
			optFns,
			config.WithCredentialsProvider(
				aws.NewCredentialsCache(
					stscreds.NewWebIdentityRoleProvider(
						stsClient,
						d.Role,
						d.webIdentityTokenRetriever,
					),
				),
			),
		)
	case !d.Ambient:
		return aws.Config{}, fmt.Errorf("unable to construct route53 provider: empty credentials; perhaps you meant to enable ambient credentials?")
	default:
		log.V(logf.DebugLevel).Info("Using ambient credentials. All AWS SDK standardized credential providers will be tried.")
	}

	if d.Role != "" && d.webIdentityTokenRetriever == nil {
		log.V(logf.DebugLevel).Info("Using assumed role", "role", d.Role)
		stsClient, err := NewWrappedSTSClient(ctx, optFns...)
		if err != nil {
			return aws.Config{}, err
		}
		optFns = append(
			optFns,
			config.WithCredentialsProvider(
				aws.NewCredentialsCache(
					stscreds.NewAssumeRoleProvider(
						stsClient,
						d.Role,
					),
				),
			),
		)
	}

	cfg, err := config.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("unable to create aws config: %s", err)
	}

	// Log some key values of the loaded configuration, so that users can
	// self-diagnose problems in the field. If users shared logs in their bug
	// reports, we can know whether the region was detected and whether an
	// alternative defaults mode has been configured.
	//
	// TODO(wallrj): Loop through the cfg.ConfigSources and log which config
	// source was used to load the region and credentials, so that it is clearer
	// to the user where environment variables or config files or IMDS metadata
	// are being used.
	log.V(logf.DebugLevel).Info(
		"loaded-config",
		"defaults-mode", cfg.DefaultsMode,
		"region", cfg.Region,
		"runtime-environment", cfg.RuntimeEnvironment,
	)

	return cfg, nil
}

func newSessionProvider(accessKeyID, secretAccessKey, region, role string, webIdentityTokenRetriever stscreds.IdentityTokenRetriever, ambient bool, userAgent string) *sessionProvider {
	return &sessionProvider{
		AccessKeyID:               accessKeyID,
		SecretAccessKey:           secretAccessKey,
		Ambient:                   ambient,
		Region:                    region,
		Role:                      role,
		webIdentityTokenRetriever: webIdentityTokenRetriever,
		userAgent:                 userAgent,
	}
}

// NewDNSProvider returns a DNSProvider instance configured for the AWS
// Route 53 service using static credentials from its parameters or, if they're
// unset and the 'ambient' option is set, credentials from the environment.
func NewDNSProvider(
	ctx context.Context,
	accessKeyID, secretAccessKey, hostedZoneID, region, role string,
	webIdentityTokenRetriever stscreds.IdentityTokenRetriever,
	ambient bool,
	dns01Nameservers []string,
	userAgent string,
) (*DNSProvider, error) {
	provider := newSessionProvider(accessKeyID, secretAccessKey, region, role, webIdentityTokenRetriever, ambient, userAgent)

	cfg, err := provider.GetSession(ctx)
	if err != nil {
		return nil, err
	}

	client := route53.NewFromConfig(cfg)

	return &DNSProvider{
		client:           client,
		hostedZoneID:     hostedZoneID,
		dns01Nameservers: dns01Nameservers,
		userAgent:        userAgent,
	}, nil
}

// Present creates a TXT record using the specified parameters
func (r *DNSProvider) Present(ctx context.Context, domain, fqdn, value string) error {
	value = `"` + value + `"`
	return r.changeRecord(ctx, route53types.ChangeActionUpsert, fqdn, value, route53TTL)
}

// CleanUp removes the TXT record matching the specified parameters
func (r *DNSProvider) CleanUp(ctx context.Context, domain, fqdn, value string) error {
	value = `"` + value + `"`
	return r.changeRecord(ctx, route53types.ChangeActionDelete, fqdn, value, route53TTL)
}

func (r *DNSProvider) changeRecord(ctx context.Context, action route53types.ChangeAction, fqdn, value string, ttl int) error {
	log := logf.FromContext(ctx)
	hostedZoneID, err := r.getHostedZoneID(ctx, fqdn)
	if err != nil {
		return fmt.Errorf("failed to determine Route 53 hosted zone ID: %v", err)
	}

	recordSet := newTXTRecordSet(fqdn, value, ttl)
	reqParams := &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(hostedZoneID),
		ChangeBatch: &route53types.ChangeBatch{
			Comment: aws.String("Managed by cert-manager"),
			Changes: []route53types.Change{
				{
					Action:            action,
					ResourceRecordSet: recordSet,
				},
			},
		},
	}

	resp, err := r.client.ChangeResourceRecordSets(ctx, reqParams)
	if err != nil {
		if errors.Is(err, &route53types.InvalidChangeBatch{}) && action == route53types.ChangeActionDelete {
			log.V(logf.DebugLevel).WithValues("error", err).Info("ignoring InvalidChangeBatch error")
			// If we try to delete something and get a 'InvalidChangeBatch' that
			// means it's already deleted, no need to consider it an error.
			return nil
		}
		return fmt.Errorf("failed to change Route 53 record set: %v", removeReqID(err))

	}

	statusID := resp.ChangeInfo.Id

	return util.WaitFor(120*time.Second, 4*time.Second, func() (bool, error) {
		reqParams := &route53.GetChangeInput{
			Id: statusID,
		}
		resp, err := r.client.GetChange(ctx, reqParams)
		if err != nil {
			return false, fmt.Errorf("failed to query Route 53 change status: %v", removeReqID(err))
		}
		if resp.ChangeInfo.Status == route53types.ChangeStatusInsync {
			return true, nil
		}
		return false, nil
	})
}

func (r *DNSProvider) getHostedZoneID(ctx context.Context, fqdn string) (string, error) {
	if r.hostedZoneID != "" {
		return r.hostedZoneID, nil
	}

	authZone, err := util.FindZoneByFqdn(ctx, fqdn, r.dns01Nameservers)
	if err != nil {
		return "", fmt.Errorf("error finding zone from fqdn: %v", err)
	}

	// .DNSName should not have a trailing dot
	reqParams := &route53.ListHostedZonesByNameInput{
		DNSName: aws.String(util.UnFqdn(authZone)),
	}
	resp, err := r.client.ListHostedZonesByName(ctx, reqParams)
	if err != nil {
		return "", removeReqID(err)
	}

	zoneToID := make(map[string]string)
	var hostedZones []string
	for _, hostedZone := range resp.HostedZones {
		// .Name has a trailing dot
		if !hostedZone.Config.PrivateZone {
			zoneToID[*hostedZone.Name] = *hostedZone.Id
			hostedZones = append(hostedZones, *hostedZone.Name)
		}
	}
	authZone, err = util.FindBestMatch(fqdn, hostedZones...)
	if err != nil {
		return "", fmt.Errorf("zone %s not found in Route 53 for domain %s", authZone, fqdn)
	}

	hostedZoneID, ok := zoneToID[authZone]

	if len(hostedZoneID) == 0 || !ok {
		return "", fmt.Errorf("zone %s not found in Route 53 for domain %s", authZone, fqdn)
	}

	hostedZoneID = strings.TrimPrefix(hostedZoneID, "/hostedzone/")

	return hostedZoneID, nil
}

func newTXTRecordSet(fqdn, value string, ttl int) *route53types.ResourceRecordSet {
	return &route53types.ResourceRecordSet{
		Name:             aws.String(fqdn),
		Type:             route53types.RRTypeTxt,
		TTL:              aws.Int64(int64(ttl)),
		MultiValueAnswer: aws.Bool(true),
		SetIdentifier:    aws.String(value),
		ResourceRecords: []route53types.ResourceRecord{
			{Value: aws.String(value)},
		},
	}
}

// The aws-sdk-go library appends a request id to its error messages. We
// want our error messages to be the same when the cause is the same to
// avoid spurious challenge updates.
//
// This function must be called everywhere we have an error coming from
// an aws-sdk-go func. The passed error is modified in place.
func removeReqID(err error) error {
	var responseError *awshttp.ResponseError
	if errors.As(err, &responseError) {
		before := responseError.Error()
		// remove the request id from the error message
		responseError.RequestID = "<REDACTED>"
		after := responseError.Error()
		return errors.New(strings.Replace(err.Error(), before, after, 1))
	}
	return err
}

type ServiceAccountTokenCreator interface {
	CreateToken(ctx context.Context, serviceAccountName string, tokenRequest *authv1.TokenRequest, opts metav1.CreateOptions) (*authv1.TokenRequest, error)
}

type KubernetesServiceAccountTokenRetriever struct {
	ServiceAccountName string
	Audiences          []string
	Namespace          string
	Client             ServiceAccountTokenCreator
}

var _ stscreds.IdentityTokenRetriever = &KubernetesServiceAccountTokenRetriever{}

func (o *KubernetesServiceAccountTokenRetriever) GetIdentityToken() ([]byte, error) {
	tokenrequest, err := o.Client.CreateToken(context.TODO(), o.ServiceAccountName, &authv1.TokenRequest{
		Spec: authv1.TokenRequestSpec{
			Audiences:         o.Audiences,
			ExpirationSeconds: ptr.To(int64(600)),
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to request token for %s/%s: %w", o.Namespace, o.ServiceAccountName, err)
	}

	return []byte(tokenrequest.Status.Token), nil
}
