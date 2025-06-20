// +skip_license_check

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
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/logging"
	"github.com/aws/smithy-go/middleware"

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
	AccessKeyID      string
	SecretAccessKey  string
	Ambient          bool
	Region           string
	Role             string
	WebIdentityToken string
	StsProvider      func(aws.Config) StsClient
	userAgent        string
}

type StsClient interface {
	AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
	AssumeRoleWithWebIdentity(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

func (d *sessionProvider) GetSession(ctx context.Context) (aws.Config, error) {
	switch {
	case d.Role == "" && d.WebIdentityToken != "":
		return aws.Config{}, fmt.Errorf("unable to construct route53 provider: role must be set when web identity token is set")
	case d.AccessKeyID == "" && d.SecretAccessKey == "":
		if !d.Ambient && d.WebIdentityToken == "" {
			return aws.Config{}, fmt.Errorf("unable to construct route53 provider: empty credentials; perhaps you meant to enable ambient credentials?")
		}
	case d.AccessKeyID == "" || d.SecretAccessKey == "":
		// It's always an error to set one of those but not the other
		return aws.Config{}, fmt.Errorf("unable to construct route53 provider: only one of access and secret key was provided")
	}

	useAmbientCredentials := d.Ambient && (d.AccessKeyID == "" && d.SecretAccessKey == "") && d.WebIdentityToken == ""

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
		config.WithClientLogMode(aws.LogDeprecatedUsage | aws.LogRequest),
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
	case d.Role != "" && d.WebIdentityToken != "":
		log.V(logf.DebugLevel).Info("using assume role with web identity")
	case useAmbientCredentials:
		log.V(logf.DebugLevel).Info("using ambient credentials")
		// Leaving credentials unset results in a default credential chain being
		// used; this chain is a reasonable default for getting ambient creds.
		// https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html#specifying-credentials
	default:
		log.V(logf.DebugLevel).Info("not using ambient credentials")
		optFns = append(optFns, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(d.AccessKeyID, d.SecretAccessKey, "")))
	}

	cfg, err := config.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("unable to create aws config: %s", err)
	}

	if d.Role != "" && d.WebIdentityToken == "" {
		log.V(logf.DebugLevel).WithValues("role", d.Role).Info("assuming role")
		stsSvc := d.StsProvider(cfg)
		result, err := stsSvc.AssumeRole(ctx, &sts.AssumeRoleInput{
			RoleArn:         aws.String(d.Role),
			RoleSessionName: aws.String("cert-manager"),
		})
		if err != nil {
			return aws.Config{}, fmt.Errorf("unable to assume role: %s", removeReqID(err))
		}

		cfg.Credentials = credentials.NewStaticCredentialsProvider(
			*result.Credentials.AccessKeyId,
			*result.Credentials.SecretAccessKey,
			*result.Credentials.SessionToken,
		)
	}

	if d.Role != "" && d.WebIdentityToken != "" {
		log.V(logf.DebugLevel).WithValues("role", d.Role).Info("assuming role with web identity")

		stsSvc := d.StsProvider(cfg)
		result, err := stsSvc.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{
			RoleArn:          aws.String(d.Role),
			RoleSessionName:  aws.String("cert-manager"),
			WebIdentityToken: aws.String(d.WebIdentityToken),
		})
		if err != nil {
			return aws.Config{}, fmt.Errorf("unable to assume role with web identity: %s", removeReqID(err))
		}

		cfg.Credentials = credentials.NewStaticCredentialsProvider(
			*result.Credentials.AccessKeyId,
			*result.Credentials.SecretAccessKey,
			*result.Credentials.SessionToken,
		)
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

func newSessionProvider(accessKeyID, secretAccessKey, region, role string, webIdentityToken string, ambient bool, userAgent string) *sessionProvider {
	return &sessionProvider{
		AccessKeyID:      accessKeyID,
		SecretAccessKey:  secretAccessKey,
		Ambient:          ambient,
		Region:           region,
		Role:             role,
		WebIdentityToken: webIdentityToken,
		StsProvider:      defaultSTSProvider,
		userAgent:        userAgent,
	}
}

func defaultSTSProvider(cfg aws.Config) StsClient {
	return sts.NewFromConfig(cfg)
}

// NewDNSProvider returns a DNSProvider instance configured for the AWS
// Route 53 service using static credentials from its parameters or, if they're
// unset and the 'ambient' option is set, credentials from the environment.
func NewDNSProvider(
	ctx context.Context,
	accessKeyID, secretAccessKey, hostedZoneID, region, role, webIdentityToken string,
	ambient bool,
	dns01Nameservers []string,
	userAgent string,
) (*DNSProvider, error) {
	provider := newSessionProvider(accessKeyID, secretAccessKey, region, role, webIdentityToken, ambient, userAgent)

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
		// If we try to delete something and get a 'InvalidChangeBatch' that
		// means it's already deleted, no need to consider it an error.
		var apiErr *route53types.InvalidChangeBatch
		if errors.As(err, &apiErr) && action == route53types.ChangeActionDelete {
			log.V(logf.DebugLevel).Info(
				"Got InvalidChangeBatch error when attempting to delete the TXT record. "+
					"Ignoring the error and assuming that the TXT record has already been deleted.",
				"error", err,
			)
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
