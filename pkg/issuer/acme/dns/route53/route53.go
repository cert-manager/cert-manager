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

	logf "github.com/cert-manager/cert-manager/pkg/logs"

	"github.com/go-logr/logr"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/middleware"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

const (
	route53TTL = 10
)

// DNSProvider implements the util.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers []string
	client           *route53.Client
	hostedZoneID     string
	log              logr.Logger

	userAgent string
}

type sessionProvider struct {
	AccessKeyID     string
	SecretAccessKey string
	Ambient         bool
	Region          string
	Role            string
	StsProvider     func(aws.Config) StsClient
	log             logr.Logger
	userAgent       string
}

type StsClient interface {
	AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

func (d *sessionProvider) GetSession() (aws.Config, error) {
	if d.AccessKeyID == "" && d.SecretAccessKey == "" {
		if !d.Ambient {
			return aws.Config{}, fmt.Errorf("unable to construct route53 provider: empty credentials; perhaps you meant to enable ambient credentials?")
		}
	} else if d.AccessKeyID == "" || d.SecretAccessKey == "" {
		// It's always an error to set one of those but not the other
		return aws.Config{}, fmt.Errorf("unable to construct route53 provider: only one of access and secret key was provided")
	}

	useAmbientCredentials := d.Ambient && (d.AccessKeyID == "" && d.SecretAccessKey == "")

	var optFns []func(*config.LoadOptions) error

	if useAmbientCredentials {
		d.log.V(logf.DebugLevel).Info("using ambient credentials")
		// Leaving credentials unset results in a default credential chain being
		// used; this chain is a reasonable default for getting ambient creds.
		// https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html#specifying-credentials
	} else {
		d.log.V(logf.DebugLevel).Info("not using ambient credentials")
		optFns = append(optFns, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(d.AccessKeyID, d.SecretAccessKey, "")))
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(), optFns...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("unable to create aws config: %s", err)
	}

	if d.Role != "" {
		d.log.V(logf.DebugLevel).WithValues("role", d.Role).Info("assuming role")
		stsSvc := d.StsProvider(cfg)
		result, err := stsSvc.AssumeRole(context.TODO(), &sts.AssumeRoleInput{
			RoleArn:         aws.String(d.Role),
			RoleSessionName: aws.String("cert-manager"),
		})
		if err != nil {
			return aws.Config{}, fmt.Errorf("unable to assume role: %s", err)
		}

		cfg.Credentials = credentials.NewStaticCredentialsProvider(
			*result.Credentials.AccessKeyId,
			*result.Credentials.SecretAccessKey,
			*result.Credentials.SessionToken,
		)
	}

	// If ambient credentials aren't permitted, always set the region, even if to
	// empty string, to avoid it falling back on the environment.
	// this has to be set after session is constructed
	if d.Region != "" || !useAmbientCredentials {
		cfg.Region = d.Region
	}

	cfg.APIOptions = append(cfg.APIOptions, func(stack *middleware.Stack) error {
		return awsmiddleware.AddUserAgentKeyValue("cert-manager", d.userAgent)(stack)
	})

	return cfg, nil
}

func newSessionProvider(accessKeyID, secretAccessKey, region, role string, ambient bool, userAgent string) (*sessionProvider, error) {
	return &sessionProvider{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		Ambient:         ambient,
		Region:          region,
		Role:            role,
		StsProvider:     defaultSTSProvider,
		log:             logf.Log.WithName("route53-session-provider"),
		userAgent:       userAgent,
	}, nil
}

func defaultSTSProvider(cfg aws.Config) StsClient {
	return sts.NewFromConfig(cfg)
}

// NewDNSProvider returns a DNSProvider instance configured for the AWS
// Route 53 service using static credentials from its parameters or, if they're
// unset and the 'ambient' option is set, credentials from the environment.
func NewDNSProvider(accessKeyID, secretAccessKey, hostedZoneID, region, role string,
	ambient bool,
	dns01Nameservers []string,
	userAgent string,
) (*DNSProvider, error) {
	provider, err := newSessionProvider(accessKeyID, secretAccessKey, region, role, ambient, userAgent)
	if err != nil {
		return nil, err
	}

	cfg, err := provider.GetSession()
	if err != nil {
		return nil, err
	}

	client := route53.NewFromConfig(cfg)

	return &DNSProvider{
		client:           client,
		hostedZoneID:     hostedZoneID,
		dns01Nameservers: dns01Nameservers,
		log:              logf.Log.WithName("route53"),
		userAgent:        userAgent,
	}, nil
}

// Present creates a TXT record using the specified parameters
func (r *DNSProvider) Present(domain, fqdn, value string) error {
	value = `"` + value + `"`
	return r.changeRecord(route53types.ChangeActionUpsert, fqdn, value, route53TTL)
}

// CleanUp removes the TXT record matching the specified parameters
func (r *DNSProvider) CleanUp(domain, fqdn, value string) error {
	value = `"` + value + `"`
	return r.changeRecord(route53types.ChangeActionDelete, fqdn, value, route53TTL)
}

func (r *DNSProvider) changeRecord(action route53types.ChangeAction, fqdn, value string, ttl int) error {
	hostedZoneID, err := r.getHostedZoneID(fqdn)
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

	resp, err := r.client.ChangeResourceRecordSets(context.TODO(), reqParams)
	if err != nil {
		if errors.Is(err, &route53types.InvalidChangeBatch{}) && action == route53types.ChangeActionDelete {
			r.log.V(logf.DebugLevel).WithValues("error", err).Info("ignoring InvalidChangeBatch error")
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
		resp, err := r.client.GetChange(context.TODO(), reqParams)
		if err != nil {
			return false, fmt.Errorf("failed to query Route 53 change status: %v", removeReqID(err))
		}
		if resp.ChangeInfo.Status == route53types.ChangeStatusInsync {
			return true, nil
		}
		return false, nil
	})
}

func (r *DNSProvider) getHostedZoneID(fqdn string) (string, error) {
	if r.hostedZoneID != "" {
		return r.hostedZoneID, nil
	}

	authZone, err := util.FindZoneByFqdn(fqdn, r.dns01Nameservers)
	if err != nil {
		return "", fmt.Errorf("error finding zone from fqdn: %v", err)
	}

	// .DNSName should not have a trailing dot
	reqParams := &route53.ListHostedZonesByNameInput{
		DNSName: aws.String(util.UnFqdn(authZone)),
	}
	resp, err := r.client.ListHostedZonesByName(context.TODO(), reqParams)
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
// The given error must not be nil. This function must be called everywhere
// we have a non-nil error coming from an aws-sdk-go func. The passed error
// is modified in place. This function does not work in case the full error
// message is pre-generated at construction time (instead of when Error() is
// called), which is the case for eg. fmt.Errorf("error message: %w", err).
func removeReqID(err error) error {
	var responseError *awshttp.ResponseError
	if errors.As(err, &responseError) {
		// remove the request id from the error message
		responseError.RequestID = "<REDACTED>"
	}
	return err
}
