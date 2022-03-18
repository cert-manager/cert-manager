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
	"fmt"
	"strings"
	"time"

	logf "github.com/cert-manager/cert-manager/pkg/logs"

	"github.com/go-logr/logr"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

const (
	route53TTL = 10
)

// DNSProvider implements the util.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers []string
	client           *route53.Route53
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
	StsProvider     func(*session.Session) stsiface.STSAPI
	log             logr.Logger
	userAgent       string
}

func (d *sessionProvider) GetSession() (*session.Session, error) {
	if d.AccessKeyID == "" && d.SecretAccessKey == "" {
		if !d.Ambient {
			return nil, fmt.Errorf("unable to construct route53 provider: empty credentials; perhaps you meant to enable ambient credentials?")
		}
	} else if d.AccessKeyID == "" || d.SecretAccessKey == "" {
		// It's always an error to set one of those but not the other
		return nil, fmt.Errorf("unable to construct route53 provider: only one of access and secret key was provided")
	}

	useAmbientCredentials := d.Ambient && (d.AccessKeyID == "" && d.SecretAccessKey == "")

	config := aws.NewConfig()
	sessionOpts := session.Options{
		Config: *config,
	}

	if useAmbientCredentials {
		d.log.V(logf.DebugLevel).Info("using ambient credentials")
		// Leaving credentials unset results in a default credential chain being
		// used; this chain is a reasonable default for getting ambient creds.
		// https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html#specifying-credentials
	} else {
		d.log.V(logf.DebugLevel).Info("not using ambient credentials")
		sessionOpts.Config.Credentials = credentials.NewStaticCredentials(d.AccessKeyID, d.SecretAccessKey, "")
		// also disable 'ambient' region sources
		sessionOpts.SharedConfigState = session.SharedConfigDisable
	}

	sess, err := session.NewSessionWithOptions(sessionOpts)
	if err != nil {
		return nil, fmt.Errorf("unable to create aws session: %s", err)
	}

	if d.Role != "" {
		d.log.V(logf.DebugLevel).WithValues("role", d.Role).Info("assuming role")
		stsSvc := d.StsProvider(sess)
		result, err := stsSvc.AssumeRole(&sts.AssumeRoleInput{
			RoleArn:         aws.String(d.Role),
			RoleSessionName: aws.String("cert-manager"),
		})
		if err != nil {
			return nil, fmt.Errorf("unable to assume role: %s", err)
		}

		creds := credentials.Value{
			AccessKeyID:     *result.Credentials.AccessKeyId,
			SecretAccessKey: *result.Credentials.SecretAccessKey,
			SessionToken:    *result.Credentials.SessionToken,
		}
		sessionOpts.Config.Credentials = credentials.NewStaticCredentialsFromCreds(creds)

		sess, err = session.NewSessionWithOptions(sessionOpts)
		if err != nil {
			return nil, fmt.Errorf("unable to create aws session: %s", err)
		}
	}

	// If ambient credentials aren't permitted, always set the region, even if to
	// empty string, to avoid it falling back on the environment.
	// this has to be set after session is constructed
	if d.Region != "" || !useAmbientCredentials {
		sess.Config.WithRegion(d.Region)
	}

	sess.Handlers.Build.PushBack(request.WithAppendUserAgent(d.userAgent))
	return sess, nil
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

func defaultSTSProvider(sess *session.Session) stsiface.STSAPI {
	return sts.New(sess)
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

	sess, err := provider.GetSession()
	if err != nil {
		return nil, err
	}

	client := route53.New(sess)

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
	return r.changeRecord(route53.ChangeActionUpsert, fqdn, value, route53TTL)
}

// CleanUp removes the TXT record matching the specified parameters
func (r *DNSProvider) CleanUp(domain, fqdn, value string) error {
	value = `"` + value + `"`
	return r.changeRecord(route53.ChangeActionDelete, fqdn, value, route53TTL)
}

func (r *DNSProvider) changeRecord(action, fqdn, value string, ttl int) error {
	hostedZoneID, err := r.getHostedZoneID(fqdn)
	if err != nil {
		return fmt.Errorf("failed to determine Route 53 hosted zone ID: %v", err)
	}

	recordSet := newTXTRecordSet(fqdn, value, ttl)
	reqParams := &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(hostedZoneID),
		ChangeBatch: &route53.ChangeBatch{
			Comment: aws.String("Managed by cert-manager"),
			Changes: []*route53.Change{
				{
					Action:            &action,
					ResourceRecordSet: recordSet,
				},
			},
		},
	}

	resp, err := r.client.ChangeResourceRecordSets(reqParams)
	if err != nil {
		if awserr, ok := err.(awserr.Error); ok {
			if action == route53.ChangeActionDelete && awserr.Code() == route53.ErrCodeInvalidChangeBatch {
				r.log.V(logf.DebugLevel).WithValues("error", err).Info("ignoring InvalidChangeBatch error")
				// If we try to delete something and get a 'InvalidChangeBatch' that
				// means it's already deleted, no need to consider it an error.
				return nil
			}
		}
		return fmt.Errorf("failed to change Route 53 record set: %v", removeReqID(err))

	}

	statusID := resp.ChangeInfo.Id

	return util.WaitFor(120*time.Second, 4*time.Second, func() (bool, error) {
		reqParams := &route53.GetChangeInput{
			Id: statusID,
		}
		resp, err := r.client.GetChange(reqParams)
		if err != nil {
			return false, fmt.Errorf("failed to query Route 53 change status: %v", removeReqID(err))
		}
		if *resp.ChangeInfo.Status == route53.ChangeStatusInsync {
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
	resp, err := r.client.ListHostedZonesByName(reqParams)
	if err != nil {
		return "", removeReqID(err)
	}

	zoneToID := make(map[string]string)
	var hostedZones []string
	for _, hostedZone := range resp.HostedZones {
		// .Name has a trailing dot
		if !*hostedZone.Config.PrivateZone {
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

	if strings.HasPrefix(hostedZoneID, "/hostedzone/") {
		hostedZoneID = strings.TrimPrefix(hostedZoneID, "/hostedzone/")
	}

	return hostedZoneID, nil
}

func newTXTRecordSet(fqdn, value string, ttl int) *route53.ResourceRecordSet {
	return &route53.ResourceRecordSet{
		Name:             aws.String(fqdn),
		Type:             aws.String(route53.RRTypeTxt),
		TTL:              aws.Int64(int64(ttl)),
		MultiValueAnswer: aws.Bool(true),
		SetIdentifier:    aws.String(value),
		ResourceRecords: []*route53.ResourceRecord{
			{Value: aws.String(value)},
		},
	}
}

// The aws-sdk-go library appends a request id to its error messages. We
// want our error messages to be the same when the cause is the same to
// avoid spurious challenge updates.
//
// The given error must not be nil. This function must be called everywhere
// we have a non-nil error coming from an aws-sdk-go func.
func removeReqID(err error) error {
	// NOTE(mael): I first tried to unwrap the RequestFailure to get rid of
	// this request id. But the concrete type requestFailure is private, so
	// I can't unwrap it. Instead, I recreate a new awserr.baseError. It's
	// also a awserr.Error except it doesn't have the request id.
	//
	// Also note that we do not give the origErr to awserr.New. If we did,
	// err.Error() would show the origErr, which we don't want since it
	// contains a request id.
	if e, ok := err.(awserr.RequestFailure); ok {
		return awserr.New(e.Code(), e.Message(), nil)
	}
	return err
}
