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
	"math/rand"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/golang/glog"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	pkgutil "github.com/jetstack/cert-manager/pkg/util"
)

const (
	maxRetries = 5
	route53TTL = 10
)

// DNSProvider implements the util.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers []string
	client           *route53.Route53
	hostedZoneID     string
}

// customRetryer implements the client.Retryer interface by composing the
// DefaultRetryer. It controls the logic for retrying recoverable request
// errors (e.g. when rate limits are exceeded).
type customRetryer struct {
	client.DefaultRetryer
}

// RetryRules overwrites the DefaultRetryer's method.
// It uses a basic exponential backoff algorithm that returns an initial
// delay of ~400ms with an upper limit of ~30 seconds which should prevent
// causing a high number of consecutive throttling errors.
// For reference: Route 53 enforces an account-wide(!) 5req/s query limit.
func (d customRetryer) RetryRules(r *request.Request) time.Duration {
	retryCount := r.RetryCount
	if retryCount > 7 {
		retryCount = 7
	}

	delay := (1 << uint(retryCount)) * (rand.Intn(50) + 200)
	return time.Duration(delay) * time.Millisecond
}

// NewDNSProvider returns a DNSProvider instance configured for the AWS
// Route 53 service using static credentials from its parameters or, if they're
// unset and the 'ambient' option is set, credentials from the environment.
func NewDNSProvider(accessKeyID, secretAccessKey, hostedZoneID, region string, ambient bool, dns01Nameservers []string) (*DNSProvider, error) {
	if accessKeyID == "" && secretAccessKey == "" {
		if !ambient {
			return nil, fmt.Errorf("unable to construct route53 provider: empty credentials; perhaps you meant to enable ambient credentials?")
		}
	} else if accessKeyID == "" || secretAccessKey == "" {
		// It's always an error to set one of those but not the other
		return nil, fmt.Errorf("unable to construct route53 provider: only one of access and secret key was provided")
	}

	useAmbientCredentials := ambient && (accessKeyID == "" && secretAccessKey == "")

	r := customRetryer{}
	r.NumMaxRetries = maxRetries
	config := request.WithRetryer(aws.NewConfig(), r)
	sessionOpts := session.Options{}

	if useAmbientCredentials {
		glog.V(5).Infof("using ambient credentials")
		// Leaving credentials unset results in a default credential chain being
		// used; this chain is a reasonable default for getting ambient creds.
		// https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html#specifying-credentials
	} else {
		glog.V(5).Infof("not using ambient credentials")
		config.WithCredentials(credentials.NewStaticCredentials(accessKeyID, secretAccessKey, ""))
		// also disable 'ambient' region sources
		sessionOpts.SharedConfigState = session.SharedConfigDisable
	}

	// If ambient credentials aren't permitted, always set the region, even if to
	// empty string, to avoid it falling back on the environment.
	if region != "" || !useAmbientCredentials {
		config.WithRegion(region)
	}
	sess, err := session.NewSessionWithOptions(sessionOpts)
	if err != nil {
		return nil, fmt.Errorf("unable to create aws session: %s", err)
	}
	sess.Handlers.Build.PushBack(request.WithAppendUserAgent(pkgutil.CertManagerUserAgent))
	client := route53.New(sess, config)

	return &DNSProvider{
		client:           client,
		hostedZoneID:     hostedZoneID,
		dns01Nameservers: dns01Nameservers,
	}, nil
}

// Present creates a TXT record using the specified parameters
func (r *DNSProvider) Present(domain, fqdn, value string) error {
	value = `"` + value + `"`
	return r.addRecord(fqdn, value, route53TTL)
}

// CleanUp removes the TXT record matching the specified parameters
func (r *DNSProvider) CleanUp(domain, fqdn, value string) error {
	value = `"` + value + `"`
	return r.removeRecord(fqdn, value, route53TTL)
}

func (r *DNSProvider) addRecord(fqdn, value string, ttl int) error {
	hostedZoneID, err := r.getHostedZoneID(fqdn)
	if err != nil {
		return fmt.Errorf("Failed to determine Route 53 hosted zone ID: %v", err)
	}

	rrset, err := r.fetchRRSet(fqdn, hostedZoneID)
	if err != nil {
		return err
	}
	recordSet := addTXTRecord(fqdn, value, ttl, rrset)
	return r.performChange(recordSet, hostedZoneID, route53.ChangeActionUpsert)
}

func (r *DNSProvider) removeRecord(fqdn, value string, ttl int) error {
	hostedZoneID, err := r.getHostedZoneID(fqdn)
	if err != nil {
		return fmt.Errorf("Failed to determine Route 53 hosted zone ID: %v", err)
	}

	rrset, err := r.fetchRRSet(fqdn, hostedZoneID)
	if err != nil {
		return err
	}
	newRRSet := removeTXTRecord(value, rrset)
	if newRRSet != nil {
		// record doesn't exist
		return nil
	}
	
	changeaction := route53.ChangeActionDelete
	if len(newRRSet) > 0 {
		changeaction = route53.ChangeActionUpsert
		rrset.ResourceRecords = newRRSet
	}
	return r.performChange(rrset, hostedZoneID, changeaction)
}

func (r *DNSProvider) performChange(recordSet *route53.ResourceRecordSet, hostedZoneID string, action string) error {
	reqParams := &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(hostedZoneID),
		ChangeBatch: &route53.ChangeBatch{
			Comment: aws.String("Managed by cert-manager"),
			Changes: []*route53.Change{
				{
					Action:            aws.String(action),
					ResourceRecordSet: recordSet,
				},
			},
		},
	}
	resp, err := r.client.ChangeResourceRecordSets(reqParams)
	if err != nil {
		if awserr, ok := err.(awserr.Error); ok {
			if action == route53.ChangeActionDelete && awserr.Code() == route53.ErrCodeInvalidChangeBatch {
				glog.V(5).Infof("ignoring InvalidChangeBatch error: %v", err)
				// If we try to delete something and get a 'InvalidChangeBatch' that
				// means it's already deleted, no need to consider it an error.
				return nil
			}
		}
		return fmt.Errorf("Failed to change Route 53 record set: %v", err)

	}

	statusID := resp.ChangeInfo.Id

	return util.WaitFor(120*time.Second, 4*time.Second, func() (bool, error) {
		reqParams := &route53.GetChangeInput{
			Id: statusID,
		}
		resp, err := r.client.GetChange(reqParams)
		if err != nil {
			return false, fmt.Errorf("Failed to query Route 53 change status: %v", err)
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
		return "", err
	}

	var hostedZoneID string
	for _, hostedZone := range resp.HostedZones {
		// .Name has a trailing dot
		if !*hostedZone.Config.PrivateZone && *hostedZone.Name == authZone {
			hostedZoneID = *hostedZone.Id
			break
		}
	}

	if len(hostedZoneID) == 0 {
		return "", fmt.Errorf("Zone %s not found in Route 53 for domain %s", authZone, fqdn)
	}

	if strings.HasPrefix(hostedZoneID, "/hostedzone/") {
		hostedZoneID = strings.TrimPrefix(hostedZoneID, "/hostedzone/")
	}

	return hostedZoneID, nil
}

func (r *DNSProvider) fetchRRSet(fqdn string, hostedZoneID string) (*route53.ResourceRecordSet, error) {
	// AWS doesn't let you just ask for a single RRSet, instead you get a window
	// into a sorted zonefile. Ask for 1 record set starting at TXT records, then check if we
	// got a hit
	rrsets, err := r.client.ListResourceRecordSets(&route53.ListResourceRecordSetsInput{
		HostedZoneId:    aws.String(hostedZoneID),
		StartRecordName: aws.String(fqdn),
		StartRecordType: aws.String("TXT"),
		MaxItems:        aws.String("1"),
	})
	// TODO(dmo): figure out what AWS does here when there are no records
	if err != nil {
		return nil, fmt.Errorf("Failed to list Route 53 hosted zone: %v", err)
	}
	if len(rrsets.ResourceRecordSets) == 1 {
		// check if this is a TXT record and for the
		// FQDN
		set := rrsets.ResourceRecordSets[0]
		if *set.Name == fqdn && *set.Type == "TXT" {
			return set, nil
		}
	}
	return nil, nil
}

func addTXTRecord(fqdn, value string, ttl int, oldSet *route53.ResourceRecordSet) *route53.ResourceRecordSet {
	var txtrr []*route53.ResourceRecord
	if oldSet != nil {
		txtrr = oldSet.ResourceRecords
	}
	txtrr = append(txtrr, &route53.ResourceRecord{
		Value: aws.String(value),
	})
	return &route53.ResourceRecordSet{
		Name:            aws.String(fqdn),
		Type:            aws.String(route53.RRTypeTxt),
		TTL:             aws.Int64(int64(ttl)),
		ResourceRecords: txtrr,
	}
}

func removeTXTRecord(value string, oldSet *route53.ResourceRecordSet) []*route53.ResourceRecord {
	if oldSet == nil {
		return nil
	}
	newValues := make([]*route53.ResourceRecord, 0, len(oldSet.ResourceRecords))
	for _, rr := range oldSet.ResourceRecords {
		if *rr.Value != value {
			newValues = append(newValues, rr)
		}
	}
	if len(newValues) == len(oldSet.ResourceRecords) {
		// nothing to be done
		return nil
	}
	return newValues
}
