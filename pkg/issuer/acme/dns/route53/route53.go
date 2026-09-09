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
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"k8s.io/utils/ptr"

	utiloptions "github.com/cert-manager/cert-manager/internal/options"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

const (
	route53TTL = 10

	changePollTimeout  = 120 * time.Second
	changePollInterval = 4 * time.Second
)

// DNSProvider implements the util.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers []string
	client           *route53.Client
	hostedZoneID     string
	userAgent        string
	resolver         util.Resolver
	pendingChanges   *PendingChangesCache

	// pollTimeout and pollInterval control how long a single Present or
	// CleanUp call waits for a submitted record change to reach the INSYNC
	// status. They exist so that tests can wait for less than the default
	// changePollTimeout.
	pollTimeout  time.Duration
	pollInterval time.Duration
}

func NewDNSProviderFromOptions(ctx context.Context, options ...DNSProviderOption) (*DNSProvider, error) {
	var opt DNSProviderOptions
	for _, o := range options {
		o.ApplyToDNSProviderOptions(&opt)
	}

	err := errors.Join(
		utiloptions.Required(&opt.Resolver, "resolver is required"),
		utiloptions.NotEmpty(&opt.Nameservers, "nameservers is required"),
	)

	if err != nil {
		return nil, err
	}

	provider := newSessionProvider(
		opt.AccessKeyID,
		opt.SecretAccessKey,
		opt.Region,
		opt.Role,
		opt.WebIdentityToken,
		ptr.Deref(opt.Ambient, false),
		opt.UserAgent,
	)

	cfg, err := provider.GetSession(ctx)
	if err != nil {
		return nil, err
	}

	client := route53.NewFromConfig(cfg)

	pendingChanges := opt.PendingChanges
	if pendingChanges == nil {
		pendingChanges = NewPendingChangesCache()
	}

	return &DNSProvider{
		client:           client,
		hostedZoneID:     opt.HostedZoneID,
		dns01Nameservers: opt.Nameservers,
		userAgent:        opt.UserAgent,
		resolver:         opt.Resolver,
		pendingChanges:   pendingChanges,
		pollTimeout:      changePollTimeout,
		pollInterval:     changePollInterval,
	}, nil
}

// NewDNSProvider returns a DNSProvider instance configured for the AWS
// Route 53 service using static credentials from its parameters or, if they're
// unset and the 'ambient' option is set, credentials from the environment.
//
// Deprecated: Use NewDNSProviderFromOptions
func NewDNSProvider(
	ctx context.Context,
	accessKeyID, secretAccessKey, hostedZoneID, region, role, webIdentityToken string,
	ambient bool,
	dns01Nameservers []string,
	userAgent string,
) (*DNSProvider, error) {
	return NewDNSProviderFromOptions(ctx,
		AccessKeyID(accessKeyID),
		SecretAccessKey(secretAccessKey),
		HostedZoneID(hostedZoneID),
		Region(region),
		Role(role),
		WebIdentityToken(webIdentityToken),
		Ambient(ambient),
		Nameservers(dns01Nameservers),
		UserAgent(userAgent),
		Resolver(util.LegacyCachedResolver()),
	)
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

	changeID, resuming := r.pendingChanges.get(action, fqdn, value)
	if resuming {
		log.V(logf.DebugLevel).Info(
			"Found a previously submitted Route 53 record change which has not yet propagated. "+
				"Resuming the wait for it to reach the INSYNC status instead of submitting a new change.",
			"changeID", changeID,
		)
	} else {
		// Forget any pending change for the same record with a different
		// action; the change submitted below supersedes it.
		r.pendingChanges.delete(fqdn, value)

		hostedZoneID, err := r.getHostedZoneID(ctx, fqdn)
		if err != nil {
			return fmt.Errorf("failed to determine Route 53 hosted zone ID: %w", err)
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
			return fmt.Errorf("failed to change Route 53 record set: %w", err)

		}

		changeID = *resp.ChangeInfo.Id
		r.pendingChanges.put(action, fqdn, value, changeID)
	}

	// util.WaitFor has no way to stop early with an error, so a fatal poll
	// result is smuggled out through vanishedErr.
	var vanishedErr error
	waitErr := util.WaitFor(r.pollTimeout, r.pollInterval, func() (bool, error) {
		reqParams := &route53.GetChangeInput{
			Id: aws.String(changeID),
		}
		resp, err := r.client.GetChange(ctx, reqParams)
		if err != nil {
			// The remembered change no longer exists, so forget it, stop
			// waiting, and let the next attempt submit a new change.
			if _, ok := errors.AsType[*route53types.NoSuchChange](err); ok {
				r.pendingChanges.delete(fqdn, value)
				vanishedErr = fmt.Errorf("failed to query Route 53 change status: %w", err)
				return true, nil
			}
			return false, fmt.Errorf("failed to query Route 53 change status: %w", err)
		}
		if resp.ChangeInfo.Status == route53types.ChangeStatusInsync {
			r.pendingChanges.delete(fqdn, value)
			return true, nil
		}
		return false, nil
	})
	if vanishedErr != nil {
		return vanishedErr
	}
	return waitErr
}

func (r *DNSProvider) getHostedZoneID(ctx context.Context, fqdn string) (string, error) {
	if r.hostedZoneID != "" {
		return r.hostedZoneID, nil
	}

	authZone, err := r.resolver.FindZoneByFQDN(ctx, fqdn, r.dns01Nameservers)
	if err != nil {
		return "", fmt.Errorf("error finding zone from fqdn: %w", err)
	}

	// .DNSName should not have a trailing dot
	reqParams := &route53.ListHostedZonesByNameInput{
		DNSName: aws.String(util.UnFqdn(authZone)),
	}
	resp, err := r.client.ListHostedZonesByName(ctx, reqParams)
	if err != nil {
		return "", err
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
