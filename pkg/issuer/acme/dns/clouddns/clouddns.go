// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

// Package clouddns implements a DNS provider for solving the DNS-01
// challenge using Google Cloud DNS.
package clouddns

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/option"
	"k8s.io/utils/ptr"

	utiloptions "github.com/cert-manager/cert-manager/internal/options"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// DNSProvider is an implementation of the DNSProvider interface.
type DNSProvider struct {
	hostedZoneName   string
	dns01Nameservers []string
	project          string
	client           *dns.Service
	resolver         util.Resolver
	log              logr.Logger
}

// NewDNSProviderFromOptions constructs an ACME DNS provider for Google Cloud DNS.
//
// All options are passed via the variadic options parameter.
//
// Required options:
// - Project
// - Nameservers
// - Resolver
func NewDNSProviderFromOptions(ctx context.Context, options ...DNSProviderOption) (*DNSProvider, error) {
	var opt DNSProviderOptions
	for _, o := range options {
		o.ApplyToDNSProviderOptions(&opt)
	}

	err := errors.Join(
		utiloptions.Required(&opt.Project, "Google Cloud project name missing"),
		utiloptions.NotEmpty(&opt.Nameservers, "nameservers are required"),
		utiloptions.Required(&opt.Resolver, "resolver is required"),
	)

	if err != nil {
		return nil, err
	}

	// Get the DNS service for the given config
	svc, err := getDNSService(ctx, opt)
	if err != nil {
		return nil, err
	}

	return &DNSProvider{
		project:          opt.Project,
		client:           svc,
		dns01Nameservers: opt.Nameservers,
		hostedZoneName:   opt.HostedZoneName,
		resolver:         opt.Resolver,
		log:              logf.Log.WithName("clouddns"),
	}, nil

}

// NewDNSProvider returns a new DNSProvider Instance with configuration
//
// Deprecated: Use NewDNSProviderFromOptions
func NewDNSProvider(ctx context.Context, project string, saBytes []byte, dns01Nameservers []string, ambient bool, hostedZoneName string) (*DNSProvider, error) {
	return NewDNSProviderFromOptions(ctx,
		Project(project),
		ServiceAccountBytes(saBytes),
		Nameservers(dns01Nameservers),
		Ambient(ambient),
		HostedZoneName(hostedZoneName),
		Resolver(util.LegacyCachedResolver()),
	)
}

// NewDNSProviderEnvironment returns a DNSProvider instance configured for Google Cloud
// DNS. Project name must be passed in the environment variable: GCE_PROJECT.
// A Service Account file can be passed in the environment variable:
// GCE_SERVICE_ACCOUNT_FILE
//
// Deprecated: Use NewDNSProviderFromOptions
func NewDNSProviderEnvironment(ctx context.Context, dns01Nameservers []string, hostedZoneName string) (*DNSProvider, error) {
	project := os.Getenv("GCE_PROJECT")
	if saFile, ok := os.LookupEnv("GCE_SERVICE_ACCOUNT_FILE"); ok {
		return NewDNSProviderServiceAccount(ctx, project, saFile, dns01Nameservers, hostedZoneName)
	}
	return NewDNSProviderCredentials(ctx, project, dns01Nameservers, hostedZoneName)
}

// NewDNSProviderCredentials uses the supplied credentials to return a
// DNSProvider instance configured for Google Cloud DNS.
//
// Deprecated: Use NewDNSProviderFromOptions
func NewDNSProviderCredentials(ctx context.Context, project string, dns01Nameservers []string, hostedZoneName string) (*DNSProvider, error) {
	return NewDNSProviderFromOptions(ctx,
		Project(project),
		Ambient(true),
		Nameservers(dns01Nameservers),
		HostedZoneName(hostedZoneName),
		Resolver(util.LegacyCachedResolver()),
	)
}

// NewDNSProviderServiceAccount uses the supplied service account JSON file to
// return a DNSProvider instance configured for Google Cloud DNS.
//
// Deprecated: Use NewDNSProviderFromOptions
func NewDNSProviderServiceAccount(ctx context.Context, project string, saFile string, dns01Nameservers []string, hostedZoneName string) (*DNSProvider, error) {
	if saFile == "" {
		return nil, fmt.Errorf("Google Cloud Service Account file missing")
	}

	return NewDNSProviderFromOptions(ctx,
		Project(project),
		Nameservers(dns01Nameservers),
		ServiceAccountFile(saFile),
		HostedZoneName(hostedZoneName),
		Resolver(util.LegacyCachedResolver()),
	)
}

// NewDNSProviderServiceAccountBytes uses the supplied service account JSON
// file data to return a DNSProvider instance configured for Google Cloud DNS.
//
// Deprecated: Use NewDNSProviderFromOptions
func NewDNSProviderServiceAccountBytes(ctx context.Context, project string, saBytes []byte, dns01Nameservers []string, hostedZoneName string) (*DNSProvider, error) {
	if len(saBytes) == 0 {
		return nil, fmt.Errorf("Google Cloud Service Account data missing")
	}

	return NewDNSProviderFromOptions(ctx,
		Project(project),
		Nameservers(dns01Nameservers),
		ServiceAccountBytes(saBytes),
		HostedZoneName(hostedZoneName),
		Resolver(util.LegacyCachedResolver()),
	)
}

// Present creates a TXT record to fulfil the dns-01 challenge.
func (c *DNSProvider) Present(ctx context.Context, domain, fqdn, value string) error {
	zone, err := c.getHostedZone(ctx, fqdn)
	if err != nil {
		return err
	}

	rec := &dns.ResourceRecordSet{
		Name:    fqdn,
		Rrdatas: []string{value},
		Ttl:     int64(60),
		Type:    "TXT",
	}
	change := &dns.Change{}

	// Look for existing records.
	list, err := c.client.ResourceRecordSets.
		List(c.project, zone).
		Name(fqdn).
		Type("TXT").
		Context(ctx).
		Do()
	if err != nil {
		return err
	}
	if len(list.Rrsets) > 0 {
		// Merge the existing RR Data into the new one, requires a delete and an add operation, or it will fail.
		// The operations are applied atomically to the zone, so there is no point in time where the entire TXT record is deleted.
		// Reference; https://cloud.google.com/dns/docs/reference/v1/changes
		change.Deletions = list.Rrsets
		for _, r := range list.Rrsets {
			if r.Type == "TXT" && r.Name == fqdn {
				// Check if record is already present
				for _, s := range r.Rrdatas {
					if strings.Trim(s, "\"") == value {
						return nil
					}
				}
				rec.Rrdatas = append(rec.Rrdatas, r.Rrdatas...)
			}
		}
	}
	change.Additions = []*dns.ResourceRecordSet{rec}

	chg, err := c.client.Changes.Create(c.project, zone, change).Context(ctx).Do()
	if err != nil {
		return err
	}

	// wait for change to be acknowledged
	for chg.Status == "pending" {
		time.Sleep(time.Second)

		chg, err = c.client.Changes.Get(c.project, zone, chg.Id).Context(ctx).Do()
		if err != nil {
			return err
		}
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (c *DNSProvider) CleanUp(ctx context.Context, domain, fqdn, value string) error {
	zone, err := c.getHostedZone(ctx, fqdn)
	if err != nil {
		return err
	}

	records, err := c.findTxtRecords(ctx, zone, fqdn, value)
	if err != nil {
		return err
	}

	for _, rec := range records {
		change := &dns.Change{
			Deletions: []*dns.ResourceRecordSet{rec},
		}
		// If more than our rrdata, then filter it out but keep the rest
		// Like in the Present() call, to keep the other rrdata we must delete, and re-add it, in one atomic operation.
		if len(rec.Rrdatas) > 1 {
			filtered := new(dns.ResourceRecordSet)
			*filtered = *rec // shallow copy
			filtered.Rrdatas = make([]string, 0, len(rec.Rrdatas))
			for _, r := range rec.Rrdatas {
				if strings.Trim(r, "\"") != value {
					filtered.Rrdatas = append(filtered.Rrdatas, r)
				}
			}
			change.Additions = []*dns.ResourceRecordSet{filtered}
		}
		_, err = c.client.Changes.Create(c.project, zone, change).Context(ctx).Do()
		if err != nil {
			return err
		}
	}
	return nil
}

// getHostedZone returns the managed-zone
func (c *DNSProvider) getHostedZone(ctx context.Context, domain string) (string, error) {
	if c.hostedZoneName != "" {
		return c.hostedZoneName, nil
	}

	authZone, err := c.resolver.FindZoneByFQDN(ctx, util.ToFqdn(domain), c.dns01Nameservers)
	if err != nil {
		return "", err
	}

	zones, err := c.client.ManagedZones.
		List(c.project).
		DnsName(authZone).
		Context(ctx).
		Do()
	if err != nil {
		return "", fmt.Errorf("GoogleCloud API call failed: %v", err)
	}

	if len(zones.ManagedZones) == 0 {
		return "", fmt.Errorf("No matching GoogleCloud domain found for domain %s", authZone)
	}

	// attempt to get the first public zone
	for _, zone := range zones.ManagedZones {
		if zone.Visibility == "public" {
			return zone.Name, nil
		}
	}

	c.log.V(logf.DebugLevel).Info("No matching public GoogleCloud managed-zone for domain, falling back to a private managed-zone", "authZone", authZone)
	// fall back to first available zone, if none public
	return zones.ManagedZones[0].Name, nil
}

func (c *DNSProvider) findTxtRecords(ctx context.Context, zone, fqdn, value string) ([]*dns.ResourceRecordSet, error) {
	recs, err := c.client.ResourceRecordSets.
		List(c.project, zone).
		Name(fqdn).
		Type("TXT").
		Context(ctx).
		Do()
	if err != nil {
		return nil, err
	}

	found := []*dns.ResourceRecordSet{}
RecLoop:
	for _, r := range recs.Rrsets {
		for _, s := range r.Rrdatas {
			if strings.Trim(s, "\"") == value {
				found = append(found, r)
				continue RecLoop
			}
		}
	}

	return found, nil
}

func getDNSService(ctx context.Context, o DNSProviderOptions) (*dns.Service, error) {
	// Get the service account bytes from either config or the file
	saBytes, err := getServiceAccountBytes(o)
	if err != nil {
		return nil, err
	}

	// If we have no service account then we are using ambient credentials
	if len(saBytes) == 0 {
		if !ptr.Deref(o.Ambient, false) {
			return nil, fmt.Errorf("unable to construct clouddns provider: empty credentials; perhaps you meant to enable ambient credentials?")
		}

		client, err := google.DefaultClient(ctx, dns.NdevClouddnsReadwriteScope)
		if err != nil {
			return nil, fmt.Errorf("Unable to get Google Cloud client: %v", err)
		}

		svc, err := dns.NewService(ctx, option.WithHTTPClient(client))
		if err != nil {
			return nil, fmt.Errorf("Unable to create Google Cloud DNS service: %v", err)
		}

		return svc, nil
	}

	conf, err := google.JWTConfigFromJSON(saBytes, dns.NdevClouddnsReadwriteScope)
	if err != nil {
		return nil, fmt.Errorf("Unable to acquire config: %v", err)
	}

	client := conf.Client(ctx)

	svc, err := dns.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("Unable to create Google Cloud DNS service: %v", err)
	}

	return svc, nil
}

func getServiceAccountBytes(o DNSProviderOptions) ([]byte, error) {
	if len(o.ServiceAccountBytes) != 0 {
		return o.ServiceAccountBytes, nil
	}

	if len(o.ServiceAccountFile) != 0 {
		data, err := os.ReadFile(o.ServiceAccountFile)
		if err != nil {
			return nil, fmt.Errorf("Unable to read Service Account file: %v", err)
		}
		return data, nil
	}

	return nil, nil
}
