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
	"fmt"
	"os"
	"strings"
	"time"

	logf "github.com/cert-manager/cert-manager/pkg/logs"

	"github.com/go-logr/logr"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/option"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

// DNSProvider is an implementation of the DNSProvider interface.
type DNSProvider struct {
	hostedZoneName   string
	dns01Nameservers []string
	project          string
	client           *dns.Service
	log              logr.Logger
}

// NewDNSProvider returns a new DNSProvider Instance with configuration
func NewDNSProvider(project string, saBytes []byte, dns01Nameservers []string, ambient bool, hostedZoneName string) (*DNSProvider, error) {
	// project is a required field
	if project == "" {
		return nil, fmt.Errorf("Google Cloud project name missing")
	}
	// if the service account bytes are not provided, we will attempt to instantiate
	// with 'ambient credentials' (if they are allowed/enabled)
	if len(saBytes) == 0 {
		if !ambient {
			return nil, fmt.Errorf("unable to construct clouddns provider: empty credentials; perhaps you meant to enable ambient credentials?")
		}
		return NewDNSProviderCredentials(project, dns01Nameservers, hostedZoneName)
	}
	// if service account data is provided, we instantiate using that
	if len(saBytes) != 0 {
		return NewDNSProviderServiceAccountBytes(project, saBytes, dns01Nameservers, hostedZoneName)
	}
	return nil, fmt.Errorf("missing Google Cloud DNS provider credentials")
}

// NewDNSProviderEnvironment returns a DNSProvider instance configured for Google Cloud
// DNS. Project name must be passed in the environment variable: GCE_PROJECT.
// A Service Account file can be passed in the environment variable:
// GCE_SERVICE_ACCOUNT_FILE
func NewDNSProviderEnvironment(dns01Nameservers []string, hostedZoneName string) (*DNSProvider, error) {
	project := os.Getenv("GCE_PROJECT")
	if saFile, ok := os.LookupEnv("GCE_SERVICE_ACCOUNT_FILE"); ok {
		return NewDNSProviderServiceAccount(project, saFile, dns01Nameservers, hostedZoneName)
	}
	return NewDNSProviderCredentials(project, dns01Nameservers, hostedZoneName)
}

// NewDNSProviderCredentials uses the supplied credentials to return a
// DNSProvider instance configured for Google Cloud DNS.
func NewDNSProviderCredentials(project string, dns01Nameservers []string, hostedZoneName string) (*DNSProvider, error) {
	if project == "" {
		return nil, fmt.Errorf("Google Cloud project name missing")
	}

	ctx := context.Background()
	client, err := google.DefaultClient(ctx, dns.NdevClouddnsReadwriteScope)
	if err != nil {
		return nil, fmt.Errorf("Unable to get Google Cloud client: %v", err)
	}
	svc, err := dns.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("Unable to create Google Cloud DNS service: %v", err)
	}
	return &DNSProvider{
		project:          project,
		client:           svc,
		dns01Nameservers: dns01Nameservers,
		hostedZoneName:   hostedZoneName,
		log:              logf.Log.WithName("clouddns"),
	}, nil
}

// NewDNSProviderServiceAccount uses the supplied service account JSON file to
// return a DNSProvider instance configured for Google Cloud DNS.
func NewDNSProviderServiceAccount(project string, saFile string, dns01Nameservers []string, hostedZoneName string) (*DNSProvider, error) {
	if project == "" {
		return nil, fmt.Errorf("Google Cloud project name missing")
	}
	if saFile == "" {
		return nil, fmt.Errorf("Google Cloud Service Account file missing")
	}

	dat, err := os.ReadFile(saFile)
	if err != nil {
		return nil, fmt.Errorf("Unable to read Service Account file: %v", err)
	}
	return NewDNSProviderServiceAccountBytes(project, dat, dns01Nameservers, hostedZoneName)
}

// NewDNSProviderServiceAccountBytes uses the supplied service account JSON
// file data to return a DNSProvider instance configured for Google Cloud DNS.
func NewDNSProviderServiceAccountBytes(project string, saBytes []byte, dns01Nameservers []string, hostedZoneName string) (*DNSProvider, error) {
	if project == "" {
		return nil, fmt.Errorf("Google Cloud project name missing")
	}
	if len(saBytes) == 0 {
		return nil, fmt.Errorf("Google Cloud Service Account data missing")
	}

	conf, err := google.JWTConfigFromJSON(saBytes, dns.NdevClouddnsReadwriteScope)
	if err != nil {
		return nil, fmt.Errorf("Unable to acquire config: %v", err)
	}

	ctx := context.Background()
	client := conf.Client(ctx)

	svc, err := dns.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("Unable to create Google Cloud DNS service: %v", err)
	}
	return &DNSProvider{
		project:          project,
		client:           svc,
		dns01Nameservers: dns01Nameservers,
		hostedZoneName:   hostedZoneName,
		log:              logf.Log.WithName("clouddns"),
	}, nil
}

// Present creates a TXT record to fulfil the dns-01 challenge.
func (c *DNSProvider) Present(domain, fqdn, value string) error {
	zone, err := c.getHostedZone(fqdn)
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
	list, err := c.client.ResourceRecordSets.List(c.project, zone).Name(fqdn).Type("TXT").Do()
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

	chg, err := c.client.Changes.Create(c.project, zone, change).Do()
	if err != nil {
		return err
	}

	// wait for change to be acknowledged
	for chg.Status == "pending" {
		time.Sleep(time.Second)

		chg, err = c.client.Changes.Get(c.project, zone, chg.Id).Do()
		if err != nil {
			return err
		}
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (c *DNSProvider) CleanUp(domain, fqdn, value string) error {
	zone, err := c.getHostedZone(fqdn)
	if err != nil {
		return err
	}

	records, err := c.findTxtRecords(zone, fqdn, value)
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
		_, err = c.client.Changes.Create(c.project, zone, change).Do()
		if err != nil {
			return err
		}
	}
	return nil
}

// getHostedZone returns the managed-zone
func (c *DNSProvider) getHostedZone(domain string) (string, error) {
	if c.hostedZoneName != "" {
		return c.hostedZoneName, nil
	}

	authZone, err := util.FindZoneByFqdn(util.ToFqdn(domain), c.dns01Nameservers)
	if err != nil {
		return "", err
	}

	zones, err := c.client.ManagedZones.
		List(c.project).
		DnsName(authZone).
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

	c.log.V(logf.DebugLevel).Info("No matching public GoogleCloud managed-zone for domain, falling back to a private managed-zone", authZone)
	// fall back to first available zone, if none public
	return zones.ManagedZones[0].Name, nil
}

func (c *DNSProvider) findTxtRecords(zone, fqdn, value string) ([]*dns.ResourceRecordSet, error) {
	recs, err := c.client.ResourceRecordSets.List(c.project, zone).Do()
	if err != nil {
		return nil, err
	}

	found := []*dns.ResourceRecordSet{}
RecLoop:
	for _, r := range recs.Rrsets {
		if r.Type == "TXT" && r.Name == fqdn {
			for _, s := range r.Rrdatas {
				if strings.Trim(s, "\"") == value {
					found = append(found, r)
					continue RecLoop
				}
			}
		}
	}

	return found, nil
}
