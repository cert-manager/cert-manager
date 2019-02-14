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
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/dns/v1"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

// DNSProvider is an implementation of the DNSProvider interface.
type DNSProvider struct {
	dns01Nameservers []string
	project          string
	client           *dns.Service
}

func NewDNSProvider(project string, saBytes []byte, dns01Nameservers []string, ambient bool) (*DNSProvider, error) {
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
		return NewDNSProviderCredentials(project, dns01Nameservers)
	}
	// if service account data is provided, we instantiate using that
	if len(saBytes) != 0 {
		return NewDNSProviderServiceAccountBytes(project, saBytes, dns01Nameservers)
	}
	return nil, fmt.Errorf("missing Google Cloud DNS provider credentials")
}

// NewDNSProviderEnvironment returns a DNSProvider instance configured for Google Cloud
// DNS. Project name must be passed in the environment variable: GCE_PROJECT.
// A Service Account file can be passed in the environment variable:
// GCE_SERVICE_ACCOUNT_FILE
func NewDNSProviderEnvironment(dns01Nameservers []string) (*DNSProvider, error) {
	project := os.Getenv("GCE_PROJECT")
	if saFile, ok := os.LookupEnv("GCE_SERVICE_ACCOUNT_FILE"); ok {
		return NewDNSProviderServiceAccount(project, saFile, dns01Nameservers)
	}
	return NewDNSProviderCredentials(project, dns01Nameservers)
}

// NewDNSProviderCredentials uses the supplied credentials to return a
// DNSProvider instance configured for Google Cloud DNS.
func NewDNSProviderCredentials(project string, dns01Nameservers []string) (*DNSProvider, error) {
	if project == "" {
		return nil, fmt.Errorf("Google Cloud project name missing")
	}

	client, err := google.DefaultClient(context.Background(), dns.NdevClouddnsReadwriteScope)
	if err != nil {
		return nil, fmt.Errorf("Unable to get Google Cloud client: %v", err)
	}
	svc, err := dns.New(client)
	if err != nil {
		return nil, fmt.Errorf("Unable to create Google Cloud DNS service: %v", err)
	}
	return &DNSProvider{
		project:          project,
		client:           svc,
		dns01Nameservers: dns01Nameservers,
	}, nil
}

// NewDNSProviderServiceAccount uses the supplied service account JSON file to
// return a DNSProvider instance configured for Google Cloud DNS.
func NewDNSProviderServiceAccount(project string, saFile string, dns01Nameservers []string) (*DNSProvider, error) {
	if project == "" {
		return nil, fmt.Errorf("Google Cloud project name missing")
	}
	if saFile == "" {
		return nil, fmt.Errorf("Google Cloud Service Account file missing")
	}

	dat, err := ioutil.ReadFile(saFile)
	if err != nil {
		return nil, fmt.Errorf("Unable to read Service Account file: %v", err)
	}
	return NewDNSProviderServiceAccountBytes(project, dat, dns01Nameservers)
}

// NewDNSProviderServiceAccountBytes uses the supplied service account JSON
// file data to return a DNSProvider instance configured for Google Cloud DNS.
func NewDNSProviderServiceAccountBytes(project string, saBytes []byte, dns01Nameservers []string) (*DNSProvider, error) {
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
	client := conf.Client(oauth2.NoContext)

	svc, err := dns.New(client)
	if err != nil {
		return nil, fmt.Errorf("Unable to create Google Cloud DNS service: %v", err)
	}
	return &DNSProvider{
		project:          project,
		client:           svc,
		dns01Nameservers: dns01Nameservers,
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
	change := &dns.Change{
		Additions: []*dns.ResourceRecordSet{rec},
	}

	// Look for existing records.
	list, err := c.client.ResourceRecordSets.List(c.project, zone).Name(fqdn).Type("TXT").Do()
	if err != nil {
		return err
	}
	if len(list.Rrsets) > 0 {
		// Attempt to delete the existing records when adding our new one.
		change.Deletions = list.Rrsets
	}

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

	records, err := c.findTxtRecords(zone, fqdn)
	if err != nil {
		return err
	}

	for _, rec := range records {
		change := &dns.Change{
			Deletions: []*dns.ResourceRecordSet{rec},
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

	return zones.ManagedZones[0].Name, nil
}

func (c *DNSProvider) findTxtRecords(zone, fqdn string) ([]*dns.ResourceRecordSet, error) {

	recs, err := c.client.ResourceRecordSets.List(c.project, zone).Do()
	if err != nil {
		return nil, err
	}

	found := []*dns.ResourceRecordSet{}
	for _, r := range recs.Rrsets {
		if r.Type == "TXT" && r.Name == fqdn {
			found = append(found, r)
		}
	}

	return found, nil
}
