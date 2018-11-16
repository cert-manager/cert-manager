// Package godaddy implements a DNS provider for solving the DNS-01 challenge using godaddy DNS.
package godaddy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	pkgutil "github.com/jetstack/cert-manager/pkg/util"
)

const (
	// defaultBaseURL represents the API endpoint to call.
	defaultBaseURL = "https://api.godaddy.com"
	minTTL         = 600
)

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers []string
	authAPIKey       string
	authAPISecret    string

	transport              http.RoundTripper
	findHostedDomainByFqdn func(string) (string, error)
}

// DNSRecord a DNS record
type DNSRecord struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Data     string `json:"data"`
	Priority int    `json:"priority,omitempty"`
	TTL      int    `json:"ttl,omitempty"`
}

// NewDNSProvider returns a DNSProvider instance configured for godaddy.
// Credentials must be passed in the the Issuer CRD and secret reference:
func NewDNSProvider(apiKey, apiSecret string, dns01Nameservers []string) (*DNSProvider, error) {
	if apiKey == "" || apiSecret == "" {
		return nil, fmt.Errorf("godaddy: some credentials are missing: apiKey or apiSecret")
	}
	return &DNSProvider{
		dns01Nameservers: dns01Nameservers,
		// authEmail:        authEmail,
		authAPIKey:    apiKey,
		authAPISecret: apiSecret,
	}, nil

}

// Timeout returns the timeout and interval to use when checking for DNS
// propagation. Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	// return d.config.PropagationTimeout, d.config.PollingInterval
	return 5 * time.Minute, 5 * time.Second
}

func (d *DNSProvider) extractRecordName(fqdn, domain string) string {
	name := util.UnFqdn(fqdn)
	if idx := strings.Index(name, "."+domain); idx != -1 {
		return name[:idx]
	}
	return name
}

// Present creates a TXT record to fulfill the dns-01 challenge
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	fqdn, value, _, err := util.DNS01Record(domain, keyAuth, d.dns01Nameservers)
	domainZone, err := d.getZone(fqdn)
	if err != nil {
		return err
	}

	recordName := d.extractRecordName(fqdn, domainZone)
	rec := []DNSRecord{
		{
			Type: "TXT",
			Name: recordName,
			Data: value,
			TTL:  minTTL,
		},
	}

	return d.updateRecords(rec, domainZone, recordName)
}

func (d *DNSProvider) updateRecords(records []DNSRecord, domainZone string, recordName string) error {
	body, err := json.Marshal(records)
	if err != nil {
		return err
	}

	var resp *http.Response
	resp, err = d.makeRequest(http.MethodPut, fmt.Sprintf("/v1/domains/%s/records/TXT/%s", domainZone, recordName), bytes.NewReader(body))
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("could not create record %v; Status: %v; Body: %s", string(body), resp.StatusCode, string(bodyBytes))
	}
	return nil
}

// CleanUp sets null value in the TXT DNS record as GoDaddy has no proper DELETE record method
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	fqdn, _, _, err := util.DNS01Record(domain, keyAuth, d.dns01Nameservers)
	if err != nil {
		return err
	}
	domainZone, err := d.getZone(fqdn)
	if err != nil {
		return err
	}

	recordName := d.extractRecordName(fqdn, domainZone)
	rec := []DNSRecord{
		{
			Type: "TXT",
			Name: recordName,
			Data: "null",
		},
	}

	return d.updateRecords(rec, domainZone, recordName)
}

func (d *DNSProvider) getZone(fqdn string) (string, error) {
	authZone, err := util.FindZoneByFqdn(fqdn, util.RecursiveNameservers)
	if err != nil {
		return "", err
	}
	return util.UnFqdn(authZone), nil
}

func (d *DNSProvider) makeRequest(method, uri string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, fmt.Sprintf("%s%s", defaultBaseURL, uri), body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", pkgutil.CertManagerUserAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("sso-key %s:%s", d.authAPIKey, d.authAPISecret))

	client := http.Client{
		Transport: d.transport,
		Timeout:   30 * time.Second,
	}

	return client.Do(req)
}
