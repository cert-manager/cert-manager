// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

// Package godaddy implements a DNS provider for solving the DNS-01 challenge
// using Godaddy DNS.
package godaddy

import (
	"fmt"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// defaultBaseURL represents the API endpoint to call.
	defaultBaseURL = "https://api.godaddy.com"
	minTTL         = 600
)

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers []string
	apiKey             string
	apiSecret          string
	propagationTimeout time.Duration
	pollingInterval    time.Duration
	sequenceInterval   time.Duration
	ttl                int
	httpclient         *http.Client
}

// NewDNSProvider returns a DNSProvider instance configured for godaddy.
// Credentials must be passed as environment variables:
// GODADDY_API_KEY and GODADDY_API_SECRET.
func NewDNSProvider(dns01Nameservers []string) (*DNSProvider, error) {
	apiKey := os.Getenv("GODADDY_API_KEY")
	apiSecret := os.Getenv( "GODADDY_API_SECRET")
    ttl := os.Getenv("GODADDY_TTL")
    propagationTimeout := os.Getenv("GODADDY_PROPAGATION_TIMEOUT")
	pollingInterval := os.Getenv("GODADDY_POLLING_INTERVAL")
	sequenceInterval := os.Getenv("GODADDY_SEQUENCE_INTERVAL")
	httpTimeout := os.Getenv("GODADDY_HTTP_TIMEOUT")
	return NewDNSProviderCredentials(apiKey, apiSecret, ttl, propagationTimeout, pollingInterval, sequenceInterval, httpTimeout, dns01Nameservers)
}

// NewDNSProviderCredentials return a DNSProvider instance configured for godaddy.
func NewDNSProviderCredentials(apiKey, apiSecret, ttl, propagationTimeOut, pollingInterval, sequenceInterval, httpTimeout string, dns01Nameservers []string) (*DNSProvider, error) {
	if apiKey == "" || apiSecret == "" {
		return nil, fmt.Errorf("Godaddy: credentials missing (apiKey and/or apiSecret)")
	}
	return &DNSProvider{
		dns01Nameservers: dns01Nameservers,
		apiKey:apiKey,
		apiSecret:apiSecret,
		ttl: stringToInt(ttl),
		sequenceInterval: time.Duration(stringToInt(sequenceInterval)) * time.Second,
		pollingInterval: time.Duration(stringToInt(pollingInterval)) * time.Second,
		propagationTimeout: time.Duration(stringToInt(propagationTimeOut)) * time.Second,
		httpclient: &http.Client{
		   Timeout: time.Duration(stringToInt(httpTimeout)),
	    },
	}, nil
}

// Timeout returns the timeout and interval to use when checking for DNS
// propagation. Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.propagationTimeout, d.pollingInterval
}

// Present creates a TXT record using the specified parameters
func (d *DNSProvider) Present(domain, fqdn, value string) error {
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
			TTL:  d.ttl,
		},
	}

	return d.updateRecords(rec, domainZone, recordName)
}

// CleanUp sets null value in the TXT DNS record as GoDaddy has no proper DELETE record method
func (d *DNSProvider) CleanUp(domain, fqdn, value string) error {
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

func (d *DNSProvider) extractRecordName(fqdn, domain string) string {
	name := util.UnFqdn(fqdn)
	if idx := strings.Index(name, "."+domain); idx != -1 {
		return name[:idx]
	}
	return name
}

func (d *DNSProvider) getZone(fqdn string) (string, error) {
	authZone, err := util.FindZoneByFqdn(fqdn,d.dns01Nameservers)
	if err != nil {
		return "", err
	}

	return util.UnFqdn(authZone), nil
}

func stringToInt(val string) int {
	i, err := strconv.Atoi(val)
	if err != nil {
		fmt.Errorf("can't convert TTL to int : %s",val)
	}
	return i
}

