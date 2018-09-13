// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

// Package livedns implements a DNS provider for solving the DNS-01
// challenge using gandi livedns DNS service.
package livedns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang/glog"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

// Gandi API reference:       http://doc.livedns.gandi.net/

var (
	// endpoint is the Gandi API endpoint used by Present and
	// CleanUp. It is overridden during tests.
	endpoint = "https://dns.api.gandi.net/api/v5"

	// findZoneByFqdn determines the DNS zone of an fqdn. It is overridden
	// during tests.
	findZoneByFqdn = util.FindZoneByFqdn
)

// DNSProvider is an implementation of the
// acme.ChallengeProviderTimeout interface that uses Gandi's LiveDNS
// API to manage TXT records for a domain.
type DNSProvider struct {
	dns01Nameservers []string
	apiKey           string
	client           *http.Client
}

// NewDNSProviderCredentials uses the supplied credentials to return a
// DNSProvider instance configured for Gandi.
func NewDNSProviderCredentials(apiKey string, dns01Nameservers []string) (*DNSProvider, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("Gandi DNS: No Gandi API Key given")
	}
	return &DNSProvider{
		apiKey:           apiKey,
		client:           &http.Client{Timeout: 10 * time.Second},
		dns01Nameservers: dns01Nameservers,
	}, nil
}

// Present creates a TXT record using the specified parameters.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	fqdn, value, ttl, err := util.DNS01Record(domain, keyAuth, d.dns01Nameservers)
	if err != nil {
		return err
	}

	if ttl < 300 {
		ttl = 300 // 300 is gandi minimum value for ttl
	}

	// find authZone
	authZone, err := findZoneByFqdn(fqdn, util.RecursiveNameservers)
	if err != nil {
		return fmt.Errorf("Gandi DNS: findZoneByFqdn failure: %v", err)
	}

	// determine name of TXT record
	if !strings.HasSuffix(
		strings.ToLower(fqdn), strings.ToLower("."+authZone)) {
		return fmt.Errorf(
			"Gandi DNS: unexpected authZone %s for fqdn %s", authZone, fqdn)
	}
	name := fqdn[:len(fqdn)-len("."+authZone)]

	// add TXT record into authZone
	err = d.addTXTRecord(util.UnFqdn(authZone), name, value, ttl)
	if err != nil {
		return err
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	fqdn, _, _, err := util.DNS01Record(domain, keyAuth, d.dns01Nameservers)
	if err != nil {
		return err
	}

	// find authZone
	authZone, err := findZoneByFqdn(fqdn, util.RecursiveNameservers)
	if err != nil {
		return fmt.Errorf("Gandi DNS: findZoneByFqdn failure: %v", err)
	}

	// determine name of TXT record
	if !strings.HasSuffix(
		strings.ToLower(fqdn), strings.ToLower("."+authZone)) {
		return fmt.Errorf(
			"Gandi DNS: unexpected authZone %s for fqdn %s", authZone, fqdn)
	}
	name := fqdn[:len(fqdn)-len("."+authZone)]

	// delete TXT record from authZone
	return d.deleteTXTRecord(util.UnFqdn(authZone), name)
}

// Timeout returns the values (20*time.Minute, 20*time.Second) which
// are used by the acme package as timeout and check interval values
// when checking for DNS record propagation with Gandi.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return 20 * time.Minute, 20 * time.Second
}

// types for JSON method calls and parameters

type addFieldRequest struct {
	RRSetTTL    int      `json:"rrset_ttl"`
	RRSetValues []string `json:"rrset_values"`
}

type deleteFieldRequest struct {
	Delete bool `json:"delete"`
}

// types for JSON responses

type responseStruct struct {
	Message string `json:"message"`
}

// POSTing/Marshalling/Unmarshalling

func (d *DNSProvider) sendRequest(method string, resource string, payload interface{}) (*responseStruct, error) {
	url := fmt.Sprintf("%s/%s", endpoint, resource)

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if len(d.apiKey) > 0 {
		req.Header.Set("X-Api-Key", d.apiKey)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("Gandi DNS: request failed with HTTP status code %d", resp.StatusCode)
	}
	var response responseStruct
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil && method != http.MethodDelete {
		return nil, err
	}

	return &response, nil
}

// functions to perform API actions

func (d *DNSProvider) addTXTRecord(domain string, name string, value string, ttl int) error {
	target := fmt.Sprintf("domains/%s/records/%s/TXT", domain, name)
	response, err := d.sendRequest(http.MethodPut, target, addFieldRequest{
		RRSetTTL:    ttl,
		RRSetValues: []string{value},
	})
	if response != nil {
		glog.Infof("Gandi DNS: %s", response.Message)
	}
	return err
}

func (d *DNSProvider) deleteTXTRecord(domain string, name string) error {
	target := fmt.Sprintf("domains/%s/records/%s/TXT", domain, name)
	response, err := d.sendRequest(http.MethodDelete, target, deleteFieldRequest{
		Delete: true,
	})
	if response != nil && response.Message == "" {
		glog.Infof("Gandi DNS: Zone record deleted")
	}
	return err
}
