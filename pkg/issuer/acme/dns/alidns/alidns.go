// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

// Package Alidns implements a DNS provider for solving the DNS-01 challenge
// using Alibaba Cloud DNS.
package alidns

import (
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/alidns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"os"
	"strings"
)

// DNSProvider implements the util.ChallengeProvider interface
type DNSProvider struct {
	client           *alidns.Client
	dns01Nameservers []string
}

// NewDNSProvider returns a DNSProvider instance configured for the Azure
// DNS service.
// Credentials are automatically detected from environment variables
func NewDNSProvider(dns01Nameservers []string) (*DNSProvider, error) {
	accessKeyID := os.Getenv("ALIBABA_ACCESS_KEY_ID")
	accessKeySecret := os.Getenv("ALIBABA_ACCESS_KEY_SECRET")
	return NewDNSProviderCredentials(accessKeyID, accessKeySecret, dns01Nameservers)
}

// NewDNSProviderCredentials returns a DNSProvider instance configured for the Alidns
// DNS service using static credentials from its parameters
func NewDNSProviderCredentials(accessKeyID, accessKeySecret string, dns01Nameservers []string) (*DNSProvider, error) {

	aliDNSClient, err := alidns.NewClientWithAccessKey(
		"cn-hangzhou",   // Your Region ID
		accessKeyID,     // Your AccessKey ID
		accessKeySecret) // Your AccessKey Secret
	if err != nil {
		return &DNSProvider{}, err
	}
	return &DNSProvider{
		client:           aliDNSClient,
		dns01Nameservers: dns01Nameservers,
	}, nil
}

// Present creates a TXT record to fulfill the dns-01 challenge.
func (d *DNSProvider) Present(domain, fqdn, value string) error {
	_, zoneName, err := d.getHostedZone(domain)
	if err != nil {
		return fmt.Errorf("alicloud: %v", err)
	}

	recordAttributes := d.newTxtRecord(zoneName, fqdn, value)

	_, err = d.client.AddDomainRecord(recordAttributes)
	if err != nil {
		return fmt.Errorf("alicloud: API call failed: %v", err)
	}
	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, fqdn, value string) error {
	records, err := d.findTxtRecords(domain, fqdn)
	if err != nil {
		return fmt.Errorf("alicloud: %v", err)
	}

	_, _, err = d.getHostedZone(domain)
	if err != nil {
		return fmt.Errorf("alicloud: %v", err)
	}

	for _, rec := range records {
		request := alidns.CreateDeleteDomainRecordRequest()
		request.RecordId = rec.RecordId
		_, err = d.client.DeleteDomainRecord(request)
		if err != nil {
			return fmt.Errorf("alicloud: %v", err)
		}
	}
	return nil
}

func (d *DNSProvider) getHostedZone(domain string) (string, string, error) {
	request := alidns.CreateDescribeDomainsRequest()

	var domains []alidns.Domain
	startPage := 1

	for {
		request.PageNumber = requests.NewInteger(startPage)

		response, err := d.client.DescribeDomains(request)
		if err != nil {
			return "", "", fmt.Errorf("API call failed: %v", err)
		}

		domains = append(domains, response.Domains.Domain...)

		if response.PageNumber >= response.PageSize {
			break
		}

		startPage++
	}

	authZone, err := util.FindZoneByFqdn(util.ToFqdn(domain), util.RecursiveNameservers)
	if err != nil {
		return "", "", err
	}

	var hostedZone alidns.Domain
	for _, zone := range domains {
		if zone.DomainName == util.UnFqdn(authZone) {
			hostedZone = zone
		}
	}

	if hostedZone.DomainId == "" {
		return "", "", fmt.Errorf("zone %s not found in AliDNS for domain %s", authZone, domain)
	}
	return fmt.Sprintf("%v", hostedZone.DomainId), hostedZone.DomainName, nil
}

func (d *DNSProvider) newTxtRecord(zone, fqdn, value string) *alidns.AddDomainRecordRequest {
	request := alidns.CreateAddDomainRecordRequest()
	request.Type = "TXT"
	request.DomainName = zone
	request.RR = d.extractRecordName(fqdn, zone)
	request.Value = value
	request.TTL = requests.NewInteger(600)
	return request
}

func (d *DNSProvider) findTxtRecords(domain, fqdn string) ([]alidns.Record, error) {
	_, zoneName, err := d.getHostedZone(domain)
	if err != nil {
		return nil, err
	}

	request := alidns.CreateDescribeDomainRecordsRequest()
	request.DomainName = zoneName
	request.PageSize = requests.NewInteger(500)

	var records []alidns.Record

	result, err := d.client.DescribeDomainRecords(request)
	if err != nil {
		return records, fmt.Errorf("API call has failed: %v", err)
	}

	recordName := d.extractRecordName(fqdn, zoneName)
	for _, record := range result.DomainRecords.Record {
		if record.RR == recordName {
			records = append(records, record)
		}
	}
	return records, nil
}

func (d *DNSProvider) extractRecordName(fqdn, domain string) string {
	name := util.UnFqdn(fqdn)
	if idx := strings.Index(name, "."+domain); idx != -1 {
		return name[:idx]
	}
	return name
}
