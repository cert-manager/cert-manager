// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

// Package alibabacloud implements a DNS provider for solving the DNS-01
// challenge using Alibaba Cloud DNS.
package alibabacloud

import (
	"errors"
	"fmt"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/xenolf/lego/platform/config/env"
	"strings"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth/credentials"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/alidns"
)

const defaultRegionID = "cn-hangzhou"

// Config is used to configure the creation of the DNSProvider
type Config struct {
	APIKey             string
	SecretKey          string
	RegionID           string
	PropagationTimeout time.Duration
	PollingInterval    time.Duration
	TTL                int
	HTTPTimeout        time.Duration
}

// NewDefaultConfig returns a default configuration for the DNSProvider
func NewDefaultConfig() *Config {
	return &Config{
		TTL:                env.GetOrDefaultInt("ALICLOUD_TTL", 600),
		PropagationTimeout: env.GetOrDefaultSecond("ALICLOUD_PROPAGATION_TIMEOUT", util.DNSTimeout),
		PollingInterval:    env.GetOrDefaultSecond("ALICLOUD_POLLING_INTERVAL", 2*time.Second),
		HTTPTimeout:        env.GetOrDefaultSecond("ALICLOUD_HTTP_TIMEOUT", 10*time.Second),
	}
}

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers []string
	config           *Config
	client           *alidns.Client
}

// NewDNSProvider returns a DNSProvider instance configured for Alibaba Cloud DNS.
func NewDNSProvider(accessKey string, secretKey string, regionId string, dns01Nameservers []string) (*DNSProvider, error) {
	config := NewDefaultConfig()
	config.APIKey = accessKey
	config.SecretKey = secretKey
	config.RegionID = regionId

	return NewDNSProviderConfig(config, dns01Nameservers)
}

// NewDNSProviderConfig return a DNSProvider instance configured for alidns.
func NewDNSProviderConfig(config *Config, dns01Nameservers []string) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("alicloud: the configuration of the DNS provider is nil")
	}

	if config.APIKey == "" || config.SecretKey == "" {
		return nil, fmt.Errorf("alicloud: credentials missing")
	}

	if len(config.RegionID) == 0 {
		config.RegionID = defaultRegionID
	}

	conf := sdk.NewConfig().WithTimeout(config.HTTPTimeout)
	credential := credentials.NewAccessKeyCredential(config.APIKey, config.SecretKey)

	client, err := alidns.NewClientWithOptions(config.RegionID, conf, credential)
	if err != nil {
		return nil, fmt.Errorf("alicloud: credentials failed: %v", err)
	}

	return &DNSProvider{dns01Nameservers: dns01Nameservers, config: config, client: client}, nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
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

		if response.PageNumber*response.PageSize >= response.TotalCount {
			break
		}

		startPage++
	}

	authZone, err := dns01.FindZoneByFqdn(dns01.ToFqdn(domain))
	authZone, err := util.FindZoneByFqdn(util.ToFqdn(domain), d.dns01Nameservers)
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
	request.TTL = requests.NewInteger(d.config.TTL)
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
