package alidns

import (
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"strings"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/alidns"
)

const defaultRegionID = "cn-hangzhou"

// DNSProvider is an implementation of the DNSProvider interface.
type DNSProvider struct {
	regionId string
	accessKeyId string
	accessKeySecret string
	dns01Nameservers []string
	client *alidns.Client
}

func NewDNSProvider(regionId string, accessKeyId string, accessKeySecret string, dns01Nameservers []string) (*DNSProvider, error) {

	if len(regionId) == 0 {
		regionId = defaultRegionID
	}

	client, err := alidns.NewClientWithAccessKey(regionId, accessKeyId, accessKeySecret)

	if err != nil {
		fmt.Print(err.Error())
	}

	return &DNSProvider{
		regionId:          	regionId,
		accessKeyId: 		accessKeyId,
		accessKeySecret: 	accessKeySecret,
		dns01Nameservers: 	dns01Nameservers,
		client:				client,
	}, nil
}

// Present creates a TXT record to fulfil the dns-01 challenge.
func (c *DNSProvider) Present(domain, fqdn, value string) error {
	_, zoneName, err := c.getHostedZone(domain)
	if err != nil {
		return fmt.Errorf("alicloud: %v", err)
	}
	recordAttributes := c.newTxtRecord(zoneName, fqdn, value)

	_, err = c.client.AddDomainRecord(recordAttributes)
	if err != nil {
		return fmt.Errorf("alicloud: API call failed: %v", err)
	}
	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (c *DNSProvider) CleanUp(domain, fqdn, value string) error {
	records, err := c.findTxtRecords(domain, fqdn)
	if err != nil {
		return fmt.Errorf("alicloud: %v", err)
	}

	_, _, err = c.getHostedZone(domain)
	if err != nil {
		return fmt.Errorf("alicloud: %v", err)
	}

	for _, rec := range records {
		request := alidns.CreateDeleteDomainRecordRequest()
		request.RecordId = rec.RecordId
		_, err = c.client.DeleteDomainRecord(request)
		if err != nil {
			return fmt.Errorf("alicloud: %v", err)
		}
	}
	return nil
}

func (c *DNSProvider) getHostedZone(domain string) (string, string, error) {
	request := alidns.CreateDescribeDomainsRequest()

	var domains []alidns.Domain
	startPage := 1

	for {
		request.PageNumber = requests.NewInteger(startPage)

		response, err := c.client.DescribeDomains(request)
		if err != nil {
			return "", "", fmt.Errorf("API call failed: %v", err)
		}

		domains = append(domains, response.Domains.Domain...)

		if response.PageNumber*response.PageSize >= response.TotalCount {
			break
		}

		startPage++
	}

	authZone, err := util.FindZoneByFqdn(util.ToFqdn(domain), c.dns01Nameservers)
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

func (c *DNSProvider) newTxtRecord(zone, fqdn, value string) *alidns.AddDomainRecordRequest {
	request := alidns.CreateAddDomainRecordRequest()
	request.Type = "TXT"
	request.DomainName = zone
	request.RR = c.extractRecordName(fqdn, zone)
	request.Value = value
	return request
}

func (c *DNSProvider) findTxtRecords(domain, fqdn string) ([]alidns.Record, error) {
	_, zoneName, err := c.getHostedZone(domain)
	if err != nil {
		return nil, err
	}

	request := alidns.CreateDescribeDomainRecordsRequest()
	request.DomainName = zoneName
	request.PageSize = requests.NewInteger(500)

	var records []alidns.Record

	result, err := c.client.DescribeDomainRecords(request)
	if err != nil {
		return records, fmt.Errorf("API call has failed: %v", err)
	}

	recordName := c.extractRecordName(fqdn, zoneName)
	for _, record := range result.DomainRecords.Record {
		if record.RR == recordName {
			records = append(records, record)
		}
	}
	return records, nil
}

func (c *DNSProvider) extractRecordName(fqdn, domain string) string {
	name := util.UnFqdn(fqdn)
	if idx := strings.Index(name, "."+domain); idx != -1 {
		return name[:idx]
	}
	return name
}