package alibabadns

import (
	"github.com/aliyun/alibaba-cloud-sdk-go/services/alidns"
	"os"
)

// 定义一个实体
type DNSProvider struct {
	dnsClient        *alidns.Client
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

// 新建一个请求DNS
func NewDNSProviderCredentials(accessKeyID, accessKeySecret string, dns01Nameservers []string) (*DNSProvider, error) {

	aliDNSClient, err := alidns.NewClientWithAccessKey(
		"cn-hangzhou",   // Your Region ID
		accessKeyID,     // Your AccessKey ID
		accessKeySecret) // Your AccessKey Secret
	if err != nil {
		return &DNSProvider{}, nil
	}
	return &DNSProvider{
		dnsClient:        aliDNSClient,
		dns01Nameservers: dns01Nameservers,
	}, nil
}

// Present creates a TXT record to fulfil the dns-01 challenge
func (a *DNSProvider) Present(domain, fqdn, value string) error {
	return a.setTxtRecord(domain, fqdn, value)
}

// 设置DNS解析
func (a *DNSProvider) setTxtRecord(domain, fqdn, value string) error {
	domainRecord := &alidns.AddDomainRecordRequest{
		DomainName: domain,
		RR:         fqdn,
		Type:       "TXT",
		Value:      value,
	}
	_, err := a.dnsClient.AddDomainRecord(domainRecord)
	return err
}

// CleanUp removes the TXT record matching the specified parameters
func (a *DNSProvider) CleanUp(domain, fqdn, value string) error {
	return a.removeTxt(domain, fqdn)
}

// remove TXT record
func (a *DNSProvider) removeTxt(domain, fqdn string) error {
	removeRecord := &alidns.DeleteSubDomainRecordsRequest{
		DomainName: domain,
		RR:         fqdn,
		Type:       "TXT",
	}
	_, err := a.dnsClient.DeleteSubDomainRecords(removeRecord)
	return err
}
