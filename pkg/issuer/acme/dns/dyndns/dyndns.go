// +skip_license_check

// Package dyndns implements a DNS provider for solving the DNS-01 challenge
// using Dyn DNS.
package dyndns

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/nesv/go-dynect/dynect"
	"k8s.io/klog"
)

// DNSProvider implements the util.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers []string
	client           *dynect.Client
	zoneName         string
}

// ZonePublishRequest is missing from dynect but the notes field is a nice place to let
// external-dns report some internal info during commit
type ZonePublishRequest struct {
	Publish bool   `json:"publish"`
	Notes   string `json:"notes"`
}

type ZonePublishResponse struct {
	dynect.ResponseBlock
	Data map[string]interface{} `json:"data"`
}

// NewDNSProviderCredentials returns a DNSProvider instance configured for the Azure
// DNS service using static credentials from its parameters
func NewDNSProvider(dynCustomerName, dynUsername, dynPassword, dynZoneName string, dns01Nameservers []string) (*DNSProvider, error) {
	klog.V(4).Infof("Creating a new dyndns provider")
	client := dynect.NewClient(dynCustomerName)
	var resp dynect.LoginResponse
	var req = dynect.LoginBlock{
		Username:     dynUsername,
		Password:     dynPassword,
		CustomerName: dynCustomerName}

	errSession := client.Do("POST", "Session", req, &resp)
	if errSession != nil {
		klog.Errorf("Problem creating a session error: %s", errSession)
		return nil, errSession
	} else {
		klog.V(4).Infof("Successfully created Dyn session")
	}
	client.Token = resp.Data.Token

	return &DNSProvider{
		client:           client,
		zoneName:         dynZoneName,
		dns01Nameservers: dns01Nameservers,
	}, nil
}

func errorOrValue(err error, value interface{}) interface{} {
	if err == nil {
		return value
	}

	return err
}

// Present creates a TXT record using the specified parameters
func (c *DNSProvider) Present(domain, token, value string) error {
	klog.V(4).Infof("Creating a new dyndns record: %s, token: %s, keyAuth: %s\n", domain, token, value)
	fqdn, err := util.DNS01LookupFQDN(domain, false)
	//                         domain string, followCNAME bool, nameservers ...string) (string, error)
	if err != nil {
		klog.Errorf("error %v", err)
	}

	err = c.getRecord(fqdn, value)
	if err == nil {
		klog.Errorf("Record already exists, skipping create.")
		return nil
	}

	return c.createRecord(fqdn, value, 60)
}

// CleanUp removes the TXT record matching the specified parameters
func (c *DNSProvider) CleanUp(domain, token, value string) error {
	klog.V(4).Infof("Deleting dyndns record: %s, token: %s, keyAuth: %s\n", domain, token, value)
	fqdn, err := util.DNS01LookupFQDN(domain, false)

	if err != nil {
		klog.Errorf("error %v", err)
	}

	err = c.getRecord(fqdn, value)
	if err != nil {
		klog.Errorf("Record does not exist, skipping delete.")
		return nil
	}

	return c.deleteRecord(domain, fqdn)
}

func (c *DNSProvider) createRecord(fqdn, value string, ttl int) error {
	link := fmt.Sprintf("%sRecord/%s/%s/", "TXT", c.zoneName, fqdn)
	klog.V(4).Infof("the link is: %s", link)

	recordData := dynect.DataBlock{}
	recordData.TxtData = value
	record := dynect.RecordRequest{
		TTL:   "30",
		RData: recordData,
	}

	response := dynect.RecordResponse{}
	err := c.client.Do("POST", link, record, &response)
	klog.Infof("Creating record %s: %+v,", link, errorOrValue(err, &response))
	if err != nil {
		klog.Errorf("Error creating record: %s, %v", fqdn, err)
		return err
	}
	klog.V(4).Infof("Publishing changes")
	publish(c)
	return nil
}

func (c *DNSProvider) getRecord(fqdn, value string) error {
	link := fmt.Sprintf("%sRecord/%s/%s/", "TXT", c.zoneName, fqdn)
	klog.V(4).Infof("the link is: %s", link)

	err := c.client.Do("GET", link, nil, nil)
	klog.Infof("Getting record %s: %+v,", link, err)
	if err != nil {
		klog.V(4).Infof("Record not found: %s, %v", fqdn, err)
		return err
	}

	return nil
}

func (c *DNSProvider) deleteRecord(domain, fqdn string) error {
	link := fmt.Sprintf("%sRecord/%s/%s/", "TXT", c.zoneName, fqdn)
	response := dynect.RecordResponse{}
	err := c.client.Do("DELETE", link, nil, &response)
	klog.Infof("Deleting record %s: %+v\n", link, errorOrValue(err, &response))
	if err != nil {
		klog.Errorf("Error getting deleting domain name: %s, %v", domain, err)
		return err
	}
	klog.V(4).Infof("Publishing changes")
	publish(c)
	return nil
}

// Timeout returns the timeout and interval to use when checking for DNS
// propagation. Adjusting here to cope with spikes in propagation times.
func (c *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return 120 * time.Second, 2 * time.Second
}

func (c *DNSProvider) getHostedZoneName(fqdn string) (string, error) {
	if c.zoneName != "" {
		return c.zoneName, nil
	}
	z, err := util.FindZoneByFqdn(fqdn, util.RecursiveNameservers)
	if err != nil {
		return "", err
	}

	if len(z) == 0 {
		return "", fmt.Errorf("Zone %s not found for domain %s", z, fqdn)
	}

	return util.UnFqdn(z), nil
}

func (c *DNSProvider) trimFqdn(fqdn string) string {
	return strings.TrimSuffix(strings.TrimSuffix(fqdn, "."), "."+c.zoneName)
}

// publish publishes all pending zone changes. It will always attempt to commit, if there are no
func publish(c *DNSProvider) error {
	// extra call if in debug mode to fetch pending changes
	h, err := os.Hostname()
	if err != nil {
		h = "unknown-host"
	}
	notes := fmt.Sprintf("Change by external-dns@%s, DynAPI@%s, %s on %s",
		"external-dns-client",
		"external-dns-client-version",
		time.Now().Format(time.RFC3339),
		h,
	)

	zonePublish := ZonePublishRequest{
		Publish: true,
		Notes:   notes,
	}

	response := ZonePublishResponse{}
	klog.Infof("Publishing changes for zone %s: %+v", c.zoneName, errorOrValue(err, &response))
	err = c.client.Do("PUT", fmt.Sprintf("Zone/%s/", c.zoneName), &zonePublish, &response)
	if err != nil {
		klog.Errorf("Error publishing changes to zone, error: %v", err)
		return err
	} else {
		klog.Info(response)
	}

	return nil
}
