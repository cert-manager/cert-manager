// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

// Package infobloxdns implements a DNS provider for solving the DNS-01
// challenge using Infoblox DNS.
package infobloxdns

import (
	"strconv"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/infobloxopen/infoblox-go-client"
)

// DNSProvider is an implementation of the DNSProvider interface.
type DNSProvider struct {
	dns01Nameservers []string
	client           ibclient.IBConnector
	host             string
}

// NewDNSProvider returns a DNSProvider instance configured for Infoblox.
func NewDNSProvider(gridHost string, username string, secret string, port string, version string, sslVerify bool, dns01Nameservers []string) (*DNSProvider, error) {
	hostConfig := ibclient.HostConfig{
		Host:     gridHost,
		Port:     port,
		Username: username,
		Password: secret,
		Version:  version,
	}

	httpPoolConnections := 10
	httpRequestTimeout := 60

	transportConfig := ibclient.NewTransportConfig(
		strconv.FormatBool(sslVerify),
		httpRequestTimeout,
		httpPoolConnections,
	)

	requestBuilder := &ibclient.WapiRequestBuilder{}
	requestor := &ibclient.WapiHttpRequestor{}

	client, err := ibclient.NewConnector(hostConfig, transportConfig, requestBuilder, requestor)
	if err != nil {
		return nil, err
	}

	return &DNSProvider{
		dns01Nameservers: dns01Nameservers,
		client:           client,
		host:             gridHost,
	}, nil
}

// Present creates a TXT record to fulfil the dns-01 challenge.
func (c *DNSProvider) Present(domain, fqdn, value string) error {
	fqdn = strings.TrimSuffix(fqdn, ".")

	rt := ibclient.NewRecordTXT(ibclient.RecordTXT{Name: fqdn})

	var records []ibclient.RecordTXT
	err := c.client.GetObject(rt, "", &records)
	if err != nil {
		return err
	}

	for _, rec := range records {
		if rec.Text == value {
			return nil
		}
	}

	rt = ibclient.NewRecordTXT(ibclient.RecordTXT{
		Name: fqdn,
		Text: value})

	ref, err := c.client.CreateObject(rt)
	if err != nil {
		return err
	}

	glog.Infof("INFOBLOX: created TXT record %v, %s -> %s", rt, value, ref)

	return nil
}

// CleanUp removes the TXT record matching the specified parameters
func (c *DNSProvider) CleanUp(domain, fqdn, value string) error {

	fqdn = strings.TrimSuffix(fqdn, ".")
	rt := ibclient.NewRecordTXT(ibclient.RecordTXT{Name: fqdn})

	var records []ibclient.RecordTXT
	err := c.client.GetObject(rt, "", &records)
	if err != nil {
		return err
	}

	var ref string
	for _, rec := range records {
		if rec.Text == value {
			ref = rec.Ref
			break
		}
	}

	if len(ref) == 0 {
		return nil
	}

	_, err = c.client.DeleteObject(ref)
	if err != nil {
		return err
	}

	glog.Infof("INFOBLOX: deleting TXT record %s, %s -> %s", domain, value, ref)

	return nil
}

// Timeout returns the timeout and interval to use when checking for DNS
// propagation.
func (c *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return 180 * time.Second, 5 * time.Second
}
