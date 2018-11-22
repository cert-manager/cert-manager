// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

// Package transip implements a DNS provider for solving the DNS-01 challenge
// using TransIP  DNS.
package transip

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/transip/gotransip"
	"github.com/transip/gotransip/domain"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

const (
	maxRetries = 5
	TTL        = 60
)

// DNSProvider implements the util.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers []string
	client           gotransip.SOAPClient
	mockup			 bool
	mockupDomains	 []domain.Domain
	waitTime	     time.Duration
}

// NewDNSProvider returns a DNSProvider instance configured for the TransIP Api
// service using static credentials from its parameters or, if they're
// unset and the 'ambient' option is set, credentials from the environment.
func NewDNSProvider(accountName string, PrivateKey []byte, dns01Nameservers []string) (*DNSProvider, error) {
	if accountName == "" || PrivateKey == nil {
		// It's always an error to set one of those but not the other
		return nil, fmt.Errorf("unable to construct transip provider: only one of access and secret key was provided")
	}

	c, err := gotransip.NewSOAPClient(gotransip.ClientConfig{
		AccountName:    accountName,
		PrivateKeyBody: PrivateKey,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to construct transip provider: " + err.Error())
	}

	return &DNSProvider{
		client:           c,
		dns01Nameservers: dns01Nameservers,
		mockup: false,
		mockupDomains: nil,
		waitTime: 120,
	}, err

}

// Present creates a TXT record using the specified parameters
func (t *DNSProvider) Present(domain, token, keyAuth string) error {
	fqdn, value, _, err := util.DNS01Record(domain, keyAuth, t.dns01Nameservers)
	if err != nil {
		return err
	}

	_, err = t.changeRecord(domain, fqdn, value, 60)

	if err!= nil {
		return err
	}

	return util.WaitFor(t.waitTime*time.Second, 4*time.Second, func() (bool, error) {
		return false, nil
	})
}

// CleanUp removes the TXT record matching the specified parameters
func (t *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	fqdn, value, _, err := util.DNS01Record(domain, keyAuth, t.dns01Nameservers)
	if err != nil {
		return err
	}


	_, err = t.changeRecord(domain, fqdn, value, 0)

	if err!= nil {
		return err
	}

	return util.WaitFor(t.waitTime*time.Second, 4*time.Second, func() (bool, error) {
		return false, nil
	})

}


/**
  Wrapper function to domain.functions with mockup escape
**/
func (t *DNSProvider) getInfo(c gotransip.Client, domainName string) (domain.Domain, error) {
	if t.mockup == true {
		return t.mockupGetInfo(c,domainName)
	}

	return domain.GetInfo(t.client, domainName)
}


func (t *DNSProvider) getDomainNames(c gotransip.Client) ([]string, error) {
	if t.mockup == true {
		return t.mockupGetDomainNames(c)
	}

	return domain.GetDomainNames(t.client)
}

func (t *DNSProvider) setDNSEntries(c gotransip.Client, domainName string, dnsEntries domain.DNSEntries) error {
	if t.mockup == true {
		return t.mockupSetDNSEntries(c, domainName, dnsEntries)
	}

	return domain.SetDNSEntries(c, domainName, dnsEntries)
}



/**
  Helper functions
**/

func (t *DNSProvider) findDomain(dn string) (domain.Domain, string, error) {

	dom, err := t.getInfo(t.client, dn)
	// No error, so domain is the base domain, nothing more to do.
	if err == nil {
		return dom, dn, nil
	}

	// Find the best matching base domain for the requested subdomain available in the account
	// will match based on the domain prefixed with a dot so if the requested domain is dev.example.com:
	// example.com => success :: ends with .example.com
	// ample.com => fails :: does not end with .ample.com
	// in the rare situation a subdomain is registered as a separated domain the longest matching domain will be used
	// Example: dev.eu.example.com will match both .eu.example.com and .example.com,
	// but the first is uses as the match is more characters

	partialmatchIndex := -1
	partialmatch := ""
	domainList, err := t.getDomainNames(t.client)

	if err != nil {
		return domain.Domain{}, "", err
	}
	for index, name := range domainList {
		//test if know domains matches with the end of the requested domain, for example.
		if strings.HasSuffix(dn, "."+name) && len(partialmatch) < len(name) {
			partialmatchIndex = index
			partialmatch = name
		}
	}

	if partialmatchIndex == -1 {
		return domain.Domain{}, "", errors.New(fmt.Sprintf("Could not find a domain for %s", dn))
	}

	dom, err = t.getInfo(t.client, partialmatch)
	if err != nil {
		return domain.Domain{}, "", err
	}

	return dom, partialmatch, nil
}

// Timeout returns the timeout and interval to use when checking for DNS
// propagation. Adjusting here to cope with spikes in propagation times.
func (*DNSProvider) Timeout() (timeout, interval time.Duration) {
	return 120 * time.Second, 2 * time.Second
}

/**
	Change the record
	if ttl == 0 					::  remove records matching fqdn and type and value
	if ttl == 0 AND value == nil  ::  remove records matching fqdn and type
 */
func (t *DNSProvider) changeRecord(dn string, fqdn string, value string, ttl int64) (domain.DNSEntries, error) {

	// Find the registered domain name (zone)
	info, dn, err := t.findDomain(dn)

	recordName := strings.TrimSuffix(fqdn, "."+dn+".")
	recordIndex := -1
	recordFound := 0
	// print name and description for each Domain
	for index, record := range info.DNSEntries {
		// Don't need anything else than TXT records
		if record.Type != domain.DNSEntryTypeTXT {
			continue
		}

		if record.Name == recordName {
			recordIndex = index
			recordFound++
		}
	}

	if recordFound > 1 {
		return nil, errors.New(fmt.Sprintf("Found multiple text records for %s", fqdn))
	}

	if recordFound == 0 && ttl > 0 {
		// fmt.Printf("Creating a new record")
		newRecord := domain.DNSEntry{Name: recordName, TTL: ttl, Type: domain.DNSEntryTypeTXT, Content: value}
		info.DNSEntries = append(info.DNSEntries, newRecord)
		recordIndex = len(info.DNSEntries)
	} else if recordFound == 1 && ttl > 0 {
		info.DNSEntries[recordIndex].Content = value
	} else if recordFound == 1 && ttl == 0 && info.DNSEntries[recordIndex].Content == value {
		info.DNSEntries = append(info.DNSEntries[:recordIndex], info.DNSEntries[recordIndex+1:]...)
	}

	err = t.setDNSEntries(t.client, dn, info.DNSEntries)
	if err != nil {
		return nil, err
	}

	return info.DNSEntries, nil

}

/**

  Mockup functions for testing

**/

func (t *DNSProvider) mockupGetInfo(c gotransip.Client, domainName string) (domain.Domain, error) {

	fmt.Printf("mockupGetInfo::%s\n", domainName)

	retDomain := domain.Domain{}

	for _, d := range t.mockupDomains {

		if domainName == d.Name {
			return d, nil
		}

	}

	return retDomain, fmt.Errorf("Unknown domain")


}

func (t *DNSProvider) mockupGetDomainNames(c gotransip.Client) ([]string, error) {

	fmt.Println("mockupGetDomainNames")
	var retval []string

	for _, d := range t.mockupDomains {
		retval = append(retval, d.Name)
	}

	return retval, nil
}

func (t *DNSProvider) mockupSetDNSEntries(c gotransip.Client, domainName string, dnsEntries domain.DNSEntries) error {

	fmt.Println("mockupSetDNSEntries")

	fmt.Println(dnsEntries)

	return nil
}
