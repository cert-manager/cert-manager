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
}

// NewDNSProvider returns a DNSProvider instance configured for the TransIP Api
// service using static credentials from its parameters or, if they're
// unset and the 'ambient' option is set, credentials from the environment.
func NewDNSProvider(accountName string, PrivateKey []byte, dns01Nameservers []string) (*DNSProvider, error) {
	if accountName == "" || PrivateKey != nil {
		// It's always an error to set one of those but not the other
		return nil, fmt.Errorf("unable to construct transip provider: only one of access and secret key was provided")
	}

	c, err := gotransip.NewSOAPClient(gotransip.ClientConfig{
		AccountName:    accountName,
		PrivateKeyBody: PrivateKey,
	})
	if err != nil {
		panic(err.Error())
	}

	return &DNSProvider{
		client:           c,
		dns01Nameservers: dns01Nameservers,
	}, nil
}

func (t *DNSProvider) findDomain(dn string) (domain.Domain, string, error) {

	dom, err := domain.GetInfo(t.client, dn)
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
	domainList, err := domain.GetDomainNames(t.client)

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

	dom, err = domain.GetInfo(t.client, partialmatch)
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

// Present creates a TXT record using the specified parameters
func (t *DNSProvider) Present(domain, token, keyAuth string) error {
	fqdn, value, _, err := util.DNS01Record(domain, keyAuth, t.dns01Nameservers)
	if err != nil {
		return err
	}

	return t.changeRecord(domain, fqdn, value, 60)
}

// CleanUp removes the TXT record matching the specified parameters
func (t *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	fqdn, value, _, err := util.DNS01Record(domain, keyAuth, t.dns01Nameservers)
	if err != nil {
		return err
	}

	return t.changeRecord(domain, fqdn, value, 0)
}

func (t *DNSProvider) changeRecord(dn string, fqdn string, value string, ttl int64) error {

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
		return errors.New(fmt.Sprintf("Found multiple text records for %s", fqdn))
	}

	if recordFound == 0 {
		fmt.Printf("Creating a new record")
		newRecord := domain.DNSEntry{Name: recordName, TTL: ttl, Type: domain.DNSEntryTypeTXT, Content: value}
		info.DNSEntries = append(info.DNSEntries, newRecord)
		recordIndex = len(info.DNSEntries)
	} else {
		info.DNSEntries[recordIndex].Content = value
	}

	err = domain.SetDNSEntries(t.client, dn, info.DNSEntries)
	if err != nil {
		panic(err.Error())
	}

	return util.WaitFor(120*time.Second, 4*time.Second, func() (bool, error) {
		/*
			reqParams := &route53.GetChangeInput{
				Id: statusID,
			}
			resp, err := t.client.GetChange(reqParams)
			if err != nil {
				return false, fmt.Errorf("Failed to query Route 53 change status: %v", err)
			}
			if *resp.ChangeInfo.Status == route53.ChangeStatusInsync {
				return true, nil
			}
			return false, nil
		*/
	})
}
