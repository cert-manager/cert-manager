/*
Copyright 2019 The Jetstack cert-manager contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package inwx implements a DNS provider for solving the DNS-01
// challenge using inwx DNS.
package inwx

import (
	"fmt"
	"github.com/golang/glog"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/steigr/goinwx"
	"strings"
)

const (
	MinimumTTL = 300
)

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	client  *goinwx.Client
	domains []string
}

// NewDNSProvider returns a DNSProvider instance configured for ACME DNS
// Credentials and acme-dns server host are given in environment variables
func NewDNSProvider(username, password string) (*DNSProvider, error) {
	p := &DNSProvider{
		client: goinwx.NewClient(username, password, &goinwx.ClientOptions{Sandbox: false}),
	}

	glog.V(2).Info("configured ACME DNS01 Provider for Inwx")
	return p, nil
}

func (p *DNSProvider) Present(domain, fqdn, value string) error {
	glog.V(2).Info("creating secret at", fqdn)

	err := p.login()
	if err == nil {
		defer p.logout()
	} else {
		return err
	}

	request := &goinwx.NameserverRecordRequest{
		Domain:  domain,
		Name:    hostname(fqdn, domain),
		Ttl:     300, // Minimum TTL
		Type:    "TXT",
		Content: value,
	}
	ret, err := p.client.Nameservers.CreateRecord(request)
	if err != nil {
		return err
	}
	glog.V(3).Info("secret created at", fqdn, ret)
	return nil
}

func (p *DNSProvider) CleanUp(domain, fqdn, value string) error {
	glog.V(2).Info("cleaning up secret for", fqdn)

	err := p.login()
	if err == nil {
		defer p.logout()
	} else {
		return err
	}

	response, err := p.client.Nameservers.Info(fqdn, 0)
	if err != nil {
		return err
	}

	if len(response.Records) != 1 {
		return fmt.Errorf("record is not unique")
	}

	err = p.client.Nameservers.DeleteRecord(response.Records[0].Id)
	return err
}

func (p *DNSProvider) login() error {
	return p.client.Account.Login()
}

func (p *DNSProvider) logout() {
	err := p.client.Account.Logout()
	if err != nil {
		glog.V(2).Info("inwx login failed", err)
	}
	return
}

// enumerate domains in account
func (p *DNSProvider) getDomains() ([]string, error) {
	var domains []string
	if inwxNameserverDomains, err := p.client.Nameservers.List(""); err == nil {
		for _, inwxNameserverDomain := range inwxNameserverDomains.Domains {
			domains = append(domains, inwxNameserverDomain.Domain)
		}
	} else {
		return nil, err
	}
	p.domains = domains
	return domains, nil
}

// select domain from registered domains
func (p *DNSProvider) getDomainOf(name string) string {
	updated := false
	for {
		for _, domain := range p.domains {
			if strings.HasSuffix("."+name, "."+domain) {
				return domain
			}
		}
		if updated {
			break
		} else {
			_, err := p.getDomains()
			if err != nil {
				break
			}
		}
		updated = true
	}
	return ""
}

// remove (dot)domain from fqdn
func hostname(fqdn, domain string) string {
	return fqdn[:len(fqdn)-len(domain)-1]
}

func newTxtRecord(domain, fqdn, value string) *goinwx.NameserverRecordRequest {
	return &goinwx.NameserverRecordRequest{
		Domain:  domain,
		Name:    hostname(util.UnFqdn(fqdn), domain),
		Ttl:     MinimumTTL, // Minimum TTL
		Type:    "TXT",
		Content: value,
	}
}
