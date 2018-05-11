package inwx

import (
	"errors"
	"os"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/mitchellh/mapstructure"
	"github.com/steigr/goinwx"
)

const (
	maxRetries = 5
	inwxTTL    = 300
)

// DNSProvider implements the util.ChallengeProvider interface
type DNSProvider struct {
	client *goinwx.Client
}

// NewDNSProvider returns a DNSProvider instance configured for the INWX
// XML-RPC service.

func NewDNSProvider() (*DNSProvider, error) {
	username := os.Getenv("INWX_USERNAME")
	password := os.Getenv("INWX_PASSWORD")
	sandbox := (os.Getenv("INWX_SANDBOX") == "true")

	opts := &goinwx.ClientOptions{
		Sandbox: sandbox,
	}
	client := goinwx.NewClient(username, password, opts)

	return &DNSProvider{
		client: client,
	}, nil
}

// NewDNSProviderAccessKey returns a DNSProvider instance configured for the INWX
// XML-RPC service using static credentials from its parameters
func NewDNSProviderCredentials(username, password string) (*DNSProvider, error) {
	opts := goinwx.ClientOptions{
		Sandbox: false,
	}

	client := goinwx.NewClient(username, password, &opts)

	return &DNSProvider{
		client: client,
	}, nil
}

// INWX needs really long timeouts because propagation is slow
// So wait for 3mins and retry every 10 seconds
func (c *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return 180 * time.Second, 10 * time.Second
}

// Present DNS01 Challenge
func (r *DNSProvider) Present(domain, token, keyAuth string) error {
	err := r.login()
	if err != nil {
		return err
	}
	defer r.logout()
	r.deleteRecord(domain, token, keyAuth)
	err = r.createRecord(domain, token, keyAuth)
	return err
}

// CleanUp DNS01 Challenge
func (r *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	err := r.login()
	if err != nil {
		return err
	}
	defer r.logout()
	err = r.deleteRecord(domain, token, keyAuth)
	return err
}

// internal methods

// log into INWX account
func (r *DNSProvider) login() error {
	return r.client.Account.Login()
}

// log out of INWX account
func (r *DNSProvider) logout() error {
	return r.client.Account.Logout()
}

// create record
func (r *DNSProvider) createRecord(domain, token, keyAuth string) error {
	fqdn, value, _ := util.DNS01Record(domain, keyAuth)
	domainOfAccount, name, err := r.normalizeRecordData(domain, fqdn)
	record := &goinwx.NameserverRecordRequest{
		Domain:  domainOfAccount,
		Name:    name,
		Type:    "TXT",
		Content: value,
		Ttl:     inwxTTL,
	}
	roid, err := r.client.Nameservers.CreateRecord(record)
	if err != nil {
		return err
	}
	glog.V(4).Infof("Created DNS01 challenge with RoID %d", roid)

	// r.waitForChallenge(domain, name, value)
	return nil
}

// delete record if present
func (r *DNSProvider) deleteRecord(domain, token, keyAuth string) error {
	fqdn, _, _ := util.DNS01Record(domain, keyAuth)
	domainOfAccount, name, err := r.normalizeRecordData(domain, fqdn)

	roid, err := r.getRoId(domainOfAccount, name)
	if err != nil {
		return nil
	}
	glog.V(4).Infof("Deleting DNS01 challenge with RoID %d", roid)

	err = r.client.Nameservers.DeleteRecord(roid)
	if err != nil {
		return err
	}
	if err != nil {
		return err
	}

	return nil
}

// resolve roid of given record
func (r *DNSProvider) getRoId(domain, name string) (int, error) {
	var (
		roid       int
		result     goinwx.NamserverInfoResponse
		requestMap = make(map[string]interface{})
	)
	requestMap["domain"] = domain
	requestMap["name"] = name
	request := r.client.NewRequest("nameserver.info", requestMap)
	response, err := r.client.Do(*request)
	if err != nil {
		return roid, err
	}
	err = mapstructure.Decode(*response, &result)
	if err != nil {
		return roid, err
	}
	if len(result.Records) < 1 {
		return roid, errors.New("No Records found")
	}
	roid = result.Records[0].Id
	return roid, nil
}

// create records applicable for INWX API
func (r *DNSProvider) normalizeRecordData(record, fqdn string) (string, string, error) {
	var domainOfAccount, recordPrefix string
	domainOfAccount, err := r.getRegisteredDomainOf(record)
	if err != nil {
		return domainOfAccount, recordPrefix, err
	}
	recordPrefix = strings.Replace(fqdn, "."+domainOfAccount+".", "", 1)
	return domainOfAccount, recordPrefix, nil
}

// select domain from registered domains
func (r *DNSProvider) getRegisteredDomainOf(record string) (string, error) {
	var registeredDomain string

	domains, err := r.client.Domains.List(&goinwx.DomainListRequest{})
	if err != nil {
		glog.V(4).Info(err.Error())
		return "", err
	}
	for _, dom := range domains.Domains {

		// prepend dot to match correct domain
		// e.g.
		// dom.Domain = "example.com"
		//
		// domain = "server.example.com"
		// suffix-Check(".server.example.com",".example.com") --> domain is ok
		//
		// domain = "example.com"
		// suffix-Check(".example.com",".example.com") --> domain is ok
		//
		// dom.Domain = "myexample.com"
		// domain = "server.example.com"
		// suffix-Check(".server.example.com",".myexample.com") --> domain is not ok
		//
		// dom.Domain = "myexample.com"
		// domain = "example.com"
		// suffix-Check(".example.com",".myexample.com") --> domain is not ok

		if strings.HasSuffix("."+record, "."+dom.Domain) {
			return dom.Domain, nil
		}
	}
	return registeredDomain, nil
}
