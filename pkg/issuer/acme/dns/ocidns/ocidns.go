// +skip_license_check

// Package ocidns implements a DNS provider for solving the DNS-01 challenge
// using OCI DNS.
package ocidns

import (
	"context"
	"strings"

	"github.com/oracle/oci-go-sdk/common"
	"github.com/oracle/oci-go-sdk/common/auth"
	ocidns "github.com/oracle/oci-go-sdk/dns"
	"gopkg.in/yaml.v2"
	"k8s.io/klog"
)

// OCIAuthConfig holds connection parameters for the OCI API.
type OCIAuthConfig struct {
	Region      string `yaml:"region"`
	TenancyID   string `yaml:"tenancy"`
	UserID      string `yaml:"user"`
	PrivateKey  string `yaml:"key"`
	Fingerprint string `yaml:"fingerprint"`
	Passphrase  string `yaml:"passphrase"`
}

// OCIConfig holds the configuration for the OCI Provider.
type OCIConfig struct {
	Auth          OCIAuthConfig `yaml:"auth"`
	CompartmentID string        `yaml:"compartment"`
}

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	useInstancePrincipals bool
	client                *ocidns.DnsClient
	compartmentId         string
	zoneName              string
	dns01Nameservers      []string
}

// NewDNSProvider initialises a new OCI DNS based Provider.
func NewDNSProvider(
	useInstancePrincipals bool,
	zoneName string,
	compartmentId string,
	keyData []byte,
	dns01Nameservers []string) (*DNSProvider, error) {

	var configProvider common.ConfigurationProvider
	var cfg OCIConfig
	var err error

	if useInstancePrincipals == true {
		klog.V(4).Info("Initializing OCI Dns instance principal configProvider")
		configProvider, err = auth.InstancePrincipalConfigurationProvider()
		if err != nil {
			klog.Errorf("initializing OCI DNS Instance Principal config provider: %v", err)
			return nil, err
		}

	} else { //Effectively making key credentials default
		// tenancy, compartmentid,user, region, fingerprint, privateKey, privateKeyPassphrase
		klog.V(4).Info("Initializing OCI Raw config provider")

		if err := yaml.Unmarshal(keyData, &cfg); err != nil {
			klog.Errorf("parsing OCI YAML from secret:%v", err)
			return nil, err
		}
		configProvider = common.NewRawConfigurationProvider(
			cfg.Auth.TenancyID,
			cfg.Auth.UserID,
			cfg.Auth.Region,
			cfg.Auth.Fingerprint,
			cfg.Auth.PrivateKey,
			&cfg.Auth.Passphrase,
		)
		// set this to match the compartment found when using instance principals
		compartmentId = cfg.CompartmentID
	}

	dnsClient, err := ocidns.NewDnsClientWithConfigurationProvider(configProvider)
	if err != nil {
		klog.Errorf("initializing OCI DNS API client%v", err)
		return nil, err
	}

	return &DNSProvider{
		useInstancePrincipals,
		&dnsClient,
		compartmentId,
		zoneName,
		dns01Nameservers,
	}, nil
}

// Present creates a TXT record using the specified parameters
func (c *DNSProvider) Present(domain, fqdn, value string) error {
	klog.V(4).Infof("Creating a new ocidns TXT record: %s, in domain: %s, rData: %s\n", fqdn, domain, value)
	ttl := 60

	fqdn = removeSuffix(fqdn, ".")

	op := []ocidns.RecordOperation{}

	op = append(op, newRecordOperation(fqdn, value, ttl, ocidns.RecordOperationOperationAdd))

	return patchRecord(c, domain, fqdn, op)

}

// CleanUp removes the TXT record matching the specified parameters
func (c *DNSProvider) CleanUp(domain, fqdn, value string) error {
	klog.V(4).Infof("Deleting ocidns TXT record: %s, from domain: %s, rData: %s\n", fqdn, domain, value)
	ttl := 60

	fqdn = removeSuffix(fqdn, ".")

	op := []ocidns.RecordOperation{}

	op = append(op, newRecordOperation(fqdn, value, ttl, ocidns.RecordOperationOperationRemove))

	return patchRecord(c, domain, fqdn, op)
}

// newRecordOperation returns a RecordOperation based on a given fqdn
func newRecordOperation(fqdn, value string, ttl int, opType ocidns.RecordOperationOperationEnum) ocidns.RecordOperation {
	rdata := value
	rtype := "TXT"
	var ociTTL int
	isProtected := false

	if ttl == 0 {
		ociTTL = 60
	} else {
		ociTTL = ttl
	}
	return ocidns.RecordOperation{
		Domain:      &fqdn,
		Rdata:       &rdata,
		Ttl:         &ociTTL,
		Rtype:       &rtype,
		IsProtected: &isProtected,
		Operation:   opType,
	}
}

//Use the oci dns client to UPDATE the oci dns record
func patchRecord(p *DNSProvider, domain, fqdn string, op []ocidns.RecordOperation) error {

	klog.V(4).Infof("Patch in zone: %q\n", p.zoneName)
	klog.V(4).Infof("Patch in domain: %q\n", domain)
	klog.V(4).Infof("Patch FQDN: %q\n", fqdn)
	klog.V(4).Infof("Patch change operation: %q\n", op)

	ctx := context.Background()

	patchRequest := ocidns.PatchDomainRecordsRequest{
		Domain:                    &fqdn,
		CompartmentId:             &p.compartmentId,
		ZoneNameOrId:              &p.zoneName,
		PatchDomainRecordsDetails: ocidns.PatchDomainRecordsDetails{Items: op},
	}

	klog.V(4).Infof("PatchDomainRecordRequest: %s\n", patchRequest.String())

	patchResponse, err := p.client.PatchDomainRecords(ctx, patchRequest)

	klog.V(4).Infof("PatchDomainRecordResponse: %s\n", patchResponse.String())

	if err != nil {
		klog.Errorf("Patch Zone Error: %q, Patch Response:%q\n", err, patchResponse.String())
	}

	return err
}

//temporary workaround function for oci dns failure to handle fully qualified domain name
func removeSuffix(str, suff string) string {
	if strings.HasSuffix(str, suff) {
		str = str[:len(str)-len(suff)]
	}
	return str
}
