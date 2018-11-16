// Package inwx implements a DNS provider for solving the DNS-01 challenge using inwx dom robot
package inwx

import (
	"errors"
	"fmt"
	"time"

	"github.com/smueller18/goinwx"
	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/log"
	"github.com/xenolf/lego/platform/config/env"
)

// Config is used to configure the creation of the DNSProvider
type Config struct {
	Username           string
	Password           string
	Sandbox            bool
	PropagationTimeout time.Duration
	PollingInterval    time.Duration
	TTL                int
}

// NewDefaultConfig returns a default configuration for the DNSProvider
func NewDefaultConfig() *Config {
	return &Config{
		PropagationTimeout: env.GetOrDefaultSecond("INWX_PROPAGATION_TIMEOUT", acme.DefaultPropagationTimeout),
		PollingInterval:    env.GetOrDefaultSecond("INWX_POLLING_INTERVAL", acme.DefaultPollingInterval),
		TTL:                env.GetOrDefaultInt("INWX_TTL", 300),
		Sandbox:            env.GetOrDefaultBool("INWX_SANDBOX", false),
	}
}

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	config *Config
	client *goinwx.Client
}

// NewDNSProvider returns a DNSProvider instance configured for Dyn DNS.
// Credentials must be passed in the environment variables:
// INWX_USERNAME and INWX_PASSWORD.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get("INWX_USERNAME", "INWX_PASSWORD")
	if err != nil {
		return nil, fmt.Errorf("inwx: %v", err)
	}

	config := NewDefaultConfig()
	config.Username = values["INWX_USERNAME"]
	config.Password = values["INWX_PASSWORD"]

	return NewDNSProviderConfig(config)
}

// NewDNSProviderConfig return a DNSProvider instance configured for Dyn DNS
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("inwx: the configuration of the DNS provider is nil")
	}

	if config.Username == "" || config.Password == "" {
		return nil, fmt.Errorf("inwx: credentials missing")
	}

	if config.Sandbox {
		log.Infof("inwx: sandbox mode is enabled")
	}

	client := goinwx.NewClient(config.Username, config.Password, &goinwx.ClientOptions{Sandbox: config.Sandbox})

	return &DNSProvider{config: config, client: client}, nil
}

// Present creates a TXT record using the specified parameters
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	fqdn, value, _ := acme.DNS01Record(domain, keyAuth)

	authZone, err := acme.FindZoneByFqdn(fqdn, acme.RecursiveNameservers)
	if err != nil {
		return fmt.Errorf("inwx: %v", err)
	}

	err = d.client.Account.Login()
	if err != nil {
		return fmt.Errorf("inwx: %v", err)
	}

	defer func() {
		errL := d.client.Account.Logout()
		if errL != nil {
			log.Infof("inwx: failed to logout: %v", errL)
		}
	}()

	var request = &goinwx.NameserverRecordRequest{
		Domain:  acme.UnFqdn(authZone),
		Name:    acme.UnFqdn(fqdn),
		Type:    "TXT",
		Content: value,
		Ttl:     d.config.TTL,
	}

	_, err = d.client.Nameservers.CreateRecord(request)
	if err != nil {
		switch err.(type) {
		case *goinwx.ErrorResponse:
			if err.(*goinwx.ErrorResponse).Message == "Object exists" {
				return nil
			}
			return fmt.Errorf("inwx: %v", err)
		default:
			return fmt.Errorf("inwx: %v", err)
		}
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	fqdn, _, _ := acme.DNS01Record(domain, keyAuth)

	authZone, err := acme.FindZoneByFqdn(fqdn, acme.RecursiveNameservers)
	if err != nil {
		return fmt.Errorf("inwx: %v", err)
	}

	err = d.client.Account.Login()
	if err != nil {
		return fmt.Errorf("inwx: %v", err)
	}

	defer func() {
		errL := d.client.Account.Logout()
		if errL != nil {
			log.Infof("inwx: failed to logout: %v", errL)
		}
	}()

	response, err := d.client.Nameservers.Info(&goinwx.NameserverInfoRequest{
		Domain: acme.UnFqdn(authZone),
		Name:   acme.UnFqdn(fqdn),
		Type:   "TXT",
	})
	if err != nil {
		return fmt.Errorf("inwx: %v", err)
	}

	var lastErr error
	for _, record := range response.Records {
		err = d.client.Nameservers.DeleteRecord(record.Id)
		if err != nil {
			lastErr = fmt.Errorf("inwx: %v", err)
		}
	}

	return lastErr
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}
