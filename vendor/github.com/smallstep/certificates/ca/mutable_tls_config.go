package ca

import (
	"crypto/tls"
	"crypto/x509"
	"sync"

	"github.com/smallstep/certificates/api"
)

// mutableTLSConfig allows to use a tls.Config with mutable cert pools.
type mutableTLSConfig struct {
	sync.RWMutex
	config         *tls.Config
	clientCerts    []*x509.Certificate
	rootCerts      []*x509.Certificate
	mutClientCerts []*x509.Certificate
	mutRootCerts   []*x509.Certificate
}

// newMutableTLSConfig creates a new mutableTLSConfig that will be later
// initialized with a tls.Config.
func newMutableTLSConfig() *mutableTLSConfig {
	return &mutableTLSConfig{
		clientCerts:    []*x509.Certificate{},
		rootCerts:      []*x509.Certificate{},
		mutClientCerts: []*x509.Certificate{},
		mutRootCerts:   []*x509.Certificate{},
	}
}

// Init initializes the mutable tls.Config with the given tls.Config.
func (c *mutableTLSConfig) Init(base *tls.Config) {
	c.Lock()
	c.config = base.Clone()
	c.Unlock()
}

// TLSConfig returns the updated tls.Config it it has changed. It's used in the
// tls.Config GetConfigForClient.
func (c *mutableTLSConfig) TLSConfig() (config *tls.Config) {
	c.RLock()
	config = c.config
	c.RUnlock()
	return
}

// Reload reloads the tls.Config with the new CAs.
func (c *mutableTLSConfig) Reload() {
	// Prepare new pools
	c.RLock()
	rootCAs := x509.NewCertPool()
	clientCAs := x509.NewCertPool()
	// Fixed certs
	for _, cert := range c.rootCerts {
		rootCAs.AddCert(cert)
	}
	for _, cert := range c.clientCerts {
		clientCAs.AddCert(cert)
	}
	// Mutable certs
	for _, cert := range c.mutRootCerts {
		rootCAs.AddCert(cert)
	}
	for _, cert := range c.mutClientCerts {
		clientCAs.AddCert(cert)
	}
	c.RUnlock()

	// Set new pool
	c.Lock()
	c.config.RootCAs = rootCAs
	c.config.ClientCAs = clientCAs
	c.mutRootCerts = []*x509.Certificate{}
	c.mutClientCerts = []*x509.Certificate{}
	c.Unlock()
}

// AddImmutableClientCACert add an immutable cert to ClientCAs.
func (c *mutableTLSConfig) AddImmutableClientCACert(cert *x509.Certificate) {
	c.Lock()
	c.clientCerts = append(c.clientCerts, cert)
	c.Unlock()
}

// AddImmutableRootCACert add an immutable cert to RootCas.
func (c *mutableTLSConfig) AddImmutableRootCACert(cert *x509.Certificate) {
	c.Lock()
	c.rootCerts = append(c.rootCerts, cert)
	c.Unlock()
}

// AddClientCAs add mutable certs to ClientCAs.
func (c *mutableTLSConfig) AddClientCAs(certs []api.Certificate) {
	c.Lock()
	for _, cert := range certs {
		c.mutClientCerts = append(c.mutClientCerts, cert.Certificate)
	}
	c.Unlock()
}

// AddRootCAs add mutable certs to RootCAs.
func (c *mutableTLSConfig) AddRootCAs(certs []api.Certificate) {
	c.Lock()
	for _, cert := range certs {
		c.mutRootCerts = append(c.mutRootCerts, cert.Certificate)
	}
	c.Unlock()
}
