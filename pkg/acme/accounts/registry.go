/*
Copyright 2020 The cert-manager Authors.

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

package accounts

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"sync"

	acmecl "github.com/cert-manager/cert-manager/pkg/acme/client"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
)

// ErrNotFound is returned by GetClient if there is no ACME client registered.
var ErrNotFound = errors.New("ACME client for issuer not initialised/available")

// A registry provides a means to store and access ACME clients using an issuer
// objects UID.
// This is used as a shared cache of ACME clients across various controllers.
type Registry interface {
	// AddClient will ensure the registry has a stored ACME client for the Issuer
	// object with the given UID, configuration and private key.
	AddClient(httpClient *http.Client, uid string, config cmacme.ACMEIssuer, privateKey *rsa.PrivateKey, userAgent string)

	// RemoveClient will remove a registered client using the UID of the Issuer
	// resource that constructed it.
	RemoveClient(uid string)

	// IsKeyCheckSumCached checks if the private key checksum is cached with registered client.
	// If not cached, the account is re-verified for the private key.
	IsKeyCheckSumCached(lastPrivateKeyHash string, privateKey *rsa.PrivateKey) bool

	Getter
}

// Getter is an interface that contains the read-only methods for a registry.
type Getter interface {
	// GetClient will fetch a registered client using the UID of the Issuer
	// resources that constructed it.
	// If no client is found, ErrNotFound will be returned.
	GetClient(uid string) (acmecl.Interface, error)

	// ListClients will return a full list of all ACME clients by their UIDs.
	// This can be used to enumerate all registered clients and call RemoveClient
	// on any clients that should no longer be registered, e.g., because their
	// corresponding Issuer resource has been deleted.
	ListClients() map[string]acmecl.Interface
}

// NewDefaultRegistry returns a new default instantiation of a client registry.
func NewDefaultRegistry() Registry {
	return &registry{
		clients: make(map[string]clientWithMeta),
	}
}

// Implementation of the Registry interface
type registry struct {
	lock sync.RWMutex

	// a map of an issuer's 'uid' to an ACME client with metadata
	clients map[string]clientWithMeta
}

// stableOptions contains data about an ACME client that can be used to compare
// for 'equality' between two clients. This is used to determine whether any
// options that should trigger a re-initialisation of a client have changed.
type stableOptions struct {
	serverURL     string
	skipVerifyTLS bool
	issuerUID     string
	publicKey     string
	exponent      int
	caBundle      string
	keyChecksum   [sha256.Size]byte
}

func (c stableOptions) equalTo(c2 stableOptions) bool {
	return c == c2
}

func newStableOptions(uid string, config cmacme.ACMEIssuer, privateKey *rsa.PrivateKey) stableOptions {
	// Encoding a big.Int cannot fail
	publicNBytes, _ := privateKey.PublicKey.N.GobEncode()
	checksum := sha256.Sum256(x509.MarshalPKCS1PrivateKey(privateKey))

	return stableOptions{
		serverURL:     config.Server,
		skipVerifyTLS: config.SkipTLSVerify,
		issuerUID:     uid,
		publicKey:     string(publicNBytes),
		exponent:      privateKey.PublicKey.E,
		caBundle:      string(config.CABundle),
		keyChecksum:   checksum,
	}
}

// clientWithMeta wraps an ACME client with additional metadata used to
// identify the options used to instantiate the client.
type clientWithMeta struct {
	acmecl.Interface

	stableOptions
}

// AddClient will ensure the registry has a stored ACME client for the Issuer
// object with the given UID, configuration and private key.
func (r *registry) AddClient(httpClient *http.Client, uid string, config cmacme.ACMEIssuer, privateKey *rsa.PrivateKey, userAgent string) {
	// ensure the client is up to date for the current configuration
	r.ensureClient(httpClient, uid, config, privateKey, userAgent)
}

// ensureClient will ensure an ACME client with the given parameters is registered.
// If one is already registered and it was constructed using the same input options,
// the client will NOT be mutated or replaced, allowing this method to be called
// even if the client does not need replacing/updating without causing issues for
// consumers of the registry.
func (r *registry) ensureClient(httpClient *http.Client, uid string, config cmacme.ACMEIssuer, privateKey *rsa.PrivateKey, userAgent string) {
	// acquire a read-write lock even if we hit the fast-path where the client
	// is already present to avoid having to RLock, RUnlock and Lock again,
	// which could itself cause a race
	r.lock.Lock()
	defer r.lock.Unlock()

	newOpts := newStableOptions(uid, config, privateKey)
	// fast-path if there is nothing to do
	if meta, ok := r.clients[uid]; ok && meta.equalTo(newOpts) {
		return
	}

	// create a new client if one is not registered or if the
	// 'metadata' does not match
	r.clients[uid] = clientWithMeta{
		Interface:     NewClient(httpClient, config, privateKey, userAgent),
		stableOptions: newOpts,
	}
}

// GetClient will fetch a registered client using the UID of the Issuer
// resources that constructed it.
// If no client is found, ErrNotFound will be returned.
func (r *registry) GetClient(uid string) (acmecl.Interface, error) {
	r.lock.RLock()
	defer r.lock.RUnlock()
	// fast-path if the client is already registered
	if c, ok := r.clients[uid]; ok {
		return c.Interface, nil
	}
	return nil, ErrNotFound
}

// RemoveClient will remove a registered client using the UID of the Issuer
// resource that constructed it.
func (r *registry) RemoveClient(uid string) {
	r.lock.Lock()
	defer r.lock.Unlock()
	if _, ok := r.clients[uid]; !ok {
		return
	}
	delete(r.clients, uid)
}

// ListClients will return a full list of all ACME clients by their UIDs.
// This can be used to enumerate all registered clients and call RemoveClient
// on any clients that should no longer be registered, e.g., because their
// corresponding Issuer resource has been deleted.
func (r *registry) ListClients() map[string]acmecl.Interface {
	r.lock.RLock()
	defer r.lock.RUnlock()
	// strip the client metadata before returning
	out := make(map[string]acmecl.Interface)
	for k, v := range r.clients {
		out[k] = v.Interface
	}
	return out
}

// IsKeyCheckSumCached returns true when there is no difference in private key checksum.
// This can be used to identify if the private key has changed for the existing
// registered client.
func (r *registry) IsKeyCheckSumCached(lastPrivateKeyHash string, privateKey *rsa.PrivateKey) bool {
	r.lock.RLock()
	defer r.lock.RUnlock()

	if privateKey != nil && lastPrivateKeyHash != "" {
		privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		checksum := sha256.Sum256(privateKeyBytes)
		checksumString := base64.StdEncoding.EncodeToString(checksum[:])

		if lastPrivateKeyHash == checksumString {
			return true
		}

	}

	// Either there is no entry found in client cache for uid
	// or private key checksum does not match with cached entry
	return false
}
