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
	"errors"
	"sync"

	acmecl "github.com/cert-manager/cert-manager/pkg/acme/client"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
)

// ErrNotFound is returned by GetClient if there is no ACME client registered.
var ErrNotFound = errors.New("ACME client for issuer not initialised/available")

// ErrNotUpToDate is returned by GetClient if the ACME client is not up-to-date with the issuer spec.
var ErrNotUpToDate = errors.New("ACME client for issuer does not yet match its spec")

// ErrNotRegistered is returned by GetClient if the ACME client is yet registered.
var ErrNotRegistered = errors.New("ACME client for issuer is not yet registered")

// A registry provides a means to store and access ACME clients using an issuer
// objects UID.
// This is used as a shared cache of ACME clients across various controllers.
type Registry interface {
	// AddClient will ensure the registry has a stored ACME client for the Issuer
	// object with the given UID, configuration and private key.
	AddClient(uid string, options RegistryItem, newClient NewClientFunc)

	// RemoveClient will remove a registered client using the UID of the Issuer
	// resource that constructed it.
	RemoveClient(uid string)

	Getter
}

// Getter is an interface that contains the read-only methods for a registry.
type Getter interface {
	// GetClient will fetch a registered client using the UID of the Issuer
	// resources that constructed it.
	// If no client is found, ErrNotFound will be returned.
	GetClient(uid string, spec *cmacme.ACMEIssuer, status *cmacme.ACMEIssuerStatus) (acmecl.Interface, error)

	// ListClients will return a full list of all ACME clients by their UIDs.
	// This can be used to enumerate all registered clients and call RemoveClient
	// on any clients that should no longer be registered, e.g. because their
	// corresponding Issuer resource has been deleted.
	ListClients() map[string]acmecl.Interface
}

// NewDefaultRegistry returns a new default instantiation of a client registry.
func NewDefaultRegistry() Registry {
	return &registry{
		clients: make(map[string]registryItemWithClient),
	}
}

// Implementation of the Registry interface
type registry struct {
	lock sync.RWMutex

	// a map of an issuer's 'uid' to an ACME client with metadata
	clients map[string]registryItemWithClient
}

type registryItemWithClient struct {
	item   RegistryItem
	client acmecl.Interface
}

// AddClient will ensure the registry has a stored ACME client for the Issuer
// object with the given UID, configuration and private key.
func (r *registry) AddClient(uid string, options RegistryItem, newClient NewClientFunc) {
	// acquire a read-write lock even if we hit the fast-path where the client
	// is already present to avoid having to RLock, RUnlock and Lock again,
	// which could itself cause a race
	r.lock.Lock()
	defer r.lock.Unlock()

	r.clients[uid] = registryItemWithClient{
		item:   options,
		client: newClient(options.NewClientOptions),
	}
}

// GetClient will fetch a registered client using the UID of the Issuer
// resources that constructed it.
// If no client is found, ErrNotFound will be returned.
func (r *registry) GetClient(uid string, spec *cmacme.ACMEIssuer, status *cmacme.ACMEIssuerStatus) (acmecl.Interface, error) {
	r.lock.RLock()
	defer r.lock.RUnlock()
	// fast-path if the client is already registered
	c, ok := r.clients[uid]
	if !ok {
		return nil, ErrNotFound
	}

	if !c.item.IsUpToDate(spec) {
		return nil, ErrNotUpToDate
	}

	if !c.item.IsRegistered(status) {
		return nil, ErrNotRegistered
	}

	return c.client, nil
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
// on any clients that should no longer be registered, e.g. because their
// corresponding Issuer resource has been deleted.
func (r *registry) ListClients() map[string]acmecl.Interface {
	r.lock.RLock()
	defer r.lock.RUnlock()
	// strip the client metadata before returning
	out := make(map[string]acmecl.Interface)
	for k, v := range r.clients {
		out[k] = v.client
	}
	return out
}
