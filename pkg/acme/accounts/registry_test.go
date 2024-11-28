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
	"testing"

	"github.com/cert-manager/cert-manager/pkg/acme/client"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

var nilClientContructor = func(options NewClientOptions) client.Interface {
	return &client.FakeACME{}
}

func testSetup(t *testing.T) (RegistryItem, *v1.ACMEIssuer, *v1.ACMEIssuerStatus) {
	pk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	ri := RegistryItem{
		NewClientOptions: NewClientOptions{
			Server:        "https://test.cert-manager.io/server/url",
			CABundle:      []byte("[ca bundle]"),
			SkipTLSVerify: true,

			PrivateKey: pk,
		},
		Email: "[email]",
	}

	return ri, &v1.ACMEIssuer{
			Server:        "https://test.cert-manager.io/server/url",
			Email:         "[email]",
			CABundle:      []byte("[ca bundle]"),
			SkipTLSVerify: true,
		}, &v1.ACMEIssuerStatus{
			URI:                 "https://test.cert-manager.io/account/url",
			LastRegisteredEmail: "[email]",
			LastPrivateKeyHash:  ri.privateKeyHash(),
		}
}

func TestRegistry_AddClient(t *testing.T) {
	r := NewDefaultRegistry()

	ri, spec, status := testSetup(t)

	// Register a new client
	r.AddClient("abc", ri, nilClientContructor)

	c, err := r.GetClient("abc", spec, status)
	if err != nil {
		t.Errorf("unexpected error getting client: %v", err)
	}
	if c == nil {
		t.Error("nil client returned")
	}
}

func TestRegistry_RemoveClient(t *testing.T) {
	r := NewDefaultRegistry()

	ri, spec, status := testSetup(t)

	// Register a new client
	r.AddClient("abc", ri, nilClientContructor)

	c, err := r.GetClient("abc", spec, status)
	if err != nil {
		t.Errorf("unexpected error getting client: %v", err)
	}
	if c == nil {
		t.Error("nil client returned")
	}

	r.RemoveClient("abc")
	c, err = r.GetClient("abc", spec, status)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound but got: %v", err)
	}
	if c != nil {
		t.Error("expected nil client to be returned")
	}
}

func TestRegistry_RemoveClient_EmptyRegistry(t *testing.T) {
	r := NewDefaultRegistry()
	r.RemoveClient("abc")
	c, err := r.GetClient("abc", nil, nil)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound but got: %v", err)
	}
	if c != nil {
		t.Error("expected nil client to be returned")
	}
}

func TestRegistry_ListClients(t *testing.T) {
	r := NewDefaultRegistry()

	// Register a new client
	r.AddClient("abc", RegistryItem{}, nilClientContructor)
	l := r.ListClients()
	if len(l) != 1 {
		t.Errorf("expected ListClients to have 1 item but it has %d", len(l))
	}

	// Register a second client
	r.AddClient("abc2", RegistryItem{}, nilClientContructor)
	l = r.ListClients()
	if len(l) != 2 {
		t.Errorf("expected ListClients to have 2 items but it has %d", len(l))
	}

	// Register a third client with the same options as the second, meaning
	// it should be de-duplicated
	r.AddClient("abc2", RegistryItem{}, nilClientContructor)
	l = r.ListClients()
	if len(l) != 2 {
		t.Errorf("expected ListClients to have 2 items but it has %d", len(l))
	}

	// Update the second client with a new server URL
	r.AddClient("abc2", RegistryItem{
		NewClientOptions: NewClientOptions{
			Server: "abc.com",
		},
	}, nilClientContructor)
	l = r.ListClients()
	if len(l) != 2 {
		t.Errorf("expected ListClients to have 2 items but it has %d", len(l))
	}
}

func TestRegistry_AddClient_UpdatesExistingWhenPrivateKeyChanges(t *testing.T) {
	r := NewDefaultRegistry()

	// Register a new client
	r.AddClient("abc", RegistryItem{}, nilClientContructor)
	l := r.ListClients()
	if len(l) != 1 {
		t.Errorf("expected ListClients to have 1 item but it has %d", len(l))
	}

	// Update the client with a new private key
	r.AddClient("abc", RegistryItem{}, nilClientContructor)
	l = r.ListClients()
	if len(l) != 1 {
		t.Errorf("expected ListClients to have 1 item but it has %d", len(l))
	}
}

func TestRegistry_AddClient_UpdatesClientPKChecksum(t *testing.T) {
	r := NewDefaultRegistry()
	ri1, spec1, status1 := testSetup(t)

	// Register a new client
	r.AddClient("abc", ri1, nilClientContructor)
	l := r.ListClients()
	if len(l) != 1 {
		t.Errorf("expected ListClients to have 1 item but it has %d", len(l))
	}

	if _, err := r.GetClient("abc", spec1, status1); err != nil {
		t.Fatal("checksum failed for same key")
	}

	status1.LastPrivateKeyHash = "other value"

	if _, err := r.GetClient("abc", spec1, status1); err == nil {
		t.Fatal("checksum reported same for different keys")
	}
}
