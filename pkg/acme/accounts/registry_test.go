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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/cert-manager/cert-manager/pkg/acme/client"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

func TestRegistry_AddClient(t *testing.T) {
	r := NewDefaultRegistry(func(options NewClientOptions) client.Interface {
		return newClientFromHTTPClient(http.DefaultClient, "cert-manager-test", options)
	})
	pk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	// Register a new client
	r.AddClient("abc", NewClientOptions{
		PrivateKey: pk,
	})

	c, err := r.GetClient("abc")
	if err != nil {
		t.Errorf("unexpected error getting client: %v", err)
	}
	if c == nil {
		t.Error("nil client returned")
	}
}

func TestRegistry_RemoveClient(t *testing.T) {
	r := NewDefaultRegistry(func(options NewClientOptions) client.Interface {
		return newClientFromHTTPClient(http.DefaultClient, "cert-manager-test", options)
	})
	pk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	// Register a new client
	r.AddClient("abc", NewClientOptions{
		PrivateKey: pk,
	})

	c, err := r.GetClient("abc")
	if err != nil {
		t.Errorf("unexpected error getting client: %v", err)
	}
	if c == nil {
		t.Error("nil client returned")
	}

	r.RemoveClient("abc")
	c, err = r.GetClient("abc")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound but got: %v", err)
	}
	if c != nil {
		t.Error("expected nil client to be returned")
	}
}

func TestRegistry_RefreshClient(t *testing.T) {
	r := NewDefaultRegistry(func(options NewClientOptions) client.Interface {
		return newClientFromHTTPClient(http.DefaultClient, "cert-manager-test", options)
	})
	if _, err := r.RefreshClient("abc"); err != ErrNotFound {
		t.Errorf("expected ErrNotFound but got: %v", err)
	}

	pk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	r.AddClient("abc", NewClientOptions{PrivateKey: pk})
	before, err := r.GetClient("abc")
	if err != nil {
		t.Fatal(err)
	}

	refreshed, err := r.RefreshClient("abc")
	if err != nil {
		t.Fatal(err)
	}
	if refreshed == before {
		t.Error("expected RefreshClient to return a new client")
	}
	after, err := r.GetClient("abc")
	if err != nil {
		t.Fatal(err)
	}
	if after != refreshed {
		t.Error("expected GetClient to return the refreshed client")
	}

	// The refreshed client was built from the same options, so AddClient
	// with those options must not replace it.
	r.AddClient("abc", NewClientOptions{PrivateKey: pk})
	if c, _ := r.GetClient("abc"); c != refreshed {
		t.Error("expected AddClient with unchanged options to keep the refreshed client")
	}
}

func TestRegistry_RemoveClient_EmptyRegistry(t *testing.T) {
	r := NewDefaultRegistry(nil)
	r.RemoveClient("abc")
	c, err := r.GetClient("abc")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound but got: %v", err)
	}
	if c != nil {
		t.Error("expected nil client to be returned")
	}
}

func TestRegistry_ListClients(t *testing.T) {
	r := NewDefaultRegistry(func(options NewClientOptions) client.Interface {
		return newClientFromHTTPClient(http.DefaultClient, "cert-manager-test", options)
	})
	pk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	// Register a new client
	r.AddClient("abc", NewClientOptions{
		PrivateKey: pk,
	})
	l := r.ListClients()
	if len(l) != 1 {
		t.Errorf("expected ListClients to have 1 item but it has %d", len(l))
	}

	// Register a second client
	r.AddClient("abc2", NewClientOptions{
		PrivateKey: pk,
	})
	l = r.ListClients()
	if len(l) != 2 {
		t.Errorf("expected ListClients to have 2 items but it has %d", len(l))
	}

	// Register a third client with the same options as the second, meaning
	// it should be de-duplicated
	r.AddClient("abc2", NewClientOptions{
		PrivateKey: pk,
	})
	l = r.ListClients()
	if len(l) != 2 {
		t.Errorf("expected ListClients to have 2 items but it has %d", len(l))
	}

	// Update the second client with a new server URL
	r.AddClient("abc2", NewClientOptions{
		Server:     "abc.com",
		PrivateKey: pk,
	})
	l = r.ListClients()
	if len(l) != 2 {
		t.Errorf("expected ListClients to have 2 items but it has %d", len(l))
	}
}

func TestRegistry_AddClient_UpdatesExistingWhenPrivateKeyChanges(t *testing.T) {
	r := NewDefaultRegistry(func(options NewClientOptions) client.Interface {
		return newClientFromHTTPClient(http.DefaultClient, "cert-manager-test", options)
	})
	pk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	pk2, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	// Register a new client
	r.AddClient("abc", NewClientOptions{
		PrivateKey: pk,
	})
	l := r.ListClients()
	if len(l) != 1 {
		t.Errorf("expected ListClients to have 1 item but it has %d", len(l))
	}

	// Update the client with a new private key
	r.AddClient("abc", NewClientOptions{
		PrivateKey: pk2,
	})
	l = r.ListClients()
	if len(l) != 1 {
		t.Errorf("expected ListClients to have 1 item but it has %d", len(l))
	}
}

func TestRegistry_AddClient_UpdatesClientPKChecksum(t *testing.T) {
	r := NewDefaultRegistry(func(options NewClientOptions) client.Interface {
		return newClientFromHTTPClient(http.DefaultClient, "cert-manager-test", options)
	})
	pk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	pk2, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	pkBytes := x509.MarshalPKCS1PrivateKey(pk)
	pkChecksum := sha256.Sum256(pkBytes)
	pkChecksumString := base64.StdEncoding.EncodeToString(pkChecksum[:])

	// Register a new client
	r.AddClient("abc", NewClientOptions{
		PrivateKey: pk,
	})
	l := r.ListClients()
	if len(l) != 1 {
		t.Errorf("expected ListClients to have 1 item but it has %d", len(l))
	}

	isCached := r.IsKeyCheckSumCached(pkChecksumString, pk)
	if isCached == false {
		t.Fatal("checksum failed for same key")
	}

	isCached = r.IsKeyCheckSumCached(pkChecksumString, pk2)
	if isCached == true {
		t.Fatal("checksum reported same for different keys")
	}
}
