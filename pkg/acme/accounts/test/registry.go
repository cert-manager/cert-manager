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

package test

import (
	"crypto/rsa"

	acmecl "github.com/cert-manager/cert-manager/pkg/acme/client"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
)

// FakeRegistry implements the accounts.Registry interface using stub functions
type FakeRegistry struct {
	AddClientFunc    func(uid string, config cmacme.ACMEIssuer, privateKey *rsa.PrivateKey)
	RemoveClientFunc func(uid string)
	GetClientFunc    func(uid string) (acmecl.Interface, error)
	ListClientsFunc  func() map[string]acmecl.Interface
}

func (f *FakeRegistry) AddClient(uid string, config cmacme.ACMEIssuer, privateKey *rsa.PrivateKey) {
	f.AddClientFunc(uid, config, privateKey)
}

func (f *FakeRegistry) RemoveClient(uid string) {
	f.RemoveClientFunc(uid)
}

func (f *FakeRegistry) GetClient(uid string) (acmecl.Interface, error) {
	return f.GetClientFunc(uid)
}

func (f *FakeRegistry) ListClients() map[string]acmecl.Interface {
	return f.ListClientsFunc()
}
