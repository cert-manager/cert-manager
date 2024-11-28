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
	"github.com/cert-manager/cert-manager/pkg/acme/accounts"
	acmecl "github.com/cert-manager/cert-manager/pkg/acme/client"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
)

var _ accounts.Registry = &FakeRegistry{}

// FakeRegistry implements the accounts.Registry interface using stub functions
type FakeRegistry struct {
	AddClientFunc    func(uid string, options accounts.RegistryItem, newClient accounts.NewClientFunc)
	RemoveClientFunc func(uid string)
	GetClientFunc    func(uid string, spec *cmacme.ACMEIssuer, status *cmacme.ACMEIssuerStatus) (acmecl.Interface, error)
	ListClientsFunc  func() map[string]acmecl.Interface
}

func (f *FakeRegistry) AddClient(uid string, options accounts.RegistryItem, newClient accounts.NewClientFunc) {
	f.AddClientFunc(uid, options, newClient)
}

func (f *FakeRegistry) RemoveClient(uid string) {
	f.RemoveClientFunc(uid)
}

func (f *FakeRegistry) GetClient(uid string, spec *cmacme.ACMEIssuer, status *cmacme.ACMEIssuerStatus) (acmecl.Interface, error) {
	return f.GetClientFunc(uid, spec, status)
}

func (f *FakeRegistry) ListClients() map[string]acmecl.Interface {
	return f.ListClientsFunc()
}
