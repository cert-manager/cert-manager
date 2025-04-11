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

package fake

import (
	"errors"
	"testing"

	vault "github.com/hashicorp/vault/api"
)

type FakeClient struct {
	NewRequestS  *vault.Request
	RawRequestFn func(r *vault.Request) (*vault.Response, error)
	GotToken     string
	T            *testing.T
}

func NewFakeClient() *FakeClient {
	return &FakeClient{
		NewRequestS: new(vault.Request),
		RawRequestFn: func(r *vault.Request) (*vault.Response, error) {
			return nil, errors.New("unexpected RawRequest call")
		},
	}
}

func (c *FakeClient) CloneConfig() *vault.Config {
	return vault.DefaultConfig()
}

func (c *FakeClient) WithNewRequest(r *vault.Request) *FakeClient {
	c.NewRequestS = r
	return c
}

func (c *FakeClient) WithRawRequest(resp *vault.Response, err error) *FakeClient {
	c.RawRequestFn = func(r *vault.Request) (*vault.Response, error) {
		return resp, err
	}
	return c
}

func (c *FakeClient) WithRawRequestFn(fn func(t *testing.T, r *vault.Request) (*vault.Response, error)) *FakeClient {
	c.RawRequestFn = func(req *vault.Request) (*vault.Response, error) {
		return fn(c.T, req)
	}
	return c
}

func (c *FakeClient) NewRequest(method, requestPath string) *vault.Request {
	return c.NewRequestS
}

func (c *FakeClient) SetToken(v string) {
	c.GotToken = v
}

func (c *FakeClient) RawRequest(r *vault.Request) (*vault.Response, error) {
	return c.RawRequestFn(r)
}
