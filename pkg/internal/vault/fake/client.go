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

	vault "github.com/hashicorp/vault/api"
)

type Client struct {
	NewRequestS  *vault.Request
	RawRequestFn func(r *vault.Request) (*vault.Response, error)
	token        string
}

func NewFakeClient() *Client {
	return &Client{
		NewRequestS: new(vault.Request),
		RawRequestFn: func(r *vault.Request) (*vault.Response, error) {
			return nil, errors.New("unexpected RawRequest call")
		},
	}
}

func (c *Client) WithNewRequest(r *vault.Request) *Client {
	c.NewRequestS = r
	return c
}

func (c *Client) WithRawRequest(resp *vault.Response, err error) *Client {
	c.RawRequestFn = func(r *vault.Request) (*vault.Response, error) {
		return resp, err
	}
	return c
}

func (c *Client) NewRequest(method, requestPath string) *vault.Request {
	return c.NewRequestS
}

func (c *Client) SetToken(v string) {
	c.token = v
}

func (c *Client) Token() string {
	return c.token
}

func (c *Client) RawRequest(r *vault.Request) (*vault.Response, error) {
	return c.RawRequestFn(r)
}

func (c *Client) Sys() *vault.Sys {
	return nil
}
