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

package client

import (
	"context"
	"fmt"

	"golang.org/x/crypto/acme"
)

// TODO: expand this out one day to be backed by the pebble wfe package
// this will allow us to simulate a 'real' acme server in lightweight tests

// FakeACME implements Interface and can be used as a mock acme.Client in tests.
type FakeACME struct {
	FakeAuthorizeOrder          func(ctx context.Context, id []acme.AuthzID, opt ...acme.OrderOption) (*acme.Order, error)
	FakeGetOrder                func(ctx context.Context, url string) (*acme.Order, error)
	FakeFetchCert               func(ctx context.Context, url string, bundle bool) ([][]byte, error)
	FakeListCertAlternates      func(ctx context.Context, url string) ([]string, error)
	FakeWaitOrder               func(ctx context.Context, url string) (*acme.Order, error)
	FakeCreateOrderCert         func(ctx context.Context, finalizeURL string, csr []byte, bundle bool) (der [][]byte, certURL string, err error)
	FakeAccept                  func(ctx context.Context, chal *acme.Challenge) (*acme.Challenge, error)
	FakeGetChallenge            func(ctx context.Context, url string) (*acme.Challenge, error)
	FakeGetAuthorization        func(ctx context.Context, url string) (*acme.Authorization, error)
	FakeWaitAuthorization       func(ctx context.Context, url string) (*acme.Authorization, error)
	FakeRegister                func(ctx context.Context, a *acme.Account, prompt func(tosURL string) bool) (*acme.Account, error)
	FakeGetReg                  func(ctx context.Context, url string) (*acme.Account, error)
	FakeHTTP01ChallengeResponse func(token string) (string, error)
	FakeDNS01ChallengeRecord    func(token string) (string, error)
	FakeDiscover                func(ctx context.Context) (acme.Directory, error)
	FakeUpdateReg               func(ctx context.Context, a *acme.Account) (*acme.Account, error)
}

var _ Interface = &FakeACME{}

func (f *FakeACME) AuthorizeOrder(ctx context.Context, id []acme.AuthzID, opt ...acme.OrderOption) (*acme.Order, error) {
	if f.FakeAuthorizeOrder != nil {
		return f.FakeAuthorizeOrder(ctx, id, opt...)
	}
	return nil, fmt.Errorf("AuthorizeOrder not implemented")
}

func (f *FakeACME) GetOrder(ctx context.Context, url string) (*acme.Order, error) {
	if f.FakeGetOrder != nil {
		return f.FakeGetOrder(ctx, url)
	}
	return nil, fmt.Errorf("GetOrder not implemented")
}

func (f *FakeACME) FetchCert(ctx context.Context, url string, bundle bool) ([][]byte, error) {
	if f.FakeFetchCert != nil {
		return f.FakeFetchCert(ctx, url, bundle)
	}
	return nil, fmt.Errorf("FetchCert not implemented")
}

func (f *FakeACME) WaitOrder(ctx context.Context, url string) (*acme.Order, error) {
	if f.FakeWaitOrder != nil {
		return f.FakeWaitOrder(ctx, url)
	}
	return nil, fmt.Errorf("WaitOrder not implemented")
}

func (f *FakeACME) CreateOrderCert(ctx context.Context, finalizeURL string, csr []byte, bundle bool) (der [][]byte, certURL string, err error) {
	if f.FakeCreateOrderCert != nil {
		return f.FakeCreateOrderCert(ctx, finalizeURL, csr, bundle)
	}
	return nil, "", fmt.Errorf("CreateOrderCert not implemented")
}

func (f *FakeACME) Accept(ctx context.Context, chal *acme.Challenge) (*acme.Challenge, error) {
	if f.FakeAccept != nil {
		return f.FakeAccept(ctx, chal)
	}
	return nil, fmt.Errorf("Accept not implemented")
}

func (f *FakeACME) GetChallenge(ctx context.Context, url string) (*acme.Challenge, error) {
	if f.FakeGetChallenge != nil {
		return f.FakeGetChallenge(ctx, url)
	}
	return nil, fmt.Errorf("GetChallenge not implemented")
}

func (f *FakeACME) GetAuthorization(ctx context.Context, url string) (*acme.Authorization, error) {
	if f.FakeGetAuthorization != nil {
		return f.FakeGetAuthorization(ctx, url)
	}
	return nil, fmt.Errorf("GetAuthorization not implemented")
}

func (f *FakeACME) WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error) {
	if f.FakeWaitAuthorization != nil {
		return f.FakeWaitAuthorization(ctx, url)
	}
	return nil, fmt.Errorf("WaitAuthorization not implemented")
}

func (f *FakeACME) Register(ctx context.Context, a *acme.Account, prompt func(tosURL string) bool) (*acme.Account, error) {
	if f.FakeRegister != nil {
		return f.FakeRegister(ctx, a, prompt)
	}
	return nil, fmt.Errorf("Register not implemented")
}

func (f *FakeACME) GetReg(ctx context.Context, url string) (*acme.Account, error) {
	if f.FakeGetReg != nil {
		return f.FakeGetReg(ctx, url)
	}
	return nil, fmt.Errorf("GetReg not implemented")
}

func (f *FakeACME) HTTP01ChallengeResponse(token string) (string, error) {
	if f.FakeHTTP01ChallengeResponse != nil {
		return f.FakeHTTP01ChallengeResponse(token)
	}
	return "", fmt.Errorf("HTTP01ChallengeResponse not implemented")
}

func (f *FakeACME) DNS01ChallengeRecord(token string) (string, error) {
	if f.FakeDNS01ChallengeRecord != nil {
		return f.FakeDNS01ChallengeRecord(token)
	}
	return "", fmt.Errorf("DNS01ChallengeRecord not implemented")
}

func (f *FakeACME) Discover(ctx context.Context) (acme.Directory, error) {
	if f.FakeDiscover != nil {
		return f.FakeDiscover(ctx)
	}
	// We only use Discover to find CAAIdentities, so returning an
	// empty directory here will be fine
	return acme.Directory{}, nil
}

func (f *FakeACME) UpdateReg(ctx context.Context, a *acme.Account) (*acme.Account, error) {
	if f.FakeUpdateReg != nil {
		return f.FakeUpdateReg(ctx, a)
	}
	return nil, fmt.Errorf("UpdateReg not implemented")
}

func (f *FakeACME) ListCertAlternates(ctx context.Context, url string) ([]string, error) {
	if f.FakeListCertAlternates != nil {
		return f.FakeListCertAlternates(ctx, url)
	}
	return nil, fmt.Errorf("ListCertAlternates not implemented")
}
