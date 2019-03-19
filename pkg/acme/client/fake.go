/*
Copyright 2019 The Jetstack cert-manager contributors.

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

	"github.com/jetstack/cert-manager/third_party/crypto/acme"
)

// TODO: expand this out one day to be backed by the pebble wfe package
// this will allow us to simulate a 'real' acme server in lightweight tests

// FakeACME is a convenience structure to create a stub ACME implementation
type FakeACME struct {
	FakeCreateOrder             func(ctx context.Context, order *acme.Order) (*acme.Order, error)
	FakeGetOrder                func(ctx context.Context, url string) (*acme.Order, error)
	FakeGetCertificate          func(ctx context.Context, url string) ([][]byte, error)
	FakeWaitOrder               func(ctx context.Context, url string) (*acme.Order, error)
	FakeFinalizeOrder           func(ctx context.Context, finalizeURL string, csr []byte) (der [][]byte, err error)
	FakeAcceptChallenge         func(ctx context.Context, chal *acme.Challenge) (*acme.Challenge, error)
	FakeGetChallenge            func(ctx context.Context, url string) (*acme.Challenge, error)
	FakeGetAuthorization        func(ctx context.Context, url string) (*acme.Authorization, error)
	FakeWaitAuthorization       func(ctx context.Context, url string) (*acme.Authorization, error)
	FakeCreateAccount           func(ctx context.Context, a *acme.Account) (*acme.Account, error)
	FakeGetAccount              func(ctx context.Context) (*acme.Account, error)
	FakeHTTP01ChallengeResponse func(token string) (string, error)
	FakeDNS01ChallengeRecord    func(token string) (string, error)
	FakeDiscover                func(ctx context.Context) (acme.Directory, error)
}

func (f *FakeACME) CreateOrder(ctx context.Context, order *acme.Order) (*acme.Order, error) {
	if f.FakeCreateOrder != nil {
		return f.FakeCreateOrder(ctx, order)
	}
	return nil, fmt.Errorf("CreateOrder not implemented")
}

func (f *FakeACME) GetOrder(ctx context.Context, url string) (*acme.Order, error) {
	if f.FakeGetOrder != nil {
		return f.FakeGetOrder(ctx, url)
	}
	return nil, fmt.Errorf("GetOrder not implemented")
}

func (f *FakeACME) GetCertificate(ctx context.Context, url string) ([][]byte, error) {
	if f.FakeGetCertificate != nil {
		return f.FakeGetCertificate(ctx, url)
	}
	return nil, fmt.Errorf("GetCertificate not implemented")
}

func (f *FakeACME) WaitOrder(ctx context.Context, url string) (*acme.Order, error) {
	if f.FakeWaitOrder != nil {
		return f.FakeWaitOrder(ctx, url)
	}
	return nil, fmt.Errorf("WaitOrder not implemented")
}

func (f *FakeACME) FinalizeOrder(ctx context.Context, finalizeURL string, csr []byte) (der [][]byte, err error) {
	if f.FakeFinalizeOrder != nil {
		return f.FakeFinalizeOrder(ctx, finalizeURL, csr)
	}
	return nil, fmt.Errorf("FinalizeOrder not implemented")
}

func (f *FakeACME) AcceptChallenge(ctx context.Context, chal *acme.Challenge) (*acme.Challenge, error) {
	if f.FakeAcceptChallenge != nil {
		return f.FakeAcceptChallenge(ctx, chal)
	}
	return nil, fmt.Errorf("AcceptChallenge not implemented")
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

func (f *FakeACME) CreateAccount(ctx context.Context, a *acme.Account) (*acme.Account, error) {
	if f.FakeCreateAccount != nil {
		return f.FakeCreateAccount(ctx, a)
	}
	return nil, fmt.Errorf("CreateAccount not implemented")
}

func (f *FakeACME) GetAccount(ctx context.Context) (*acme.Account, error) {
	if f.FakeGetAccount != nil {
		return f.FakeGetAccount(ctx)
	}
	return nil, fmt.Errorf("GetAccount not implemented")
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
