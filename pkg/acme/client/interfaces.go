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

	acmeutil "github.com/cert-manager/cert-manager/pkg/acme/util"

	"golang.org/x/crypto/acme"
)

// Interface is an Automatic Certificate Management Environment (ACME) client
// implementing an Order-based flow.
//
// For more information see https://pkg.go.dev/golang.org/x/crypto/acme#Client
// and RFC 8555 (https://tools.ietf.org/html/rfc8555).
type Interface interface {
	AuthorizeOrder(ctx context.Context, id []acme.AuthzID, opt ...acme.OrderOption) (*acme.Order, error)
	GetOrder(ctx context.Context, url string) (*acme.Order, error)
	FetchCert(ctx context.Context, url string, bundle bool) ([][]byte, error)
	ListCertAlternates(ctx context.Context, url string) ([]string, error)
	WaitOrder(ctx context.Context, url string) (*acme.Order, error)
	CreateOrderCert(ctx context.Context, finalizeURL string, csr []byte, bundle bool) (der [][]byte, certURL string, err error)
	Accept(ctx context.Context, chal *acme.Challenge) (*acme.Challenge, error)
	GetChallenge(ctx context.Context, url string) (*acme.Challenge, error)
	GetAuthorization(ctx context.Context, url string) (*acme.Authorization, error)
	WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error)
	Register(ctx context.Context, acct *acme.Account, prompt func(tosURL string) bool) (*acme.Account, error)
	GetReg(ctx context.Context, url string) (*acme.Account, error)
	HTTP01ChallengeResponse(token string) (string, error)
	DNS01ChallengeRecord(token string) (string, error)
	Discover(ctx context.Context) (acme.Directory, error)
	UpdateReg(ctx context.Context, a *acme.Account) (*acme.Account, error)
}

var _ Interface = &acme.Client{
	RetryBackoff: acmeutil.RetryBackoff,
}
