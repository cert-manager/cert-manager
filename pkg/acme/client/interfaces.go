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

	"github.com/jetstack/cert-manager/third_party/crypto/acme"
)

type Interface interface {
	CreateOrder(ctx context.Context, order *acme.Order) (*acme.Order, error)
	GetOrder(ctx context.Context, url string) (*acme.Order, error)
	GetCertificate(ctx context.Context, url string) ([][]byte, error)
	WaitOrder(ctx context.Context, url string) (*acme.Order, error)
	FinalizeOrder(ctx context.Context, finalizeURL string, csr []byte) (der [][]byte, err error)
	AcceptChallenge(ctx context.Context, chal *acme.Challenge) (*acme.Challenge, error)
	GetChallenge(ctx context.Context, url string) (*acme.Challenge, error)
	GetAuthorization(ctx context.Context, url string) (*acme.Authorization, error)
	WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error)
	CreateAccount(ctx context.Context, a *acme.Account) (*acme.Account, error)
	GetAccount(ctx context.Context) (*acme.Account, error)
	HTTP01ChallengeResponse(token string) (string, error)
	DNS01ChallengeRecord(token string) (string, error)
	Discover(ctx context.Context) (acme.Directory, error)
}

var _ Interface = &acme.Client{}
