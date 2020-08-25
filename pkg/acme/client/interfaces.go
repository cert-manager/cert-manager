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
	"crypto/rand"
	"math/big"
	"net/http"
	"time"

	"golang.org/x/crypto/acme"
)

type Interface interface {
	AuthorizeOrder(ctx context.Context, id []acme.AuthzID, opt ...acme.OrderOption) (*acme.Order, error)
	GetOrder(ctx context.Context, url string) (*acme.Order, error)
	FetchCert(ctx context.Context, url string, bundle bool) ([][]byte, error)
	WaitOrder(ctx context.Context, url string) (*acme.Order, error)
	CreateOrderCert(ctx context.Context, finalizeURL string, csr []byte, bundle bool) (der [][]byte, certURL string, err error)
	Accept(ctx context.Context, chal *acme.Challenge) (*acme.Challenge, error)
	GetChallenge(ctx context.Context, url string) (*acme.Challenge, error)
	GetAuthorization(ctx context.Context, url string) (*acme.Authorization, error)
	WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error)
	Register(ctx context.Context, a *acme.Account, prompt func(tosURL string) bool) (*acme.Account, error)
	GetReg(ctx context.Context, url string) (*acme.Account, error)
	HTTP01ChallengeResponse(token string) (string, error)
	DNS01ChallengeRecord(token string) (string, error)
	Discover(ctx context.Context) (acme.Directory, error)
	UpdateReg(ctx context.Context, a *acme.Account) (*acme.Account, error)
}

var _ Interface = &acme.Client{
	// inspired by acme/http.go
	RetryBackoff: func(n int, r *http.Request, res *http.Response) time.Duration {
		var jitter time.Duration
		if x, err := rand.Int(rand.Reader, big.NewInt(1000)); err == nil {
			// Set the minimum to 1ms to avoid a case where
			// an invalid Retry-After value is parsed into 0 below,
			// resulting in the 0 returned value which would unintentionally
			// stop the retries.
			jitter = (1 + time.Duration(x.Int64())) * time.Millisecond
		}
		if _, ok := res.Header["Retry-After"]; ok {
			// if Retry-After is set we should
			// error and let the cert-manager logic retry instead
			return -1
		}

		// classic backoff here in case we got no reply
		// eg. flakes
		if n < 1 {
			n = 1
		}
		if n > 30 {
			n = 30
		}
		d := time.Duration(1<<uint(n-1))*time.Second + jitter
		if d > 10*time.Second {
			return 10 * time.Second
		}
		return d
	},
}
