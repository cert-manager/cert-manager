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

package middleware

import (
	"context"

	"github.com/go-logr/logr"
	"golang.org/x/crypto/acme"

	"github.com/cert-manager/cert-manager/pkg/acme/client"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

func NewLogger(baseCl client.Interface) client.Interface {
	return &Logger{
		baseCl: baseCl,
		log:    logf.Log.WithName("acme-middleware"),
	}
}

// Logger is a glog based logging middleware for an ACME client
type Logger struct {
	baseCl client.Interface
	log    logr.Logger
}

var _ client.Interface = &Logger{}

func (l *Logger) AuthorizeOrder(ctx context.Context, id []acme.AuthzID, opt ...acme.OrderOption) (*acme.Order, error) {
	l.log.V(logf.TraceLevel).Info("Calling AuthorizeOrder")

	return l.baseCl.AuthorizeOrder(ctx, id, opt...)
}

func (l *Logger) GetOrder(ctx context.Context, url string) (*acme.Order, error) {
	l.log.V(logf.TraceLevel).Info("Calling GetOrder")

	return l.baseCl.GetOrder(ctx, url)
}

func (l *Logger) FetchCert(ctx context.Context, url string, bundle bool) ([][]byte, error) {
	l.log.V(logf.TraceLevel).Info("Calling FetchCert")

	return l.baseCl.FetchCert(ctx, url, bundle)
}

func (l *Logger) ListCertAlternates(ctx context.Context, url string) ([]string, error) {
	l.log.V(logf.TraceLevel).Info("Calling ListCertAlternates")

	return l.baseCl.ListCertAlternates(ctx, url)
}

func (l *Logger) WaitOrder(ctx context.Context, url string) (*acme.Order, error) {
	l.log.V(logf.TraceLevel).Info("Calling WaitOrder")

	return l.baseCl.WaitOrder(ctx, url)
}

func (l *Logger) CreateOrderCert(ctx context.Context, finalizeURL string, csr []byte, bundle bool) (der [][]byte, certURL string, err error) {
	l.log.V(logf.TraceLevel).Info("Calling CreateOrderCert")

	return l.baseCl.CreateOrderCert(ctx, finalizeURL, csr, bundle)
}

func (l *Logger) Accept(ctx context.Context, chal *acme.Challenge) (*acme.Challenge, error) {
	l.log.V(logf.TraceLevel).Info("Calling Accept")

	return l.baseCl.Accept(ctx, chal)
}

func (l *Logger) GetChallenge(ctx context.Context, url string) (*acme.Challenge, error) {
	l.log.V(logf.TraceLevel).Info("Calling GetChallenge")

	return l.baseCl.GetChallenge(ctx, url)
}

func (l *Logger) GetAuthorization(ctx context.Context, url string) (*acme.Authorization, error) {
	l.log.V(logf.TraceLevel).Info("Calling GetAuthorization")

	return l.baseCl.GetAuthorization(ctx, url)
}

func (l *Logger) WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error) {
	l.log.V(logf.TraceLevel).Info("Calling WaitAuthorization")

	return l.baseCl.WaitAuthorization(ctx, url)
}

func (l *Logger) Register(ctx context.Context, a *acme.Account, prompt func(tosURL string) bool) (*acme.Account, error) {
	l.log.V(logf.TraceLevel).Info("Calling Register")

	return l.baseCl.Register(ctx, a, prompt)
}

func (l *Logger) GetReg(ctx context.Context, url string) (*acme.Account, error) {
	l.log.V(logf.TraceLevel).Info("Calling GetReg")

	return l.baseCl.GetReg(ctx, url)
}

func (l *Logger) HTTP01ChallengeResponse(token string) (string, error) {
	l.log.V(logf.TraceLevel).Info("Calling HTTP01ChallengeResponse")

	return l.baseCl.HTTP01ChallengeResponse(token)
}

func (l *Logger) DNS01ChallengeRecord(token string) (string, error) {
	l.log.V(logf.TraceLevel).Info("Calling DNS01ChallengeRecord")

	return l.baseCl.DNS01ChallengeRecord(token)
}

func (l *Logger) Discover(ctx context.Context) (acme.Directory, error) {
	l.log.V(logf.TraceLevel).Info("Calling Discover")

	return l.baseCl.Discover(ctx)
}

func (l *Logger) UpdateReg(ctx context.Context, a *acme.Account) (*acme.Account, error) {
	l.log.V(logf.TraceLevel).Info("Calling UpdateReg")

	return l.baseCl.UpdateReg(ctx, a)
}
