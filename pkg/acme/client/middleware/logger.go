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

package middleware

import (
	"context"
	"time"

	"golang.org/x/crypto/acme"
	"k8s.io/klog"

	"github.com/jetstack/cert-manager/pkg/acme/client"
)

const (
	timeout = time.Second * 30
)

func NewLogger(baseCl client.Interface) client.Interface {
	return &Logger{baseCl: baseCl}
}

// Logger is a glog based logging middleware for an ACME client
type Logger struct {
	baseCl client.Interface
}

var _ client.Interface = &Logger{}

func (l *Logger) AuthorizeOrder(ctx context.Context, id []acme.AuthzID, opt ...acme.OrderOption) (*acme.Order, error) {
	klog.Infof("Calling CreateOrder")

	acmectx, cancel := l.acmeContext(ctx)
	defer cancel()

	return l.baseCl.AuthorizeOrder(acmectx, id, opt...)
}

func (l *Logger) GetOrder(ctx context.Context, url string) (*acme.Order, error) {
	klog.Infof("Calling GetOrder")

	acmectx, cancel := l.acmeContext(ctx)
	defer cancel()

	return l.baseCl.GetOrder(acmectx, url)
}

func (l *Logger) FetchCert(ctx context.Context, url string, bundle bool) ([][]byte, error) {
	klog.Infof("Calling GetCertificate")

	acmectx, cancel := l.acmeContext(ctx)
	defer cancel()

	return l.baseCl.FetchCert(acmectx, url, bundle)
}

func (l *Logger) WaitOrder(ctx context.Context, url string) (*acme.Order, error) {
	klog.Infof("Calling WaitOrder")

	acmectx, cancel := l.acmeContext(ctx)
	defer cancel()

	return l.baseCl.WaitOrder(acmectx, url)
}

func (l *Logger) CreateOrderCert(ctx context.Context, finalizeURL string, csr []byte, bundle bool) (der [][]byte, certURL string, err error) {
	klog.Infof("Calling FinalizeOrder")

	acmectx, cancel := l.acmeContext(ctx)
	defer cancel()

	return l.baseCl.CreateOrderCert(acmectx, finalizeURL, csr, bundle)
}

func (l *Logger) Accept(ctx context.Context, chal *acme.Challenge) (*acme.Challenge, error) {
	klog.Infof("Calling AcceptChallenge")

	acmectx, cancel := l.acmeContext(ctx)
	defer cancel()

	return l.baseCl.Accept(acmectx, chal)
}

func (l *Logger) GetChallenge(ctx context.Context, url string) (*acme.Challenge, error) {
	klog.Infof("Calling GetChallenge")

	acmectx, cancel := l.acmeContext(ctx)
	defer cancel()

	return l.baseCl.GetChallenge(acmectx, url)
}

func (l *Logger) GetAuthorization(ctx context.Context, url string) (*acme.Authorization, error) {
	klog.Infof("Calling GetAuthorization")

	acmectx, cancel := l.acmeContext(ctx)
	defer cancel()

	return l.baseCl.GetAuthorization(acmectx, url)
}

func (l *Logger) WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error) {
	klog.Infof("Calling WaitAuthorization")

	acmectx, cancel := l.acmeContext(ctx)
	defer cancel()

	return l.baseCl.WaitAuthorization(acmectx, url)
}

func (l *Logger) Register(ctx context.Context, a *acme.Account, prompt func(tosURL string) bool) (*acme.Account, error) {
	klog.Infof("Calling CreateAccount")

	acmectx, cancel := l.acmeContext(ctx)
	defer cancel()

	return l.baseCl.Register(acmectx, a, prompt)
}

func (l *Logger) GetReg(ctx context.Context, url string) (*acme.Account, error) {
	klog.Infof("Calling GetAccount")

	acmectx, cancel := l.acmeContext(ctx)
	defer cancel()

	return l.baseCl.GetReg(acmectx, url)
}

func (l *Logger) HTTP01ChallengeResponse(token string) (string, error) {
	klog.Infof("Calling HTTP01ChallengeResponse")
	return l.baseCl.HTTP01ChallengeResponse(token)
}

func (l *Logger) DNS01ChallengeRecord(token string) (string, error) {
	klog.Infof("Calling DNS01ChallengeRecord")
	return l.baseCl.DNS01ChallengeRecord(token)
}

func (l *Logger) Discover(ctx context.Context) (acme.Directory, error) {
	klog.Infof("Calling Discover")
	return l.baseCl.Discover(ctx)
}

func (l *Logger) UpdateReg(ctx context.Context, a *acme.Account) (*acme.Account, error) {
	klog.Infof("Calling UpdateAccount")

	acmectx, cancel := l.acmeContext(ctx)
	defer cancel()

	return l.baseCl.UpdateReg(acmectx, a)
}

func (l *Logger) acmeContext(ctx context.Context) (context.Context, context.CancelFunc) {
	acmectx, cancel := context.WithTimeout(context.Background(), timeout)

	go func() {
		select {
		case <-ctx.Done():
			cancel()
		case <-acmectx.Done():
			return
		}
	}()

	return acmectx, cancel
}
