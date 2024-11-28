/*
Copyright 2024 The cert-manager Authors.

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

package accounts

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	acmeapi "golang.org/x/crypto/acme"

	"github.com/cert-manager/cert-manager/pkg/acme/client"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
)

func Test_IsUpToDate(t *testing.T) {
	ri, spec, _ := testSetup(t)

	type testCase struct {
		issuer        func(*v1.ACMEIssuer)
		expIsUpToDate bool
	}

	for i, tt := range []testCase{
		{
			issuer: func(a *v1.ACMEIssuer) {
				a.Email = "other"
			},
			expIsUpToDate: false,
		},
		{
			issuer: func(a *v1.ACMEIssuer) {
				a.Server = "other"
			},
			expIsUpToDate: false,
		},
		{
			issuer: func(a *v1.ACMEIssuer) {
				a.CABundle = []byte("other")
			},
			expIsUpToDate: false,
		},
		{
			issuer: func(a *v1.ACMEIssuer) {
				a.SkipTLSVerify = false
			},
			expIsUpToDate: false,
		},
		{
			issuer:        func(a *v1.ACMEIssuer) {},
			expIsUpToDate: true,
		},
	} {
		t.Run(fmt.Sprintf("item-%d", i), func(t *testing.T) {
			specCopy := *spec
			tt.issuer(&specCopy)
			isUpToDate := ri.IsUpToDate(&specCopy)
			require.Equal(t, tt.expIsUpToDate, isUpToDate)
		})
	}
}

func Test_IsRegistered(t *testing.T) {
	ri, _, status := testSetup(t)

	type testCase struct {
		status          func(*v1.ACMEIssuerStatus)
		expIsRegistered bool
	}

	for i, tt := range []testCase{
		{
			status: func(a *v1.ACMEIssuerStatus) {
				a.URI = "https://other.cert-manager.io"
			},
			expIsRegistered: false,
		},
		{
			status: func(a *v1.ACMEIssuerStatus) {
				a.LastRegisteredEmail = "other"
			},
			expIsRegistered: false,
		},
		{
			status: func(a *v1.ACMEIssuerStatus) {
				a.LastPrivateKeyHash = "other"
			},
			expIsRegistered: false,
		},
		{
			status:          func(a *v1.ACMEIssuerStatus) {},
			expIsRegistered: true,
		},
	} {
		t.Run(fmt.Sprintf("item-%d", i), func(t *testing.T) {
			statusCopy := *status
			tt.status(&statusCopy)
			isRegistered := ri.IsRegistered(&statusCopy)
			require.Equal(t, tt.expIsRegistered, isRegistered)
		})
	}
}

func Test_Register(t *testing.T) {
	runFunc := func(fn func(a *acmeapi.Account) error) func(a *acmeapi.Account) error {
		if fn == nil {
			return func(a *acmeapi.Account) error {
				return nil
			}
		}
		return fn
	}
	type testCase struct {
		fakeRegister     func(*acmeapi.Account) error
		fakeGetReg       func(*acmeapi.Account) error
		fakeUpdateReg    func(*acmeapi.Account) error
		expRegisterCount int
		expGetCount      int
		expUpdateCount   int
	}
	for i, tt := range []testCase{
		// Normal case, a new account is registered
		{
			expRegisterCount: 1,
			expGetCount:      0,
			expUpdateCount:   0,
		},
		// The account was already registered, GetReg is called
		{
			fakeRegister: func(a *acmeapi.Account) error {
				return acmeapi.ErrAccountAlreadyExists
			},
			expRegisterCount: 1,
			expGetCount:      1,
			expUpdateCount:   0,
		},
		// The returned account is missing the email, UpdateReg is called
		{
			fakeRegister: func(a *acmeapi.Account) error {
				a.Contact = nil
				return nil
			},
			expRegisterCount: 1,
			expGetCount:      0,
			expUpdateCount:   1,
		},
		// The account was already registered and is missing the email,
		// both GetReg and UpdateReg are called
		{
			fakeRegister: func(a *acmeapi.Account) error {
				return acmeapi.ErrAccountAlreadyExists
			},
			fakeGetReg: func(a *acmeapi.Account) error {
				a.Contact = nil
				return nil
			},
			expRegisterCount: 1,
			expGetCount:      1,
			expUpdateCount:   1,
		},
	} {
		t.Run(fmt.Sprintf("item-%d", i), func(t *testing.T) {
			ri, _, expStatus := testSetup(t)
			var registerCount atomic.Int32
			var getCount atomic.Int32
			var updateCount atomic.Int32
			fakeAccount := acmeapi.Account{
				URI:     expStatus.URI,
				Contact: []string{fmt.Sprintf("mailto:%s", strings.ToLower(ri.Email))},
			}
			status, err := ri.Register(context.Background(), func(options NewClientOptions) client.Interface {
				return &client.FakeACME{
					FakeRegister: func(ctx context.Context, a *acmeapi.Account, prompt func(tosURL string) bool) (*acmeapi.Account, error) {
						registerCount.Add(1)
						acc := fakeAccount
						return &acc, runFunc(tt.fakeRegister)(&acc)
					},
					FakeGetReg: func(ctx context.Context, url string) (*acmeapi.Account, error) {
						getCount.Add(1)
						acc := fakeAccount
						return &acc, runFunc(tt.fakeGetReg)(&acc)
					},
					FakeUpdateReg: func(ctx context.Context, a *acmeapi.Account) (*acmeapi.Account, error) {
						updateCount.Add(1)
						acc := fakeAccount
						return &acc, runFunc(tt.fakeUpdateReg)(&acc)
					},
				}
			}, nil)
			require.NoError(t, err)
			require.Equal(t, expStatus, status)
			require.Equal(t, tt.expRegisterCount, int(registerCount.Load()))
			require.Equal(t, tt.expGetCount, int(getCount.Load()))
			require.Equal(t, tt.expUpdateCount, int(updateCount.Load()))
		})
	}
}
