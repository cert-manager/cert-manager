/*
Copyright 2026 The cert-manager Authors.

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
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestTokenCache_IsValid(t *testing.T) {
	tests := []struct {
		name      string
		setupFn   func(*tokenCache)
		wantValid bool
	}{
		{
			name:      "empty cache is invalid",
			setupFn:   func(*tokenCache) {},
			wantValid: false,
		},
		{
			name: "cache with future expiry is valid",
			setupFn: func(tc *tokenCache) {
				tc.set("mytoken", time.Now().Add(time.Hour))
			},
			wantValid: true,
		},
		{
			name: "cache with past expiry is invalid",
			setupFn: func(tc *tokenCache) {
				tc.set("mytoken", time.Now().Add(-time.Second))
			},
			wantValid: false,
		},
		{
			name: "empty token is always invalid even with future expiry",
			setupFn: func(tc *tokenCache) {
				tc.set("", time.Now().Add(time.Hour))
			},
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &tokenCache{}
			tt.setupFn(tc)
			if got := tc.isValid(); got != tt.wantValid {
				t.Errorf("isValid() = %v, want %v", got, tt.wantValid)
			}
		})
	}
}

func TestTokenCache_GetSet(t *testing.T) {
	tc := &tokenCache{}
	token := "abc123"
	expiry := time.Now().Add(time.Hour).Truncate(time.Second)

	tc.set(token, expiry)
	gotToken, gotExpiry := tc.get()

	if gotToken != token {
		t.Errorf("get() token = %q, want %q", gotToken, token)
	}
	if !gotExpiry.Equal(expiry) {
		t.Errorf("get() expiry = %v, want %v", gotExpiry, expiry)
	}
}

func TestAuthFailedError_ErrorAndUnwrap(t *testing.T) {
	underlying := fmt.Errorf("401 Unauthorized")
	err := AuthFailedError{Err: underlying}

	if err.Error() != "OAuth token request failed: 401 Unauthorized" {
		t.Errorf("Error() = %q", err.Error())
	}
	if !errors.Is(err, underlying) {
		t.Error("errors.Is should find underlying error through Unwrap chain")
	}

	var authErr AuthFailedError
	wrapped := fmt.Errorf("client.VerifyCredentials: %w", err)
	if !errors.As(wrapped, &authErr) {
		t.Error("errors.As should find AuthFailedError through wrapping chain")
	}
}

func TestIsNetworkError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil is not a network error",
			err:  nil,
			want: false,
		},
		{
			name: "plain fmt.Errorf is not a network error",
			err:  fmt.Errorf("401 Unauthorized"),
			want: false,
		},
		{
			name: "AuthFailedError is not a network error",
			err:  AuthFailedError{Err: fmt.Errorf("bad creds")},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNetworkError(tt.err); got != tt.want {
				t.Errorf("isNetworkError() = %v, want %v", got, tt.want)
			}
		})
	}
}
