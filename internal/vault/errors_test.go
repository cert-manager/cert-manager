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

package vault

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	vault "github.com/hashicorp/vault/api"

	cmerrors "github.com/cert-manager/cert-manager/pkg/util/errors"
)

// sentinel is a string which must never be copied into an Issuer status
// condition. It stands in for whatever an endpoint which is not Vault happens
// to reflect back at us.
const sentinel = "SENSITIVE-RESPONSE-BODY"

func TestSafeErrorMessage(t *testing.T) {
	tests := map[string]struct {
		err error

		// want asserts on the whole message, wantContains on a substring.
		want         string
		wantContains string
	}{
		"a local error is reflected verbatim": {
			err:  errors.New("error initializing Vault client: parse \" https://vault.example.com\": first path segment in URL cannot contain colon"),
			want: "error initializing Vault client: parse \" https://vault.example.com\": first path segment in URL cannot contain colon",
		},
		"a raw response body is omitted": {
			err: &vault.ResponseError{
				StatusCode: 500,
				RawError:   true,
				Errors:     []string{sentinel},
			},
			want: fmt.Sprintf(messageTemplateNonVaultErrorResponse, 500),
		},
		"a raw response body is omitted when the error has been wrapped": {
			err: fmt.Errorf("error calling Vault server: %w", &vault.ResponseError{
				StatusCode: 302,
				RawError:   true,
				Errors:     []string{sentinel},
			}),
			want: fmt.Sprintf(messageTemplateNonVaultErrorResponse, 302),
		},
		"a Vault error response is reflected": {
			err: &vault.ResponseError{
				StatusCode: 403,
				Errors:     []string{"permission denied"},
			},
			wantContains: "permission denied",
		},
		"a wrapped Vault error response keeps the context it was wrapped with": {
			err: fmt.Errorf("error logging in to Vault server: %w", &vault.ResponseError{
				StatusCode: 400,
				Errors:     []string{"invalid role ID"},
			}),
			wantContains: "error logging in to Vault server: ",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := SafeErrorMessage(test.err)

			if strings.Contains(got, sentinel) {
				t.Errorf("SafeErrorMessage() = %q, which leaks the response body", got)
			}
			if len(got) > maxVaultErrorMessageLength {
				t.Errorf("message is %d bytes, want at most %d", len(got), maxVaultErrorMessageLength)
			}

			switch {
			case test.want != "":
				if got != test.want {
					t.Errorf("SafeErrorMessage() = %q, want %q", got, test.want)
				}
			case test.wantContains != "":
				if !strings.Contains(got, test.wantContains) {
					t.Errorf("SafeErrorMessage() = %q, want it to contain %q", got, test.wantContains)
				}
			}
		})
	}
}

func TestSafeErrorMessageBoundsLength(t *testing.T) {
	// Even a genuine Vault server must not be able to fill the Issuer status,
	// which is persisted to the API server.
	err := &vault.ResponseError{
		StatusCode: 403,
		Errors:     []string{strings.Repeat("a", 4*maxVaultErrorMessageLength)},
	}

	got := SafeErrorMessage(err)
	if !strings.HasSuffix(got, cmerrors.TruncationMarker) {
		t.Errorf("SafeErrorMessage() = %q, want it to be marked as truncated", got)
	}
	if len(got) > maxVaultErrorMessageLength {
		t.Errorf("message is %d bytes, want at most %d", len(got), maxVaultErrorMessageLength)
	}
}

func TestSanitizeError(t *testing.T) {
	rawResponse := &vault.ResponseError{
		StatusCode: 500,
		RawError:   true,
		Errors:     []string{sentinel},
	}

	tests := map[string]struct {
		err error

		// wantUnchanged asserts that the same error is handed straight back,
		// which matters for the callers that match on it without errors.As.
		wantUnchanged bool
		wantMessage   string
	}{
		"a nil error stays nil": {
			err:           nil,
			wantUnchanged: true,
		},
		"a local error is left alone": {
			err:           errors.New("error initializing Vault client: unable to load credentials"),
			wantUnchanged: true,
		},
		"an invalid data error is left alone so that IsInvalidData still matches": {
			err:           cmerrors.NewInvalidData("no data for %q in secret", "key1"),
			wantUnchanged: true,
		},
		"a Vault error response short enough to reflect is left alone": {
			err: &vault.ResponseError{
				StatusCode: 403,
				Errors:     []string{"permission denied"},
			},
			wantUnchanged: true,
		},
		"a raw response body is replaced": {
			err:         rawResponse,
			wantMessage: fmt.Sprintf(messageTemplateNonVaultErrorResponse, 500),
		},
		"a raw response body is replaced when the error has been wrapped": {
			err:         fmt.Errorf("failed to sign certificate by vault: %w", rawResponse),
			wantMessage: fmt.Sprintf(messageTemplateNonVaultErrorResponse, 500),
		},
		"an oversized Vault error response is truncated": {
			err: &vault.ResponseError{
				StatusCode: 403,
				Errors:     []string{strings.Repeat("a", 4*maxVaultErrorMessageLength)},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := sanitizeError(test.err)

			if test.wantUnchanged {
				if got != test.err {
					t.Fatalf("sanitizeError() = %v, want the error to be handed back unchanged", got)
				}

				return
			}

			if strings.Contains(got.Error(), sentinel) {
				t.Errorf("sanitizeError() = %q, which leaks the response body", got)
			}
			if len(got.Error()) > maxVaultErrorMessageLength {
				t.Errorf("message is %d bytes, want at most %d", len(got.Error()), maxVaultErrorMessageLength)
			}
			if test.wantMessage != "" && got.Error() != test.wantMessage {
				t.Errorf("sanitizeError() = %q, want %q", got, test.wantMessage)
			}

			// The original has to stay reachable, both for the logs and for the
			// callers that match on what the server returned.
			if !strings.Contains(LoggableErrorMessage(got), test.err.Error()) {
				t.Errorf("LoggableErrorMessage() = %q, want it to keep the original error", LoggableErrorMessage(got))
			}
			if _, ok := errors.AsType[*vault.ResponseError](got); !ok {
				t.Error("sanitizeError() returned an error that errors.As can no longer unwrap to a *vault.ResponseError")
			}
		})
	}
}

func TestSanitizeErrorKeepsInvalidDataMatchable(t *testing.T) {
	// cmerrors.IsInvalidData type-asserts rather than using errors.As, so an
	// invalid data error must never be wrapped on its way out of this package.
	// The signing controller relies on this to decide not to retry.
	err := sanitizeError(cmerrors.NewInvalidData("no data for %q in secret", "key1"))

	if !cmerrors.IsInvalidData(err) {
		t.Errorf("IsInvalidData() = false for %v, want true", err)
	}
}

func TestLoggableErrorMessageBoundsLength(t *testing.T) {
	// The logs are allowed to carry the response body, but an unbounded body
	// must not be able to flood them.
	err := &vault.ResponseError{
		StatusCode: 500,
		RawError:   true,
		Errors:     []string{strings.Repeat("a", 4*maxVaultErrorLogLength)},
	}

	got := LoggableErrorMessage(err)
	if !strings.HasSuffix(got, cmerrors.TruncationMarker) {
		t.Errorf("LoggableErrorMessage() = %q, want it to be marked as truncated", got)
	}
	if len(got) > maxVaultErrorLogLength {
		t.Errorf("message is %d bytes, want at most %d", len(got), maxVaultErrorLogLength)
	}
}
