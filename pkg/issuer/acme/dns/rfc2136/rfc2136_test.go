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

package rfc2136

import (
	"context"
	"strings"
	"testing"

	"k8s.io/klog/v2/ktesting"

	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// captureLogs returns a context carrying a buffering logger and a function that
// returns everything logged through it so far.
func captureLogs(t *testing.T) (context.Context, func() string) {
	t.Helper()

	logger := ktesting.NewLogger(t, ktesting.NewConfig(ktesting.BufferLogs(true)))
	underlier, ok := logger.GetSink().(ktesting.Underlier)
	if !ok {
		t.Fatal("ktesting logger does not implement ktesting.Underlier")
	}

	return logf.NewContext(t.Context(), logger), func() string {
		return underlier.GetBuffer().String()
	}
}

func TestNewDNSProviderCredentials_DeprecatedTSIGAlgorithmWarning(t *testing.T) {
	tests := map[string]struct {
		tsigAlgorithm string
		tsigKeyName   string
		tsigSecret    string
		wantMessage   string
	}{
		"defaulted algorithm warns": {
			tsigKeyName: "key",
			tsigSecret:  "secret",
			wantMessage: defaultedTSIGAlgorithmMessage,
		},
		"explicit HMACMD5 warns": {
			tsigAlgorithm: "HMACMD5",
			tsigKeyName:   "key",
			tsigSecret:    "secret",
			wantMessage:   deprecatedTSIGAlgorithmMessage,
		},
		"explicit HMACSHA1 warns": {
			tsigAlgorithm: "hmacsha1",
			tsigKeyName:   "key",
			tsigSecret:    "secret",
			wantMessage:   deprecatedTSIGAlgorithmMessage,
		},
		"supported algorithm does not warn": {
			tsigAlgorithm: "HMACSHA256",
			tsigKeyName:   "key",
			tsigSecret:    "secret",
		},
		"TSIG disabled does not warn": {},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, logs := captureLogs(t)

			if _, err := NewDNSProviderCredentials(ctx, "127.0.0.1", tt.tsigAlgorithm, tt.tsigKeyName, tt.tsigSecret); err != nil {
				t.Fatalf("NewDNSProviderCredentials() error = %v", err)
			}

			got := logs()
			if tt.wantMessage == "" {
				if strings.Contains(got, "deprecated") {
					t.Errorf("expected no deprecation warning, got:\n%s", got)
				}
				return
			}
			if !strings.Contains(got, tt.wantMessage) {
				t.Errorf("expected log to contain %q, got:\n%s", tt.wantMessage, got)
			}
		})
	}
}
