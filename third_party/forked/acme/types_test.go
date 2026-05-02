// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package acme

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestExternalAccountBindingString(t *testing.T) {
	eab := ExternalAccountBinding{
		KID: "kid",
		Key: []byte("key"),
	}
	got := eab.String()
	want := `&{KID: "kid", Key: redacted}`
	if got != want {
		t.Errorf("eab.String() = %q, want: %q", got, want)
	}
}

func TestRateLimit(t *testing.T) {
	now := time.Date(2017, 04, 27, 10, 0, 0, 0, time.UTC)
	f := timeNow
	defer func() { timeNow = f }()
	timeNow = func() time.Time { return now }

	h120, hTime := http.Header{}, http.Header{}
	h120.Set("Retry-After", "120")
	hTime.Set("Retry-After", "Tue Apr 27 11:00:00 2017")

	err1 := &Error{
		ProblemType: "urn:ietf:params:acme:error:nolimit",
		Header:      h120,
	}
	err2 := &Error{
		ProblemType: "urn:ietf:params:acme:error:rateLimited",
		Header:      h120,
	}
	err3 := &Error{
		ProblemType: "urn:ietf:params:acme:error:rateLimited",
		Header:      nil,
	}
	err4 := &Error{
		ProblemType: "urn:ietf:params:acme:error:rateLimited",
		Header:      hTime,
	}

	tt := []struct {
		err error
		res time.Duration
		ok  bool
	}{
		{nil, 0, false},
		{errors.New("dummy"), 0, false},
		{err1, 0, false},
		{err2, 2 * time.Minute, true},
		{err3, 0, true},
		{err4, time.Hour, true},
	}
	for i, test := range tt {
		res, ok := RateLimit(test.err)
		if ok != test.ok {
			t.Errorf("%d: RateLimit(%+v): ok = %v; want %v", i, test.err, ok, test.ok)
			continue
		}
		if res != test.res {
			t.Errorf("%d: RateLimit(%+v) = %v; want %v", i, test.err, res, test.res)
		}
	}
}

func TestAuthorizationError(t *testing.T) {
	tests := []struct {
		desc string
		err  *AuthorizationError
		msg  string
	}{
		{
			desc: "when auth error identifier is set",
			err: &AuthorizationError{
				Identifier: "domain.com",
				Errors: []error{
					(&wireError{
						Status: 403,
						Type:   "urn:ietf:params:acme:error:caa",
						Detail: "CAA record for domain.com prevents issuance",
					}).error(nil),
				},
			},
			msg: "acme: authorization error for domain.com: 403 urn:ietf:params:acme:error:caa: CAA record for domain.com prevents issuance",
		},

		{
			desc: "when auth error identifier is unset",
			err: &AuthorizationError{
				Errors: []error{
					(&wireError{
						Status: 403,
						Type:   "urn:ietf:params:acme:error:caa",
						Detail: "CAA record for domain.com prevents issuance",
					}).error(nil),
				},
			},
			msg: "acme: authorization error: 403 urn:ietf:params:acme:error:caa: CAA record for domain.com prevents issuance",
		},
	}

	for _, tt := range tests {
		if tt.err.Error() != tt.msg {
			t.Errorf("got: %s\nwant: %s", tt.err, tt.msg)
		}
	}
}

func TestSubproblems(t *testing.T) {
	tests := []struct {
		wire        wireError
		expectedOut Error
	}{
		{
			wire: wireError{
				Status: 1,
				Type:   "urn:error",
				Detail: "it's an error",
			},
			expectedOut: Error{
				StatusCode:  1,
				ProblemType: "urn:error",
				Detail:      "it's an error",
			},
		},
		{
			wire: wireError{
				Status: 1,
				Type:   "urn:error",
				Detail: "it's an error",
				Subproblems: []Subproblem{
					{
						Type:   "urn:error:sub",
						Detail: "it's a subproblem",
					},
				},
			},
			expectedOut: Error{
				StatusCode:  1,
				ProblemType: "urn:error",
				Detail:      "it's an error",
				Subproblems: []Subproblem{
					{
						Type:   "urn:error:sub",
						Detail: "it's a subproblem",
					},
				},
			},
		},
		{
			wire: wireError{
				Status: 1,
				Type:   "urn:error",
				Detail: "it's an error",
				Subproblems: []Subproblem{
					{
						Type:       "urn:error:sub",
						Detail:     "it's a subproblem",
						Identifier: &AuthzID{Type: "dns", Value: "example"},
					},
				},
			},
			expectedOut: Error{
				StatusCode:  1,
				ProblemType: "urn:error",
				Detail:      "it's an error",
				Subproblems: []Subproblem{
					{
						Type:       "urn:error:sub",
						Detail:     "it's a subproblem",
						Identifier: &AuthzID{Type: "dns", Value: "example"},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		out := tc.wire.error(nil)
		if !reflect.DeepEqual(*out, tc.expectedOut) {
			t.Errorf("Unexpected error: wanted %v, got %v", tc.expectedOut, *out)
		}
	}
}

func TestErrorStringerWithSubproblems(t *testing.T) {
	err := Error{
		StatusCode:  1,
		ProblemType: "urn:error",
		Detail:      "it's an error",
		Subproblems: []Subproblem{
			{
				Type:   "urn:error:sub",
				Detail: "it's a subproblem",
			},
			{
				Type:       "urn:error:sub",
				Detail:     "it's a subproblem",
				Identifier: &AuthzID{Type: "dns", Value: "example"},
			},
		},
	}
	expectedStr := "1 urn:error: it's an error; subproblems:\n\turn:error:sub: it's a subproblem\n\turn:error:sub: [dns: example] it's a subproblem"
	if err.Error() != expectedStr {
		t.Errorf("Unexpected error string: wanted %q, got %q", expectedStr, err.Error())
	}
}

func TestCertIDFromCertificate(t *testing.T) {
	certPEM := `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`

	ariCertID := "LoAHzycL0XaAXr7dXG9AN00KVlM.O15HnjLTbfcYa-3RajMqHXZCKBI"

	certPEMBlock, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(certPEMBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	got, err := CertificateARIID(cert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, ".") {
		t.Fatalf("expected dot-separated certID, got %q", got)
	}
	parts := strings.Split(got, ".")
	if len(parts) != 2 {
		t.Fatalf("expected 2 parts, got %d (%q)", len(parts), got)
	}
	// Ensure both parts are valid base64url (raw).
	if _, err := base64.RawURLEncoding.DecodeString(parts[0]); err != nil {
		t.Fatalf("AKI part not base64url: %v", err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(parts[1]); err != nil {
		t.Fatalf("serial part not base64url: %v", err)
	}

	if got != ariCertID {
		t.Fatalf("unexpected certID: got %q, want %q", got, ariCertID)
	}
}
