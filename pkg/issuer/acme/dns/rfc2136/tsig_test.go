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

// Package rfc2136 implements a DNS provider for solving the DNS-01 challenge
// using the rfc2136 dynamic update.

package rfc2136

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func Test_tsigHMACProvider_Generate(t *testing.T) {
	var (
		someSecret        = base64.StdEncoding.EncodeToString(([]byte("foo-secret")))
		someMessage       = "foo-message"
		someMessageMD5    = md5Message(t, []byte("foo-secret"), []byte("foo-message"))
		someMessageSHA1   = sha1Message(t, []byte("foo-secret"), []byte("foo-message"))
		someMessageSHA224 = sha224Message(t, []byte("foo-secret"), []byte("foo-message"))
		someMessageSHA384 = sha384Message(t, []byte("foo-secret"), []byte("foo-message"))
		someMessageSHA256 = sha256Message(t, []byte("foo-secret"), []byte("foo-message"))
		someMessageSHA512 = sha512Message(t, []byte("foo-secret"), []byte("foo-message"))
	)
	tests := map[string]struct {
		key     tsigHMACProvider
		msg     []byte
		tsig    *dns.TSIG
		want    []byte
		wantErr bool
	}{
		"message gets signed with HMACMD5": {
			key:  tsigHMACProvider(someSecret),
			msg:  []byte(someMessage),
			tsig: &dns.TSIG{Algorithm: dns.HmacMD5},
			want: someMessageMD5,
		},
		"message gets signed with HMACSHA1": {
			key:  tsigHMACProvider(someSecret),
			msg:  []byte(someMessage),
			tsig: &dns.TSIG{Algorithm: dns.HmacSHA1},
			want: someMessageSHA1,
		},
		"message gets signed with HMACSHA224": {
			key:  tsigHMACProvider(someSecret),
			msg:  []byte(someMessage),
			tsig: &dns.TSIG{Algorithm: dns.HmacSHA224},
			want: someMessageSHA224,
		},
		"message gets signed with HMACSHA384": {
			key:  tsigHMACProvider(someSecret),
			msg:  []byte(someMessage),
			tsig: &dns.TSIG{Algorithm: dns.HmacSHA384},
			want: someMessageSHA384,
		},
		"message gets signed with HMACSHA256": {
			key:  tsigHMACProvider(someSecret),
			msg:  []byte(someMessage),
			tsig: &dns.TSIG{Algorithm: dns.HmacSHA256},
			want: someMessageSHA256,
		},
		"message gets signed with HMAC512": {
			key:  tsigHMACProvider(someSecret),
			msg:  []byte(someMessage),
			tsig: &dns.TSIG{Algorithm: dns.HmacSHA512},
			want: someMessageSHA512,
		},
		"unknown algorithm value results in an error": {
			key:     tsigHMACProvider(someSecret),
			tsig:    &dns.TSIG{Algorithm: "xyz"},
			wantErr: true,
		},
		"secret that isn't base64 results in an error": {
			key:     tsigHMACProvider("foo"),
			wantErr: true,
		},
	}
	for name, scenario := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := scenario.key.Generate(scenario.msg, scenario.tsig)
			if (err != nil) != scenario.wantErr {
				t.Errorf("tsigHMACProvider.Generate() error = %v, wantErr %v", err, scenario.wantErr)
			}
			assert.Equalf(t, got, scenario.want, "tsigHMACProvider.Generate() = %v, want %v", got, scenario.want)
			// if !reflect.DeepEqual(got, scenario.want) {
			// 	t.Errorf("tsigHMACProvider.Generate() = %v, want %v", got, scenario.want)
			// }
		})
	}
}

func md5Message(t *testing.T, secret []byte, message []byte) []byte {
	t.Helper()
	h := hmac.New(md5.New, secret)
	_, err := h.Write(message)
	assert.NoError(t, err)
	return h.Sum(nil)
}

func sha1Message(t *testing.T, secret []byte, message []byte) []byte {
	t.Helper()
	h := hmac.New(sha1.New, secret)
	_, err := h.Write(message)
	assert.NoError(t, err)
	return h.Sum(nil)
}

func sha224Message(t *testing.T, secret []byte, message []byte) []byte {
	t.Helper()
	h := hmac.New(sha256.New224, secret)
	_, err := h.Write(message)
	assert.NoError(t, err)
	return h.Sum(nil)
}

func sha384Message(t *testing.T, secret []byte, message []byte) []byte {
	t.Helper()
	h := hmac.New(sha512.New384, secret)
	_, err := h.Write(message)
	assert.NoError(t, err)
	return h.Sum(nil)
}

func sha256Message(t *testing.T, secret []byte, message []byte) []byte {
	t.Helper()
	h := hmac.New(sha256.New, secret)
	_, err := h.Write(message)
	assert.NoError(t, err)
	return h.Sum(nil)
}

func sha512Message(t *testing.T, secret []byte, message []byte) []byte {
	t.Helper()
	h := hmac.New(sha512.New, secret)
	_, err := h.Write(message)
	assert.NoError(t, err)
	return h.Sum(nil)
}
