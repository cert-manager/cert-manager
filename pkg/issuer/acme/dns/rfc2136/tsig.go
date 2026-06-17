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
	"crypto/md5"  // #nosec G501 -- MD5 is a supported TSIG Algorithm
	"crypto/sha1" // #nosec G505 -- SHA1 is a supported TSIG Algorithm
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"

	"github.com/miekg/dns"
)

// The code in this file is largely copied from https://github.com/miekg/dns/blob/v1.1.47/tsig.go

// tsigHMACProvider is our implementation of github.com/miekg/dns.TsigProvider interface
// that also supports HMACMD5 as a TSIG algorithm, which is no longer supported
// by the default TsigProvider implementation in github.com/miekg/dns.
// For context see the discussion on https://github.com/cert-manager/cert-manager/pull/4942
type tsigHMACProvider string

var _ dns.TsigProvider = tsigHMACProvider("")

// Generate is a largely copied from
// github.com/miekg/dns.tsigHMACProvider.Generate
// https://github.com/miekg/dns/blob/v1.1.47/tsig.go#L37-L60
func (key tsigHMACProvider) Generate(msg []byte, t *dns.TSIG) ([]byte, error) {
	rawsecret, err := fromBase64([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("error decoding the provided TSIG secret: %w", err)
	}
	var h hash.Hash
	switch dns.CanonicalName(t.Algorithm) {
	case dns.HmacSHA1:
		h = hmac.New(sha1.New, rawsecret)
	case dns.HmacSHA224:
		h = hmac.New(sha256.New224, rawsecret)
	case dns.HmacSHA256:
		h = hmac.New(sha256.New, rawsecret)
	case dns.HmacSHA384:
		h = hmac.New(sha512.New384, rawsecret)
	case dns.HmacSHA512:
		h = hmac.New(sha512.New, rawsecret)
	case dns.HmacMD5:
		h = hmac.New(md5.New, rawsecret)
	default:
		return nil, dns.ErrKeyAlg
	}
	_, err = h.Write(msg)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// Verify is copied from github.com/miekg/dns.tsigHMACProvider.Verify
// https://github.com/miekg/dns/blob/v1.1.47/tsig.go#L62-L75
func (key tsigHMACProvider) Verify(msg []byte, t *dns.TSIG) error {
	b, err := key.Generate(msg, t)
	if err != nil {
		return err
	}
	mac, err := hex.DecodeString(t.MAC)
	if err != nil {
		return err
	}
	if !hmac.Equal(b, mac) {
		return dns.ErrSig
	}
	return nil
}

func fromBase64(s []byte) ([]byte, error) {
	buflen := base64.StdEncoding.DecodedLen(len(s))
	buf := make([]byte, buflen)
	n, err := base64.StdEncoding.Decode(buf, s)
	buf = buf[:n]
	return buf, err
}
