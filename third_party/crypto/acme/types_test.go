// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package acme

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestRateLimit(t *testing.T) {
	now := time.Date(2017, 04, 27, 10, 0, 0, 0, time.UTC)
	f := timeNow
	defer func() { timeNow = f }()
	timeNow = func() time.Time { return now }

	h120, hTime := http.Header{}, http.Header{}
	h120.Set("Retry-After", "120")
	hTime.Set("Retry-After", "Tue Apr 27 11:00:00 2017")

	err1 := &Error{
		Type:   "urn:ietf:params:acme:error:nolimit",
		Header: h120,
	}
	err2 := &Error{
		Type:   "urn:ietf:params:acme:error:rateLimited",
		Header: h120,
	}
	err3 := &Error{
		Type:   "urn:ietf:params:acme:error:rateLimited",
		Header: nil,
	}
	err4 := &Error{
		Type:   "urn:ietf:params:acme:error:rateLimited",
		Header: hTime,
	}

	tt := []struct {
		err error
		res time.Time
		ok  bool
	}{
		{},
		{err: errors.New("dummy")},
		{err: err1},
		{err: err2, res: now.Add(2 * time.Minute), ok: true},
		{err: err3, ok: true},
		{err: err4, res: now.Add(time.Hour), ok: true},
	}
	for i, test := range tt {
		res, ok := RateLimit(test.err)
		if ok != test.ok {
			t.Errorf("%d: RateLimit(%+v): ok = %v; want %v", i, test.err, ok, test.ok)
			continue
		}
		if !res.Equal(test.res) {
			t.Errorf("%d: RateLimit(%+v) = %v; want %v", i, test.err, res, test.res)
		}
	}
}
