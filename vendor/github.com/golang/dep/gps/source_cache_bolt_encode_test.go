// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gps

import (
	"bytes"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
)

func TestPropertiesFromCache(t *testing.T) {
	for _, test := range []struct {
		name string
		ip   ProjectRoot
		pp   ProjectProperties
	}{
		{"defaultBranch",
			"root", ProjectProperties{"", newDefaultBranch("test")}},
		{"branch",
			"root", ProjectProperties{"source", NewBranch("test")}},
		{"semver",
			"root", ProjectProperties{"", testSemverConstraint(t, "^1.0.0")}},
		{"rev",
			"root", ProjectProperties{"source", Revision("test")}},
		{"any",
			"root", ProjectProperties{"source", Any()}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var buf projectPropertiesMsgs
			buf.copyFrom(test.ip, test.pp)
			v, err := proto.Marshal(&buf.pp)
			if err != nil {
				t.Fatal(err)
			}

			if err := proto.Unmarshal(v, &buf.pp); err != nil {
				t.Fatal(err)
			} else {
				ip, pp, err := propertiesFromCache(&buf.pp)
				if err != nil {
					t.Fatal(err)
				}
				if ip != test.ip {
					t.Errorf("decoded unexpected ProjectRoot:\n\t(GOT): %#v\n\t(WNT): %#v", ip, test.ip)
				}
				if pp.Source != test.pp.Source {
					t.Errorf("decoded unexpected ProjectRoot.Source:\n\t(GOT): %s\n\t (WNT): %s", pp.Source, test.pp.Source)
				}
				if !pp.Constraint.identical(test.pp.Constraint) {
					t.Errorf("decoded non-identical ProjectRoot.Constraint:\n\t(GOT): %#v\n\t(WNT): %#v", pp.Constraint, test.pp.Constraint)
				}
			}
		})
	}
}

func TestCacheTimestampedKey(t *testing.T) {
	pre := byte('p')
	for _, test := range []struct {
		ts     time.Time
		suffix []byte
	}{
		{time.Unix(0, 0), []byte{0, 0, 0, 0, 0, 0, 0, 0}},
		{time.Unix(100, 0), []byte{0, 0, 0, 0, 0, 0, 0, 100}},
		{time.Unix(255, 0), []byte{0, 0, 0, 0, 0, 0, 0, 255}},
		{time.Unix(1+1<<8+1<<16+1<<24, 0), []byte{0, 0, 0, 0, 1, 1, 1, 1}},
		{time.Unix(255<<48, 0), []byte{0, 255, 0, 0, 0, 0, 0, 0}},
	} {
		b := cacheTimestampedKey(pre, test.ts)
		if !bytes.Equal(b, append([]byte{pre}, test.suffix...)) {
			t.Errorf("unexpected suffix:\n\t(GOT):%v\n\t(WNT):%v", b[4:], test.suffix)
		}
	}
}
