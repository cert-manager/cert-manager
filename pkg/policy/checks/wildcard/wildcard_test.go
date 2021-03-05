/*
Copyright 2021 The cert-manager Authors.

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

package wildcard

import (
	"fmt"
	"testing"
)

func TestSubset(t *testing.T) {
	tests := []struct {
		patterns []string
		texts    []string
		exp      bool
	}{
		{
			patterns: []string{},
			texts:    []string{},
			exp:      true,
		},
		{
			patterns: []string{
				"cert-manager",
			},
			texts: []string{
				"cert-manager",
			},
			exp: true,
		},
		{
			patterns: []string{
				"cert-manager",
				"foo",
			},
			texts: []string{
				"cert-manager",
			},
			exp: true,
		},
		{
			patterns: []string{
				"cert-manager",
			},
			texts: []string{
				"cert-manager",
				"foo",
			},
			exp: false,
		},
		{
			patterns: []string{
				"foo",
				"cert-manager",
				"bar",
			},
			texts: []string{
				"cert-manager",
				"foo",
			},
			exp: true,
		},
		{
			patterns: []string{
				"foo",
				"cert-*",
				"bar",
			},
			texts: []string{
				"cert-manager",
				"foo",
			},
			exp: true,
		},
		{
			patterns: []string{
				"*",
			},
			texts: []string{
				"cert-manager",
				"foo",
			},
			exp: true,
		},
		{
			patterns: []string{
				"foo.*",
			},
			texts: []string{
				"cert-manager",
				"foo.",
			},
			exp: false,
		},
		{
			patterns: []string{
				"foo.*",
			},
			texts: []string{
				"foo.cert-manager",
				"foo.",
			},
			exp: true,
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%v: %v", test.patterns, test.texts), func(t *testing.T) {
			if match := Subset(test.patterns, test.texts); match != test.exp {
				t.Errorf("unexpected subset (%v, %v): exp=%t got=%t",
					test.patterns, test.texts, test.exp, match)
			}
		})
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		patterns []string
		text     string
		exp      bool
	}{
		{
			patterns: []string{},
			text:     "cert-manager",
			exp:      false,
		},
		{
			patterns: []string{
				"cert-manager",
			},
			text: "cert-manager",
			exp:  true,
		},
		{
			patterns: []string{
				"",
			},
			text: "",
			exp:  true,
		},
		{
			patterns: []string{
				"cert-manager",
				"foo",
			},
			text: "cert-manager",
			exp:  true,
		},
		{
			patterns: []string{
				"foo",
				"cert-manager",
			},
			text: "cert-manager",
			exp:  true,
		},
		{
			patterns: []string{
				"foo",
				"cert-*",
			},
			text: "cert-manager",
			exp:  true,
		},
		{
			patterns: []string{
				"foo",
				"cert-*manager",
			},
			text: "cert-manager",
			exp:  true,
		},
		{
			patterns: []string{
				"foo",
				"cert-m*",
			},
			text: "cert-",
			exp:  false,
		},
		{
			patterns: []string{
				"foo",
				"cert-manager",
			},
			text: "bar",
			exp:  false,
		},
		{
			patterns: []string{
				"foo",
				"*",
			},
			text: "bar",
			exp:  true,
		},
		{
			patterns: []string{
				"foo",
				"",
			},
			text: "bar",
			exp:  false,
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%v: %s", test.patterns, test.text), func(t *testing.T) {
			if match := Contains(test.patterns, test.text); match != test.exp {
				t.Errorf("unexpected contains (%v, %q): exp=%t got=%t",
					test.patterns, test.text, test.exp, match)
			}
		})
	}
}

func TestMatchs(t *testing.T) {
	tests := map[string]struct {
		pattern string
		text    string
		exp     bool
	}{
		"only wildcard pattern: true": {
			pattern: "*",
			text:    "cert-manager",
			exp:     true,
		},
		"empty pattern: false": {
			pattern: "",
			text:    "cert-manager",
			exp:     false,
		},
		"empty pattern and text: true": {
			pattern: "",
			text:    "",
			exp:     true,
		},
		"short parrten with wildcard: true": {
			pattern: "cert-*",
			text:    "cert-manager.io",
			exp:     true,
		},
		"bigger pattern: false": {
			pattern: "cert-manager-foo",
			text:    "cert-manager",
			exp:     false,
		},
		"same pattern and text: true": {
			pattern: "cert-manager",
			text:    "cert-manager",
			exp:     true,
		},
		"same pattern with wildcard: true": {
			pattern: "cert-manager.io*",
			text:    "cert-manager.io",
			exp:     true,
		},
		"same pattern with wildcard at start: true": {
			pattern: "*cert-manager.io",
			text:    "cert-manager.io",
			exp:     true,
		},
		"same pattern with middle wildcard: true": {
			pattern: "cert-*manager.io",
			text:    "cert-manager.io",
			exp:     true,
		},
		"wrong pattern with wildcard: false": {
			pattern: "cert-foo*",
			text:    "cert-manager.io",
			exp:     false,
		},
		"pattren with wildcards inside: true": {
			pattern: "ce*t-*ger*io",
			text:    "cert-manager.io",
			exp:     true,
		},
		"pattern with wildcards inside but short: false": {
			pattern: "ce*t-*ger*.",
			text:    "cert-manager.io",
			exp:     false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if match := Matchs(test.pattern, test.text); match != test.exp {
				t.Errorf("unexpected match (%q, %q): exp=%t got=%t",
					test.pattern, test.text, test.exp, match)
			}
		})
	}
}
