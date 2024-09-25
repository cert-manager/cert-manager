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

package util

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/rest"
)

func Test_RestConfigWithUserAgent(t *testing.T) {
	AppGitCommit = "test-commit"

	tests := map[string]struct {
		component     []string
		expRestConfig rest.Config
	}{
		"if no component name given, expect just cert-manager field manager": {
			component: nil,
			expRestConfig: rest.Config{
				UserAgent: "cert-manager/canary-test-commit (" + runtime.GOOS + "/" + runtime.GOARCH + ") cert-manager/test-commit",
			},
		},
		"if single component name given, expect cert-manager with single component field manager": {
			component: []string{"controller"},
			expRestConfig: rest.Config{
				UserAgent: "cert-manager-controller/canary-test-commit (" + runtime.GOOS + "/" + runtime.GOARCH + ") cert-manager/test-commit",
			},
		},
		"if multiple component names given, expect cert-manager with multiple component field manager": {
			component: []string{"controller", "issuing-foo", "bar"},
			expRestConfig: rest.Config{
				UserAgent: "cert-manager-controller-issuing-foo-bar/canary-test-commit (" + runtime.GOOS + "/" + runtime.GOARCH + ") cert-manager/test-commit",
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gotRestConfig := RestConfigWithUserAgent(new(rest.Config), test.component...)
			assert.Equal(t, &test.expRestConfig, gotRestConfig)
		})
	}
}

// Adapted from
// https://github.com/kubernetes/apiserver/blob/cecf3a2e57ffdfa8f3b36db4ee0c44e59ad656e9/pkg/endpoints/handlers/create_test.go#L24
func Test_PrefixFromUserAgent(t *testing.T) {
	tests := map[string]struct {
		userAgent string
		expPrefix string
	}{
		"typical user agent with '/'": {
			userAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36",
			expPrefix: "Mozilla",
		},
		"a long user agent with '/'": {
			userAgent: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff/Something",
			expPrefix: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		},
		"a user agent that exceeds the maximum rune length should be shortened": {
			userAgent: "🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔",
			expPrefix: "🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔🍔",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.expPrefix, PrefixFromUserAgent(test.userAgent), test.userAgent)
		})
	}
}
