/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package test

import (
	"reflect"

	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/pkg/issuer"
)

// Ensure issuer response from test is nil.
func MustNoResponse(builder *testpkg.Builder, args ...interface{}) {
	resp, ok := args[0].(*issuer.IssueResponse)
	if !ok {
		builder.T.Errorf("unexpected argument to be of type IssuerResponse: %+v", args[0])
	}

	if resp != nil {
		builder.T.Errorf("unexpected response, exp='nil' got='%+v'", resp)
	}
}

// Ensure no private key exists in test response.
// Ensure no signed certificate or CA	certificate in test response.
func NoPrivateKeyFieldsSetCheck(expectedCA []byte) func(builder *testpkg.Builder, args ...interface{}) {
	return func(builder *testpkg.Builder, args ...interface{}) {
		resp := args[0].(*issuer.IssueResponse)

		if resp == nil {
			builder.T.Errorf("no response given, got=%s", resp)
			return
		}

		if len(resp.PrivateKey) > 0 {
			builder.T.Errorf("expected no new private key to be generated but got: %s",
				resp.PrivateKey)
		}

		CertificatesFieldsSetCheck(expectedCA)(builder, args...)
	}
}

// Ensure no signed certificate or CA	certificate in test response.
func CertificatesFieldsSetCheck(expectedCA []byte) func(builder *testpkg.Builder, args ...interface{}) {
	return func(builder *testpkg.Builder, args ...interface{}) {
		resp := args[0].(*issuer.IssueResponse)

		if resp.Certificate == nil {
			builder.T.Errorf("expected new certificate to be issued")
		}
		if resp.CA == nil || !reflect.DeepEqual(expectedCA, resp.CA) {
			builder.T.Errorf("expected CA certificate to be returned")
		}
	}
}
