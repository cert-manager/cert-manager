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

package acme

import (
	"context"
	"testing"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
)

type testT struct {
	issuer      *cmapi.Issuer
	builder     *testpkg.Builder
	expectedErr bool
}

func runSetupTest(t *testing.T, test testT) {
	test.builder.T = t
	test.builder.Init()
	defer test.builder.Stop()

	c, err := New(test.builder.Context, test.issuer)
	if err != nil {
		t.Fatalf("error building ACME fixture: %v", err)
	}
	test.builder.Start()

	err = c.Setup(context.Background())
	if err != nil && !test.expectedErr {
		t.Errorf("expected to not get an error, but got: %v", err)
	}
	if err == nil && test.expectedErr {
		t.Errorf("expected to get an error but did not get one")
	}

	test.builder.CheckAndFinish(err)
}
