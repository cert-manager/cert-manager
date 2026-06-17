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

// Package dnsproviders contains addons that create DNS provider credentials
// in the target test environment.
// In most cases, those credentials are access via the CLI flags passed to the
// test suite.
package dnsproviders

import (
	"fmt"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
)

var (
	ErrNoCredentials = fmt.Errorf("no credentials provided for provider")
)

type Details struct {
	// Domain is a domain that can be validated using these credentials
	BaseDomain string

	// ProviderConfig is the issuer config needed to use these newly created credentials
	ProviderConfig cmacme.ACMEChallengeSolverDNS01
}
