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

package conformance

import (
	_ "github.com/jetstack/cert-manager/test/e2e/suite/conformance/certificates/acme"
	_ "github.com/jetstack/cert-manager/test/e2e/suite/conformance/certificates/ca"
	_ "github.com/jetstack/cert-manager/test/e2e/suite/conformance/certificates/external"
	_ "github.com/jetstack/cert-manager/test/e2e/suite/conformance/certificates/selfsigned"
	_ "github.com/jetstack/cert-manager/test/e2e/suite/conformance/certificates/vault"
	_ "github.com/jetstack/cert-manager/test/e2e/suite/conformance/certificates/venafi"
	_ "github.com/jetstack/cert-manager/test/e2e/suite/conformance/certificates/venaficloud"
	_ "github.com/jetstack/cert-manager/test/e2e/suite/conformance/certificatesigningrequests/acme"
	_ "github.com/jetstack/cert-manager/test/e2e/suite/conformance/certificatesigningrequests/ca"
	_ "github.com/jetstack/cert-manager/test/e2e/suite/conformance/certificatesigningrequests/selfsigned"
	_ "github.com/jetstack/cert-manager/test/e2e/suite/conformance/certificatesigningrequests/vault"
	_ "github.com/jetstack/cert-manager/test/e2e/suite/conformance/certificatesigningrequests/venafi"
	_ "github.com/jetstack/cert-manager/test/e2e/suite/conformance/rbac"
)
