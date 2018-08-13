/*
Copyright 2018 The Jetstack cert-manager contributors.

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

package issuer

import (
	"context"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

type Interface interface {
	// Setup initialises the issuer. This may include registering accounts with
	// a service, creating a CA and storing it somewhere, or verifying
	// credentials and authorization with a remote server.
	Setup(ctx context.Context) error
	// Prepare
	Prepare(context.Context, *v1alpha1.Certificate) error
	// Issue attempts to issue a certificate as described by the certificate
	// resource given
	Issue(context.Context, *v1alpha1.Certificate) ([]byte, []byte, error)
	// Renew attempts to renew the certificate describe by the certificate
	// resource given. If no certificate exists, an error is returned.
	Renew(context.Context, *v1alpha1.Certificate) ([]byte, []byte, error)
}
