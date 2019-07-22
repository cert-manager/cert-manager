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

	// Issue attempts to issue a certificate as described by the certificate
	// resource given
	Issue(context.Context, *v1alpha1.Certificate) (*IssueResponse, error)
}

type IssueResponse struct {
	// Certificate is the certificate resource that should be stored in the
	// target secret.
	// It will only be set if the corresponding private key is also set on the
	// IssuerResponse structure.
	Certificate []byte

	// PrivateKey is the private key that should be stored in the target secret.
	// If set, the certificate and CA field will also be overwritten with the
	// contents of the field.
	// If Certificate is not set, the existing Certificate will be overwritten.
	PrivateKey []byte

	// CA is the CA certificate that should be stored in the target secret.
	// This field should only be set if the private key field is set, similar
	// to the Certificate field.
	CA []byte
}
