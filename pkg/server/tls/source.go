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

package tls

import (
	"context"
	"crypto/tls"
	"errors"
)

var (
	ErrNotAvailable = errors.New("no tls.Certificate available")
)

type CertificateSource interface {
	// GetCertificate returns a Certificate based on the given
	// ClientHelloInfo. It will only be called if the client supplies SNI
	// information or if Certificates is empty.
	//
	// If GetCertificate is nil or returns nil, then the certificate is
	// retrieved from NameToCertificate. If NameToCertificate is nil, the
	// first element of Certificates will be used.
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)

	// Start will start the certificate source.
	// This may include setting up watches on certificate stores, or any other
	// kind of background operation.
	// The Start function should return when stopCh is closed, and may return an
	// error if an irrecoverable error occurs whilst running.
	Start(context.Context) error

	// Healthy can be used to check the status of the CertificateSource.
	// It will return true if the source has a certificate available.
	Healthy() bool
}
