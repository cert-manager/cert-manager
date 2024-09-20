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

package server

import (
	"crypto/tls"
	"net"

	ciphers "k8s.io/component-base/cli/flag"

	servertls "github.com/cert-manager/cert-manager/pkg/server/tls"
)

// ListenerConfig defines the config of the listener, this mainly deals with
// configuring the TLSConfig
type ListenerConfig struct {
	TLSEnabled bool
	TLSConfig  tls.Config
}

// ListenerOption is function used to mutate the config, it allows for convenience
// methods such as WithCertificateSource
type ListenerOption func(*ListenerConfig) error

// Listen will listen on a given network and port, with additional options available
// for enabling TLS and obtaining certificates.
func Listen(network, addr string, options ...ListenerOption) (net.Listener, error) {
	// Create the base listener on the configured network and address
	listener, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}

	// Apply the options, these configure the TLS options
	config := ListenerConfig{}
	for _, option := range options {
		if err := option(&config); err != nil {
			return nil, err
		}
	}

	// If the options have enabled TLS we wrap the original listener with
	// a TLS listener
	if config.TLSEnabled {
		listener = tls.NewListener(listener, &config.TLSConfig)
	}

	return listener, nil
}

// WithCertificateSource specifies the certificate source for TLS, this also implicitly
// enables TLS for the listener when not nil
func WithCertificateSource(certificateSource servertls.CertificateSource) ListenerOption {
	return func(config *ListenerConfig) error {
		if certificateSource != nil {
			config.TLSEnabled = true
			config.TLSConfig.GetCertificate = certificateSource.GetCertificate
		}
		return nil
	}
}

// WithTLSCipherSuites specifies the allowed cipher suites, when an empty/nil array is passed
// the go defaults are used
func WithTLSCipherSuites(suites []string) ListenerOption {
	return func(config *ListenerConfig) error {
		if len(suites) > 0 {
			cipherSuites, err := ciphers.TLSCipherSuites(suites)
			if err != nil {
				return err
			}

			config.TLSConfig.CipherSuites = cipherSuites
		}

		return nil
	}
}

// WithTLSMinVersion specifies the minimum TLS version, when an empty string is passed the
// go defaults are used
func WithTLSMinVersion(version string) ListenerOption {
	return func(config *ListenerConfig) error {
		if len(version) > 0 {
			minVersion, err := ciphers.TLSVersion(version)
			if err != nil {
				return err
			}

			config.TLSConfig.MinVersion = minVersion
		}

		return nil
	}
}
