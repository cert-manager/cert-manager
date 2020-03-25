/*
Copyright 2020 The Jetstack cert-manager contributors.

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

package options

import (
	"github.com/spf13/pflag"
)

type WebhookOptions struct {
	ListenPort  int
	HealthzPort int

	// Path to TLS certificate and private key on disk.
	// Both must be specified if either is.
	TLSCertFile string
	TLSKeyFile  string

	TLSCipherSuites []string
}

func (o *WebhookOptions) AddFlags(fs *pflag.FlagSet) {
	// TODO: rename secure-port to listen-port
	fs.IntVar(&o.ListenPort, "secure-port", 6443, "port number to listen on for secure TLS connections")
	fs.IntVar(&o.HealthzPort, "healthz-port", 6080, "port number to listen on for insecure healthz connections")
	fs.StringVar(&o.TLSCertFile, "tls-cert-file", "", "path to the file containing the TLS certificate to serve with")
	fs.StringVar(&o.TLSKeyFile, "tls-private-key-file", "", "path to the file containing the TLS private key to serve with")
	fs.StringSliceVar(&o.TLSCipherSuites, "tls-cipher-suites", defaultCipherSuites, "comma separated list of TLS 1.2 cipher suites to use (TLS 1.3 cipher suites are not configurable)")
}

var (
	defaultCipherSuites = []string{
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		"TLS_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_RSA_WITH_AES_128_CBC_SHA",
		"TLS_RSA_WITH_AES_256_CBC_SHA",
	}
)
