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

package tls

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"sync"
	"time"

	"github.com/go-logr/logr"
	crlog "sigs.k8s.io/controller-runtime/pkg/log"

	logf "github.com/jetstack/cert-manager/pkg/logs"
)

// FileCertificateSource provides certificate data for a golang HTTP server by
// reloading data on disk periodically.
type FileCertificateSource struct {
	// CertPath is the path to the TLS certificate.
	// This file will be read periodically and will be used as the private key
	// for TLS connections.
	CertPath string

	// KeyPath is the path to the private key.
	// This file will be read periodically and will be used as the private key
	// for TLS connections.
	KeyPath string

	// UpdateInterval is how often the CertPath and KeyPath will be checked for
	// changes.
	// If not specified, a default of 10s will be used.
	UpdateInterval time.Duration

	// MaxFailures is the maximum number of times a failure to read data from
	// disk should be allowed before treating it as fatal.
	// If not specified, a default of 12 will be used.
	MaxFailures int

	// Log is an optional logger to write informational and error messages to.
	// If not specified, no messages will be logged.
	Log logr.Logger

	cachedCertificate *tls.Certificate
	cachedCertBytes   []byte
	cachedKeyBytes    []byte
	lock              sync.Mutex
}

const defaultUpdateInterval = time.Second * 10
const defaultMaxFailures = 12

var _ CertificateSource = &FileCertificateSource{}

func (f *FileCertificateSource) Run(stopCh <-chan struct{}) error {
	if f.Log == nil {
		f.Log = crlog.NullLogger{}
	}

	updateInterval := f.UpdateInterval
	if updateInterval == 0 {
		updateInterval = defaultUpdateInterval
	}
	maxFailures := f.MaxFailures
	if maxFailures == 0 {
		maxFailures = defaultMaxFailures
	}

	// read the certificate data for the first time immediately, but allow
	// retrying if the first attempt fails
	if err := f.updateCertificateFromDisk(); err != nil {
		f.Log.Error(err, "failed to read certificate from disk")
	}

	failures := 0
	ticker := time.NewTicker(updateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return nil
		case <-ticker.C:
			if err := f.updateCertificateFromDisk(); err != nil {
				failures++
				f.Log.Error(err, "failed to update certificate from disk", "failures", failures)
				if failures >= maxFailures {
					return fmt.Errorf("failed to update certificate from disk %d times: %v", failures, err)
				}
				continue
			}
			f.Log.V(logf.DebugLevel).Info("refreshed certificate from data on disk")
		}
	}
}

func (f *FileCertificateSource) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	f.lock.Lock()
	defer f.lock.Unlock()
	if f.cachedCertificate == nil {
		return nil, fmt.Errorf("no tls.Certificate available")
	}
	return f.cachedCertificate, nil
}

func (f *FileCertificateSource) Healthy() bool {
	return f.cachedCertificate != nil
}

// updateCertificateFromDisk will read private key and certificate data from
// disk and update the cached tls.Certificate if the data on disk has changed.
func (f *FileCertificateSource) updateCertificateFromDisk() error {
	keyData, err := ioutil.ReadFile(f.KeyPath)
	if err != nil {
		return fmt.Errorf("failed to read keyPath: %w", err)
	}

	certData, err := ioutil.ReadFile(f.CertPath)
	if err != nil {
		return fmt.Errorf("failed to read certPath: %w", err)
	}

	f.lock.Lock()
	defer f.lock.Unlock()
	if bytes.Compare(keyData, f.cachedKeyBytes) == 0 && bytes.Compare(certData, f.cachedCertBytes) == 0 {
		f.Log.V(logf.DebugLevel).Info("key and certificate on disk have not changed")
		return nil
	}
	f.Log.Info("detected private key or certificate data on disk has changed. reloading certificate")

	cert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return err
	}

	f.cachedCertBytes = certData
	f.cachedKeyBytes = keyData
	f.cachedCertificate = &cert

	return nil
}
