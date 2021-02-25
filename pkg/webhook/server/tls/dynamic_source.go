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
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	logf "github.com/cert-manager/cert-manager/pkg/logs"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/util/wait"
	crlog "sigs.k8s.io/controller-runtime/pkg/log"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/pkg/webhook/authority"
)

// DynamicSource provides certificate data for a golang HTTP server by
// automatically generating certificates using an authority.SignFunc.
type DynamicSource struct {
	// DNSNames that will be set on certificates this source produces.
	DNSNames []string

	// The authority used to sign certificate templates.
	Authority *authority.DynamicAuthority

	// Log is an optional logger to write informational and error messages to.
	// If not specified, no messages will be logged.
	Log logr.Logger

	cachedCertificate *tls.Certificate
	nextRenew         time.Time
	lock              sync.Mutex
}

var _ CertificateSource = &DynamicSource{}

func (f *DynamicSource) Run(stopCh <-chan struct{}) error {
	if f.Log == nil {
		f.Log = crlog.NullLogger{}
	}

	// Run the authority in a separate goroutine
	authorityErrChan := make(chan error)
	go func() {
		defer close(authorityErrChan)
		authorityErrChan <- f.Authority.Run(stopCh)
	}()

	// initially fetch a certificate from the signing CA
	interval := time.Second
	if err := wait.PollUntil(interval, func() (done bool, err error) {
		// check for errors from the authority here too, to prevent retrying
		// if the authority has failed to start
		select {
		case err, ok := <-authorityErrChan:
			if err != nil {
				return true, fmt.Errorf("failed to run certificate authority: %w", err)
			}
			if !ok {
				return true, fmt.Errorf("certificate authority stopped")
			}
		default:
			// this case avoids blocking if the authority is still running
		}

		if err := f.regenerateCertificate(); err != nil {
			f.Log.Error(err, "Failed to generate initial serving certificate, retrying...", "interval", interval)
			return false, nil
		}
		return true, nil
	}, stopCh); err != nil {
		return err
	}

	// watch for changes to the root CA
	rotationChan := f.Authority.WatchRotation(stopCh)
	renewalChan := func() <-chan struct{} {
		ch := make(chan struct{})
		go func() {
			defer close(ch)
			for {
				// exit if stopCh closes
				select {
				case <-stopCh:
					return
				default:
				}
				// regenerate the certificate if we have gone past the 'nextRenew' time
				if time.Now().After(f.nextRenew) {
					ch <- struct{}{}
				}
				time.Sleep(time.Second * 5)
			}
		}()
		return ch
	}()
	// check the current certificate every 10s in case it needs updating
	return wait.PollImmediateUntil(time.Second*10, func() (done bool, err error) {
		// regenerate the serving certificate if the root CA has been rotated
		select {
		// if the authority has stopped for whatever reason, exit and return the error
		case err, ok := <-authorityErrChan:
			if err != nil {
				return true, fmt.Errorf("failed to run certificate authority: %w", err)
			}
			if !ok {
				return true, fmt.Errorf("certificate authority stopped")
			}
		// trigger regeneration if the root CA has been rotated
		case _, ok := <-rotationChan:
			if !ok {
				return true, fmt.Errorf("channel closed")
			}
			f.Log.V(logf.InfoLevel).Info("Detected root CA rotation - regenerating serving certificates")
			if err := f.regenerateCertificate(); err != nil {
				f.Log.Error(err, "Failed to regenerate serving certificate")
				// Return an error here and stop the source running - this case should never
				// occur, and if it does, indicates some form of internal error.
				return false, err
			}
		// trigger regeneration if a renewal is required
		case <-renewalChan:
			f.Log.V(logf.InfoLevel).Info("Serving certificate requires renewal, regenerating")
			if err := f.regenerateCertificate(); err != nil {
				f.Log.Error(err, "Failed to regenerate serving certificate")
				// Return an error here and stop the source running - this case should never
				// occur, and if it does, indicates some form of internal error.
				return false, err
			}
		}
		return false, nil
	}, stopCh)
}

func (f *DynamicSource) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	f.lock.Lock()
	defer f.lock.Unlock()
	if f.cachedCertificate == nil {
		return nil, ErrNotAvailable
	}
	return f.cachedCertificate, nil
}

func (f *DynamicSource) Healthy() bool {
	return f.cachedCertificate != nil
}

// regenerateCertificate will trigger the cached certificate and private key to
// be regenerated by requesting a new certificate from the authority.
func (f *DynamicSource) regenerateCertificate() error {
	f.Log.V(logf.DebugLevel).Info("Generating new ECDSA private key")
	pk, err := pki.GenerateECPrivateKey(384)
	if err != nil {
		return err
	}

	// create the certificate template to be signed
	template := &x509.Certificate{
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          pk.Public(),
		DNSNames:           f.DNSNames,
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	f.Log.V(logf.DebugLevel).Info("Signing new serving certificate")
	cert, err := f.Authority.Sign(template)
	if err != nil {
		return err
	}

	f.Log.V(logf.DebugLevel).Info("Signed new serving certificate")

	if err := f.updateCertificate(pk, cert); err != nil {
		return err
	}

	f.Log.V(logf.InfoLevel).Info("Updated serving TLS certificate")
	return nil
}

func (f *DynamicSource) updateCertificate(pk crypto.Signer, cert *x509.Certificate) error {
	f.lock.Lock()
	defer f.lock.Unlock()

	pkData, err := pki.EncodePrivateKey(pk, cmapi.PKCS8)
	if err != nil {
		return err
	}

	certData, err := pki.EncodeX509(cert)
	if err != nil {
		return err
	}

	bundle, err := tls.X509KeyPair(certData, pkData)
	if err != nil {
		return err
	}

	f.cachedCertificate = &bundle
	certDuration := cert.NotAfter.Sub(cert.NotBefore)
	// renew the certificate 1/3 of the time before its expiry
	f.nextRenew = cert.NotAfter.Add(certDuration / -3)
	return nil
}
