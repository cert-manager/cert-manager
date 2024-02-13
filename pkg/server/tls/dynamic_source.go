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
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/util/wait"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/server/tls/authority"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

// DynamicSource provides certificate data for a golang HTTP server by
// automatically generating certificates using an authority.SignFunc.
type DynamicSource struct {
	// DNSNames that will be set on certificates this source produces.
	DNSNames []string

	// The authority used to sign certificate templates.
	Authority *authority.DynamicAuthority

	log logr.Logger

	cachedCertificate *tls.Certificate
	lock              sync.Mutex
}

var _ CertificateSource = &DynamicSource{}

func (f *DynamicSource) Start(ctx context.Context) error {
	f.log = logf.FromContext(ctx)

	// Run the authority in a separate goroutine
	authorityErrChan := make(chan error)
	go func() {
		defer close(authorityErrChan)
		authorityErrChan <- f.Authority.Run(ctx)
	}()

	nextRenewCh := make(chan time.Time, 1)

	// initially fetch a certificate from the signing CA
	interval := time.Second
	if err := wait.PollUntilContextCancel(ctx, interval, true, func(ctx context.Context) (done bool, err error) {
		// check for errors from the authority here too, to prevent retrying
		// if the authority has failed to start
		select {
		case err, ok := <-authorityErrChan:
			if err != nil {
				return true, fmt.Errorf("failed to run certificate authority: %w", err)
			}
			if !ok {
				return true, context.Canceled
			}
		default:
			// this case avoids blocking if the authority is still running
		}

		if err := f.regenerateCertificate(nextRenewCh); err != nil {
			f.log.Error(err, "Failed to generate initial serving certificate, retrying...", "interval", interval)
			return false, nil
		}
		return true, nil
	}); err != nil {
		// In case of an error, the stopCh is closed; wait for authorityErrChan to be closed too
		<-authorityErrChan

		return err
	}

	// watch for changes to the root CA
	rotationChan := f.Authority.WatchRotation(ctx.Done())
	renewalChan := func() <-chan struct{} {
		ch := make(chan struct{})
		go func() {
			defer close(ch)

			var renewMoment time.Time
			select {
			case renewMoment = <-nextRenewCh:
				// We recevieved a renew moment
			default:
				// This should never happen
				panic("Unreacheable")
			}

			for {
				timer := time.NewTimer(time.Until(renewMoment))
				defer timer.Stop()

				select {
				case <-ctx.Done():
					return
				case <-timer.C:
					// Try to send a message on ch, but also allow for a stop signal or
					// a new renewMoment to be received
					select {
					case <-ctx.Done():
						return
					case ch <- struct{}{}:
						// Message was sent on channel
					case renewMoment = <-nextRenewCh:
						// We recevieved a renew moment, next loop iteration will update the timer
					}
				case renewMoment = <-nextRenewCh:
					// We recevieved a renew moment, next loop iteration will update the timer
				}
			}
		}()
		return ch
	}()

	// check the current certificate every 10s in case it needs updating
	if err := wait.PollUntilContextCancel(ctx, time.Second*10, true, func(ctx context.Context) (done bool, err error) {
		// regenerate the serving certificate if the root CA has been rotated
		select {
		// if the authority has stopped for whatever reason, exit and return the error
		case err, ok := <-authorityErrChan:
			if err != nil {
				return true, fmt.Errorf("failed to run certificate authority: %w", err)
			}
			if !ok {
				return true, context.Canceled
			}
		// trigger regeneration if the root CA has been rotated
		case _, ok := <-rotationChan:
			if !ok {
				return true, context.Canceled
			}
			f.log.V(logf.InfoLevel).Info("Detected root CA rotation - regenerating serving certificates")
			if err := f.regenerateCertificate(nextRenewCh); err != nil {
				f.log.Error(err, "Failed to regenerate serving certificate")
				// Return an error here and stop the source running - this case should never
				// occur, and if it does, indicates some form of internal error.
				return false, err
			}
		// trigger regeneration if a renewal is required
		case <-renewalChan:
			f.log.V(logf.InfoLevel).Info("cert-manager webhook certificate requires renewal, regenerating", "DNSNames", f.DNSNames)
			if err := f.regenerateCertificate(nextRenewCh); err != nil {
				f.log.Error(err, "Failed to regenerate serving certificate")
				// Return an error here and stop the source running - this case should never
				// occur, and if it does, indicates some form of internal error.
				return false, err
			}
		case <-ctx.Done():
			return true, context.Canceled
		}
		return false, nil
	}); err != nil {
		// In case of an error, the stopCh is closed; wait for all channels to close
		<-authorityErrChan
		<-rotationChan
		<-renewalChan

		return err
	}

	return nil
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
func (f *DynamicSource) regenerateCertificate(nextRenew chan<- time.Time) error {
	f.log.V(logf.DebugLevel).Info("Generating new ECDSA private key")
	pk, err := pki.GenerateECPrivateKey(384)
	if err != nil {
		return err
	}

	// create the certificate template to be signed
	template := &x509.Certificate{
		Version:            3,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          pk.Public(),
		DNSNames:           f.DNSNames,
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	f.log.V(logf.DebugLevel).Info("Signing new serving certificate")
	cert, err := f.Authority.Sign(template)
	if err != nil {
		return err
	}

	f.log.V(logf.DebugLevel).Info("Signed new serving certificate")

	if err := f.updateCertificate(pk, cert, nextRenew); err != nil {
		return err
	}
	return nil
}

func (f *DynamicSource) updateCertificate(pk crypto.Signer, cert *x509.Certificate, nextRenew chan<- time.Time) error {
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
	nextRenew <- cert.NotAfter.Add(certDuration / -3)
	f.log.V(logf.InfoLevel).Info("Updated cert-manager TLS certificate", "DNSNames", f.DNSNames)

	return nil
}
