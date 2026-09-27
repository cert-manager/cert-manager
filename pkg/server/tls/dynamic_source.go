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
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/util/wait"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/server/tls/authority"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

type Authority interface {
	// Run starts the authority and blocks until it is stopped or an error occurs.
	Run(ctx context.Context) error

	// WatchRotation adds a watcher to the authority that will notify the given
	// channel when the root CA has been rotated. It is guaranteed to post a message
	// to the channel when the root CA has been rotated and the channel is not full.
	WatchRotation(ch chan<- struct{})

	// StopWatchingRotation removes the watcher from the authority.
	StopWatchingRotation(ch chan<- struct{})

	// Sign signs the given certificate template and returns the signed certificate.
	// WARNING: The WatchRotation method should be called before Sign to ensure that
	// the rotation of the CA used to sign the certificate in this call is detected.
	Sign(template *x509.Certificate) (*x509.Certificate, error)
}

// DynamicSource provides certificate data for a golang HTTP server by
// automatically generating certificates using an authority.SignFunc.
type DynamicSource struct {
	// DNSNames that will be set on certificates this source produces.
	DNSNames []string

	// The authority used to sign certificate templates.
	Authority Authority

	RetryInterval time.Duration

	log logr.Logger

	cachedCertificate *tls.Certificate
	lock              sync.Mutex
}

var _ CertificateSource = &DynamicSource{}

// renewalStaleAfter is the grace period after the scheduled renewal moment
// beyond which the renewal is considered to have been missed, e.g. because
// the container was paused during the renewal window.
const renewalStaleAfter = 5 * time.Second

// renewalCheckInterval is how often the renewal watcher polls time.Now() to
// detect a missed renewal moment.
const renewalCheckInterval = 1 * time.Minute

// Implements Runnable (https://github.com/kubernetes-sigs/controller-runtime/blob/56159419231e985c091ef3e7a8a3dee40ddf1d73/pkg/manager/manager.go#L287)
func (f *DynamicSource) Start(ctx context.Context) error {
	f.log = logf.FromContext(ctx)

	if f.RetryInterval == 0 {
		f.RetryInterval = 1 * time.Second
	}

	group, ctx := errgroup.WithContext(ctx)
	group.Go(func() error {
		if err := f.Authority.Run(ctx); err != nil {
			return fmt.Errorf("failed to run certificate authority: %w", err)
		}

		if ctx.Err() == nil {
			return fmt.Errorf("certificate authority stopped unexpectedly")
		}

		// Context was cancelled, return nil
		return nil
	})

	// channel which will be notified when the authority has rotated its root CA
	// We start watching the rotation of the root CA before we start generating
	// certificates to ensure we don't miss any rotations.
	rotationChan := make(chan struct{}, 1)
	f.Authority.WatchRotation(rotationChan)
	defer f.Authority.StopWatchingRotation(rotationChan)

	nextRenewCh := make(chan time.Time, 1)

	// initially fetch a certificate from the signing CA
	if err := f.tryRegenerateCertificate(ctx, nextRenewCh); err != nil {
		if err := group.Wait(); err != nil {
			return err
		}

		if errors.Is(err, context.Canceled) {
			return nil
		}

		return err
	}

	// channel which will be notified when the leaf certificate reaches 2/3 of its lifetime
	// and needs to be renewed
	renewalChan := make(chan struct{}, 1)
	group.Go(func() error {
		var renewMoment time.Time

		for {
			if done := func() bool {
				watcherContext, cancel := context.WithCancel(ctx)
				defer cancel()
				needsRenewalChan := f.startRenewalWatcher(watcherContext, renewMoment, renewMoment.Add(renewalStaleAfter), renewalCheckInterval)

				// Wait for the renewal watcher to signal, or for a new renewal moment to be received
				select {
				case <-ctx.Done():
					// context was cancelled, return nil
					return true
				case reason := <-needsRenewalChan:
					f.log.V(logf.InfoLevel).Info("Certificate needs renewal", "reason", reason)
					renewMoment = time.Time{}
				case renewMoment = <-nextRenewCh:
					// We received a renew moment, next loop iteration will update the timer
					return false
				}

				// the renewal channel has a buffer of 1 - drop event if we are already issuing
				select {
				case renewalChan <- struct{}{}:
				default:
				}
				return false
			}(); done {
				return nil
			}
		}
	})

	// check the current certificate in case it needs updating
	if err := func() error {
		for {
			// regenerate the serving certificate if the root CA has been rotated
			select {
			// check if the context has been cancelled
			case <-ctx.Done():
				return ctx.Err()

			// trigger regeneration if the root CA has been rotated
			case <-rotationChan:
				f.log.V(logf.InfoLevel).Info("Detected root CA rotation - regenerating serving certificates")

			// trigger regeneration if a renewal is required
			case <-renewalChan:
				f.log.V(logf.InfoLevel).Info("cert-manager webhook certificate requires renewal, regenerating", "DNSNames", f.DNSNames)
			}

			if err := f.tryRegenerateCertificate(ctx, nextRenewCh); err != nil {
				return err
			}
		}
	}(); err != nil {
		if err := group.Wait(); err != nil {
			return err
		}

		if errors.Is(err, context.Canceled) {
			return nil
		}

		return err
	}

	return nil
}

// Implements LeaderElectionRunnable (https://github.com/kubernetes-sigs/controller-runtime/blob/56159419231e985c091ef3e7a8a3dee40ddf1d73/pkg/manager/manager.go#L305)
func (f *DynamicSource) NeedLeaderElection() bool {
	return false
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
	f.lock.Lock()
	defer f.lock.Unlock()
	return f.cachedCertificate != nil
}

func (f *DynamicSource) tryRegenerateCertificate(ctx context.Context, nextRenewCh chan<- time.Time) error {
	return wait.PollUntilContextCancel(ctx, f.RetryInterval, true, func(ctx context.Context) (done bool, err error) {
		f.log.Info("try to generate a serving certificate")
		if err := f.regenerateCertificate(ctx, nextRenewCh); err != nil {
			if errors.Is(err, authority.ErrCertificateNotAvailable) {
				f.log.Info("Certificate is not yet created, retrying...", "interval", f.RetryInterval)
			} else {
				f.log.Error(err, "Failed to generate serving certificate, retrying...", "interval", f.RetryInterval)
			}
			return false, nil
		}
		f.log.Info("Serving certificate generated successfully")
		return true, nil
	})
}

// regenerateCertificate will trigger the cached certificate and private key to
// be regenerated by requesting a new certificate from the authority.
func (f *DynamicSource) regenerateCertificate(ctx context.Context, nextRenew chan<- time.Time) error {
	f.log.V(logf.DebugLevel).Info("Generating new ECDSA private key")
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

	f.log.V(logf.DebugLevel).Info("Signing new serving certificate")
	cert, err := f.Authority.Sign(template)
	if err != nil {
		return err
	}

	f.log.V(logf.DebugLevel).Info("Signed new serving certificate")

	return f.updateCertificate(ctx, pk, cert, nextRenew)
}

func (f *DynamicSource) updateCertificate(ctx context.Context, pk crypto.Signer, cert *x509.Certificate, nextRenewCh chan<- time.Time) error {
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
	renewMoment := cert.NotAfter.Add(certDuration / -3)

	select {
	case <-ctx.Done():
		return nil

	case nextRenewCh <- renewMoment:
	}

	f.log.V(logf.InfoLevel).Info("Updated cert-manager TLS certificate", "DNSNames", f.DNSNames)

	return nil
}

type renewalReason string

const (
	certificateAboutToExpire       renewalReason = "certificateAboutToExpire"
	certificateRenewalMomentMissed renewalReason = "certificateRenewalMomentMissed"
)

// startRenewalWatcher monitors whether the serving certificate needs renewal.
//
// System suspend (S3/S4) or VM live migration stops CLOCK_MONOTONIC, so the
// one-shot renewal timer (which uses Go's monotonic clock) never fires. When
// the system resumes, the timer deadline has not yet been reached — even though
// wall-clock time has advanced past the renewal moment. To cover this case,
// startRenewalWatcher runs a periodic ticker that polls time.Now() against the
// wall-clock deadline (renewalAfter). Because time.Now() uses CLOCK_REALTIME
// for comparisons with wall-clock timestamps, the ticker detects the missed
// renewal regardless of whether CLOCK_MONOTONIC advanced.
//
// If renewalAt is the zero time (no renewal scheduled yet), no goroutine is
// started and the returned channel never sends — the caller's select blocks on
// other cases until a renewal moment is received.
//
// Otherwise the watcher sends exactly one renewalReason on the returned channel
// and then exits. The caller reads one value per invocation and cancels the
// context to clean up the goroutine.
func (f *DynamicSource) startRenewalWatcher(ctx context.Context, renewalAt time.Time, renewalAfter time.Time, retryPeriod time.Duration) <-chan renewalReason {
	var renewalChan = make(chan renewalReason, 1)

	if renewalAt.IsZero() {
		return renewalChan
	}

	go func() {
		timer := time.NewTimer(time.Until(renewalAt))
		defer timer.Stop()

		ticker := time.NewTicker(retryPeriod)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				select {
				case renewalChan <- certificateAboutToExpire:
				case <-ctx.Done():
				}
				return
			case <-ticker.C:
				if !time.Now().After(renewalAfter) {
					continue
				}
				select {
				case renewalChan <- certificateRenewalMomentMissed:
				case <-ctx.Done():
				}
				return
			}
		}
	}()

	return renewalChan
}
