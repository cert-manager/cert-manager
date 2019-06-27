package ca

import (
	"context"
	"crypto/tls"
	"math/rand"
	"sync"
	"time"

	"github.com/pkg/errors"
)

// RenewFunc defines the type of the functions used to get a new tls
// certificate.
type RenewFunc func() (*tls.Certificate, error)

var minCertDuration = time.Minute

// TLSRenewer automatically renews a tls certificate using a RenewFunc.
type TLSRenewer struct {
	sync.RWMutex
	RenewCertificate RenewFunc
	cert             *tls.Certificate
	timer            *time.Timer
	renewBefore      time.Duration
	renewJitter      time.Duration
	certNotAfter     time.Time
}

type tlsRenewerOptions func(r *TLSRenewer) error

// WithRenewBefore modifies a tlsRenewer by setting the renewBefore attribute.
func WithRenewBefore(b time.Duration) func(r *TLSRenewer) error {
	return func(r *TLSRenewer) error {
		r.renewBefore = b
		return nil
	}
}

// WithRenewJitter modifies a tlsRenewer by setting the renewJitter attribute.
func WithRenewJitter(j time.Duration) func(r *TLSRenewer) error {
	return func(r *TLSRenewer) error {
		r.renewJitter = j
		return nil
	}
}

// NewTLSRenewer creates a TLSRenewer for the given cert. It will use the given
// RenewFunc to get a new certificate when required.
func NewTLSRenewer(cert *tls.Certificate, fn RenewFunc, opts ...tlsRenewerOptions) (*TLSRenewer, error) {
	r := &TLSRenewer{
		RenewCertificate: fn,
		cert:             cert,
	}

	for _, f := range opts {
		if err := f(r); err != nil {
			return nil, errors.Wrap(err, "error applying options")
		}
	}

	period := cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore)
	if period < minCertDuration {
		return nil, errors.Errorf("period must be greater than or equal to %s, but got %v.", minCertDuration, period)
	}
	// By default we will try to renew the cert before 2/3 of the validity
	// period have expired.
	if r.renewBefore == 0 {
		r.renewBefore = period / 3
	}
	// By default we set the jitter to 1/20th of the validity period.
	if r.renewJitter == 0 {
		r.renewJitter = period / 20
	}

	return r, nil
}

// Run starts the certificate renewer for the given certificate.
func (r *TLSRenewer) Run() {
	cert := r.getCertificate()
	next := r.nextRenewDuration(cert.Leaf.NotAfter)
	r.timer = time.AfterFunc(next, r.renewCertificate)
}

// RunContext starts the certificate renewer for the given certificate.
func (r *TLSRenewer) RunContext(ctx context.Context) {
	r.Run()
	go func() {
		<-ctx.Done()
		r.Stop()
	}()
}

// Stop prevents the renew timer from firing.
func (r *TLSRenewer) Stop() bool {
	if r.timer != nil {
		return r.timer.Stop()
	}
	return true
}

// GetCertificate returns the current server certificate.
//
// This method is set in the tls.Config GetCertificate property.
func (r *TLSRenewer) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.getCertificate(), nil
}

// GetCertificateForCA returns the current server certificate. It can only be
// used if the renew function creates the new certificate and do not uses a TLS
// request. It's intended to be use by the certificate authority server.
//
// This method is set in the tls.Config GetCertificate property.
func (r *TLSRenewer) GetCertificateForCA(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.getCertificateForCA(), nil
}

// GetClientCertificate returns the current client certificate.
//
// This method is set in the tls.Config GetClientCertificate property.
func (r *TLSRenewer) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return r.getCertificate(), nil
}

// getCertificate returns the certificate using a read-only lock.
//
// Known issue: It cannot renew an expired certificate because the /renew
// endpoint requires a valid client certificate. The certificate can expire
// if the timer does not fire e.g. when the CA is run from a laptop that
// enters sleep mode.
func (r *TLSRenewer) getCertificate() *tls.Certificate {
	r.RLock()
	cert := r.cert
	r.RUnlock()
	return cert
}

// getCertificateForCA returns the certificate using a read-only lock. It will
// automatically renew the certificate if it has expired.
func (r *TLSRenewer) getCertificateForCA() *tls.Certificate {
	r.RLock()
	// Force certificate renewal if the timer didn't run.
	// This is an special case that can happen after a computer sleep.
	if time.Now().After(r.certNotAfter) {
		r.RUnlock()
		r.renewCertificate()
		r.RLock()
	}
	cert := r.cert
	r.RUnlock()
	return cert
}

// setCertificate updates the certificate using a read-write lock. It also
// updates certNotAfter with 1m of delta; this will force the renewal of the
// certificate if it is about to expire.
func (r *TLSRenewer) setCertificate(cert *tls.Certificate) {
	r.Lock()
	r.cert = cert
	r.certNotAfter = cert.Leaf.NotAfter.Add(-1 * time.Minute)
	r.Unlock()
}

func (r *TLSRenewer) renewCertificate() {
	var next time.Duration
	cert, err := r.RenewCertificate()
	if err != nil {
		next = r.renewJitter / 2
		next += time.Duration(rand.Int63n(int64(next)))
	} else {
		r.setCertificate(cert)
		next = r.nextRenewDuration(cert.Leaf.NotAfter)
	}
	r.Lock()
	r.timer.Reset(next)
	r.Unlock()
}

func (r *TLSRenewer) nextRenewDuration(notAfter time.Time) time.Duration {
	d := notAfter.Sub(time.Now()) - r.renewBefore
	n := rand.Int63n(int64(r.renewJitter))
	d -= time.Duration(n)
	if d < 0 {
		d = 0
	}
	return d
}
