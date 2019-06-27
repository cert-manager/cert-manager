package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"golang.org/x/net/http2"
)

// GetClientTLSConfig returns a tls.Config for client use configured with the
// sign certificate, and a new certificate pool with the sign root certificate.
// The client certificate will automatically rotate before expiring.
func (c *Client) GetClientTLSConfig(ctx context.Context, sign *api.SignResponse, pk crypto.PrivateKey, options ...TLSOption) (*tls.Config, error) {
	tlsConfig, _, err := c.getClientTLSConfig(ctx, sign, pk, options)
	if err != nil {
		return nil, err
	}
	return tlsConfig, nil
}

func (c *Client) getClientTLSConfig(ctx context.Context, sign *api.SignResponse, pk crypto.PrivateKey, options []TLSOption) (*tls.Config, *http.Transport, error) {
	cert, err := TLSCertificate(sign, pk)
	if err != nil {
		return nil, nil, err
	}
	renewer, err := NewTLSRenewer(cert, nil)
	if err != nil {
		return nil, nil, err
	}

	tlsConfig := getDefaultTLSConfig(sign)
	// Note that with GetClientCertificate tlsConfig.Certificates is not used.
	// Without tlsConfig.Certificates there's not need to use tlsConfig.BuildNameToCertificate()
	tlsConfig.GetClientCertificate = renewer.GetClientCertificate
	tlsConfig.PreferServerCipherSuites = true

	// Apply options and initialize mutable tls.Config
	tlsCtx := newTLSOptionCtx(c, tlsConfig, sign)
	if err := tlsCtx.apply(options); err != nil {
		return nil, nil, err
	}

	// Update renew function with transport
	tr, err := getDefaultTransport(tlsConfig)
	if err != nil {
		return nil, nil, err
	}
	// Use mutable tls.Config on renew
	tr.DialTLS = c.buildDialTLS(tlsCtx)
	renewer.RenewCertificate = getRenewFunc(tlsCtx, c, tr, pk)

	// Update client transport
	c.SetTransport(tr)

	// Start renewer
	renewer.RunContext(ctx)
	return tlsConfig, tr, nil
}

// GetServerTLSConfig returns a tls.Config for server use configured with the
// sign certificate, and a new certificate pool with the sign root certificate.
// The returned tls.Config will only verify the client certificate if provided.
// The server certificate will automatically rotate before expiring.
func (c *Client) GetServerTLSConfig(ctx context.Context, sign *api.SignResponse, pk crypto.PrivateKey, options ...TLSOption) (*tls.Config, error) {
	cert, err := TLSCertificate(sign, pk)
	if err != nil {
		return nil, err
	}
	renewer, err := NewTLSRenewer(cert, nil)
	if err != nil {
		return nil, err
	}

	tlsConfig := getDefaultTLSConfig(sign)
	// Note that GetCertificate will only be called if the client supplies SNI
	// information or if tlsConfig.Certificates is empty.
	// Without tlsConfig.Certificates there's not need to use tlsConfig.BuildNameToCertificate()
	tlsConfig.GetCertificate = renewer.GetCertificate
	tlsConfig.GetClientCertificate = renewer.GetClientCertificate
	tlsConfig.PreferServerCipherSuites = true
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert

	// Apply options and initialize mutable tls.Config
	tlsCtx := newTLSOptionCtx(c, tlsConfig, sign)
	if err := tlsCtx.apply(options); err != nil {
		return nil, err
	}

	// GetConfigForClient allows seamless root and federated roots rotation.
	// If the return of the callback is not-nil, it will use the returned
	// tls.Config instead of the default one.
	tlsConfig.GetConfigForClient = c.buildGetConfigForClient(tlsCtx)

	// Update renew function with transport
	tr, err := getDefaultTransport(tlsConfig)
	if err != nil {
		return nil, err
	}
	// Use mutable tls.Config on renew
	tr.DialTLS = c.buildDialTLS(tlsCtx)
	renewer.RenewCertificate = getRenewFunc(tlsCtx, c, tr, pk)

	// Update client transport
	c.SetTransport(tr)

	// Start renewer
	renewer.RunContext(ctx)
	return tlsConfig, nil
}

// Transport returns an http.Transport configured to use the client certificate from the sign response.
func (c *Client) Transport(ctx context.Context, sign *api.SignResponse, pk crypto.PrivateKey, options ...TLSOption) (*http.Transport, error) {
	_, tr, err := c.getClientTLSConfig(ctx, sign, pk, options)
	if err != nil {
		return nil, err
	}
	return tr, nil
}

// buildGetConfigForClient returns an implementation of GetConfigForClient
// callback in tls.Config.
//
// If the implementation returns a nil tls.Config, the original Config will be
// used, but if it's non-nil, the returned Config will be used to handle this
// connection.
func (c *Client) buildGetConfigForClient(ctx *TLSOptionCtx) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	return func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return ctx.mutableConfig.TLSConfig(), nil
	}
}

// buildDialTLS returns an implementation of DialTLS callback in http.Transport.
func (c *Client) buildDialTLS(ctx *TLSOptionCtx) func(network, addr string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
		return tls.DialWithDialer(&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}, network, addr, ctx.mutableConfig.TLSConfig())
	}
}

// Certificate returns the server or client certificate from the sign response.
func Certificate(sign *api.SignResponse) (*x509.Certificate, error) {
	if sign.ServerPEM.Certificate == nil {
		return nil, errors.New("ca: certificate does not exist")
	}
	return sign.ServerPEM.Certificate, nil
}

// IntermediateCertificate returns the CA intermediate certificate from the sign
// response.
func IntermediateCertificate(sign *api.SignResponse) (*x509.Certificate, error) {
	if sign.CaPEM.Certificate == nil {
		return nil, errors.New("ca: certificate does not exist")
	}
	return sign.CaPEM.Certificate, nil
}

// RootCertificate returns the root certificate from the sign response.
func RootCertificate(sign *api.SignResponse) (*x509.Certificate, error) {
	if sign == nil || sign.TLS == nil || len(sign.TLS.VerifiedChains) == 0 {
		return nil, errors.New("ca: certificate does not exist")
	}
	lastChain := sign.TLS.VerifiedChains[len(sign.TLS.VerifiedChains)-1]
	if len(lastChain) == 0 {
		return nil, errors.New("ca: certificate does not exist")
	}
	return lastChain[len(lastChain)-1], nil
}

// TLSCertificate creates a new TLS certificate from the sign response and the
// private key used.
func TLSCertificate(sign *api.SignResponse, pk crypto.PrivateKey) (*tls.Certificate, error) {
	certPEM, err := getPEM(sign.ServerPEM)
	if err != nil {
		return nil, err
	}
	caPEM, err := getPEM(sign.CaPEM)
	if err != nil {
		return nil, err
	}
	keyPEM, err := getPEM(pk)
	if err != nil {
		return nil, err
	}

	chain := append(certPEM, caPEM...)
	cert, err := tls.X509KeyPair(chain, keyPEM)
	if err != nil {
		return nil, errors.Wrap(err, "error creating tls certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, errors.Wrap(err, "error parsing tls certificate")
	}
	cert.Leaf = leaf
	return &cert, nil
}

func getDefaultTLSConfig(sign *api.SignResponse) *tls.Config {
	if sign.TLSOptions != nil {
		return sign.TLSOptions.TLSConfig()
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
}

// getDefaultTransport returns an http.Transport with the same parameters than
// http.DefaultTransport, but adds the given tls.Config and configures the
// transport for HTTP/2.
func getDefaultTransport(tlsConfig *tls.Config) (*http.Transport, error) {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsConfig,
	}
	if err := http2.ConfigureTransport(tr); err != nil {
		return nil, errors.Wrap(err, "error configuring transport")
	}
	return tr, nil
}

func getPEM(i interface{}) ([]byte, error) {
	block := new(pem.Block)
	switch i := i.(type) {
	case api.Certificate:
		block.Type = "CERTIFICATE"
		block.Bytes = i.Raw
	case *x509.Certificate:
		block.Type = "CERTIFICATE"
		block.Bytes = i.Raw
	case *rsa.PrivateKey:
		block.Type = "RSA PRIVATE KEY"
		block.Bytes = x509.MarshalPKCS1PrivateKey(i)
	case *ecdsa.PrivateKey:
		var err error
		block.Type = "EC PRIVATE KEY"
		block.Bytes, err = x509.MarshalECPrivateKey(i)
		if err != nil {
			return nil, errors.Wrap(err, "error marshaling private key")
		}
	default:
		return nil, errors.Errorf("unsupported key type %T", i)
	}
	return pem.EncodeToMemory(block), nil
}

func getRenewFunc(ctx *TLSOptionCtx, client *Client, tr *http.Transport, pk crypto.PrivateKey) RenewFunc {
	return func() (*tls.Certificate, error) {
		// Get updated list of roots
		if err := ctx.applyRenew(); err != nil {
			return nil, err
		}
		// Get new certificate
		sign, err := client.Renew(tr)
		if err != nil {
			return nil, err
		}
		return TLSCertificate(sign, pk)
	}
}
