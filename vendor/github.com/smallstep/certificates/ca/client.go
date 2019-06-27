package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/cli/config"
	"github.com/smallstep/cli/crypto/x509util"
	"gopkg.in/square/go-jose.v2/jwt"
)

// ClientOption is the type of options passed to the Client constructor.
type ClientOption func(o *clientOptions) error

type clientOptions struct {
	transport    http.RoundTripper
	rootSHA256   string
	rootFilename string
	rootBundle   []byte
}

func (o *clientOptions) apply(opts []ClientOption) (err error) {
	for _, fn := range opts {
		if err = fn(o); err != nil {
			return
		}
	}
	return
}

// checkTransport checks if other ways to set up a transport have been provided.
// If they have it returns an error.
func (o *clientOptions) checkTransport() error {
	if o.transport != nil || o.rootFilename != "" || o.rootSHA256 != "" || o.rootBundle != nil {
		return errors.New("multiple transport methods have been configured")
	}
	return nil
}

// getTransport returns the transport configured in the clientOptions.
func (o *clientOptions) getTransport(endpoint string) (tr http.RoundTripper, err error) {
	if o.transport != nil {
		tr = o.transport
	}
	if o.rootFilename != "" {
		if tr, err = getTransportFromFile(o.rootFilename); err != nil {
			return nil, err
		}
	}
	if o.rootSHA256 != "" {
		if tr, err = getTransportFromSHA256(endpoint, o.rootSHA256); err != nil {
			return nil, err
		}
	}
	if o.rootBundle != nil {
		if tr, err = getTransportFromCABundle(o.rootBundle); err != nil {
			return nil, err
		}
	}
	// As the last option attempt to load the default root ca
	if tr == nil {
		rootFile := getRootCAPath()
		if _, err := os.Stat(rootFile); err == nil {
			if tr, err = getTransportFromFile(rootFile); err != nil {
				return nil, err
			}
			return tr, nil
		}
		return nil, errors.New("a transport, a root cert, or a root sha256 must be used")
	}
	return tr, nil
}

// WithTransport adds a custom transport to the Client.  It will fail if a
// previous option to create the transport has been configured.
func WithTransport(tr http.RoundTripper) ClientOption {
	return func(o *clientOptions) error {
		if err := o.checkTransport(); err != nil {
			return err
		}
		o.transport = tr
		return nil
	}
}

// WithRootFile will create the transport using the given root certificate. It
// will fail if a previous option to create the transport has been configured.
func WithRootFile(filename string) ClientOption {
	return func(o *clientOptions) error {
		if err := o.checkTransport(); err != nil {
			return err
		}
		o.rootFilename = filename
		return nil
	}
}

// WithRootSHA256 will create the transport using an insecure client to retrieve
// the root certificate using its fingerprint. It will fail if a previous option
// to create the transport has been configured.
func WithRootSHA256(sum string) ClientOption {
	return func(o *clientOptions) error {
		if err := o.checkTransport(); err != nil {
			return err
		}
		o.rootSHA256 = sum
		return nil
	}
}

// WithCABundle will create the transport using the given root certificates. It
// will fail if a previous option to create the transport has been configured.
func WithCABundle(bundle []byte) ClientOption {
	return func(o *clientOptions) error {
		if err := o.checkTransport(); err != nil {
			return err
		}
		o.rootBundle = bundle
		return nil
	}
}

func getTransportFromFile(filename string) (http.RoundTripper, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading %s", filename)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.Errorf("error parsing %s: no certificates found", filename)
	}
	return getDefaultTransport(&tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		RootCAs:                  pool,
	})
}

func getTransportFromSHA256(endpoint, sum string) (http.RoundTripper, error) {
	u, err := parseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	client := &Client{endpoint: u}
	root, err := client.Root(sum)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(root.RootPEM.Certificate)
	return getDefaultTransport(&tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		RootCAs:                  pool,
	})
}

func getTransportFromCABundle(bundle []byte) (http.RoundTripper, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundle) {
		return nil, errors.New("error parsing ca bundle: no certificates found")
	}
	return getDefaultTransport(&tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		RootCAs:                  pool,
	})
}

// parseEndpoint parses and validates the given endpoint. It supports general
// URLs like https://ca.smallstep.com[:port][/path], and incomplete URLs like
// ca.smallstep.com[:port][/path].
func parseEndpoint(endpoint string) (*url.URL, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing endpoint '%s'", endpoint)
	}

	// URLs are generally parsed as:
	// [scheme:][//[userinfo@]host][/]path[?query][#fragment]
	// But URLs that do not start with a slash after the scheme are interpreted as
	// scheme:opaque[?query][#fragment]
	if u.Opaque == "" {
		if u.Scheme == "" {
			u.Scheme = "https"
		}
		if u.Host == "" {
			// endpoint looks like ca.smallstep.com or ca.smallstep.com/1.0/sign
			if u.Path != "" {
				parts := strings.SplitN(u.Path, "/", 2)
				u.Host = parts[0]
				if len(parts) == 2 {
					u.Path = parts[1]
				} else {
					u.Path = ""
				}
				return parseEndpoint(u.String())
			}
			return nil, errors.Errorf("error parsing endpoint: url '%s' is not valid", endpoint)
		}
		return u, nil
	}
	// scheme:opaque[?query][#fragment]
	// endpoint looks like ca.smallstep.com:443 or ca.smallstep.com:443/1.0/sign
	return parseEndpoint("https://" + endpoint)
}

// ProvisionerOption is the type of options passed to the Provisioner method.
type ProvisionerOption func(o *provisionerOptions) error

type provisionerOptions struct {
	cursor string
	limit  int
}

func (o *provisionerOptions) apply(opts []ProvisionerOption) (err error) {
	for _, fn := range opts {
		if err = fn(o); err != nil {
			return
		}
	}
	return
}

func (o *provisionerOptions) rawQuery() string {
	v := url.Values{}
	if len(o.cursor) > 0 {
		v.Set("cursor", o.cursor)
	}
	if o.limit > 0 {
		v.Set("limit", strconv.Itoa(o.limit))
	}
	return v.Encode()
}

// WithProvisionerCursor will request the provisioners starting with the given cursor.
func WithProvisionerCursor(cursor string) ProvisionerOption {
	return func(o *provisionerOptions) error {
		o.cursor = cursor
		return nil
	}
}

// WithProvisionerLimit will request the given number of provisioners.
func WithProvisionerLimit(limit int) ProvisionerOption {
	return func(o *provisionerOptions) error {
		o.limit = limit
		return nil
	}
}

// Client implements an HTTP client for the CA server.
type Client struct {
	client   *http.Client
	endpoint *url.URL
}

// NewClient creates a new Client with the given endpoint and options.
func NewClient(endpoint string, opts ...ClientOption) (*Client, error) {
	u, err := parseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	// Retrieve transport from options.
	o := new(clientOptions)
	if err := o.apply(opts); err != nil {
		return nil, err
	}
	tr, err := o.getTransport(endpoint)
	if err != nil {
		return nil, err
	}

	return &Client{
		client: &http.Client{
			Transport: tr,
		},
		endpoint: u,
	}, nil
}

// SetTransport updates the transport of the internal HTTP client.
func (c *Client) SetTransport(tr http.RoundTripper) {
	c.client.Transport = tr
}

// Health performs the health request to the CA and returns the
// api.HealthResponse struct.
func (c *Client) Health() (*api.HealthResponse, error) {
	u := c.endpoint.ResolveReference(&url.URL{Path: "/health"})
	resp, err := c.client.Get(u.String())
	if err != nil {
		return nil, errors.Wrapf(err, "client GET %s failed", u)
	}
	if resp.StatusCode >= 400 {
		return nil, readError(resp.Body)
	}
	var health api.HealthResponse
	if err := readJSON(resp.Body, &health); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return &health, nil
}

// Root performs the root request to the CA with the given SHA256 and returns
// the api.RootResponse struct. It uses an insecure client, but it checks the
// resulting root certificate with the given SHA256, returning an error if they
// do not match.
func (c *Client) Root(sha256Sum string) (*api.RootResponse, error) {
	sha256Sum = strings.ToLower(strings.Replace(sha256Sum, "-", "", -1))
	u := c.endpoint.ResolveReference(&url.URL{Path: "/root/" + sha256Sum})
	resp, err := getInsecureClient().Get(u.String())
	if err != nil {
		return nil, errors.Wrapf(err, "client GET %s failed", u)
	}
	if resp.StatusCode >= 400 {
		return nil, readError(resp.Body)
	}
	var root api.RootResponse
	if err := readJSON(resp.Body, &root); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	// verify the sha256
	sum := sha256.Sum256(root.RootPEM.Raw)
	if sha256Sum != strings.ToLower(hex.EncodeToString(sum[:])) {
		return nil, errors.New("root certificate SHA256 fingerprint do not match")
	}
	return &root, nil
}

// Sign performs the sign request to the CA and returns the api.SignResponse
// struct.
func (c *Client) Sign(req *api.SignRequest) (*api.SignResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling request")
	}
	u := c.endpoint.ResolveReference(&url.URL{Path: "/sign"})
	resp, err := c.client.Post(u.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, errors.Wrapf(err, "client POST %s failed", u)
	}
	if resp.StatusCode >= 400 {
		return nil, readError(resp.Body)
	}
	var sign api.SignResponse
	if err := readJSON(resp.Body, &sign); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	// Add tls.ConnectionState:
	// We'll extract the root certificate from the verified chains
	sign.TLS = resp.TLS
	return &sign, nil
}

// Renew performs the renew request to the CA and returns the api.SignResponse
// struct.
func (c *Client) Renew(tr http.RoundTripper) (*api.SignResponse, error) {
	u := c.endpoint.ResolveReference(&url.URL{Path: "/renew"})
	client := &http.Client{Transport: tr}
	resp, err := client.Post(u.String(), "application/json", http.NoBody)
	if err != nil {
		return nil, errors.Wrapf(err, "client POST %s failed", u)
	}
	if resp.StatusCode >= 400 {
		return nil, readError(resp.Body)
	}
	var sign api.SignResponse
	if err := readJSON(resp.Body, &sign); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return &sign, nil
}

// Revoke performs the revoke request to the CA and returns the api.RevokeResponse
// struct.
func (c *Client) Revoke(req *api.RevokeRequest, tr http.RoundTripper) (*api.RevokeResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling request")
	}

	var client *http.Client
	if tr != nil {
		client = &http.Client{Transport: tr}
	} else {
		client = c.client
	}

	u := c.endpoint.ResolveReference(&url.URL{Path: "/revoke"})
	resp, err := client.Post(u.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, errors.Wrapf(err, "client POST %s failed", u)
	}
	if resp.StatusCode >= 400 {
		return nil, readError(resp.Body)
	}
	var revoke api.RevokeResponse
	if err := readJSON(resp.Body, &revoke); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return &revoke, nil
}

// Provisioners performs the provisioners request to the CA and returns the
// api.ProvisionersResponse struct with a map of provisioners.
//
// ProvisionerOption WithProvisionerCursor and WithProvisionLimit can be used to
// paginate the provisioners.
func (c *Client) Provisioners(opts ...ProvisionerOption) (*api.ProvisionersResponse, error) {
	o := new(provisionerOptions)
	if err := o.apply(opts); err != nil {
		return nil, err
	}
	u := c.endpoint.ResolveReference(&url.URL{
		Path:     "/provisioners",
		RawQuery: o.rawQuery(),
	})
	resp, err := c.client.Get(u.String())
	if err != nil {
		return nil, errors.Wrapf(err, "client GET %s failed", u)
	}
	if resp.StatusCode >= 400 {
		return nil, readError(resp.Body)
	}
	var provisioners api.ProvisionersResponse
	if err := readJSON(resp.Body, &provisioners); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return &provisioners, nil
}

// ProvisionerKey performs the request to the CA to get the encrypted key for
// the given provisioner kid and returns the api.ProvisionerKeyResponse struct
// with the encrypted key.
func (c *Client) ProvisionerKey(kid string) (*api.ProvisionerKeyResponse, error) {
	u := c.endpoint.ResolveReference(&url.URL{Path: "/provisioners/" + kid + "/encrypted-key"})
	resp, err := c.client.Get(u.String())
	if err != nil {
		return nil, errors.Wrapf(err, "client GET %s failed", u)
	}
	if resp.StatusCode >= 400 {
		return nil, readError(resp.Body)
	}
	var key api.ProvisionerKeyResponse
	if err := readJSON(resp.Body, &key); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return &key, nil
}

// Roots performs the get roots request to the CA and returns the
// api.RootsResponse struct.
func (c *Client) Roots() (*api.RootsResponse, error) {
	u := c.endpoint.ResolveReference(&url.URL{Path: "/roots"})
	resp, err := c.client.Get(u.String())
	if err != nil {
		return nil, errors.Wrapf(err, "client GET %s failed", u)
	}
	if resp.StatusCode >= 400 {
		return nil, readError(resp.Body)
	}
	var roots api.RootsResponse
	if err := readJSON(resp.Body, &roots); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return &roots, nil
}

// Federation performs the get federation request to the CA and returns the
// api.FederationResponse struct.
func (c *Client) Federation() (*api.FederationResponse, error) {
	u := c.endpoint.ResolveReference(&url.URL{Path: "/federation"})
	resp, err := c.client.Get(u.String())
	if err != nil {
		return nil, errors.Wrapf(err, "client GET %s failed", u)
	}
	if resp.StatusCode >= 400 {
		return nil, readError(resp.Body)
	}
	var federation api.FederationResponse
	if err := readJSON(resp.Body, &federation); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", u)
	}
	return &federation, nil
}

// RootFingerprint is a helper method that returns the current root fingerprint.
// It does an health connection and gets the fingerprint from the TLS verified
// chains.
func (c *Client) RootFingerprint() (string, error) {
	u := c.endpoint.ResolveReference(&url.URL{Path: "/health"})
	resp, err := c.client.Get(u.String())
	if err != nil {
		return "", errors.Wrapf(err, "client GET %s failed", u)
	}
	if resp.TLS == nil || len(resp.TLS.VerifiedChains) == 0 {
		return "", errors.New("missing verified chains")
	}
	lastChain := resp.TLS.VerifiedChains[len(resp.TLS.VerifiedChains)-1]
	if len(lastChain) == 0 {
		return "", errors.New("missing verified chains")
	}
	return x509util.Fingerprint(lastChain[len(lastChain)-1]), nil
}

// CreateSignRequest is a helper function that given an x509 OTT returns a
// simple but secure sign request as well as the private key used.
func CreateSignRequest(ott string) (*api.SignRequest, crypto.PrivateKey, error) {
	token, err := jwt.ParseSigned(ott)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error parsing ott")
	}
	var claims authority.Claims
	if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, nil, errors.Wrap(err, "error parsing ott")
	}

	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error generating key")
	}

	var emails []string
	dnsNames, ips := x509util.SplitSANs(claims.SANs)
	if claims.Email != "" {
		emails = append(emails, claims.Email)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: claims.Subject,
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		DNSNames:           dnsNames,
		IPAddresses:        ips,
		EmailAddresses:     emails,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, template, pk)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error creating certificate request")
	}
	cr, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error parsing certificate request")
	}
	if err := cr.CheckSignature(); err != nil {
		return nil, nil, errors.Wrap(err, "error signing certificate request")
	}
	return &api.SignRequest{
		CsrPEM: api.CertificateRequest{CertificateRequest: cr},
		OTT:    ott,
	}, pk, nil
}

func getInsecureClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// getRootCAPath returns the path where the root CA is stored based on the
// STEPPATH environment variable.
func getRootCAPath() string {
	return filepath.Join(config.StepPath(), "certs", "root_ca.crt")
}

func readJSON(r io.ReadCloser, v interface{}) error {
	defer r.Close()
	return json.NewDecoder(r).Decode(v)
}

func readError(r io.ReadCloser) error {
	defer r.Close()
	apiErr := new(api.Error)
	if err := json.NewDecoder(r).Decode(apiErr); err != nil {
		return err
	}
	return apiErr
}
