package api

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/logging"
	"github.com/smallstep/cli/crypto/tlsutil"
)

// Authority is the interface implemented by a CA authority.
type Authority interface {
	// NOTE: Authorize will be deprecated in future releases. Please use the
	// context specific Authoirize[Sign|Revoke|etc.] methods.
	Authorize(ott string) ([]provisioner.SignOption, error)
	AuthorizeSign(ott string) ([]provisioner.SignOption, error)
	GetTLSOptions() *tlsutil.TLSOptions
	Root(shasum string) (*x509.Certificate, error)
	Sign(cr *x509.CertificateRequest, opts provisioner.Options, signOpts ...provisioner.SignOption) (*x509.Certificate, *x509.Certificate, error)
	Renew(peer *x509.Certificate) (*x509.Certificate, *x509.Certificate, error)
	LoadProvisionerByCertificate(*x509.Certificate) (provisioner.Interface, error)
	GetProvisioners(cursor string, limit int) (provisioner.List, string, error)
	Revoke(*authority.RevokeOptions) error
	GetEncryptedKey(kid string) (string, error)
	GetRoots() (federation []*x509.Certificate, err error)
	GetFederation() ([]*x509.Certificate, error)
}

// TimeDuration is an alias of provisioner.TimeDuration
type TimeDuration = provisioner.TimeDuration

// NewTimeDuration returns a TimeDuration with the defined time.
func NewTimeDuration(t time.Time) TimeDuration {
	return provisioner.NewTimeDuration(t)
}

// ParseTimeDuration returns a new TimeDuration parsing the RFC 3339 time or
// time.Duration string.
func ParseTimeDuration(s string) (TimeDuration, error) {
	return provisioner.ParseTimeDuration(s)
}

// Certificate wraps a *x509.Certificate and adds the json.Marshaler interface.
type Certificate struct {
	*x509.Certificate
}

// NewCertificate is a helper method that returns a Certificate from a
// *x509.Certificate.
func NewCertificate(cr *x509.Certificate) Certificate {
	return Certificate{
		Certificate: cr,
	}
}

// MarshalJSON implements the json.Marshaler interface. The certificate is
// quoted string using the PEM encoding.
func (c Certificate) MarshalJSON() ([]byte, error) {
	if c.Certificate == nil {
		return []byte("null"), nil
	}
	block := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Raw,
	})
	return json.Marshal(string(block))
}

// UnmarshalJSON implements the json.Unmarshaler interface. The certificate is
// expected to be a quoted string using the PEM encoding.
func (c *Certificate) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return errors.Wrap(err, "error decoding certificate")
	}
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return errors.New("error decoding certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.Wrap(err, "error decoding certificate")
	}
	c.Certificate = cert
	return nil
}

// CertificateRequest wraps a *x509.CertificateRequest and adds the
// json.Unmarshaler interface.
type CertificateRequest struct {
	*x509.CertificateRequest
}

// NewCertificateRequest is a helper method that returns a CertificateRequest
// from a *x509.CertificateRequest.
func NewCertificateRequest(cr *x509.CertificateRequest) CertificateRequest {
	return CertificateRequest{
		CertificateRequest: cr,
	}
}

// MarshalJSON implements the json.Marshaler interface. The certificate request
// is a quoted string using the PEM encoding.
func (c CertificateRequest) MarshalJSON() ([]byte, error) {
	if c.CertificateRequest == nil {
		return []byte("null"), nil
	}
	block := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: c.Raw,
	})
	return json.Marshal(string(block))
}

// UnmarshalJSON implements the json.Unmarshaler interface. The certificate
// request is expected to be a quoted string using the PEM encoding.
func (c *CertificateRequest) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return errors.Wrap(err, "error decoding csr")
	}
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return errors.New("error decoding csr")
	}
	cr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return errors.Wrap(err, "error decoding csr")
	}
	c.CertificateRequest = cr
	return nil
}

// Router defines a common router interface.
type Router interface {
	// MethodFunc adds routes for `pattern` that matches
	// the `method` HTTP method.
	MethodFunc(method, pattern string, h http.HandlerFunc)
}

// RouterHandler is the interface that a HTTP handler that manages multiple
// endpoints will implement.
type RouterHandler interface {
	Route(r Router)
}

// HealthResponse is the response object that returns the health of the server.
type HealthResponse struct {
	Status string `json:"status"`
}

// RootResponse is the response object that returns the PEM of a root certificate.
type RootResponse struct {
	RootPEM Certificate `json:"ca"`
}

// SignRequest is the request body for a certificate signature request.
type SignRequest struct {
	CsrPEM    CertificateRequest `json:"csr"`
	OTT       string             `json:"ott"`
	NotAfter  TimeDuration       `json:"notAfter"`
	NotBefore TimeDuration       `json:"notBefore"`
}

// ProvisionersResponse is the response object that returns the list of
// provisioners.
type ProvisionersResponse struct {
	Provisioners provisioner.List `json:"provisioners"`
	NextCursor   string           `json:"nextCursor"`
}

// ProvisionerKeyResponse is the response object that returns the encrypted key
// of a provisioner.
type ProvisionerKeyResponse struct {
	Key string `json:"key"`
}

// Validate checks the fields of the SignRequest and returns nil if they are ok
// or an error if something is wrong.
func (s *SignRequest) Validate() error {
	if s.CsrPEM.CertificateRequest == nil {
		return BadRequest(errors.New("missing csr"))
	}
	if err := s.CsrPEM.CertificateRequest.CheckSignature(); err != nil {
		return BadRequest(errors.Wrap(err, "invalid csr"))
	}
	if s.OTT == "" {
		return BadRequest(errors.New("missing ott"))
	}

	return nil
}

// SignResponse is the response object of the certificate signature request.
type SignResponse struct {
	ServerPEM  Certificate          `json:"crt"`
	CaPEM      Certificate          `json:"ca"`
	TLSOptions *tlsutil.TLSOptions  `json:"tlsOptions,omitempty"`
	TLS        *tls.ConnectionState `json:"-"`
}

// RootsResponse is the response object of the roots request.
type RootsResponse struct {
	Certificates []Certificate `json:"crts"`
}

// FederationResponse is the response object of the federation request.
type FederationResponse struct {
	Certificates []Certificate `json:"crts"`
}

// caHandler is the type used to implement the different CA HTTP endpoints.
type caHandler struct {
	Authority Authority
}

// New creates a new RouterHandler with the CA endpoints.
func New(authority Authority) RouterHandler {
	return &caHandler{
		Authority: authority,
	}
}

func (h *caHandler) Route(r Router) {
	r.MethodFunc("GET", "/health", h.Health)
	r.MethodFunc("GET", "/root/{sha}", h.Root)
	r.MethodFunc("POST", "/sign", h.Sign)
	r.MethodFunc("POST", "/renew", h.Renew)
	r.MethodFunc("POST", "/revoke", h.Revoke)
	r.MethodFunc("GET", "/provisioners", h.Provisioners)
	r.MethodFunc("GET", "/provisioners/{kid}/encrypted-key", h.ProvisionerKey)
	r.MethodFunc("GET", "/roots", h.Roots)
	r.MethodFunc("GET", "/federation", h.Federation)
	// For compatibility with old code:
	r.MethodFunc("POST", "/re-sign", h.Renew)
}

// Health is an HTTP handler that returns the status of the server.
func (h *caHandler) Health(w http.ResponseWriter, r *http.Request) {
	JSON(w, HealthResponse{Status: "ok"})
}

// Root is an HTTP handler that using the SHA256 from the URL, returns the root
// certificate for the given SHA256.
func (h *caHandler) Root(w http.ResponseWriter, r *http.Request) {
	sha := chi.URLParam(r, "sha")
	sum := strings.ToLower(strings.Replace(sha, "-", "", -1))
	// Load root certificate with the
	cert, err := h.Authority.Root(sum)
	if err != nil {
		WriteError(w, NotFound(errors.Wrapf(err, "%s was not found", r.RequestURI)))
		return
	}

	JSON(w, &RootResponse{RootPEM: Certificate{cert}})
}

// Sign is an HTTP handler that reads a certificate request and an
// one-time-token (ott) from the body and creates a new certificate with the
// information in the certificate request.
func (h *caHandler) Sign(w http.ResponseWriter, r *http.Request) {
	var body SignRequest
	if err := ReadJSON(r.Body, &body); err != nil {
		WriteError(w, BadRequest(errors.Wrap(err, "error reading request body")))
		return
	}

	logOtt(w, body.OTT)
	if err := body.Validate(); err != nil {
		WriteError(w, err)
		return
	}

	opts := provisioner.Options{
		NotBefore: body.NotBefore,
		NotAfter:  body.NotAfter,
	}

	signOpts, err := h.Authority.AuthorizeSign(body.OTT)
	if err != nil {
		WriteError(w, Unauthorized(err))
		return
	}

	cert, root, err := h.Authority.Sign(body.CsrPEM.CertificateRequest, opts, signOpts...)
	if err != nil {
		WriteError(w, Forbidden(err))
		return
	}

	w.WriteHeader(http.StatusCreated)
	logCertificate(w, cert)
	JSON(w, &SignResponse{
		ServerPEM:  Certificate{cert},
		CaPEM:      Certificate{root},
		TLSOptions: h.Authority.GetTLSOptions(),
	})
}

// Renew uses the information of certificate in the TLS connection to create a
// new one.
func (h *caHandler) Renew(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		WriteError(w, BadRequest(errors.New("missing peer certificate")))
		return
	}

	cert, root, err := h.Authority.Renew(r.TLS.PeerCertificates[0])
	if err != nil {
		WriteError(w, Forbidden(err))
		return
	}

	w.WriteHeader(http.StatusCreated)
	logCertificate(w, cert)
	JSON(w, &SignResponse{
		ServerPEM:  Certificate{cert},
		CaPEM:      Certificate{root},
		TLSOptions: h.Authority.GetTLSOptions(),
	})
}

// Provisioners returns the list of provisioners configured in the authority.
func (h *caHandler) Provisioners(w http.ResponseWriter, r *http.Request) {
	cursor, limit, err := parseCursor(r)
	if err != nil {
		WriteError(w, BadRequest(err))
		return
	}

	p, next, err := h.Authority.GetProvisioners(cursor, limit)
	if err != nil {
		WriteError(w, InternalServerError(err))
		return
	}
	JSON(w, &ProvisionersResponse{
		Provisioners: p,
		NextCursor:   next,
	})
}

// ProvisionerKey returns the encrypted key of a provisioner by it's key id.
func (h *caHandler) ProvisionerKey(w http.ResponseWriter, r *http.Request) {
	kid := chi.URLParam(r, "kid")
	key, err := h.Authority.GetEncryptedKey(kid)
	if err != nil {
		WriteError(w, NotFound(err))
		return
	}
	JSON(w, &ProvisionerKeyResponse{key})
}

// Roots returns all the root certificates for the CA.
func (h *caHandler) Roots(w http.ResponseWriter, r *http.Request) {
	roots, err := h.Authority.GetRoots()
	if err != nil {
		WriteError(w, Forbidden(err))
		return
	}

	certs := make([]Certificate, len(roots))
	for i := range roots {
		certs[i] = Certificate{roots[i]}
	}

	w.WriteHeader(http.StatusCreated)
	JSON(w, &RootsResponse{
		Certificates: certs,
	})
}

// Federation returns all the public certificates in the federation.
func (h *caHandler) Federation(w http.ResponseWriter, r *http.Request) {
	federated, err := h.Authority.GetFederation()
	if err != nil {
		WriteError(w, Forbidden(err))
		return
	}

	certs := make([]Certificate, len(federated))
	for i := range federated {
		certs[i] = Certificate{federated[i]}
	}

	w.WriteHeader(http.StatusCreated)
	JSON(w, &FederationResponse{
		Certificates: certs,
	})
}

var oidStepProvisioner = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1}

type stepProvisioner struct {
	Type         int
	Name         []byte
	CredentialID []byte
}

func logOtt(w http.ResponseWriter, token string) {
	if rl, ok := w.(logging.ResponseLogger); ok {
		rl.WithFields(map[string]interface{}{
			"ott": token,
		})
	}
}

func logCertificate(w http.ResponseWriter, cert *x509.Certificate) {
	if rl, ok := w.(logging.ResponseLogger); ok {
		m := map[string]interface{}{
			"serial":      cert.SerialNumber,
			"subject":     cert.Subject.CommonName,
			"issuer":      cert.Issuer.CommonName,
			"valid-from":  cert.NotBefore.Format(time.RFC3339),
			"valid-to":    cert.NotAfter.Format(time.RFC3339),
			"public-key":  fmtPublicKey(cert),
			"certificate": base64.StdEncoding.EncodeToString(cert.Raw),
		}
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(oidStepProvisioner) {
				val := &stepProvisioner{}
				rest, err := asn1.Unmarshal(ext.Value, val)
				if err != nil || len(rest) > 0 {
					break
				}
				m["provisioner"] = fmt.Sprintf("%s (%s)", val.Name, val.CredentialID)
				break
			}
		}
		rl.WithFields(m)
	}
}

func parseCursor(r *http.Request) (cursor string, limit int, err error) {
	q := r.URL.Query()
	cursor = q.Get("cursor")
	if v := q.Get("limit"); len(v) > 0 {
		limit, err = strconv.Atoi(v)
		if err != nil {
			return "", 0, errors.Wrapf(err, "error converting %s to integer", v)
		}
	}
	return
}

// TODO: add support for Ed25519 once it's supported
func fmtPublicKey(cert *x509.Certificate) string {
	var params string
	switch pk := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		params = pk.Curve.Params().Name
	case *rsa.PublicKey:
		params = strconv.Itoa(pk.Size() * 8)
	case *dsa.PublicKey:
		params = strconv.Itoa(pk.Q.BitLen() * 8)
	default:
		params = "unknown"
	}
	return fmt.Sprintf("%s %s", cert.PublicKeyAlgorithm, params)
}
