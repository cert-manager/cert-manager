package api

import (
	"net/http"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/logging"
	"golang.org/x/crypto/ocsp"
)

// RevokeResponse is the response object that returns the health of the server.
type RevokeResponse struct {
	Status string `json:"status"`
}

// RevokeRequest is the request body for a revocation request.
type RevokeRequest struct {
	Serial     string `json:"serial"`
	OTT        string `json:"ott"`
	ReasonCode int    `json:"reasonCode"`
	Reason     string `json:"reason"`
	Passive    bool   `json:"passive"`
}

// Validate checks the fields of the RevokeRequest and returns nil if they are ok
// or an error if something is wrong.
func (r *RevokeRequest) Validate() (err error) {
	if r.Serial == "" {
		return BadRequest(errors.New("missing serial"))
	}
	if r.ReasonCode < ocsp.Unspecified || r.ReasonCode > ocsp.AACompromise {
		return BadRequest(errors.New("reasonCode out of bounds"))
	}
	if !r.Passive {
		return NotImplemented(errors.New("non-passive revocation not implemented"))
	}

	return
}

// Revoke supports handful of different methods that revoke a Certificate.
//
// NOTE: currently only Passive revocation is supported.
//
// TODO: Add CRL and OCSP support.
func (h *caHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	var body RevokeRequest
	if err := ReadJSON(r.Body, &body); err != nil {
		WriteError(w, BadRequest(errors.Wrap(err, "error reading request body")))
		return
	}

	if err := body.Validate(); err != nil {
		WriteError(w, err)
		return
	}

	opts := &authority.RevokeOptions{
		Serial:      body.Serial,
		Reason:      body.Reason,
		ReasonCode:  body.ReasonCode,
		PassiveOnly: body.Passive,
	}

	// A token indicates that we are using the api via a provisioner token,
	// otherwise it is assumed that the certificate is revoking itself over mTLS.
	if len(body.OTT) > 0 {
		logOtt(w, body.OTT)
		opts.OTT = body.OTT
	} else {
		// If no token is present, then the request must be made over mTLS and
		// the client certificate Serial Number must match the serial number
		// being revoked.
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			WriteError(w, BadRequest(errors.New("missing ott or peer certificate")))
			return
		}
		opts.Crt = r.TLS.PeerCertificates[0]
		logCertificate(w, opts.Crt)
		opts.MTLS = true
	}

	if err := h.Authority.Revoke(opts); err != nil {
		WriteError(w, Forbidden(err))
		return
	}

	logRevoke(w, opts)

	w.WriteHeader(http.StatusOK)
	JSON(w, &RevokeResponse{Status: "ok"})
}

func logRevoke(w http.ResponseWriter, ri *authority.RevokeOptions) {
	if rl, ok := w.(logging.ResponseLogger); ok {
		rl.WithFields(map[string]interface{}{
			"serial":      ri.Serial,
			"reasonCode":  ri.ReasonCode,
			"reason":      ri.Reason,
			"passiveOnly": ri.PassiveOnly,
			"mTLS":        ri.MTLS,
		})
	}
}
