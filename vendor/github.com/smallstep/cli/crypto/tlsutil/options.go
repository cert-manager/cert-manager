package tlsutil

import (
	"crypto/tls"

	"github.com/smallstep/cli/crypto/x509util"
)

// TLSOptions represents the TLS options that can be specified on *tls.Config
// types to configure HTTPS servers and clients.
type TLSOptions struct {
	CipherSuites  x509util.CipherSuites `json:"cipherSuites" step:"cipherSuites"`
	MinVersion    x509util.TLSVersion   `json:"minVersion"   step:"minVersion"`
	MaxVersion    x509util.TLSVersion   `json:"maxVersion"   step:"maxVersion"`
	Renegotiation bool                  `json:"renegotiation" step:"renegotiation"`
}

// TLSConfig returns the tls.Config equivalent of the TLSOptions.
func (t *TLSOptions) TLSConfig() *tls.Config {
	var rs tls.RenegotiationSupport
	if t.Renegotiation {
		rs = tls.RenegotiateFreelyAsClient
	} else {
		rs = tls.RenegotiateNever
	}

	return &tls.Config{
		CipherSuites:  t.CipherSuites.Value(),
		MinVersion:    t.MinVersion.Value(),
		MaxVersion:    t.MaxVersion.Value(),
		Renegotiation: rs,
	}
}
