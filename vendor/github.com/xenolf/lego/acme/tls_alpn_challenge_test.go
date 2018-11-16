package acme

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTLSALPNChallenge(t *testing.T) {
	domain := "localhost:23457"

	mockValidate := func(_ *jws, _, _ string, chlng challenge) error {
		conn, err := tls.Dial("tcp", domain, &tls.Config{
			InsecureSkipVerify: true,
		})
		require.NoError(t, err, "Expected to connect to challenge server without an error")

		// Expect the server to only return one certificate
		connState := conn.ConnectionState()
		assert.Len(t, connState.PeerCertificates, 1, "Expected the challenge server to return exactly one certificate")

		remoteCert := connState.PeerCertificates[0]
		assert.Len(t, remoteCert.DNSNames, 1, "Expected the challenge certificate to have exactly one DNSNames entry")
		assert.Equal(t, domain, remoteCert.DNSNames[0], "challenge certificate DNSName ")
		assert.NotEmpty(t, remoteCert.Extensions, "Expected the challenge certificate to contain extensions")

		idx := -1
		for i, ext := range remoteCert.Extensions {
			if idPeAcmeIdentifierV1.Equal(ext.Id) {
				idx = i
				break
			}
		}

		require.NotEqual(t, -1, idx, "Expected the challenge certificate to contain an extension with the id-pe-acmeIdentifier id,")

		ext := remoteCert.Extensions[idx]
		assert.True(t, ext.Critical, "Expected the challenge certificate id-pe-acmeIdentifier extension to be marked as critical")

		zBytes := sha256.Sum256([]byte(chlng.KeyAuthorization))
		value, err := asn1.Marshal(zBytes[:sha256.Size])
		require.NoError(t, err, "Expected marshaling of the keyAuth to return no error")

		if subtle.ConstantTimeCompare(value[:], ext.Value) != 1 {
			t.Errorf("Expected the challenge certificate id-pe-acmeIdentifier extension to contain the SHA-256 digest of the keyAuth, %v, but was %v", zBytes[:], ext.Value)
		}

		return nil
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 512)
	require.NoError(t, err, "Could not generate test key")

	solver := &tlsALPNChallenge{
		jws:      &jws{privKey: privKey},
		validate: mockValidate,
		provider: &TLSALPNProviderServer{port: "23457"},
	}

	clientChallenge := challenge{Type: string(TLSALPN01), Token: "tlsalpn1"}

	err = solver.Solve(clientChallenge, domain)
	require.NoError(t, err)
}

func TestTLSALPNChallengeInvalidPort(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 128)
	require.NoError(t, err, "Could not generate test key")

	solver := &tlsALPNChallenge{
		jws:      &jws{privKey: privKey},
		validate: stubValidate,
		provider: &TLSALPNProviderServer{port: "123456"},
	}

	clientChallenge := challenge{Type: string(TLSALPN01), Token: "tlsalpn1"}

	err = solver.Solve(clientChallenge, "localhost:123456")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid port")
	assert.Contains(t, err.Error(), "123456")
}
