package acme

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratePrivateKey(t *testing.T) {
	key, err := generatePrivateKey(RSA2048)
	require.NoError(t, err, "Error generating private key")

	assert.NotNil(t, key)
}

func TestGenerateCSR(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 512)
	require.NoError(t, err, "Error generating private key")

	csr, err := generateCsr(key, "fizz.buzz", nil, true)
	require.NoError(t, err, "Error generating CSR")

	assert.NotEmpty(t, csr)
}

func TestPEMEncode(t *testing.T) {
	buf := bytes.NewBufferString("TestingRSAIsSoMuchFun")

	reader := MockRandReader{b: buf}
	key, err := rsa.GenerateKey(reader, 32)
	require.NoError(t, err, "Error generating private key")

	data := pemEncode(key)
	require.NotNil(t, data)
	assert.Len(t, data, 127)
}

func TestPEMCertExpiration(t *testing.T) {
	privKey, err := generatePrivateKey(RSA2048)
	require.NoError(t, err, "Error generating private key")

	expiration := time.Now().Add(365)
	expiration = expiration.Round(time.Second)
	certBytes, err := generateDerCert(privKey.(*rsa.PrivateKey), expiration, "test.com", nil)
	require.NoError(t, err, "Error generating cert")

	buf := bytes.NewBufferString("TestingRSAIsSoMuchFun")

	// Some random string should return an error.
	ctime, err := GetPEMCertExpiration(buf.Bytes())
	require.Errorf(t, err, "Expected getCertExpiration to return an error for garbage string but returned %v", ctime)

	// A DER encoded certificate should return an error.
	_, err = GetPEMCertExpiration(certBytes)
	require.Error(t, err, "Expected getCertExpiration to return an error for DER certificates")

	// A PEM encoded certificate should work ok.
	pemCert := pemEncode(derCertificateBytes(certBytes))
	ctime, err = GetPEMCertExpiration(pemCert)
	require.NoError(t, err)

	assert.Equal(t, expiration.UTC(), ctime)
}

type MockRandReader struct {
	b *bytes.Buffer
}

func (r MockRandReader) Read(p []byte) (int, error) {
	return r.b.Read(p)
}
