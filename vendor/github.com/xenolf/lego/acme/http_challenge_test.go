package acme

import (
	"crypto/rand"
	"crypto/rsa"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPChallenge(t *testing.T) {
	mockValidate := func(_ *jws, _, _ string, chlng challenge) error {
		uri := "http://localhost:23457/.well-known/acme-challenge/" + chlng.Token
		resp, err := httpGet(uri)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if want := "text/plain"; resp.Header.Get("Content-Type") != want {
			t.Errorf("Get(%q) Content-Type: got %q, want %q", uri, resp.Header.Get("Content-Type"), want)
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		bodyStr := string(body)

		if bodyStr != chlng.KeyAuthorization {
			t.Errorf("Get(%q) Body: got %q, want %q", uri, bodyStr, chlng.KeyAuthorization)
		}

		return nil
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 512)
	require.NoError(t, err, "Could not generate test key")

	solver := &httpChallenge{
		jws:      &jws{privKey: privKey},
		validate: mockValidate,
		provider: &HTTPProviderServer{port: "23457"},
	}

	clientChallenge := challenge{Type: string(HTTP01), Token: "http1"}

	err = solver.Solve(clientChallenge, "localhost:23457")
	require.NoError(t, err)
}

func TestHTTPChallengeInvalidPort(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 128)
	require.NoError(t, err, "Could not generate test key")

	solver := &httpChallenge{
		jws:      &jws{privKey: privKey},
		validate: stubValidate,
		provider: &HTTPProviderServer{port: "123456"},
	}

	clientChallenge := challenge{Type: string(HTTP01), Token: "http2"}

	err = solver.Solve(clientChallenge, "localhost:123456")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid port")
	assert.Contains(t, err.Error(), "123456")
}
