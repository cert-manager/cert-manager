package webroot

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPProvider(t *testing.T) {
	webroot := "webroot"
	domain := "domain"
	token := "token"
	keyAuth := "keyAuth"
	challengeFilePath := webroot + "/.well-known/acme-challenge/" + token

	require.NoError(t, os.MkdirAll(webroot+"/.well-known/acme-challenge", 0777))
	defer os.RemoveAll(webroot)

	provider, err := NewHTTPProvider(webroot)
	require.NoError(t, err)

	err = provider.Present(domain, token, keyAuth)
	require.NoError(t, err)

	if _, err = os.Stat(challengeFilePath); os.IsNotExist(err) {
		t.Error("Challenge file was not created in webroot")
	}

	var data []byte
	data, err = ioutil.ReadFile(challengeFilePath)
	require.NoError(t, err)

	dataStr := string(data)
	assert.Equal(t, keyAuth, dataStr)

	err = provider.CleanUp(domain, token, keyAuth)
	require.NoError(t, err)
}
