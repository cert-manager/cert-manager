package acme

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPUserAgent(t *testing.T) {
	var ua, method string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
		method = r.Method
	}))
	defer ts.Close()

	testCases := []struct {
		method string
		call   func(u string) (resp *http.Response, err error)
	}{
		{
			method: http.MethodGet,
			call:   httpGet,
		},
		{
			method: http.MethodHead,
			call:   httpHead,
		},
		{
			method: http.MethodPost,
			call: func(u string) (resp *http.Response, err error) {
				return httpPost(u, "text/plain", strings.NewReader("falalalala"))
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.method, func(t *testing.T) {

			_, err := test.call(ts.URL)
			require.NoError(t, err)

			assert.Equal(t, test.method, method)
			assert.Contains(t, ua, ourUserAgent, "User-Agent")
		})
	}
}

func TestUserAgent(t *testing.T) {
	ua := userAgent()

	assert.Contains(t, ua, defaultGoUserAgent)
	assert.Contains(t, ua, ourUserAgent)
	if strings.HasSuffix(ua, " ") {
		t.Errorf("UA should not have trailing spaces; got '%s'", ua)
	}

	// customize the UA by appending a value
	UserAgent = "MyApp/1.2.3"
	ua = userAgent()

	assert.Contains(t, ua, defaultGoUserAgent)
	assert.Contains(t, ua, ourUserAgent)
	assert.Contains(t, ua, UserAgent)
}

// TestInitCertPool tests the http.go initCertPool function for customizing the
// HTTP Client *x509.CertPool with an environment variable.
func TestInitCertPool(t *testing.T) {
	// writeTemp creates a temp file with the given contents & prefix and returns
	// the file path. If an error occurs, t.Fatalf is called to end the test run.
	writeTemp := func(t *testing.T, contents, prefix string) string {
		t.Helper()
		tmpFile, err := ioutil.TempFile("", prefix)
		if err != nil {
			t.Fatalf("Unable to create tempfile: %v", err)
		}
		err = ioutil.WriteFile(tmpFile.Name(), []byte(contents), 0700)
		if err != nil {
			t.Fatalf("Unable to write tempfile contents: %v", err)
		}
		return tmpFile.Name()
	}

	invalidFileContents := "not a certificate"
	invalidFile := writeTemp(t, invalidFileContents, "invalid.pem")

	// validFileContents is lifted from Pebble[0]. Generate your own CA cert with
	// MiniCA[1].
	// [0]: https://github.com/letsencrypt/pebble/blob/de6fa233ea1f283eeb9751d42c8e1ae72718c44e/test/certs/pebble.minica.pem
	// [1]: https://github.com/jsha/minica
	validFileContents := `
-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIIJOLbes8sTr4wDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UE
AxMVbWluaWNhIHJvb3QgY2EgMjRlMmRiMCAXDTE3MTIwNjE5NDIxMFoYDzIxMTcx
MjA2MTk0MjEwWjAgMR4wHAYDVQQDExVtaW5pY2Egcm9vdCBjYSAyNGUyZGIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC5WgZNoVJandj43kkLyU50vzCZ
alozvdRo3OFiKoDtmqKPNWRNO2hC9AUNxTDJco51Yc42u/WV3fPbbhSznTiOOVtn
Ajm6iq4I5nZYltGGZetGDOQWr78y2gWY+SG078MuOO2hyDIiKtVc3xiXYA+8Hluu
9F8KbqSS1h55yxZ9b87eKR+B0zu2ahzBCIHKmKWgc6N13l7aDxxY3D6uq8gtJRU0
toumyLbdzGcupVvjbjDP11nl07RESDWBLG1/g3ktJvqIa4BWgU2HMh4rND6y8OD3
Hy3H8MY6CElL+MOCbFJjWqhtOxeFyZZV9q3kYnk9CAuQJKMEGuN4GU6tzhW1AgMB
AAGjRTBDMA4GA1UdDwEB/wQEAwIChDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYB
BQUHAwIwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkqhkiG9w0BAQsFAAOCAQEAF85v
d40HK1ouDAtWeO1PbnWfGEmC5Xa478s9ddOd9Clvp2McYzNlAFfM7kdcj6xeiNhF
WPIfaGAi/QdURSL/6C1KsVDqlFBlTs9zYfh2g0UXGvJtj1maeih7zxFLvet+fqll
xseM4P9EVJaQxwuK/F78YBt0tCNfivC6JNZMgxKF59h0FBpH70ytUSHXdz7FKwix
Mfn3qEb9BXSk0Q3prNV5sOV3vgjEtB4THfDxSz9z3+DepVnW3vbbqwEbkXdk3j82
2muVldgOUgTwK8eT+XdofVdntzU/kzygSAtAQwLJfn51fS1GvEcYGBc1bDryIqmF
p9BI7gVKtWSZYegicA==
-----END CERTIFICATE-----
	`
	validFile := writeTemp(t, validFileContents, "valid.pem")

	testCases := []struct {
		Name        string
		EnvVar      string
		ExpectPanic bool
		ExpectNil   bool
	}{
		// Setting the env var to a file that doesn't exist should panic
		{
			Name:        "Env var with missing file",
			EnvVar:      "not.a.real.file.pem",
			ExpectPanic: true,
		},
		// Setting the env var to a file that contains invalid content should panic
		{
			Name:        "Env var with invalid content",
			EnvVar:      invalidFile,
			ExpectPanic: true,
		},
		// Setting the env var to the empty string should not panic and should
		// return nil
		{
			Name:        "No env var",
			EnvVar:      "",
			ExpectPanic: false,
			ExpectNil:   true,
		},
		// Setting the env var to a file that contains valid content should not
		// panic and should not return nil
		{
			Name:        "Env var with valid content",
			EnvVar:      validFile,
			ExpectPanic: false,
			ExpectNil:   false,
		},
	}

	for _, test := range testCases {
		t.Run(test.Name, func(t *testing.T) {
			os.Setenv(caCertificatesEnvVar, test.EnvVar)
			defer os.Setenv(caCertificatesEnvVar, "")

			defer func() {
				r := recover()

				if test.ExpectPanic {
					assert.NotNil(t, r, "expected initCertPool() to panic")
				} else {
					assert.Nil(t, r, "expected initCertPool() to not panic")
				}
			}()

			result := initCertPool()

			if test.ExpectNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
			}
		})
	}
}
