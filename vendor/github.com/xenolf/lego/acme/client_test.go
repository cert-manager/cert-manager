package acme

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
)

func TestNewClient(t *testing.T) {
	keyBits := 32 // small value keeps test fast
	keyType := RSA2048
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	require.NoError(t, err, "Could not generate test key")

	user := mockUser{
		email:      "test@test.com",
		regres:     new(RegistrationResource),
		privatekey: key,
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := json.Marshal(directory{
			NewNonceURL:   "http://test",
			NewAccountURL: "http://test",
			NewOrderURL:   "http://test",
			RevokeCertURL: "http://test",
			KeyChangeURL:  "http://test",
		})

		_, err = w.Write(data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))

	client, err := NewClient(ts.URL, user, keyType)
	require.NoError(t, err, "Could not create client")

	require.NotNil(t, client.jws, "client.jws")
	assert.Equal(t, key, client.jws.privKey, "client.jws.privKey")
	assert.Equal(t, keyType, client.keyType, "client.keyType")
	assert.Len(t, client.solvers, 2, "solvers")
}

func TestClientOptPort(t *testing.T) {
	keyBits := 32 // small value keeps test fast
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	require.NoError(t, err, "Could not generate test key")

	user := mockUser{
		email:      "test@test.com",
		regres:     new(RegistrationResource),
		privatekey: key,
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := json.Marshal(directory{
			NewNonceURL:   "http://test",
			NewAccountURL: "http://test",
			NewOrderURL:   "http://test",
			RevokeCertURL: "http://test",
			KeyChangeURL:  "http://test",
		})

		_, err = w.Write(data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))

	optPort := "1234"
	optHost := ""

	client, err := NewClient(ts.URL, user, RSA2048)
	require.NoError(t, err, "Could not create client")

	err = client.SetHTTPAddress(net.JoinHostPort(optHost, optPort))
	require.NoError(t, err)

	require.IsType(t, &httpChallenge{}, client.solvers[HTTP01])
	httpSolver := client.solvers[HTTP01].(*httpChallenge)

	assert.Equal(t, httpSolver.jws, client.jws, "Expected http-01 to have same jws as client")

	httpProviderServer := httpSolver.provider.(*HTTPProviderServer)
	assert.Equal(t, optPort, httpProviderServer.port, "port")
	assert.Equal(t, optHost, httpProviderServer.iface, "iface")

	// test setting different host
	optHost = "127.0.0.1"
	err = client.SetHTTPAddress(net.JoinHostPort(optHost, optPort))
	require.NoError(t, err)

	assert.Equal(t, optHost, httpSolver.provider.(*HTTPProviderServer).iface, "iface")
}

func TestNotHoldingLockWhileMakingHTTPRequests(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(250 * time.Millisecond)
		w.Header().Add("Replay-Nonce", "12345")
		w.Header().Add("Retry-After", "0")
		writeJSONResponse(w, &challenge{Type: "http-01", Status: "Valid", URL: "http://example.com/", Token: "token"})
	}))
	defer ts.Close()

	privKey, err := rsa.GenerateKey(rand.Reader, 512)
	require.NoError(t, err)

	j := &jws{privKey: privKey, getNonceURL: ts.URL}
	ch := make(chan bool)
	resultCh := make(chan bool)
	go func() {
		_, errN := j.Nonce()
		if errN != nil {
			t.Log(errN)
		}
		ch <- true
	}()
	go func() {
		_, errN := j.Nonce()
		if errN != nil {
			t.Log(errN)
		}
		ch <- true
	}()
	go func() {
		<-ch
		<-ch
		resultCh <- true
	}()
	select {
	case <-resultCh:
	case <-time.After(400 * time.Millisecond):
		t.Fatal("JWS is probably holding a lock while making HTTP request")
	}
}

func TestValidate(t *testing.T) {
	var statuses []string

	privKey, err := rsa.GenerateKey(rand.Reader, 512)
	require.NoError(t, err)

	// validateNoBody reads the http.Request POST body, parses the JWS and validates it to read the body.
	// If there is an error doing this,
	// or if the JWS body is not the empty JSON payload "{}" or a POST-as-GET payload "" an error is returned.
	// We use this to verify challenge POSTs to the ts below do not send a JWS body.
	validateNoBody := func(r *http.Request) error {
		reqBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return err
		}

		jws, err := jose.ParseSigned(string(reqBody))
		if err != nil {
			return err
		}

		body, err := jws.Verify(&jose.JSONWebKey{
			Key:       privKey.Public(),
			Algorithm: "RSA",
		})
		if err != nil {
			return err
		}

		if bodyStr := string(body); bodyStr != "{}" && bodyStr != "" {
			return fmt.Errorf(`expected JWS POST body "{}" or "", got %q`, bodyStr)
		}
		return nil
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Minimal stub ACME server for validation.
		w.Header().Add("Replay-Nonce", "12345")
		w.Header().Add("Retry-After", "0")

		switch r.Method {
		case http.MethodHead:
		case http.MethodPost:
			if err := validateNoBody(r); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			st := statuses[0]
			statuses = statuses[1:]
			writeJSONResponse(w, &challenge{Type: "http-01", Status: st, URL: "http://example.com/", Token: "token"})

		case http.MethodGet:
			st := statuses[0]
			statuses = statuses[1:]
			writeJSONResponse(w, &challenge{Type: "http-01", Status: st, URL: "http://example.com/", Token: "token"})

		default:
			http.Error(w, r.Method, http.StatusMethodNotAllowed)
		}
	}))
	defer ts.Close()

	j := &jws{privKey: privKey, getNonceURL: ts.URL}

	testCases := []struct {
		name     string
		statuses []string
		want     string
	}{
		{
			name:     "POST-unexpected",
			statuses: []string{"weird"},
			want:     "unexpected",
		},
		{
			name:     "POST-valid",
			statuses: []string{"valid"},
		},
		{
			name:     "POST-invalid",
			statuses: []string{"invalid"},
			want:     "Error",
		},
		{
			name:     "GET-unexpected",
			statuses: []string{"pending", "weird"},
			want:     "unexpected",
		},
		{
			name:     "GET-valid",
			statuses: []string{"pending", "valid"},
		},
		{
			name:     "GET-invalid",
			statuses: []string{"pending", "invalid"},
			want:     "Error",
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			statuses = test.statuses

			err := validate(j, "example.com", ts.URL, challenge{Type: "http-01", Token: "token"})
			if test.want == "" {
				require.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), test.want)
			}
		})
	}
}

func TestGetChallenges(t *testing.T) {
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			w.Header().Add("Replay-Nonce", "12345")
			w.Header().Add("Retry-After", "0")
			writeJSONResponse(w, directory{
				NewNonceURL:   ts.URL,
				NewAccountURL: ts.URL,
				NewOrderURL:   ts.URL,
				RevokeCertURL: ts.URL,
				KeyChangeURL:  ts.URL,
			})
		case http.MethodPost:
			writeJSONResponse(w, orderMessage{})
		}
	}))
	defer ts.Close()

	keyBits := 512 // small value keeps test fast
	keyType := RSA2048

	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	require.NoError(t, err, "Could not generate test key")

	user := mockUser{
		email:      "test@test.com",
		regres:     &RegistrationResource{URI: ts.URL},
		privatekey: key,
	}

	client, err := NewClient(ts.URL, user, keyType)
	require.NoError(t, err, "Could not create client")

	_, err = client.createOrderForIdentifiers([]string{"example.com"})
	require.NoError(t, err)
}

func TestResolveAccountByKey(t *testing.T) {
	keyBits := 512
	keyType := RSA2048

	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	require.NoError(t, err, "Could not generate test key")

	user := mockUser{
		email:      "test@test.com",
		regres:     new(RegistrationResource),
		privatekey: key,
	}

	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.RequestURI {
		case "/directory":
			writeJSONResponse(w, directory{
				NewNonceURL:   ts.URL + "/nonce",
				NewAccountURL: ts.URL + "/account",
				NewOrderURL:   ts.URL + "/newOrder",
				RevokeCertURL: ts.URL + "/revokeCert",
				KeyChangeURL:  ts.URL + "/keyChange",
			})
		case "/nonce":
			w.Header().Add("Replay-Nonce", "12345")
			w.Header().Add("Retry-After", "0")
		case "/account":
			w.Header().Set("Location", ts.URL+"/account_recovery")
		case "/account_recovery":
			writeJSONResponse(w, accountMessage{
				Status: "valid",
			})
		}
	}))

	client, err := NewClient(ts.URL+"/directory", user, keyType)
	require.NoError(t, err, "Could not create client")

	res, err := client.ResolveAccountByKey()
	require.NoError(t, err, "Unexpected error resolving account by key")

	assert.Equal(t, "valid", res.Body.Status, "Unexpected account status")
}

// writeJSONResponse marshals the body as JSON and writes it to the response.
func writeJSONResponse(w http.ResponseWriter, body interface{}) {
	bs, err := json.Marshal(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(bs); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// stubValidate is like validate, except it does nothing.
func stubValidate(_ *jws, _, _ string, _ challenge) error {
	return nil
}

type mockUser struct {
	email      string
	regres     *RegistrationResource
	privatekey *rsa.PrivateKey
}

func (u mockUser) GetEmail() string                       { return u.email }
func (u mockUser) GetRegistration() *RegistrationResource { return u.regres }
func (u mockUser) GetPrivateKey() crypto.PrivateKey       { return u.privatekey }
