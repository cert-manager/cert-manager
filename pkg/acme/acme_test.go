package acme

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestAcme_Mux(t *testing.T) {
	// uncomment to debug
	logrus.SetLevel(logrus.DebugLevel)

	a := New(nil)
	a.challengesTokenToKey["token1"] = "auth1"
	a.challengesHostToToken["domain1.example.com"] = "token1"

	req, err := http.NewRequest(
		"GET",
		"http://domain1.example.com/.well-known/acme-challenge/token1",
		nil,
	)
	assert.Nil(t, err, "no error during request")

	w := httptest.NewRecorder()
	a.Mux().ServeHTTP(w, req)

	assert.Equal(t, "text/plain", w.Header().Get("Content-Type"))
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "auth1", w.Body.String())

	req, err = http.NewRequest(
		"GET",
		"http://domain1.example.com:8080/.well-known/acme-challenge/token1",
		nil,
	)
	assert.Nil(t, err, "no error during request")

	w = httptest.NewRecorder()
	a.Mux().ServeHTTP(w, req)

	assert.Equal(t, "text/plain", w.Header().Get("Content-Type"))
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "auth1", w.Body.String())

	req, err = http.NewRequest(
		"GET",
		"http://domain666.example.com/.well-known/acme-challenge/token1",
		nil,
	)
	assert.Nil(t, err, "no error during request")

	w = httptest.NewRecorder()
	a.Mux().ServeHTTP(w, req)

	assert.Equal(t, "text/plain", w.Header().Get("Content-Type"))
	assert.Equal(t, 404, w.Code)

	req, err = http.NewRequest(
		"GET",
		"http://domain1.example.com/.well-known/acme-challenge/token666",
		nil,
	)
	assert.Nil(t, err, "no error during request")

	w = httptest.NewRecorder()
	a.Mux().ServeHTTP(w, req)

	assert.Equal(t, "text/plain", w.Header().Get("Content-Type"))
	assert.Equal(t, 404, w.Code)

	req, err = http.NewRequest(
		"GET",
		"http://domain1.example.com/aasdasdas/acme-challenge/token1",
		nil,
	)
	assert.Nil(t, err, "no error during request")

	w = httptest.NewRecorder()
	a.Mux().ServeHTTP(w, req)

	assert.Equal(t, "text/plain", w.Header().Get("Content-Type"))
	assert.Equal(t, 404, w.Code)

	req, err = http.NewRequest(
		"GET",
		"http://1.2.3.4/healthz",
		nil,
	)
	assert.Nil(t, err, "no error during request")

	w = httptest.NewRecorder()
	a.Mux().ServeHTTP(w, req)

	assert.Equal(t, "text/plain", w.Header().Get("Content-Type"))
	assert.Equal(t, 200, w.Code)

	req, err = http.NewRequest(
		"GET",
		"http://1.2.3.4/",
		nil,
	)
	assert.Nil(t, err, "no error during request")

	w = httptest.NewRecorder()
	a.Mux().ServeHTTP(w, req)

	assert.Equal(t, "text/plain", w.Header().Get("Content-Type"))
	assert.Equal(t, 200, w.Code)

}
