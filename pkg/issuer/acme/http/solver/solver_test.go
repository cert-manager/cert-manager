/*
Copyright 2020 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package solver

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/assert"
)

func TestSolver(t *testing.T) {
	cases := map[string]struct {
		solverPort           int
		solverDomain         string
		solverToken          string
		solverKey            string
		requestTarget        string
		expectedResponseCode int
	}{
		"return ok if healthcheck url - /": {
			requestTarget:        "/",
			expectedResponseCode: http.StatusOK,
		},
		"return ok if healthcheck url - /healthz": {
			requestTarget:        "/",
			expectedResponseCode: http.StatusOK,
		},
		"return not found if not-challenge url reached": {
			requestTarget:        "/test",
			expectedResponseCode: http.StatusNotFound,
		},
		"return not found if tokens do not match": {
			solverDomain:         "www.example.com",
			solverToken:          "not-secret",
			requestTarget:        "http://www.example.com" + HTTPChallengePath + "/secret",
			expectedResponseCode: http.StatusNotFound,
		},
		"return not found if domains do not match": {
			solverDomain:         "www.example2.com",
			solverToken:          "secret",
			requestTarget:        "http://www.example.com" + HTTPChallengePath + "/secret",
			expectedResponseCode: http.StatusNotFound,
		},
		"return ok if domain and token match": {
			solverDomain:         "www.example.com",
			solverToken:          "secret",
			solverKey:            "test-key",
			requestTarget:        "http://www.example.com" + HTTPChallengePath + "/secret",
			expectedResponseCode: http.StatusOK,
		},
		"return ok with ipv4": {
			solverPort:           8080,
			solverDomain:         "192.168.1.1",
			solverToken:          "secret",
			solverKey:            "test-key",
			requestTarget:        "http://192.168.1.1:8080" + HTTPChallengePath + "/secret",
			expectedResponseCode: http.StatusOK,
		},
		"return ok with ipv4 when request goes through proxy": {
			solverPort:           8080,
			solverDomain:         "192.168.1.1",
			solverToken:          "secret",
			solverKey:            "test-key",
			requestTarget:        "http://192.168.1.1:80" + HTTPChallengePath + "/secret",
			expectedResponseCode: http.StatusOK,
		},
		"return ok with ipv4 without specified port in the request": {
			solverPort:           80,
			solverDomain:         "192.168.1.1",
			solverToken:          "secret",
			solverKey:            "test-key",
			requestTarget:        "http://192.168.1.1" + HTTPChallengePath + "/secret",
			expectedResponseCode: http.StatusOK,
		},
		"return ok with ipv6": {
			solverPort:           1234,
			solverDomain:         "2001:db8:3333:4444:5555:6666:7777:8888",
			solverToken:          "secret",
			solverKey:            "test-key",
			requestTarget:        "http://[2001:db8:3333:4444:5555:6666:7777:8888]:1234" + HTTPChallengePath + "/secret",
			expectedResponseCode: http.StatusOK,
		},
		"return ok with ipv6 - 2": {
			solverPort:           1234,
			solverDomain:         "2a00:8a00:4000:435::13a",
			solverToken:          "secret",
			solverKey:            "test-key",
			requestTarget:        "http://[2a00:8a00:4000:435::13a]:1234" + HTTPChallengePath + "/secret",
			expectedResponseCode: http.StatusOK,
		},
		"return ok with ipv6 without specified port in the request": {
			solverPort:           80,
			solverDomain:         "2001:db8:3333:4444:5555:6666:7777:8888",
			solverToken:          "secret",
			solverKey:            "test-key",
			requestTarget:        "http://[2001:db8:3333:4444:5555:6666:7777:8888]" + HTTPChallengePath + "/secret",
			expectedResponseCode: http.StatusOK,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			solver := HTTP01Solver{
				ListenPort: tc.solverPort,
				Domain:     tc.solverDomain,
				Token:      tc.solverToken,
				Key:        tc.solverKey,
			}

			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.requestTarget, nil)
			w := httptest.NewRecorder()

			solver.challengeHandler(logr.Discard()).ServeHTTP(w, r)

			if w.Code != tc.expectedResponseCode {
				t.Errorf("Expected response code %d, got %d", tc.expectedResponseCode, w.Code)
			}
			response := w.Body.String()
			if tc.solverKey != "" && response != tc.solverKey {
				t.Errorf("Expected response body %q, got %q", tc.solverKey, response)
			}
		})
	}
}

func Test_parseHost(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    string
		expected string
	}{
		"FQDN with port": {
			input:    "example.com:8080",
			expected: "example.com",
		},
		"FQDN without port": {
			input:    "example.com",
			expected: "example.com",
		},
		"IPv4 address with port": {
			input:    "192.168.1.1:8080",
			expected: "192.168.1.1",
		},
		"IPv4 address without port": {
			input:    "192.168.1.1",
			expected: "192.168.1.1",
		},
		"IPv6 address with port": {
			input:    "[2001:db8:3333:4444:5555:6666:7777:8888]:1234",
			expected: "2001:db8:3333:4444:5555:6666:7777:8888",
		},
		"IPv6 address with port - 2": {
			input:    "[2a00:8a00:4000:435::13a]:1234",
			expected: "2a00:8a00:4000:435::13a",
		},
		"IPv6 address without port": {
			input:    "[2001:db8:3333:4444:5555:6666:7777:8888]",
			expected: "2001:db8:3333:4444:5555:6666:7777:8888",
		},
		"IPv6 address without bracket": {
			input:    "2001:db8:3333:4444:5555:6666:7777:8888",
			expected: "2001:db8:3333:4444:5555:6666:7777:8888",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			actual := parseHost(tc.input)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

type proxyConnDialer struct {
	c net.Conn
}

func (pcd proxyConnDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return pcd.c, nil
}
func Test_listenSolver(t *testing.T) {
	cases := map[string]struct {
		solverPort           int
		solverProxyProtocol  bool
		solverDomain         string
		solverToken          string
		solverKey            string
		requestTarget        string
		requestProxyProtocol bool
		proxyProtocolVersion byte
		expectedResponseCode int
	}{
		"return ok without proxy-protocol": {
			solverPort:           0,
			solverProxyProtocol:  false,
			solverDomain:         "localhost",
			solverToken:          "secret",
			solverKey:            "test-key",
			requestTarget:        HTTPChallengePath + "/secret",
			requestProxyProtocol: false,
			expectedResponseCode: http.StatusOK,
		},
		"return ok with proxy-protocol v1": {
			solverPort:           0,
			solverProxyProtocol:  true,
			solverDomain:         "localhost",
			solverToken:          "secret",
			solverKey:            "test-key",
			requestTarget:        HTTPChallengePath + "/secret",
			requestProxyProtocol: true,
			proxyProtocolVersion: 1,
			expectedResponseCode: http.StatusOK,
		},
		"return ok with proxy-protocol v2": {
			solverPort:           0,
			solverProxyProtocol:  true,
			solverDomain:         "localhost",
			solverToken:          "secret",
			solverKey:            "test-key",
			requestTarget:        HTTPChallengePath + "/secret",
			requestProxyProtocol: true,
			proxyProtocolVersion: 2,
			expectedResponseCode: http.StatusOK,
		},
		"return bad request with proxy-protocol mismatch": {
			solverPort:           0,
			solverProxyProtocol:  false,
			solverDomain:         "localhost",
			solverToken:          "secret",
			solverKey:            "",
			requestTarget:        HTTPChallengePath + "/secret",
			requestProxyProtocol: true,
			proxyProtocolVersion: 1,
			expectedResponseCode: http.StatusBadRequest,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			solver := HTTP01Solver{
				ListenPort:    tc.solverPort,
				ProxyProtocol: tc.solverProxyProtocol,
				Domain:        tc.solverDomain,
				Token:         tc.solverToken,
				Key:           tc.solverKey,
			}

			go func() {
				if err := solver.Listen(logr.Discard()); err != http.ErrServerClosed {
					t.Error(err)
				}
			}()
			time.Sleep(time.Second)

			addr, err := net.ResolveTCPAddr("tcp", solver.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			conn, err := net.DialTCP("tcp", nil, addr)
			if err != nil {
				t.Fatal(err)
			}

			defer func() {
				_ = conn.Close()
			}()

			target := "http://" + tc.solverDomain + ":" + strconv.Itoa(addr.Port) + tc.requestTarget
			r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
			if err != nil {
				t.Fatal(err)
			}

			if tc.requestProxyProtocol {
				header := &proxyproto.Header{
					Version:           tc.proxyProtocolVersion,
					Command:           proxyproto.PROXY,
					TransportProtocol: proxyproto.TCPv4,
					SourceAddr: &net.TCPAddr{
						IP:   net.ParseIP("10.1.1.1"),
						Port: 1000,
					},
					DestinationAddr: &net.TCPAddr{
						IP:   net.ParseIP("20.2.2.2"),
						Port: 2000,
					},
				}
				_, err = header.WriteTo(conn)
			}

			client := &http.Client{
				Transport: &http.Transport{
					DialContext: proxyConnDialer{conn}.Dial,
				},
			}
			resp, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}

			if resp.StatusCode != tc.expectedResponseCode {
				t.Errorf("Expected response code %d, got %d", tc.expectedResponseCode, resp.StatusCode)
			}
			response, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if tc.solverKey != "" && string(response) != tc.solverKey {
				t.Errorf("Expected response body %q, got %q", tc.solverKey, response)
			}
		})
	}
}
