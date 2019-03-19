/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package akamai

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"
)

// EdgeGridAuth holds all values required to perform Akamai API Client Authentication.
// See https://developer.akamai.com/introduction/Client_Auth.html.
type EdgeGridAuth struct {
	ClientToken   string
	ClientSecret  string
	AccessToken   string
	HeadersToSign []string
	MaxBody       int

	now         func() time.Time
	createNonce func() (string, error)
}

type signingData struct {
	timestamp  string
	authHeader string
	dataToSign string
}

// edgeGridAuthTimeFormat is used for timestamps in request signatures.
const edgeGridAuthTimeFormat = "20060102T15:04:05-0700" // yyyyMMddTHH:mm:ss+0000

const NoMaxBody = -1

// NewEdgeGridAuth returns a new request signer for Akamai EdgeGrid
func NewEdgeGridAuth(clientToken, clientSecret, accessToken string, headersToSign ...string) *EdgeGridAuth {
	return &EdgeGridAuth{
		ClientToken:   clientToken,
		ClientSecret:  clientSecret,
		AccessToken:   accessToken,
		HeadersToSign: headersToSign,
		MaxBody:       NoMaxBody,

		now:         time.Now,
		createNonce: createRandomNonce,
	}
}

// SignRequest calculates the signature for Akamai Open API and adds it as the Authorization header.
// The Authorization header starts with the signing algorithm moniker (name of the algorithm) used to sign the request.
// The moniker below identifies EdgeGrid V1, hash message authentication code, SHA–256 as the hash standard.
// This moniker is then followed by a space and an ordered list of name value pairs with each field separated by a semicolon.
func (e *EdgeGridAuth) SignRequest(req *http.Request) error {
	signingData, err := e.signingData(req)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf(
		"%ssignature=%s",
		signingData.authHeader,
		e.calculateRequestSignature(signingData)))

	return nil
}

func (e *EdgeGridAuth) calculateRequestSignature(signingData *signingData) string {
	return computeSignature(
		signingData.dataToSign,
		e.signingKey(signingData.timestamp))
}

func (e *EdgeGridAuth) signingData(req *http.Request) (*signingData, error) {
	nonce, err := e.createNonce()
	if err != nil {
		return nil, err
	}

	timestamp := e.now().UTC().Format(edgeGridAuthTimeFormat)
	authHeader := fmt.Sprintf("EG1-HMAC-SHA256 client_token=%s;access_token=%s;timestamp=%s;nonce=%s;",
		e.ClientToken,
		e.AccessToken,
		timestamp,
		nonce)

	return &signingData{
		timestamp:  timestamp,
		authHeader: authHeader,
		dataToSign: e.dataToSign(req, authHeader),
	}, nil
}

// dataToSign includes the information from the HTTP request that is relevant to ensuring that the request is authentic.
// This data set comprised of the request data combined with the authorization header value (excluding the signature field,
// but including the ; right before the signature field).
func (e *EdgeGridAuth) dataToSign(req *http.Request, authHeader string) string {
	var buffer bytes.Buffer

	buffer.WriteString(req.Method)
	buffer.WriteRune('\t')
	buffer.WriteString(req.URL.Scheme)
	buffer.WriteRune('\t')
	buffer.WriteString(req.URL.Host)
	buffer.WriteRune('\t')
	buffer.WriteString(relativeURL(req.URL))
	buffer.WriteRune('\t')
	buffer.WriteString(e.canonicalizedHeaders(req))
	buffer.WriteRune('\t')
	buffer.WriteString(e.computeBodyHash(req))
	buffer.WriteRune('\t')
	buffer.WriteString(authHeader)

	return buffer.String()
}

// signingKey is derived from the client secret.
// The signing key is computed as the base64 encoding of the SHA–256 HMAC of the timestamp string
// (the field value included in the HTTP authorization header described above) with the client secret as the key.
func (e *EdgeGridAuth) signingKey(timestamp string) string {
	return computeSignature(timestamp, e.ClientSecret)
}

// realtiveURL is the part of the URL that starts from the root path and includes the query string, with the handling of following special cases:
// If the path is null or empty, set it to / (forward-slash).
// If the path does not start with /, add / to the beginning.
func relativeURL(url *url.URL) string {
	relativeURL := url.Path
	if relativeURL == "" {
		return "/"
	}

	if relativeURL[0] != '/' {
		relativeURL = "/" + relativeURL
	}

	if url.RawQuery != "" {
		relativeURL += "?"
		relativeURL += url.RawQuery
	}

	return relativeURL
}

// computeBodyHash returns the base64-encoded SHA–256 hash of the POST body.
// For any other request methods, this field is empty. But the tac separator (\t) must be included.
// The size of the POST body must be less than or equal to the value specified by the service.
// Any request that does not meet this criteria SHOULD be rejected during the signing process,
// as the request will be rejected by EdgeGrid.
func (e *EdgeGridAuth) computeBodyHash(req *http.Request) string {
	if req.Body != nil {
		bodyBytes, _ := ioutil.ReadAll(req.Body)
		req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

		if req.Method == http.MethodPost && len(bodyBytes) > 0 {
			dataToHash := bodyBytes
			if e.MaxBody != NoMaxBody && len(dataToHash) > e.MaxBody {
				dataToHash = dataToHash[0:e.MaxBody]
			}
			sha256Sum := sha256.Sum256(dataToHash)
			return base64.StdEncoding.EncodeToString(sha256Sum[:])
		}
	}

	return ""
}

// canonicalizedHeaders returns the request headers as a canonicalized string.
//
// The protocol does not support multiple request headers with the same header name.
// Such requests SHOULD be rejected during the signing process. Otherwise, EdgeGrid
// will not produce the intended results by rejecting such requests or removing all
// (but one) duplicated headers.
//
//    Header names are case-insensitive per rfc2616.
//
// For each entry in the list of headers designated by the service provider to include
// in the signature in the specified order, the canonicalization of the request header
// is done as follows:
//
//    Get the first header value for the name.
//    Trim the leading and trailing white spaces.
//    Replace all repeated white spaces with a single space.
//    Concatenate the name:value pairs with the tab (\t) separator (name field is all in lower case).
//    Terminate the headers with another tab (\t) separator.
//
// NOTE: The canonicalized data is used for creating the signature only, as this step
// might alter the header value. If a header in the list is not present in the request,
// or the header value is empty, nothing for that header, neither the name nor the tab
// separator, may be included.
func (e *EdgeGridAuth) canonicalizedHeaders(req *http.Request) string {
	if len(e.HeadersToSign) < 1 {
		return ""
	}

	var headerNamesToSign []string
	for headerName := range req.Header {
		for _, sign := range e.HeadersToSign {
			if strings.EqualFold(sign, headerName) {
				headerNamesToSign = append(headerNamesToSign, headerName)
				break
			}
		}
	}

	if len(headerNamesToSign) < 1 {
		return ""
	}

	sort.Strings(headerNamesToSign)

	var buffer bytes.Buffer
	for _, headerName := range headerNamesToSign {
		for _, c := range headerName {
			buffer.WriteRune(unicode.ToLower(c))
		}

		buffer.WriteRune(':')

		white := false
		empty := true
		for _, c := range req.Header.Get(headerName) {
			if unicode.IsSpace(c) {
				white = true
			} else {
				if white && !empty {
					buffer.WriteRune(' ')
				}
				buffer.WriteRune(unicode.ToLower(c))
				empty = false
				white = false
			}
		}

		buffer.WriteRune('\t')
	}

	return buffer.String()
}

// calculateSignature is the base64-encoding of the SHA–256 HMAC of the data to sign with the signing key.
func computeSignature(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func createRandomNonce() (string, error) {
	bytes := make([]byte, 18)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(bytes), nil
}
