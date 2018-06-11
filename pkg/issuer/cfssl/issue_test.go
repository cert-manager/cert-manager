/*
Copyright 2018 The Jetstack cert-manager contributors.

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

package cfssl

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeinformers "k8s.io/client-go/informers"
	kubefake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	issuerName                = "test-cfssl-certs-issuer"
	issuerNamespace           = "test-namespace"
	tlsSecretName             = "test-secret-tls"
	authKeySecretName         = "test-auth-key"
	validAuthKeySecretValue   = "deadbeef" // Valid hexadecimal string
	invalidAuthKeySecretValue = "fooobaar" // Invalid hexadecimal string
	certStr                   = "----BEGIN CERTIFICATE----blah blah blah-----END CERTIFICATE-----"
	caCertStr                 = "----BEGIN CERTIFICATE----blah blah blah-----END CERTIFICATE-----"
)

const infoResponse = `{"success":true,"result":{"certificate":"-----BEGIN CERTIFICATE-----blah-----END CERTIFICATE-----"}}`

type statusCodes struct {
	info     int
	sign     int
	authSign int
}

type testT struct {
	algorithm           v1alpha1.KeyAlgorithm
	expectedCrt         string
	expectedRespBody    string
	expectedErrStr      string
	expectedStatusCodes statusCodes
	authKeySecret       *corev1.Secret
	tlsSecret           *corev1.Secret
	apiPrefix           string
	profile             string
	label               string
}

func TestCFSSLIssue(t *testing.T) {
	errorTests := map[string]*testT{
		"fails when authkey secret is not a valid hexadecimal string": {
			authKeySecret:  newSecret(authKeySecretName, "auth-key", invalidAuthKeySecretValue),
			algorithm:      v1alpha1.ECDSAKeyAlgorithm,
			expectedErrStr: messageAuthKeyFormat,
			expectedStatusCodes: statusCodes{
				info: http.StatusOK,
				sign: http.StatusOK,
			},
			apiPrefix: "/v1/certs",
		},
		"fails when remote cfssl server response is not success": {
			authKeySecret:    newSecret(authKeySecretName, "auth-key", validAuthKeySecretValue),
			algorithm:        v1alpha1.ECDSAKeyAlgorithm,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":false,"result":{"certificate":"%s"}}`, certStr),
			expectedErrStr:   messageServerResponseNotSuccess,
			expectedStatusCodes: statusCodes{
				info: http.StatusOK,
				sign: http.StatusOK,
			},
			apiPrefix: "/v1/certs",
		},
		"fails when remote cfssl server response status is not 200": {
			authKeySecret:    newSecret(authKeySecretName, "auth-key", validAuthKeySecretValue),
			algorithm:        v1alpha1.ECDSAKeyAlgorithm,
			expectedCrt:      certStr,
			expectedRespBody: `{"success":false,"result":{},"errors":[{"code":123, "message":"blah"}]}`,
			expectedErrStr:   messageServerResponseNon2xx,
			expectedStatusCodes: statusCodes{
				info:     http.StatusOK,
				sign:     http.StatusBadRequest,
				authSign: http.StatusBadRequest,
			},
			apiPrefix: "/v1/certs",
		},
	}

	successTests := map[string]*testT{
		"for new certificates, issues ecdsa based certs when authkey is provided": {
			authKeySecret:    newSecret(authKeySecretName, "auth-key", validAuthKeySecretValue),
			algorithm:        v1alpha1.ECDSAKeyAlgorithm,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			expectedStatusCodes: statusCodes{
				info:     http.StatusOK,
				sign:     http.StatusUnauthorized,
				authSign: http.StatusOK,
			},
			apiPrefix: "/v1/certs",
		},
		"for new certificates, issues rsa based certs when authkey is provided": {
			authKeySecret:    newSecret(authKeySecretName, "auth-key", validAuthKeySecretValue),
			algorithm:        v1alpha1.RSAKeyAlgorithm,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			expectedStatusCodes: statusCodes{
				info:     http.StatusOK,
				sign:     http.StatusUnauthorized,
				authSign: http.StatusOK,
			},
			apiPrefix: "/v1/certs",
		},
		"for new certificates, issues ecdsa based certs when authkey is not provided": {
			algorithm:        v1alpha1.ECDSAKeyAlgorithm,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			expectedStatusCodes: statusCodes{
				info:     http.StatusOK,
				sign:     http.StatusOK,
				authSign: http.StatusUnauthorized,
			},
			apiPrefix: "/v1/certs",
		},
		"for new certificates, issues rsa based certs when authkey is not provided": {
			algorithm:        v1alpha1.RSAKeyAlgorithm,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			expectedStatusCodes: statusCodes{
				info:     http.StatusOK,
				sign:     http.StatusOK,
				authSign: http.StatusUnauthorized,
			},
			apiPrefix: "/v1/certs",
		},
		"for existing certificate, issues ecdsa based certs when authkey is provided": {
			authKeySecret:    newSecret(authKeySecretName, "auth-key", validAuthKeySecretValue),
			tlsSecret:        newTLSSecret(t, tlsSecretName, v1alpha1.ECDSAKeyAlgorithm),
			algorithm:        v1alpha1.ECDSAKeyAlgorithm,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			expectedStatusCodes: statusCodes{
				info:     http.StatusOK,
				sign:     http.StatusUnauthorized,
				authSign: http.StatusOK,
			},
			apiPrefix: "/v1/certs",
		},
		"for existing certificates, issues rsa based certs when authkey is provided": {
			authKeySecret:    newSecret(authKeySecretName, "auth-key", validAuthKeySecretValue),
			tlsSecret:        newTLSSecret(t, tlsSecretName, v1alpha1.RSAKeyAlgorithm),
			algorithm:        v1alpha1.RSAKeyAlgorithm,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			expectedStatusCodes: statusCodes{
				info:     http.StatusOK,
				sign:     http.StatusUnauthorized,
				authSign: http.StatusOK,
			},
			apiPrefix: "/v1/certs",
		},
		"for existing certificates, issues ecdsa based certs when authkey is not provided": {
			tlsSecret:        newTLSSecret(t, tlsSecretName, v1alpha1.ECDSAKeyAlgorithm),
			algorithm:        v1alpha1.ECDSAKeyAlgorithm,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			expectedStatusCodes: statusCodes{
				info:     http.StatusOK,
				sign:     http.StatusOK,
				authSign: http.StatusUnauthorized,
			},
			apiPrefix: "/v1/certs",
		},
		"for existing certificates, issues rsa based certs when authkey is not provided": {
			tlsSecret:        newTLSSecret(t, tlsSecretName, v1alpha1.RSAKeyAlgorithm),
			algorithm:        v1alpha1.RSAKeyAlgorithm,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			expectedStatusCodes: statusCodes{
				info:     http.StatusOK,
				sign:     http.StatusOK,
				authSign: http.StatusUnauthorized,
			},
			apiPrefix: "/v1/certs",
		},
		"sends the label & profile provided on the certificate with the server request": {
			algorithm:        v1alpha1.RSAKeyAlgorithm,
			profile:          "blah-profile",
			label:            "blah-label",
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			expectedStatusCodes: statusCodes{
				info:     http.StatusOK,
				sign:     http.StatusOK,
				authSign: http.StatusUnauthorized,
			},
			apiPrefix: "/v1/certs",
		},
		"does not fail if APIPrefix does not start with '/'": {
			algorithm:        v1alpha1.RSAKeyAlgorithm,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			expectedStatusCodes: statusCodes{
				info:     http.StatusOK,
				sign:     http.StatusOK,
				authSign: http.StatusUnauthorized,
			},
			apiPrefix: "v1/certs",
		},
		"does not fail if APIPrefix ends with '/'": {
			algorithm:        v1alpha1.RSAKeyAlgorithm,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			expectedStatusCodes: statusCodes{
				info:     http.StatusOK,
				sign:     http.StatusOK,
				authSign: http.StatusUnauthorized,
			},
			apiPrefix: "v1/certs/",
		},
	}

	for msg, test := range errorTests {
		t.Run(msg, func(t *testing.T) {
			server := testCFSSLServer(test.expectedRespBody, test.expectedStatusCodes, test.profile, test.label)

			certificate := newCertificate(test.algorithm, test.profile, test.label)
			issuer, err := newIssuer(test.authKeySecret, test.tlsSecret, server.URL, test.apiPrefix)
			if err != nil {
				t.Fatalf(err.Error())
			}

			_, err = issuer.Issue(context.TODO(), certificate)
			if err == nil {
				t.Fatalf("expected error to occur: %s", err)
			}

			if !strings.Contains(err.Error(), test.expectedErrStr) {
				t.Fatalf(`expected err: "%s" to contain: "%s"`, err.Error(), test.expectedErrStr)
			}
		})
	}

	for msg, test := range successTests {
		t.Run(msg, func(t *testing.T) {
			server := testCFSSLServer(test.expectedRespBody, test.expectedStatusCodes, test.profile, test.label)

			certificate := newCertificate(test.algorithm, test.profile, test.label)
			issuer, err := newIssuer(test.authKeySecret, test.tlsSecret, server.URL, test.apiPrefix)
			if err != nil {
				t.Fatalf(err.Error())
			}

			response, err := issuer.Issue(context.TODO(), certificate)
			if err != nil {
				t.Fatalf(err.Error())
			}

			if string(response.Certificate) != test.expectedCrt {
				t.Fatalf(`expected "%s", got "%s"`, test.expectedCrt, response.Certificate)
			}
		})
	}
}

func newCertificate(keyAlgo v1alpha1.KeyAlgorithm, profile, label string) *v1alpha1.Certificate {
	config := &v1alpha1.CFSSLCertificateConfig{}
	if len(profile) > 0 {
		config.Profile = profile
	}

	if len(label) > 0 {
		config.Label = label
	}

	return &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("test-%s-certificate", keyAlgo),
			Namespace: issuerNamespace,
		},
		Spec: v1alpha1.CertificateSpec{
			SecretName: tlsSecretName,
			IssuerRef: v1alpha1.ObjectReference{
				Name: issuerName,
			},
			CommonName:   "test.domain",
			DNSNames:     []string{"test.other.domain"},
			KeyAlgorithm: keyAlgo,
			CFSSL:        config,
		},
	}
}

func newIssuer(authKeySecret, tlsSecret *corev1.Secret, serverURL, apiPrefix string) (issuer.Interface, error) {
	cfsslIssuer := &v1alpha1.CFSSLIssuer{
		Server:    serverURL,
		APIPrefix: apiPrefix,
	}

	client := kubefake.NewSimpleClientset()
	recorder := record.NewFakeRecorder(100)
	sharedInformerFactory := kubeinformers.NewSharedInformerFactory(client, 0)
	stopCh := make(chan struct{})
	defer close(stopCh)

	if authKeySecret != nil {
		cfsslIssuer.AuthKey = &v1alpha1.SecretKeySelector{
			LocalObjectReference: v1alpha1.LocalObjectReference{Name: authKeySecretName},
			Key:                  "auth-key",
		}

		sharedInformerFactory.Core().V1().Secrets().Informer().GetIndexer().Add(authKeySecret)
	}

	if tlsSecret != nil {
		sharedInformerFactory.Core().V1().Secrets().Informer().GetIndexer().Add(tlsSecret)
	}

	ctx := &controller.Context{
		Client:                    client,
		KubeSharedInformerFactory: sharedInformerFactory,
		IssuerOptions:             controller.IssuerOptions{},
		Recorder:                  recorder,
	}

	issuer := &v1alpha1.Issuer{
		TypeMeta: metav1.TypeMeta{
			Kind: "Issuer",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      issuerName,
			Namespace: issuerNamespace,
		},
		Spec: v1alpha1.IssuerSpec{
			IssuerConfig: v1alpha1.IssuerConfig{
				CFSSL: cfsslIssuer,
			},
		},
	}

	sharedInformerFactory.Start(stopCh)
	return NewCFSSL(ctx, issuer)
}

func testCFSSLServer(respBody string, codes statusCodes, profile, label string) *httptest.Server {
	var resp string
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "error reading request body.", http.StatusInternalServerError)
			return
		}

		switch r.RequestURI {
		case "/v1/certs/info":
			if codes.info > 0 {
				w.WriteHeader(codes.info)
			}
			if codes.info == http.StatusOK {
				resp = infoResponse
			} else {
				resp = "blah-blah"
			}
		case "/v1/certs/sign":
			var request UnauthenticatedSignRequest

			err := json.Unmarshal(requestBody, &request)
			if err != nil {
				http.Error(w, "error unmarshalling request body.", http.StatusBadRequest)
				return
			}

			if request.Label != label {
				http.Error(w, fmt.Sprintf("expected label '%s', but got '%s'.", label, request.Label), http.StatusBadRequest)
				return
			}

			if request.Profile != profile {
				http.Error(w, fmt.Sprintf("expected profile '%s', but got '%s'.", profile, request.Profile), http.StatusBadRequest)
				return
			}

			if codes.sign > 0 {
				w.WriteHeader(codes.sign)
			}
			resp = respBody
		case "/v1/certs/authsign":
			if codes.authSign > 0 {
				w.WriteHeader(codes.authSign)
			}
			resp = respBody
		default:
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Write([]byte(resp))
	}))
}

func newSecret(name, key, value string) *corev1.Secret {
	data := make(map[string][]byte)
	data[key] = []byte(value)

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: issuerNamespace,
		},
		Data: data,
	}
}

func newTLSSecret(t *testing.T, name string, keyAlgorithm v1alpha1.KeyAlgorithm) *corev1.Secret {
	cert := newCertificate(keyAlgorithm, "", "")
	privateKey, err := pki.GeneratePrivateKeyForCertificate(cert)
	if err != nil {
		t.Fatalf(err.Error())
	}

	privateKeyBytes, err := pki.EncodePrivateKey(privateKey)
	if err != nil {
		t.Fatalf(err.Error())
	}

	return newSecret(name, "tls.key", string(privateKeyBytes))
}
