package cfssl

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/issuer/cfssl/fakes"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	issuerName           = "test-cfssl-certs-issuer"
	issuerNamespace      = "test-namespace"
	ecdsaKeyAlgo         = "ecdsa"
	ecdsaKeySize         = 256
	rsaKeyAlgo           = "rsa"
	rsaKeySize           = 2048
	secretAuthKey        = "deadbeef"
	invalidSecretAuthKey = "fooobaar"
	secretTlsName        = "test-secret-tls"
	certStr              = "----BEGIN CERTIFICATE----blah blah blah-----END CERTIFICATE-----"
)

func TestCFSSLIssue(t *testing.T) {
	type testT struct {
		keyAlgo          string
		keySize          int
		authKey          string
		expectedCrt      string
		expectedRespBody string
		expectedErrStr   string
		lister           *fakes.Lister
		serverPath       string
		serverStatusCode int
		secretName       string
	}

	errorTests := map[string]testT{
		"fails when authkey provided is not a hexadecimal string": testT{
			keyAlgo:          ecdsaKeyAlgo,
			keySize:          ecdsaKeySize,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			expectedErrStr:   messageAuthKeyFormat,
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
			authKey:          invalidSecretAuthKey,
		},
		"fails when remote cfssl server response is not success": testT{
			keyAlgo:          ecdsaKeyAlgo,
			keySize:          ecdsaKeySize,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":false,"result":{"certificate":"%s"}}`, certStr),
			expectedErrStr:   messageRemoteServerResponseNotSuccess,
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
			authKey:          secretAuthKey,
		},
		"fails when remote cfssl server response status is not 200": testT{
			keyAlgo:          ecdsaKeyAlgo,
			keySize:          ecdsaKeySize,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":false,"result":{"certificate":"%s"}}`, certStr),
			expectedErrStr:   messageRemoteServerResponseNon2xx,
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusBadRequest,
			authKey:          secretAuthKey,
		},
	}

	successTests := map[string]testT{
		"issues new ecdsa based certs when authkey is provided and secret does exist": testT{
			keyAlgo:          ecdsaKeyAlgo,
			keySize:          ecdsaKeySize,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
			authKey:          secretAuthKey,
			secretName:       secretTlsName,
		},
		"issues new ecdsa based certs when authkey is provided and secret does not exist": testT{
			keyAlgo:          ecdsaKeyAlgo,
			keySize:          ecdsaKeySize,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
			authKey:          secretAuthKey,
		},
		"issues new ecdsa based certs when authkey is not provided and secret does exist": testT{
			keyAlgo:          ecdsaKeyAlgo,
			keySize:          ecdsaKeySize,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
			secretName:       secretTlsName,
		},
		"issues new ecdsa based certs when authkey is not provided and secret does not exist": testT{
			keyAlgo:          ecdsaKeyAlgo,
			keySize:          ecdsaKeySize,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
		},
		"issues new rsa based certs when authkey is provided and secret does exist": testT{
			keyAlgo:          rsaKeyAlgo,
			keySize:          rsaKeySize,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
			authKey:          secretAuthKey,
			secretName:       secretTlsName,
		},
		"issues new rsa based certs when authkey is provided and secret does not exist": testT{
			keyAlgo:          rsaKeyAlgo,
			keySize:          rsaKeySize,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
			authKey:          secretAuthKey,
		},
		"issues new rsa based certs when authkey is not provided and secret does exist": testT{
			keyAlgo:          rsaKeyAlgo,
			keySize:          rsaKeySize,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
			secretName:       secretTlsName,
		},
		"issues new rsa based certs when authkey is not provided and secret does not exist": testT{
			keyAlgo:          rsaKeyAlgo,
			keySize:          rsaKeySize,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
		},
	}

	for msg, test := range errorTests {
		t.Run(msg, func(t *testing.T) {
			authKeyRef := &v1alpha1.SecretKeySelector{
				LocalObjectReference: v1alpha1.LocalObjectReference{Name: "test-auth-key"},
				Key:                  "auth-key",
			}
			lister := fakes.NewLister()
			lister.Set("test-auth-key", fakes.NewSecret("auth-key", test.authKey))

			server := testCFSSLServer(test.expectedRespBody, test.serverStatusCode)
			certificate := createCertificate(test.secretName, test.keyAlgo, test.keySize)

			issuerObj, err := createIssuer(authKeyRef, lister, server.URL, test.serverPath)
			if err != nil {
				t.Fatalf(err.Error())
			}

			_, _, err = issuerObj.Issue(context.TODO(), certificate)
			if err == nil {
				t.Fatalf("expected error to occur: %s", err)
			}

			if !strings.Contains(strings.ToLower(err.Error()), test.expectedErrStr) {
				t.Fatalf(`expected err: "%s" to contain: "%s"`, err.Error(), test.expectedErrStr)
			}
		})
	}

	for msg, test := range successTests {
		t.Run(msg, func(t *testing.T) {
			var authKeyRef *v1alpha1.SecretKeySelector
			authKeyRef = nil

			lister := fakes.NewLister()
			if len(test.authKey) > 0 {
				authKeyRef = &v1alpha1.SecretKeySelector{
					LocalObjectReference: v1alpha1.LocalObjectReference{Name: "test-auth-key"},
					Key:                  "auth-key",
				}
				lister.Set("test-auth-key", fakes.NewSecret("auth-key", test.authKey))
			}

			if len(test.secretName) > 0 {
				privateKey, err := pki.GeneratePrivateKey(test.keyAlgo, test.keySize)
				if err != nil {
					t.Fatalf(err.Error())
				}

				privateKeyBytes, err := pki.EncodePrivateKey(privateKey)
				if err != nil {
					t.Fatalf(err.Error())
				}
				lister.Set(test.secretName, fakes.NewSecret("tls.key", string(privateKeyBytes)))
			}

			server := testCFSSLServer(test.expectedRespBody, test.serverStatusCode)
			certificate := createCertificate(test.secretName, test.keyAlgo, test.keySize)

			issuerObj, err := createIssuer(authKeyRef, lister, server.URL, test.serverPath)
			if err != nil {
				t.Fatalf(err.Error())
			}

			_, certPem, err := issuerObj.Issue(context.TODO(), certificate)
			if err != nil {
				t.Fatalf(err.Error())
			}

			if string(certPem) != test.expectedCrt {
				t.Fatalf(`expected "%s", got "%s"`, test.expectedCrt, certPem)
			}
		})
	}
}

func createCertificate(secretName, keyAlgo string, keySize int) *v1alpha1.Certificate {
	return &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("test-%s-certificate", keyAlgo),
			Namespace: issuerNamespace,
		},
		Spec: v1alpha1.CertificateSpec{
			SecretName: secretName,
			IssuerRef: v1alpha1.ObjectReference{
				Name: issuerName,
			},
			CommonName: "test.domain",
			DNSNames:   []string{"test.other.domain"},
			CFSSL: &v1alpha1.CFSSLCertificateConfig{
				Key: v1alpha1.CFSSLCertificateKeyConfig{
					Algo: keyAlgo,
					Size: keySize,
				},
			},
		},
	}
}

func createIssuer(authKey *v1alpha1.SecretKeySelector, lister *fakes.Lister, serverURL, serverPath string) (issuer.Interface, error) {
	issuerObj := &v1alpha1.Issuer{
		TypeMeta: metav1.TypeMeta{
			Kind: "Issuer",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      issuerName,
			Namespace: issuerNamespace,
		},
		Spec: v1alpha1.IssuerSpec{
			IssuerConfig: v1alpha1.IssuerConfig{
				CFSSL: &v1alpha1.CFSSLIssuer{
					Server:  serverURL,
					Path:    serverPath,
					AuthKey: authKey,
				},
			},
		},
	}

	ctx := &issuer.Context{}
	return NewCFSSL(issuerObj,
		ctx.Client,
		ctx.CMClient,
		ctx.Recorder,
		"",
		lister,
	)
}

func testCFSSLServer(respBody string, statusCode int) *httptest.Server {
	var resp string
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if statusCode != http.StatusOK {
			http.Error(w, "not found", statusCode)
			return
		}

		switch r.RequestURI {
		case "/v1/certs/sign":
			resp = respBody
		case "/v1/certs/authsign":
			resp = respBody
		default:
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Write([]byte(resp))
	}))
}
