package cfssl

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corelisters "k8s.io/client-go/listers/core/v1"

	kubeinformers "k8s.io/client-go/informers"
	kubefake "k8s.io/client-go/kubernetes/fake"
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
	tlsSecretName        = "test-secret-tls"
	authKeySecretName    = "test-auth-key"
	certStr              = "----BEGIN CERTIFICATE----blah blah blah-----END CERTIFICATE-----"
)

type testT struct {
	certificate      *v1alpha1.Certificate
	authKey          string
	expectedCrt      string
	expectedRespBody string
	expectedErrStr   string
	lister           corelisters.SecretLister
	serverPath       string
	serverStatusCode int
	secretName       string
	secrets          []*corev1.Secret
	secretSelector   *v1alpha1.SecretKeySelector
	client           *kubefake.Clientset
	genTlsSecret     bool
	genAuthKeySecret bool
	authKeyValue     string
	profile          string
	label            string
}

func (tt *testT) setup() error {
	tt.client = kubefake.NewSimpleClientset()
	sharedInformerFactory := kubeinformers.NewSharedInformerFactory(tt.client, 0)
	tt.lister = sharedInformerFactory.Core().V1().Secrets().Lister()

	if tt.genAuthKeySecret {
		secret := newSecret(authKeySecretName, "auth-key", tt.authKeyValue)
		sharedInformerFactory.Core().V1().Secrets().Informer().GetIndexer().Add(secret)

		tt.secretSelector = &v1alpha1.SecretKeySelector{
			LocalObjectReference: v1alpha1.LocalObjectReference{Name: authKeySecretName},
			Key:                  "auth-key",
		}
	}

	if tt.genTlsSecret {
		privateKey, err := pki.GeneratePrivateKeyForCertificate(tt.certificate)
		if err != nil {
			return err
		}

		secret, err := newPrivateKeySecret(privateKey, tlsSecretName)
		if err != nil {
			return err
		}

		sharedInformerFactory.Core().V1().Secrets().Informer().GetIndexer().Add(secret)
	}

	stopCh := make(chan struct{})
	defer close(stopCh)
	sharedInformerFactory.Start(stopCh)

	return nil
}

func TestCFSSLIssue(t *testing.T) {
	errorTests := map[string]*testT{
		"fails when authkey provided is not a hexadecimal string": &testT{
			certificate:      createCertificate(v1alpha1.ECDSAKeyAlgorithm, pki.ECCurve256, "", ""),
			expectedErrStr:   messageAuthKeyFormat,
			serverPath:       "/v1/certs/sign",
			genAuthKeySecret: true,
			authKeyValue:     invalidSecretAuthKey,
		},
		"fails when remote cfssl server response is not success": &testT{
			certificate:      createCertificate(v1alpha1.ECDSAKeyAlgorithm, pki.ECCurve256, "", ""),
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":false,"result":{"certificate":"%s"}}`, certStr),
			expectedErrStr:   messageRemoteServerResponseNotSuccess,
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
			genAuthKeySecret: true,
			authKeyValue:     secretAuthKey,
		},
		"fails when remote cfssl server response status is not 200": &testT{
			certificate:      createCertificate(v1alpha1.ECDSAKeyAlgorithm, pki.ECCurve256, "", ""),
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":false,"result":{"certificate":"%s"}}`, certStr),
			expectedErrStr:   messageRemoteServerResponseNon2xx,
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusBadRequest,
			genAuthKeySecret: true,
			authKeyValue:     secretAuthKey,
		},
	}

	successTests := map[string]*testT{
		"issues new ecdsa based certs when authkey is provided and secret does exist": &testT{
			certificate:      createCertificate(v1alpha1.ECDSAKeyAlgorithm, pki.ECCurve256, "", ""),
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
			genTlsSecret:     true,
			genAuthKeySecret: true,
			authKeyValue:     secretAuthKey,
		},
		"issues new ecdsa based certs when authkey is provided and secret does not exist": &testT{
			certificate:      createCertificate(v1alpha1.ECDSAKeyAlgorithm, pki.ECCurve256, "", ""),
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
			genAuthKeySecret: true,
			authKeyValue:     secretAuthKey,
		},
		"issues new ecdsa based certs when authkey is not provided and secret does exist": &testT{
			certificate:      createCertificate(v1alpha1.ECDSAKeyAlgorithm, pki.ECCurve256, "", ""),
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
			genTlsSecret:     true,
		},
		"issues new ecdsa based certs when authkey is not provided and secret does not exist": &testT{
			certificate:      createCertificate(v1alpha1.ECDSAKeyAlgorithm, pki.ECCurve256, "", ""),
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
		},
		"issues new rsa based certs when authkey is provided and secret does exist": &testT{
			certificate:      createCertificate(v1alpha1.RSAKeyAlgorithm, pki.MinRSAKeySize, "", ""),
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
			genTlsSecret:     true,
			genAuthKeySecret: true,
			authKeyValue:     secretAuthKey,
		},
		"issues new rsa based certs when authkey is provided and secret does not exist": &testT{
			certificate:      createCertificate(v1alpha1.RSAKeyAlgorithm, pki.MinRSAKeySize, "", ""),
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
			genAuthKeySecret: true,
			authKeyValue:     secretAuthKey,
		},
		"issues new rsa based certs when authkey is not provided and secret does exist": &testT{
			certificate:      createCertificate(v1alpha1.RSAKeyAlgorithm, pki.MinRSAKeySize, "", ""),
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
			genTlsSecret:     true,
		},
		"issues new rsa based certs when authkey is not provided and secret does not exist": &testT{
			certificate:      createCertificate(v1alpha1.RSAKeyAlgorithm, pki.MinRSAKeySize, "", ""),
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
		},
		"sends the label & profile provided on the certificate with the server request": &testT{
			certificate:      createCertificate(v1alpha1.RSAKeyAlgorithm, pki.MinRSAKeySize, "blah-profile", "blah-label"),
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
			profile:          "blah-profile",
			label:            "blah-label",
		},
	}

	for msg, test := range errorTests {
		t.Run(msg, func(t *testing.T) {
			test.setup()

			server := testCFSSLServer(test.expectedRespBody, test.serverStatusCode, test.profile, test.label)
			issuerObj, err := createIssuer(test.client, test.secretSelector, test.lister, server.URL, test.serverPath)
			if err != nil {
				t.Fatalf(err.Error())
			}

			_, _, err = issuerObj.Issue(context.TODO(), test.certificate)
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
			test.setup()

			server := testCFSSLServer(test.expectedRespBody, test.serverStatusCode, test.profile, test.label)
			issuerObj, err := createIssuer(test.client, test.secretSelector, test.lister, server.URL, test.serverPath)
			if err != nil {
				t.Fatalf(err.Error())
			}

			_, certPem, err := issuerObj.Issue(context.TODO(), test.certificate)
			if err != nil {
				t.Fatalf(err.Error())
			}

			if string(certPem) != test.expectedCrt {
				t.Fatalf(`expected "%s", got "%s"`, test.expectedCrt, certPem)
			}
		})
	}
}

func createCertificate(keyAlgo v1alpha1.KeyAlgorithm, keySize int, profile, label string) *v1alpha1.Certificate {
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
			KeySize:      keySize,
			CFSSL:        config,
		},
	}
}

func createIssuer(client *kubefake.Clientset, authKey *v1alpha1.SecretKeySelector, lister corelisters.SecretLister, serverURL, serverPath string) (issuer.Interface, error) {
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
		client,
		ctx.CMClient,
		ctx.Recorder,
		issuerNamespace,
		lister,
	)
}

func testCFSSLServer(respBody string, statusCode int, profile, label string) *httptest.Server {
	var resp string
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if statusCode != http.StatusOK {
			http.Error(w, "not found", statusCode)
			return
		}

		requestBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "error reading request body.", http.StatusInternalServerError)
			return
		}

		switch r.RequestURI {
		case "/v1/certs/sign":
			var request UnauthenticatedRequest

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

func newPrivateKeySecret(key crypto.PrivateKey, name string) (*corev1.Secret, error) {
	privateKeyBytes, err := pki.EncodePrivateKey(key)
	if err != nil {
		return nil, err
	}

	return newSecret(name, "tls.key", string(privateKeyBytes)), nil
}
