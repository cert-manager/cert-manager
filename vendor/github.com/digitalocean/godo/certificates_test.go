package godo

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

var certJSONResponse = `
{
	"certificate": {
		"id": "892071a0-bb95-49bc-8021-3afd67a210bf",
		"name": "web-cert-01",
		"dns_names": [
			"somedomain.com",
			"api.somedomain.com"
		],
		"not_after": "2017-02-22T00:23:00Z",
		"sha1_fingerprint": "dfcc9f57d86bf58e321c2c6c31c7a971be244ac7",
		"created_at": "2017-02-08T16:02:37Z",
		"state": "verified",
		"type": "custom"
	}
}
`

var certsJSONResponse = `
{
  	"certificates": [
    	{
      		"id": "892071a0-bb95-49bc-8021-3afd67a210bf",
			"name": "web-cert-01",
			"dns_names": [
				"somedomain.com",
				"api.somedomain.com"
			],
      		"not_after": "2017-02-22T00:23:00Z",
      		"sha1_fingerprint": "dfcc9f57d86bf58e321c2c6c31c7a971be244ac7",
			"created_at": "2017-02-08T16:02:37Z",
			"state": "verified",
			"type": "custom"
    	},
    	{
      		"id": "992071a0-bb95-49bc-8021-3afd67a210bf",
			"name": "web-cert-02",
			"dns_names":["example.com"],
      		"not_after": "2017-02-22T00:23:00Z",
      		"sha1_fingerprint": "cfcc9f57d86bf58e321c2c6c31c7a971be244ac7",
			"created_at": "2017-02-08T16:02:37Z",
			"state": "pending",
			"type": "lets_encrypt"
    	}
  	],
  	"links": {},
  	"meta": {
    	"total": 1
  	}
}
`

func TestCertificates_Get(t *testing.T) {
	setup()
	defer teardown()

	urlStr := "/v2/certificates"
	cID := "892071a0-bb95-49bc-8021-3afd67a210bf"
	urlStr = path.Join(urlStr, cID)
	mux.HandleFunc(urlStr, func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodGet)
		fmt.Fprint(w, certJSONResponse)
	})

	certificate, _, err := client.Certificates.Get(ctx, cID)
	if err != nil {
		t.Errorf("Certificates.Get returned error: %v", err)
	}

	expected := &Certificate{
		ID:              "892071a0-bb95-49bc-8021-3afd67a210bf",
		Name:            "web-cert-01",
		DNSNames:        []string{"somedomain.com", "api.somedomain.com"},
		NotAfter:        "2017-02-22T00:23:00Z",
		SHA1Fingerprint: "dfcc9f57d86bf58e321c2c6c31c7a971be244ac7",
		Created:         "2017-02-08T16:02:37Z",
		State:           "verified",
		Type:            "custom",
	}

	assert.Equal(t, expected, certificate)
}

func TestCertificates_List(t *testing.T) {
	setup()
	defer teardown()

	urlStr := "/v2/certificates"
	mux.HandleFunc(urlStr, func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodGet)
		fmt.Fprint(w, certsJSONResponse)
	})

	certificates, _, err := client.Certificates.List(ctx, nil)

	if err != nil {
		t.Errorf("Certificates.List returned error: %v", err)
	}

	expected := []Certificate{
		{
			ID:              "892071a0-bb95-49bc-8021-3afd67a210bf",
			Name:            "web-cert-01",
			DNSNames:        []string{"somedomain.com", "api.somedomain.com"},
			NotAfter:        "2017-02-22T00:23:00Z",
			SHA1Fingerprint: "dfcc9f57d86bf58e321c2c6c31c7a971be244ac7",
			Created:         "2017-02-08T16:02:37Z",
			State:           "verified",
			Type:            "custom",
		},
		{
			ID:              "992071a0-bb95-49bc-8021-3afd67a210bf",
			Name:            "web-cert-02",
			DNSNames:        []string{"example.com"},
			NotAfter:        "2017-02-22T00:23:00Z",
			SHA1Fingerprint: "cfcc9f57d86bf58e321c2c6c31c7a971be244ac7",
			Created:         "2017-02-08T16:02:37Z",
			State:           "pending",
			Type:            "lets_encrypt",
		},
	}

	assert.Equal(t, expected, certificates)
}

func TestCertificates_Create(t *testing.T) {
	tests := []struct {
		desc                string
		createRequest       *CertificateRequest
		certJSONResponse    string
		expectedCertificate *Certificate
	}{
		{
			desc: "creates custom certificate",
			createRequest: &CertificateRequest{
				Name:             "web-cert-01",
				PrivateKey:       "-----BEGIN PRIVATE KEY-----",
				LeafCertificate:  "-----BEGIN CERTIFICATE-----",
				CertificateChain: "-----BEGIN CERTIFICATE-----",
			},
			certJSONResponse: `{
				"certificate": {
					"id": "892071a0-bb95-49bc-8021-3afd67a210bf",
					"name": "custom-cert",
					"dns_names":[],
					"not_after": "2017-02-22T00:23:00Z",
					"sha1_fingerprint": "dfcc9f57d86bf58e321c2c6c31c7a971be244ac7",
					"created_at": "2017-02-08T16:02:37Z",
					"state": "verified",
					"type": "custom"
				}
			}`,
			expectedCertificate: &Certificate{
				ID:              "892071a0-bb95-49bc-8021-3afd67a210bf",
				Name:            "custom-cert",
				DNSNames:        []string{},
				NotAfter:        "2017-02-22T00:23:00Z",
				SHA1Fingerprint: "dfcc9f57d86bf58e321c2c6c31c7a971be244ac7",
				Created:         "2017-02-08T16:02:37Z",
				State:           "verified",
				Type:            "custom",
			},
		},
		{
			desc: "creates let's encrypt certificate",
			createRequest: &CertificateRequest{
				Name:     "lets-encrypt-cert",
				DNSNames: []string{"example.com", "api.example.com"},
				Type:     "lets_encrypt",
			},
			certJSONResponse: `{
				"certificate": {
					"id": "91bce928-a983-4c97-a5ee-78c585bf798d",
					"name": "lets-encrypt-cert",
					"dns_names":["example.com", "api.example.com"],
					"not_after": "2022-01-26T15:50:00Z",
					"sha1_fingerprint": "2e3c2ba8016faf80f431700ff2865ef6dba30a81",
					"created_at": "2017-08-23T20:42:46Z",
					"state": "pending",
					"type": "lets_encrypt"
				}
			}`,
			expectedCertificate: &Certificate{
				ID:              "91bce928-a983-4c97-a5ee-78c585bf798d",
				Name:            "lets-encrypt-cert",
				DNSNames:        []string{"example.com", "api.example.com"},
				NotAfter:        "2022-01-26T15:50:00Z",
				SHA1Fingerprint: "2e3c2ba8016faf80f431700ff2865ef6dba30a81",
				Created:         "2017-08-23T20:42:46Z",
				State:           "pending",
				Type:            "lets_encrypt",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			setup()
			defer teardown()

			urlStr := "/v2/certificates"
			mux.HandleFunc(urlStr, func(w http.ResponseWriter, r *http.Request) {
				v := new(CertificateRequest)
				err := json.NewDecoder(r.Body).Decode(v)
				if err != nil {
					t.Fatal(err)
				}

				testMethod(t, r, http.MethodPost)
				assert.Equal(t, test.createRequest, v)

				fmt.Fprint(w, test.certJSONResponse)
			})

			certificate, _, err := client.Certificates.Create(ctx, test.createRequest)
			if err != nil {
				t.Errorf("Certificates.Create returned error: %v", err)
			}

			assert.Equal(t, test.expectedCertificate, certificate)
		})
	}
}

func TestCertificates_Delete(t *testing.T) {
	setup()
	defer teardown()

	cID := "892071a0-bb95-49bc-8021-3afd67a210bf"
	urlStr := "/v2/certificates"
	urlStr = path.Join(urlStr, cID)
	mux.HandleFunc(urlStr, func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodDelete)
	})

	_, err := client.Certificates.Delete(ctx, cID)

	if err != nil {
		t.Errorf("Certificates.Delete returned error: %v", err)
	}
}
