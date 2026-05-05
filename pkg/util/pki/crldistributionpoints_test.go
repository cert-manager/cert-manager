package pki

import (
	"crypto/x509/pkix"
	"reflect"
	"testing"
)

func TestMarshalAndUnmarshalCRLDistributionPoints(t *testing.T) {
	type testCase struct {
		Urls        []string
		UrlsInBytes []byte
	}
	type testCases map[string]testCase

	testcases := testCases{
		"One simple url": {
			Urls:        []string{"http://example.com"},
			UrlsInBytes: []byte{48, 26, 48, 24, 160, 22, 160, 20, 134, 18, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109},
		},
		"Two simple urls": {
			Urls: []string{"http://cer1.example.com/crl1.pem", "http://cer1.example.com/crl2.pem"},
			UrlsInBytes: []byte{48, 80, 48, 38, 160, 36, 160, 34, 134, 32, 104, 116, 116, 112, 58, 47, 47, 99, 101, 114, 49, 46, 101, 120, 97, 109,
				112, 108, 101, 46, 99, 111, 109, 47, 99, 114, 108, 49, 46, 112, 101, 109, 48, 38, 160, 36, 160, 34, 134, 32, 104, 116, 116, 112,
				58, 47, 47, 99, 101, 114, 49, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 114, 108, 50, 46, 112, 101, 109,
			},
		},
		"No urls": {
			Urls:        []string{},
			UrlsInBytes: []byte{48, 0},
		},
	}

	for testName, tc := range testcases {
		{
			result, err := MarshalCRLDistributionPoints(tc.Urls)
			if err != nil {
				t.Errorf("test: %s MarshalCRLDistributionPoints returned an error: %v", testName, err)
			}
			if !reflect.DeepEqual(pkix.Extension{OIDExtensionCRLDistributionPoints, false, tc.UrlsInBytes}, result) {
				t.Errorf("test: %s Expected bytes: %v, got: %v", testName, tc.UrlsInBytes, result)
			}
		}
		{
			newresutl, err := UnmarshalCRLDistributionPoints(tc.UrlsInBytes)
			if err != nil {
				t.Errorf("test: %s UnmarshalCRLDistributionPoints returned an error: %v", testName, err)
			}

			if len(tc.Urls)+len(newresutl) > 0 && !reflect.DeepEqual(tc.Urls, newresutl) {
				t.Errorf("test: %s Expected urls: %v, got: %v", testName, tc.Urls, newresutl)
			}
		}
	}
}
