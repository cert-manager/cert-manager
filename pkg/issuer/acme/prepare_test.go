package acme

import (
	"context"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/acme"
	"gopkg.in/jarcoal/httpmock.v1"
)

func TestCheckAuthorization(t *testing.T) {
	type testT struct {
		name           string
		mockStatusCode int
		mockResponse   string
		ctx            context.Context
		uri            string
		expected       bool
		err            bool
	}
	tests := []testT{
		{
			name:           "should return no error for 404 return code",
			mockStatusCode: 404,
			mockResponse: `{
  "type": "urn:acme:error:malformed",
  "detail": "Expired authorization",
  "status": 404
}`,
			uri:      "http://testuri",
			expected: false,
			err:      false,
		},
		{
			name:           "should return valid for a 200 return code",
			mockStatusCode: 200,
			mockResponse: `{
  "status": "valid"
}`,
			uri:      "http://testuri",
			expected: true,
			err:      false,
		},
		{
			name:           "should return invalid but no error for any status that isn't 'valid'",
			mockStatusCode: 200,
			mockResponse: `{
  "status": "invalid"
}`,
			uri:      "http://testuri",
			expected: false,
			err:      false,
		},
		{
			name:           "should return an error for an invalid response",
			mockStatusCode: 500,
			// invalid response body
			mockResponse: `{
  "type": "urn:acme:error:malformed",
  "detail": "Fake error",
  "status": 500
}`,
			uri:      "http://testuri",
			expected: false,
			err:      true,
		},
	}
	testFn := func(test testT) func(t *testing.T) {
		return func(t *testing.T) {
			mock := httpmock.NewMockTransport()
			mock.RegisterResponder("GET", test.uri, httpmock.ResponderFromResponse(&http.Response{
				StatusCode: test.mockStatusCode,
				Body:       ioutil.NopCloser(strings.NewReader(test.mockResponse)),
			}))
			ctx := test.ctx
			if ctx == nil {
				ctx = context.Background()
			}
			cl := &acme.Client{
				HTTPClient: &http.Client{Transport: mock},
			}
			valid, err := checkAuthorization(ctx, cl, test.uri)
			if err != nil && !test.err {
				t.Errorf("expected no error, but got: %s", err)
			}
			if err == nil && test.err {
				t.Errorf("expected error, but got no error")
			}
			if valid != test.expected {
				t.Errorf("expected checkAuthorization to return %v, but got %v", test.expected, valid)
			}
		}
	}
	for _, test := range tests {
		t.Run(test.name, testFn(test))
	}
}
