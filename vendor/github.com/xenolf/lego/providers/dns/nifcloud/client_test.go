package nifcloud

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runTestServer(responseBody string, statusCode int) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		fmt.Fprintln(w, responseBody)
	}))
	return server
}

func TestChangeResourceRecordSets(t *testing.T) {
	responseBody := `<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2012-12-12/">
  <ChangeInfo>
    <Id>xxxxx</Id>
    <Status>INSYNC</Status>
    <SubmittedAt>2015-08-05T00:00:00.000Z</SubmittedAt>
  </ChangeInfo>
</ChangeResourceRecordSetsResponse>
`
	server := runTestServer(responseBody, http.StatusOK)
	defer server.Close()

	client, err := NewClient("A", "B")
	require.NoError(t, err)

	client.BaseURL = server.URL

	res, err := client.ChangeResourceRecordSets("example.com", ChangeResourceRecordSetsRequest{})
	require.NoError(t, err)
	assert.Equal(t, "xxxxx", res.ChangeInfo.ID)
	assert.Equal(t, "INSYNC", res.ChangeInfo.Status)
	assert.Equal(t, "2015-08-05T00:00:00.000Z", res.ChangeInfo.SubmittedAt)
}

func TestChangeResourceRecordSetsErrors(t *testing.T) {
	testCases := []struct {
		desc         string
		responseBody string
		statusCode   int
		expected     string
	}{
		{
			desc: "API error",
			responseBody: `<?xml version="1.0" encoding="UTF-8"?>
<ErrorResponse>
  <Error>
    <Type>Sender</Type>
    <Code>AuthFailed</Code>
    <Message>The request signature we calculated does not match the signature you provided.</Message>
  </Error>
</ErrorResponse>
`,
			statusCode: http.StatusUnauthorized,
			expected:   "an error occurred: The request signature we calculated does not match the signature you provided.",
		},
		{
			desc:         "response body error",
			responseBody: "foo",
			statusCode:   http.StatusOK,
			expected:     "an error occurred while unmarshaling the response body to XML: EOF",
		},
		{
			desc:         "error message error",
			responseBody: "foo",
			statusCode:   http.StatusInternalServerError,
			expected:     "an error occurred while unmarshaling the error body to XML: EOF",
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {

			server := runTestServer(test.responseBody, test.statusCode)
			defer server.Close()

			client, err := NewClient("A", "B")
			require.NoError(t, err)

			client.BaseURL = server.URL

			res, err := client.ChangeResourceRecordSets("example.com", ChangeResourceRecordSetsRequest{})
			assert.Nil(t, res)
			assert.EqualError(t, err, test.expected)
		})
	}
}

func TestGetChange(t *testing.T) {
	responseBody := `<?xml version="1.0" encoding="UTF-8"?>
<GetChangeResponse xmlns="https://route53.amazonaws.com/doc/2012-12-12/">
  <ChangeInfo>
    <Id>xxxxx</Id>
    <Status>INSYNC</Status>
    <SubmittedAt>2015-08-05T00:00:00.000Z</SubmittedAt>
  </ChangeInfo>
</GetChangeResponse>
`

	server := runTestServer(responseBody, http.StatusOK)
	defer server.Close()

	client, err := NewClient("A", "B")
	require.NoError(t, err)

	client.BaseURL = server.URL

	res, err := client.GetChange("12345")
	require.NoError(t, err)
	assert.Equal(t, "xxxxx", res.ChangeInfo.ID)
	assert.Equal(t, "INSYNC", res.ChangeInfo.Status)
	assert.Equal(t, "2015-08-05T00:00:00.000Z", res.ChangeInfo.SubmittedAt)
}

func TestGetChangeErrors(t *testing.T) {
	testCases := []struct {
		desc         string
		responseBody string
		statusCode   int
		expected     string
	}{
		{
			desc: "API error",
			responseBody: `<?xml version="1.0" encoding="UTF-8"?>
<ErrorResponse>
  <Error>
    <Type>Sender</Type>
    <Code>AuthFailed</Code>
    <Message>The request signature we calculated does not match the signature you provided.</Message>
  </Error>
</ErrorResponse>
`,
			statusCode: http.StatusUnauthorized,
			expected:   "an error occurred: The request signature we calculated does not match the signature you provided.",
		},
		{
			desc:         "response body error",
			responseBody: "foo",
			statusCode:   http.StatusOK,
			expected:     "an error occurred while unmarshaling the response body to XML: EOF",
		},
		{
			desc:         "error message error",
			responseBody: "foo",
			statusCode:   http.StatusInternalServerError,
			expected:     "an error occurred while unmarshaling the error body to XML: EOF",
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {

			server := runTestServer(test.responseBody, test.statusCode)
			defer server.Close()

			client, err := NewClient("A", "B")
			require.NoError(t, err)

			client.BaseURL = server.URL

			res, err := client.GetChange("12345")
			assert.Nil(t, res)
			assert.EqualError(t, err, test.expected)
		})
	}

}
