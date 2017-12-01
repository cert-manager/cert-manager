package httpmock

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"io/ioutil"
	"net/http"
	"reflect"
	"testing"
)

func TestResponderFromResponse(t *testing.T) {
	responder := ResponderFromResponse(NewStringResponse(200, "hello world"))

	req, err := http.NewRequest(http.MethodGet, testUrl, nil)
	if err != nil {
		t.Fatal("Error creating request")
	}
	response1, err := responder(req)
	if err != nil {
		t.Error("Error should be nil")
	}

	testUrlWithQuery := testUrl + "?a=1"
	req, err = http.NewRequest(http.MethodGet, testUrlWithQuery, nil)
	if err != nil {
		t.Fatal("Error creating request")
	}
	response2, err := responder(req)
	if err != nil {
		t.Error("Error should be nil")
	}

	// Body should be the same for both responses
	assertBody(t, response1, "hello world")
	assertBody(t, response2, "hello world")

	// Request should be non-nil and different for each response
	if response1.Request != nil && response2.Request != nil {
		if response1.Request.URL.String() != testUrl {
			t.Errorf("Expected request url %s, got: %s", testUrl, response1.Request.URL.String())
		}
		if response2.Request.URL.String() != testUrlWithQuery {
			t.Errorf("Expected request url %s, got: %s", testUrlWithQuery, response2.Request.URL.String())
		}
	} else {
		t.Error("response.Request should not be nil")
	}
}

func TestNewStringResponse(t *testing.T) {
	body := "hello world"
	status := 200
	response := NewStringResponse(status, body)

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}

	if string(data) != body {
		t.FailNow()
	}

	if response.StatusCode != status {
		t.FailNow()
	}
}

func TestNewBytesResponse(t *testing.T) {
	body := []byte("hello world")
	status := 200
	response := NewBytesResponse(status, body)

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}

	if string(data) != string(body) {
		t.FailNow()
	}

	if response.StatusCode != status {
		t.FailNow()
	}
}

func TestNewJsonResponse(t *testing.T) {
	type schema struct {
		Hello string `json:"hello"`
	}

	body := &schema{"world"}
	status := 200

	response, err := NewJsonResponse(status, body)
	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != status {
		t.FailNow()
	}

	if response.Header.Get("Content-Type") != "application/json" {
		t.FailNow()
	}

	checkBody := &schema{}
	if err := json.NewDecoder(response.Body).Decode(checkBody); err != nil {
		t.Fatal(err)
	}

	if checkBody.Hello != body.Hello {
		t.FailNow()
	}
}

func TestNewXmlResponse(t *testing.T) {
	type schema struct {
		Hello string `xml:"hello"`
	}

	body := &schema{"world"}
	status := 200

	response, err := NewXmlResponse(status, body)
	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != status {
		t.FailNow()
	}

	if response.Header.Get("Content-Type") != "application/xml" {
		t.FailNow()
	}

	checkBody := &schema{}
	if err := xml.NewDecoder(response.Body).Decode(checkBody); err != nil {
		t.Fatal(err)
	}

	if checkBody.Hello != body.Hello {
		t.FailNow()
	}
}

func TestNewErrorResponder(t *testing.T) {
	responder := NewErrorResponder(errors.New("oh no"))
	req, err := http.NewRequest(http.MethodGet, testUrl, nil)
	if err != nil {
		t.Fatal("Error creating request")
	}
	response, err := responder(req)
	if response != nil {
		t.Error("Response should be nil")
	}
	expected := errors.New("oh no")
	if !reflect.DeepEqual(err, expected) {
		t.Errorf("Expected error %#v, got: %#v", expected, err)
	}
}

func TestRewindResponse(t *testing.T) {
	body := []byte("hello world")
	status := 200
	responses := []*http.Response{
		NewBytesResponse(status, body),
		NewStringResponse(status, string(body)),
	}

	for _, response := range responses {

		data, err := ioutil.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}

		if string(data) != string(body) {
			t.FailNow()
		}

		if response.StatusCode != status {
			t.FailNow()
		}

		data, err = ioutil.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}

		if string(data) != string(body) {
			t.FailNow()
		}

		if response.StatusCode != status {
			t.FailNow()
		}
	}
}
