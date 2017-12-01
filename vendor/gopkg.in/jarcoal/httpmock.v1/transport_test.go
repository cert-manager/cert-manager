package httpmock

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

var testUrl = "http://www.example.com/"

func assertBody(t *testing.T, resp *http.Response, expected string) {
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	got := string(data)

	if got != expected {
		t.Errorf("Expected body: %#v, got %#v", expected, got)
	}
}

func TestMockTransport(t *testing.T) {
	Activate()
	defer Deactivate()

	url := "https://github.com/"
	body := "hello world"

	RegisterResponder("GET", url, NewStringResponder(200, body))

	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if string(data) != body {
		t.FailNow()
	}

	// the http client wraps our NoResponderFound error, so we just try and match on text
	if _, err := http.Get(testUrl); !strings.Contains(err.Error(),
		NoResponderFound.Error()) {

		t.Fatal(err)
	}
}

func TestMockTransportReset(t *testing.T) {
	DeactivateAndReset()

	if len(DefaultTransport.responders) > 0 {
		t.Fatal("expected no responders at this point")
	}

	RegisterResponder("GET", testUrl, nil)

	if len(DefaultTransport.responders) != 1 {
		t.Fatal("expected one responder")
	}

	Reset()

	if len(DefaultTransport.responders) > 0 {
		t.Fatal("expected no responders as they were just reset")
	}
}

func TestMockTransportNoResponder(t *testing.T) {
	Activate()
	defer DeactivateAndReset()

	Reset()

	if DefaultTransport.noResponder != nil {
		t.Fatal("expected noResponder to be nil")
	}

	if _, err := http.Get(testUrl); err == nil {
		t.Fatal("expected to receive a connection error due to lack of responders")
	}

	RegisterNoResponder(NewStringResponder(200, "hello world"))

	resp, err := http.Get(testUrl)
	if err != nil {
		t.Fatal("expected request to succeed")
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if string(data) != "hello world" {
		t.Fatal("expected body to be 'hello world'")
	}
}

func TestMockTransportQuerystringFallback(t *testing.T) {
	Activate()
	defer DeactivateAndReset()

	// register the testUrl responder
	RegisterResponder("GET", testUrl, NewStringResponder(200, "hello world"))

	// make a request for the testUrl with a querystring
	resp, err := http.Get(testUrl + "?hello=world")
	if err != nil {
		t.Fatal("expected request to succeed")
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if string(data) != "hello world" {
		t.Fatal("expected body to be 'hello world'")
	}
}

type dummyTripper struct{}

func (d *dummyTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, nil
}

func TestMockTransportInitialTransport(t *testing.T) {
	DeactivateAndReset()

	tripper := &dummyTripper{}
	http.DefaultTransport = tripper

	Activate()

	if http.DefaultTransport == tripper {
		t.Fatal("expected http.DefaultTransport to be a mock transport")
	}

	Deactivate()

	if http.DefaultTransport != tripper {
		t.Fatal("expected http.DefaultTransport to be dummy")
	}
}

func TestMockTransportNonDefault(t *testing.T) {
	// create a custom http client w/ custom Roundtripper
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			Dial: (&net.Dialer{
				Timeout:   60 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout: 60 * time.Second,
		},
	}

	// activate mocks for the client
	ActivateNonDefault(client)
	defer DeactivateAndReset()

	body := "hello world!"

	RegisterResponder("GET", testUrl, NewStringResponder(200, body))

	req, err := http.NewRequest("GET", testUrl, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if string(data) != body {
		t.FailNow()
	}
}

func TestMockTransportRespectsCancel(t *testing.T) {
	Activate()
	defer DeactivateAndReset()

	cases := []struct {
		withCancel   bool
		cancelNow    bool
		withPanic    bool
		expectedBody string
		expectedErr  error
	}{
		// No cancel specified at all. Falls back to normal behavior
		{false, false, false, "hello world", nil},

		// Cancel returns error
		{true, true, false, "", errors.New("request canceled")},

		// Request can be cancelled but it is not cancelled.
		{true, false, false, "hello world", nil},

		// Panic in cancelled request is handled
		{true, false, true, "", errors.New(`panic in responder: got "oh no"`)},
	}

	for _, c := range cases {
		Reset()
		if c.withPanic {
			RegisterResponder("GET", testUrl, func(r *http.Request) (*http.Response, error) {
				time.Sleep(time.Millisecond)
				panic("oh no")
			})
		} else {
			RegisterResponder("GET", testUrl, func(r *http.Request) (*http.Response, error) {
				time.Sleep(time.Millisecond)
				return NewStringResponse(http.StatusOK, "hello world"), nil
			})
		}

		req, err := http.NewRequest("GET", testUrl, nil)
		if err != nil {
			t.Fatal(err)
		}
		if c.withCancel {
			cancel := make(chan struct{}, 1)
			req.Cancel = cancel
			if c.cancelNow {
				cancel <- struct{}{}
			}
		}

		resp, err := http.DefaultClient.Do(req)

		// If we expect and error but none was returned, it's fatal for this test...
		if err == nil && c.expectedErr != nil {
			t.Fatal("Error should not be nil")
		}

		if err != nil {
			got := err.(*url.Error)
			if !reflect.DeepEqual(got.Err, c.expectedErr) {
				t.Errorf("Expected: %#v, got: %#v", c.expectedErr, got.Err)
			}
		}

		if c.expectedBody != "" {
			assertBody(t, resp, c.expectedBody)
		}
	}
}

func TestMockTransportRespectsTimeout(t *testing.T) {
	timeout := time.Millisecond
	client := &http.Client{
		Timeout: timeout,
	}

	ActivateNonDefault(client)
	defer DeactivateAndReset()

	RegisterResponder(
		"GET", testUrl,
		func(r *http.Request) (*http.Response, error) {
			time.Sleep(2 * timeout)
			return NewStringResponse(http.StatusOK, ""), nil
		},
	)

	_, err := client.Get(testUrl)
	if err == nil {
		t.Fail()
	}
}

func TestMockTransportCallCount(t *testing.T) {
	Reset()
	Activate()
	defer Deactivate()

	url := "https://github.com/"
	url2 := "https://gitlab.com/"

	RegisterResponder("GET", url, NewStringResponder(200, "body"))
	RegisterResponder("POST", url2, NewStringResponder(200, "body"))

	_, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}

	buff := new(bytes.Buffer)
	json.NewEncoder(buff).Encode("{}")
	_, err1 := http.Post(url2, "application/json", buff)
	if err1 != nil {
		t.Fatal(err1)
	}

	_, err2 := http.Get(url)
	if err2 != nil {
		t.Fatal(err2)
	}

	totalCallCount := GetTotalCallCount()
	if totalCallCount != 3 {
		t.Fatalf("did not track the total count of calls correctly. expected it to be 3, but it was %v", totalCallCount)
	}

	info := GetCallCountInfo()
	expectedInfo := map[string]int{}
	urlCallkey := "GET " + url
	url2Callkey := "POST " + url2
	expectedInfo[urlCallkey] = 2
	expectedInfo[url2Callkey] = 1

	if !reflect.DeepEqual(info, expectedInfo) {
		t.Fatalf("did not correctly track the call count info. expected it to be \n %+v \n but it was \n %+v \n", expectedInfo, info)
	}

	Reset()

	afterResetTotalCallCount := GetTotalCallCount()
	if afterResetTotalCallCount != 0 {
		t.Fatalf("did not reset the total count of calls correctly. expected it to be 0 after reset, but it was %v", afterResetTotalCallCount)
	}

}
