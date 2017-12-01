package httpmock

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// Responders are callbacks that receive and http request and return a mocked response.
type Responder func(*http.Request) (*http.Response, error)

// NoResponderFound is returned when no responders are found for a given HTTP method and URL.
var NoResponderFound = errors.New("no responder found")

// ConnectionFailure is a responder that returns a connection failure.  This is the default
// responder, and is called when no other matching responder is found.
func ConnectionFailure(*http.Request) (*http.Response, error) {
	return nil, NoResponderFound
}

// NewMockTransport creates a new *MockTransport with no responders.
func NewMockTransport() *MockTransport {
	return &MockTransport{
		responders:    make(map[string]Responder),
		callCountInfo: make(map[string]int),
	}
}

// MockTransport implements http.RoundTripper, which fulfills single http requests issued by
// an http.Client.  This implementation doesn't actually make the call, instead deferring to
// the registered list of responders.
type MockTransport struct {
	mu             sync.RWMutex
	responders     map[string]Responder
	noResponder    Responder
	callCountInfo  map[string]int
	totalCallCount int
}

// RoundTrip receives HTTP requests and routes them to the appropriate responder.  It is required to
// implement the http.RoundTripper interface.  You will not interact with this directly, instead
// the *http.Client you are using will call it for you.
func (m *MockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	url := req.URL.String()

	// try and get a responder that matches the method and URL
	key := req.Method + " " + url
	responder := m.responderForKey(key)

	// if we weren't able to find a responder and the URL contains a querystring
	// then we strip off the querystring and try again.
	if responder == nil && strings.Contains(url, "?") {
		key = req.Method + " " + strings.Split(url, "?")[0]
		responder = m.responderForKey(key)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// if we found a responder, call it
	if responder != nil {
		m.callCountInfo[key]++
		m.totalCallCount++
		return runCancelable(responder, req)
	}

	// we didn't find a responder, so fire the 'no responder' responder
	if m.noResponder == nil {
		return ConnectionFailure(req)
	}
	m.callCountInfo["NO_RESPONDER"]++
	m.totalCallCount++
	return runCancelable(m.noResponder, req)
}

func runCancelable(responder Responder, req *http.Request) (*http.Response, error) {
	if req.Cancel == nil {
		return responder(req)
	}

	// Set up a goroutine that translates a close(req.Cancel) into a
	// "request canceled" error, and another one that runs the
	// responder. Then race them: first to the result channel wins.

	type result struct {
		response *http.Response
		err      error
	}
	resultch := make(chan result, 1)
	done := make(chan struct{}, 1)

	go func() {
		select {
		case <-req.Cancel:
			resultch <- result{
				response: nil,
				err:      errors.New("request canceled"),
			}
		case <-done:
		}
	}()

	go func() {
		defer func() {
			if err := recover(); err != nil {
				resultch <- result{
					response: nil,
					err:      fmt.Errorf("panic in responder: got %q", err),
				}
			}
		}()

		response, err := responder(req)
		resultch <- result{
			response: response,
			err:      err,
		}
	}()

	r := <-resultch

	// if a close(req.Cancel) is never coming,
	// we'll need to unblock the first goroutine.
	done <- struct{}{}

	return r.response, r.err
}

// do nothing with timeout
func (m *MockTransport) CancelRequest(req *http.Request) {}

// responderForKey returns a responder for a given key
func (m *MockTransport) responderForKey(key string) Responder {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for k, r := range m.responders {
		if k != key {
			continue
		}
		return r
	}
	return nil
}

// RegisterResponder adds a new responder, associated with a given HTTP method and URL.  When a
// request comes in that matches, the responder will be called and the response returned to the client.
func (m *MockTransport) RegisterResponder(method, url string, responder Responder) {
	key := method + " " + url

	m.mu.Lock()
	m.responders[key] = responder
	m.callCountInfo[key] = 0
	m.mu.Unlock()
}

// RegisterNoResponder is used to register a responder that will be called if no other responder is
// found.  The default is ConnectionFailure.
func (m *MockTransport) RegisterNoResponder(responder Responder) {
	m.mu.Lock()
	m.noResponder = responder
	m.mu.Unlock()
}

// Reset removes all registered responders (including the no responder) from the MockTransport
func (m *MockTransport) Reset() {
	m.mu.Lock()
	m.responders = make(map[string]Responder)
	m.noResponder = nil
	m.callCountInfo = make(map[string]int)
	m.totalCallCount = 0
	m.mu.Unlock()
}

// GetCallCountInfo returns callCountInfo
func (m *MockTransport) GetCallCountInfo() map[string]int {
	res := map[string]int{}
	m.mu.RLock()
	for k, v := range m.callCountInfo {
		res[k] = v
	}
	m.mu.RUnlock()
	return res
}

// GetTotalCallCount returns the totalCallCount
func (m *MockTransport) GetTotalCallCount() int {
	m.mu.RLock()
	count := m.totalCallCount
	m.mu.RUnlock()
	return count
}

// DefaultTransport is the default mock transport used by Activate, Deactivate, Reset,
// DeactivateAndReset, RegisterResponder, and RegisterNoResponder.
var DefaultTransport = NewMockTransport()

// InitialTransport is a cache of the original transport used so we can put it back
// when Deactivate is called.
var InitialTransport = http.DefaultTransport

// Used to handle custom http clients (i.e clients other than http.DefaultClient)
var oldTransport http.RoundTripper
var oldClient *http.Client

// Activate starts the mock environment.  This should be called before your tests run.  Under the
// hood this replaces the Transport on the http.DefaultClient with DefaultTransport.
//
// To enable mocks for a test, simply activate at the beginning of a test:
// 		func TestFetchArticles(t *testing.T) {
// 			httpmock.Activate()
// 			// all http requests will now be intercepted
// 		}
//
// If you want all of your tests in a package to be mocked, just call Activate from init():
// 		func init() {
// 			httpmock.Activate()
// 		}
func Activate() {
	if Disabled() {
		return
	}

	// make sure that if Activate is called multiple times it doesn't overwrite the InitialTransport
	// with a mock transport.
	if http.DefaultTransport != DefaultTransport {
		InitialTransport = http.DefaultTransport
	}

	http.DefaultTransport = DefaultTransport
}

// ActivateNonDefault starts the mock environment with a non-default http.Client.
// This emulates the Activate function, but allows for custom clients that do not use
// http.DefaultTransport
//
// To enable mocks for a test using a custom client, activate at the beginning of a test:
// 		client := &http.Client{Transport: &http.Transport{TLSHandshakeTimeout: 60 * time.Second}}
// 		httpmock.ActivateNonDefault(client)
func ActivateNonDefault(client *http.Client) {
	if Disabled() {
		return
	}

	// save the custom client & it's RoundTripper
	oldTransport = client.Transport
	oldClient = client
	client.Transport = DefaultTransport
}

// GetCallCountInfo gets the info on all the calls httpmock has taken since it was activated or
// reset. The info is returned as a map of the calling keys with the number of calls made to them
// as their value. The key is the method, a space, and the url all concatenated together.
func GetCallCountInfo() map[string]int {
	return DefaultTransport.GetCallCountInfo()
}

// GetTotalCallCount gets the total number of calls httpmock has taken since it was activated or
// reset.
func GetTotalCallCount() int {
	return DefaultTransport.GetTotalCallCount()
}

// Deactivate shuts down the mock environment.  Any HTTP calls made after this will use a live
// transport.
//
// Usually you'll call it in a defer right after activating the mock environment:
// 		func TestFetchArticles(t *testing.T) {
// 			httpmock.Activate()
// 			defer httpmock.Deactivate()
//
// 			// when this test ends, the mock environment will close
// 		}
func Deactivate() {
	if Disabled() {
		return
	}
	http.DefaultTransport = InitialTransport

	// reset the custom client to use it's original RoundTripper
	if oldClient != nil {
		oldClient.Transport = oldTransport
	}
}

// Reset will remove any registered mocks and return the mock environment to it's initial state.
func Reset() {
	DefaultTransport.Reset()
}

// DeactivateAndReset is just a convenience method for calling Deactivate() and then Reset()
// Happy deferring!
func DeactivateAndReset() {
	Deactivate()
	Reset()
}

// RegisterResponder adds a mock that will catch requests to the given HTTP method and URL, then
// route them to the Responder which will generate a response to be returned to the client.
//
// Example:
// 		func TestFetchArticles(t *testing.T) {
// 			httpmock.Activate()
// 			httpmock.DeactivateAndReset()
//
// 			httpmock.RegisterResponder("GET", "http://example.com/",
// 				httpmock.NewStringResponder("hello world", 200))
//
//			// requests to http://example.com/ will now return 'hello world'
// 		}
func RegisterResponder(method, url string, responder Responder) {
	DefaultTransport.RegisterResponder(method, url, responder)
}

// RegisterNoResponder adds a mock that will be called whenever a request for an unregistered URL
// is received.  The default behavior is to return a connection error.
//
// In some cases you may not want all URLs to be mocked, in which case you can do this:
// 		func TestFetchArticles(t *testing.T) {
// 			httpmock.Activate()
// 			httpmock.DeactivateAndReset()
//			httpmock.RegisterNoResponder(httpmock.InitialTransport.RoundTrip)
//
// 			// any requests that don't have a registered URL will be fetched normally
// 		}
func RegisterNoResponder(responder Responder) {
	DefaultTransport.RegisterNoResponder(responder)
}
