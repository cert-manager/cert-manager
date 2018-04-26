package pester

import (
	"context"
	"fmt"
	"log"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"errors"
	"net/http"
	"net/http/cookiejar"
)

func TestConcurrentRequests(t *testing.T) {
	t.Parallel()

	c := New()
	c.Concurrency = 3
	c.KeepLog = true

	nonExistantURL := "http://localhost:9000/foo"

	_, err := c.Get(nonExistantURL)
	if err == nil {
		t.Fatal("expected to get an error")
	}
	c.Wait()

	// in the event of an error, let's see what the logs were
	t.Log("\n", c.LogString())

	if got, want := c.LogErrCount(), c.Concurrency*c.MaxRetries; got != want {
		t.Errorf("got %d attempts, want %d", got, want)
	}
}

func TestConcurrentRequestsWith429(t *testing.T) {
	t.Parallel()

	c := New()
	c.Concurrency = 3
	c.KeepLog = true

	port, err := serverWith429()
	if err != nil {
		t.Fatal("unable to start server", err)
	}

	url := fmt.Sprintf("http://localhost:%d", port)

	response, err := c.Get(url)
	if err != nil {
		t.Fatal("unable to GET", err)
	}
	c.Wait()

	response.Body.Close()
	c.Wait()

	// in the event of an error, let's see what the logs were
	t.Log("\n", c.LogString())

	if got, want := c.LogErrCount(), c.Concurrency*c.MaxRetries; got != want {
		t.Errorf("got %d attempts, want %d", got, want)
	}
}

func TestMaxRetriesConcurrentRequestsWith429(t *testing.T) {
	t.Parallel()

	c := New()
	c.Concurrency = 3
	c.KeepLog = true
	c.MaxRetries = 5

	port, err := serverWith429()
	if err != nil {
		t.Fatal("unable to start server", err)
	}

	url := fmt.Sprintf("http://localhost:%d", port)

	response, err := c.Get(url)
	if err != nil {
		t.Fatal("unable to GET", err)
	}
	c.Wait()

	response.Body.Close()
	c.Wait()

	// in the event of an error, let's see what the logs were
	t.Log("\n", c.LogString())

	if got, want := c.LogErrCount(), c.Concurrency*c.MaxRetries; got != want {
		t.Errorf("got %d attempts, want %d", got, want)
	}
}

func TestConcurrent2Retry0(t *testing.T) {
	t.Parallel()

	c := New()
	c.Concurrency = 2
	c.MaxRetries = 0
	c.KeepLog = true

	nonExistantURL := "http://localhost:9000/foo"

	_, err := c.Get(nonExistantURL)
	if err == nil {
		t.Fatal("expected to get an error")
	}
	c.Wait()

	// in the event of an error, let's see what the logs were
	t.Log("\n", c.LogString())

	if got, want := c.LogErrCount(), c.Concurrency; got != want {
		t.Errorf("got %d attempts, want %d", got, want)
	}
}

func TestConcurrent2Retry0for429(t *testing.T) {
	t.Parallel()

	c := New()
	c.Concurrency = 2
	c.MaxRetries = 0
	c.KeepLog = true

	port, err := serverWith429()
	if err != nil {
		t.Fatal("unable to start server", err)
	}

	url := fmt.Sprintf("http://localhost:%d", port)

	_, getErr := c.Get(url)

	if getErr != nil {
		t.Fatal("unable to GET", getErr)
	}
	c.Wait()

	// in the event of an error, let's see what the logs were
	t.Log("\n", c.LogString())

	if got, want := c.LogErrCount(), c.Concurrency; got != want {
		t.Errorf("got %d attempts, want %d", got, want)
	}
}

func TestDefaultBackoff(t *testing.T) {
	t.Parallel()

	c := New()
	c.KeepLog = true

	nonExistantURL := "http://localhost:9000/foo"

	_, err := c.Get(nonExistantURL)
	if err == nil {
		t.Fatal("expected to get an error")
	}
	c.Wait()

	// in the event of an error, let's see what the logs were
	t.Log("\n", c.LogString())

	if got, want := c.Concurrency, 1; got != want {
		t.Errorf("got %d, want %d for concurrency", got, want)
	}

	if got, want := c.LogErrCount(), c.MaxRetries; got != want {
		t.Fatalf("got %d errors, want %d", got, want)
	}

	var startTime int64
	for i, e := range c.ErrLog {
		if i == 0 {
			startTime = e.Time.Unix()
			continue
		}
		if got, want := e.Time.Unix(), startTime+int64(i); got != want {
			t.Errorf("got time %d, want %d (%d greater than start time %d)", got, want, i, startTime)
		}
	}

}

func TestFormatError(t *testing.T) {
	t.Parallel()
	err := errors.New("Get http://localhost:9000/foo: dial tcp 127.0.0.1:9000: getsockopt: connection refused")
	expected := "1491271979 Get [GET] http://localhost:9000/foo request-0 retry-2 error: " + err.Error() + "\n"

	e := ErrEntry{
		Time:    time.Unix(1491271979, 0),
		Method:  "Get",
		URL:     "http://localhost:9000/foo",
		Verb:    http.MethodGet,
		Request: 0,
		Retry:   2,
		Attempt: 1,
		Err:     err,
	}

	c := New()
	formatted := c.FormatError(e)
	if strings.Compare(expected, formatted) != 0 {
		t.Errorf("\nExpected:\n%s\nGot:\n%s", expected, formatted)
	}
}

func TestCustomLogHook(t *testing.T) {
	t.Parallel()

	expectedRetries := 5
	errorLines := []ErrEntry{}

	c := New()
	//c.KeepLog = true
	c.MaxRetries = expectedRetries
	c.Backoff = func(_ int) time.Duration {
		return 10 * time.Microsecond
	}

	c.LogHook = func(e ErrEntry) {
		errorLines = append(errorLines, e)
	}

	nonExistantURL := "http://localhost:9000/foo"

	_, err := c.Get(nonExistantURL)
	if err == nil {
		t.Fatal("expected to get an error")
	}
	c.Wait()

	// in the event of an error, let's see what the logs were
	if expectedRetries != len(errorLines) {
		t.Errorf("Expected %d lines to be emitted. Got %d", expectedRetries, len(errorLines))
	}
}

func TestDefaultLogHook(t *testing.T) {
	t.Parallel()

	errorLines := 0

	c := New()
	//c.KeepLog = true
	c.MaxRetries = 5
	c.Backoff = func(_ int) time.Duration {
		return 10 * time.Microsecond
	}

	nonExistantURL := "http://localhost:9000/foo"

	_, err := c.Get(nonExistantURL)
	if err == nil {
		t.Fatal("expected to get an error")
	}
	c.Wait()

	// in the event of an error, let's see what the logs were
	if errorLines != 0 {
		t.Errorf("Expected 0 lines to be emitted. Got %d", errorLines)
	}
}

func TestLinearJitterBackoff(t *testing.T) {
	t.Parallel()
	c := New()
	c.Backoff = LinearJitterBackoff
	c.KeepLog = true

	nonExistantURL := "http://localhost:9000/foo"

	_, err := c.Get(nonExistantURL)
	if err == nil {
		t.Fatal("expected to get an error")
	}
	c.Wait()

	// in the event of an error, let's see what the logs were
	t.Log("\n", c.LogString())

	var startTime int64
	var delta int64
	for i, e := range c.ErrLog {
		switch i {
		case 0:
			startTime = e.Time.Unix()
		case 1:
			delta += 1
		case 2:
			delta += 2
		case 3:
			delta += 3
		}

		if got, want := e.Time.Unix(), startTime+delta; withinEpsilon(got, want, 0.0) {
			t.Errorf("got time %d, want %d (within epsilon of start time %d)", got, want, startTime)
		}
	}
}

func TestExponentialBackoff(t *testing.T) {
	t.Parallel()

	c := New()
	c.MaxRetries = 4
	c.Backoff = ExponentialBackoff
	c.KeepLog = true

	nonExistantURL := "http://localhost:9000/foo"

	_, err := c.Get(nonExistantURL)
	if err == nil {
		t.Fatal("expected to get an error")
	}
	c.Wait()

	// in the event of an error, let's see what the logs were
	t.Log("\n", c.LogString())

	if got, want := c.LogErrCount(), c.MaxRetries; got != want {
		t.Fatalf("got %d errors, want %d", got, want)
	}

	var startTime int64
	var delta int64
	for i, e := range c.ErrLog {
		switch i {
		case 0:
			startTime = e.Time.Unix()
		case 1:
			delta += 2
		case 2:
			delta += 4
		case 3:
			delta += 8
		}
		if got, want := e.Time.Unix(), startTime+delta; got != want {
			t.Errorf("got time %d, want %d (%d greater than start time %d)", got, want, delta, startTime)
		}
	}
}

func TestCookiesJarPersistence(t *testing.T) {
	// make sure that client properties like .Jar are held onto through the request
	port, err := cookieServer()
	if err != nil {
		t.Fatal("unable to start cookie server", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal("Cannot create cookiejar", err)
	}

	c := New()
	c.Jar = jar

	url := fmt.Sprintf("http://localhost:%d", port)

	response, err := c.Get(url)
	if err != nil {
		t.Fatal("unable to GET", err)
	}
	c.Wait()

	response.Body.Close()
	if !strings.Contains(fmt.Sprintf("%v", jar), "mah-cookie nomnomnom") {
		t.Error("unable to find expected cookie")
	}
}

func TestEmbeddedClientTimeout(t *testing.T) {
	// set up a server that will timeout
	clientTimeout := 1000 * time.Millisecond
	port, err := timeoutServer(2 * clientTimeout)
	if err != nil {
		t.Fatal("unable to start timeout server", err)
	}

	hc := http.DefaultClient
	hc.Timeout = clientTimeout

	c := NewExtendedClient(hc)
	_, err = c.Get(fmt.Sprintf("http://localhost:%d/", port))
	if err == nil {
		t.Error("expected a timeout error, did not get it")
	}
}

func TestConcurrentRequestsNotRacyAndDontLeak_FailedRequest(t *testing.T) {
	goroStart := runtime.NumGoroutine()
	c := New()
	port, err := cookieServer()
	if err != nil {
		t.Fatalf("unable to start server %v", err)
	}
	goodURL := fmt.Sprintf("http://localhost:%d", port)
	conc := 5
	errCh := make(chan error, conc)

	wg := &sync.WaitGroup{}
	block := make(chan struct{})
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			<-block
			defer wg.Done()
			resp, err := c.Get(goodURL)
			if err != nil {
				errCh <- fmt.Errorf("got unexpected error getting %s, %v", goodURL, err)
				return
			}
			if resp != nil {
				resp.Body.Close()
			}
		}()
	}
	close(block)
	go func() {
		select {
		case err := <-errCh:
			t.Fatal(err)
		case <-time.After(250 * time.Millisecond):
			return
		}
	}()
	wg.Wait()

	// give background goroutines time to clean up
	<-time.After(1000 * time.Millisecond)
	goroEnd := runtime.NumGoroutine()
	if goroStart < goroEnd {
		t.Errorf("got %d running goroutines, want %d", goroEnd, goroStart)
	}
}

func TestConcurrentRequestsNotRacyAndDontLeak_SuccessfulRequest(t *testing.T) {
	goroStart := runtime.NumGoroutine()
	c := New()
	nonExistantURL := "http://localhost:9000/foo"
	conc := 5
	errCh := make(chan error, conc)

	wg := &sync.WaitGroup{}
	block := make(chan struct{})
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			<-block
			defer wg.Done()
			resp, err := c.Get(nonExistantURL)
			if err == nil {
				errCh <- fmt.Errorf("should have had an error getting %s", nonExistantURL)
				return
			}
			if resp != nil {
				resp.Body.Close()
			}
		}()
	}
	close(block)
	go func() {
		select {
		case err := <-errCh:
			t.Fatal(err)
		case <-time.After(250 * time.Millisecond):
			return
		}
	}()
	wg.Wait()

	// give background goroutines time to clean up
	<-time.After(1000 * time.Millisecond)
	goroEnd := runtime.NumGoroutine()
	if goroStart < goroEnd {
		t.Errorf("got %d running goroutines, want %d", goroEnd, goroStart)
	}
}

func TestRetriesNotAttemptedIfContextIsCancelled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())

	port, err := timeoutServer(1 * time.Second)
	if err != nil {
		t.Fatal("unable to start timeout server", err)
	}

	timeoutURL := fmt.Sprintf("http://localhost:%d", port)
	req, err := http.NewRequest("GET", timeoutURL, nil)
	if err != nil {
		t.Fatalf("unable to create request %v", err)
	}
	req = req.WithContext(ctx)

	c := New()
	c.MaxRetries = 10
	c.KeepLog = true
	c.Backoff = ExponentialBackoff

	//Cancel the context in another routine (eg: user interrupt)
	go func() {
		cancel()
		t.Logf("\n%d - cancelled", time.Now().Unix())
	}()

	_, err = c.Do(req)
	if err == nil {
		t.Fatal("expected to get an error")
	}
	c.Wait()

	// in the event of an error, let's see what the logs were
	t.Log("\n", c.LogString())

	if got, want := c.LogErrCount(), 1; got != want {
		t.Fatalf("got %d errors, want %d", got, want)
	}
}

func withinEpsilon(got, want int64, epslion float64) bool {
	if want <= int64(epslion*float64(got)) || want >= int64(epslion*float64(got)) {
		return false
	}
	return true
}

func cookieServer() (int, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cookie := &http.Cookie{}
		cookie.Name = "mah-cookie"
		cookie.Value = "nomnomnom"
		http.SetCookie(w, cookie)
		w.Write([]byte("OK"))
	})
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return -1, fmt.Errorf("unable to secure listener %v", err)
	}
	go func() {
		if err := http.Serve(l, mux); err != nil {
			log.Fatalf("slow-server error %v", err)
		}
	}()

	var port int
	_, sport, err := net.SplitHostPort(l.Addr().String())
	if err == nil {
		port, err = strconv.Atoi(sport)
	}

	if err != nil {
		return -1, fmt.Errorf("unable to determine port %v", err)
	}
	return port, nil
}

func timeoutServer(timeout time.Duration) (int, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		<-time.After(timeout)
		w.Write([]byte("OK"))
	})
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return -1, fmt.Errorf("unable to secure listener %v", err)
	}
	go func() {
		if err := http.Serve(l, mux); err != nil {
			log.Fatalf("slow-server error %v", err)
		}
	}()

	var port int
	_, sport, err := net.SplitHostPort(l.Addr().String())
	if err == nil {
		port, err = strconv.Atoi(sport)
	}

	if err != nil {
		return -1, fmt.Errorf("unable to determine port %v", err)
	}

	return port, nil
}

func serverWith429() (int, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte("429 Too many requests"))
	})
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return -1, fmt.Errorf("unable to secure listener %v", err)
	}
	go func() {
		if err := http.Serve(l, mux); err != nil {
			log.Fatalf("slow-server error %v", err)
		}
	}()

	var port int
	_, sport, err := net.SplitHostPort(l.Addr().String())
	if err == nil {
		port, err = strconv.Atoi(sport)
	}

	if err != nil {
		return -1, fmt.Errorf("unable to determine port %v", err)
	}

	return port, nil
}
