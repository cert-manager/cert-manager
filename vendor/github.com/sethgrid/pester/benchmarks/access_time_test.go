package main

/*
	Can't use testing.B Tests because it eats up file descriptors
*/

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sethgrid/pester"
)

type getter func(string) (*http.Response, error)

func TestWarmup(t *testing.T) {
	// The first request/test takes more time.
	// Does not matter if we use http.Get or pester.Get
	// nor if we use the default client or initialize one.
	// I don't know why yet.
	c := pester.New()
	_ = runner("Warm Up", c.Get)
}

func TestStdLibGet(t *testing.T) {
	// base case - get a url with std lib
	fmt.Println(runner("Standard Library Get ", http.Get))
}

func TestPesterGetDefaults(t *testing.T) {
	fmt.Println(runner("Pester, Default", pester.Get))
}

func TestPesterRetry1Conc1(t *testing.T) {
	c := pester.New()
	c.MaxRetries = 1
	c.Concurrency = 1

	fmt.Println(runner("Pester, Retries 1, Conc 1", c.Get))
}

func TestPesterRetry2Conc2(t *testing.T) {
	c := pester.New()
	c.MaxRetries = 2
	c.Concurrency = 2

	fmt.Println(runner("Pester, Retries 2, Conc 2", c.Get))
}

func TestPesterRetry3Conc3(t *testing.T) {
	c := pester.New()
	c.MaxRetries = 3
	c.Concurrency = 3

	fmt.Println(runner("Pester, Retries 3, Conc 3", c.Get))
}

func TestPesterGetRetry0Conc1(t *testing.T) {
	c := pester.New()
	c.MaxRetries = 0
	c.Concurrency = 1

	fmt.Println(runner("Pester, Retries 0, Conc 1", c.Get))
}

func TestPesterGetRetry0Conc2(t *testing.T) {
	c := pester.New()
	c.MaxRetries = 0
	c.Concurrency = 2

	fmt.Println(runner("Pester, Retries 0, Conc 2", c.Get))
}

func TestPesterGetRetry0Conc3(t *testing.T) {
	c := pester.New()
	c.MaxRetries = 0
	c.Concurrency = 3

	fmt.Println(runner("Pester, Retries 0, Conc 3", c.Get))
}

func TestPesterGetRetry1Conc1(t *testing.T) {
	c := pester.New()
	c.MaxRetries = 0
	c.Concurrency = 1

	fmt.Println(runner("Pester, Retries 0, Conc 1", c.Get))
}

func TestPesterGetRetries2Conc1(t *testing.T) {
	c := pester.New()
	c.Concurrency = 2
	c.MaxRetries = 1

	fmt.Println(runner("Pester, Retries 2, Conc 1", c.Get))
}

func TestPesterGetRetries3Conc1(t *testing.T) {
	c := pester.New()
	c.Concurrency = 3
	c.MaxRetries = 1

	fmt.Println(runner("Pester, Retries 3, Conc 1", c.Get))
}

func reportTimings(name string, timings []int64) string {
	var sum int64
	for _, t := range timings {
		sum += t
	}
	average := sum / int64(len(timings))
	return fmt.Sprintf("  %-29s %7d ns Avg.", name, average)
}

func runServer() int {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Fatal("unable to secure listener", err)
	}
	go func() {
		if err := http.Serve(l, mux); err != nil {
			log.Fatal("stable server error", err)
		}
	}()
	port, err := strconv.Atoi(strings.Replace(l.Addr().String(), "[::]:", "", 1))
	if err != nil {
		log.Fatal("unable to determine port", err)
	}
	return port
}

func runner(name string, Do getter) string {
	var timings []int64
	for n := 0; n < 7; n++ {
		stableServerPort := runServer()

		start := time.Now().UnixNano()
		r, err := Do(fmt.Sprintf("http://localhost:%d/%d", stableServerPort, time.Now().UnixNano()))
		if err != nil {
			log.Fatal("Error came back and it should not have", err)
		}
		if r == nil {
			log.Fatal("No response!")
		}
		if r.Body == nil {
			log.Fatal("No response body!")
		}
		r.Body.Close()
		end := time.Now().UnixNano()

		timings = append(timings, end-start)
	}
	return reportTimings(name, timings)
}
