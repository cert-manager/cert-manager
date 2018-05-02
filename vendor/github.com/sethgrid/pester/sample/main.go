package main

/*
   We start up a rando response server that will give different response codes
   and different response times to simulate poor network / service conditions.

   The main function is cut into blocks to perserve variable scope and examples
   of each pester function can be seen in action.

   The server logs incoming requests while the main blocks log what they intend
   to do and what they get back.
*/

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sethgrid/pester"
)

func init() {
	rand.Seed(time.Now().Unix())
}

func main() {
	// set everything up
	var port int
	flag.IntVar(&port, "port", 9000, "set the port for the rando response server")
	flag.Parse()

	log.Printf("Starting a rando response server on :%d ...\n\n", port)

	go func() {
		http.HandleFunc("/", randoHandler)
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
	}()

	//////////////////////////////////////////////////////
	// begin running through each of the pestor methods //
	//////////////////////////////////////////////////////

	log.Println("> pester.Get default")
	{ // drop in replacement for http.Get and other client methods
		resp, err := pester.Get(fmt.Sprintf("http://localhost:%d", port))
		if err != nil {
			log.Fatalf("error GETing default", err)
		}
		defer resp.Body.Close()

		log.Printf("GET :%d %s \n\n", port, resp.Status)
	}

	log.Println("> pester.Get with set backoff stategy, concurrency and retries increased")
	{ // control the resiliency
		client := pester.New()
		client.Concurrency = 3
		client.MaxRetries = 5
		client.Backoff = pester.ExponentialJitterBackoff
		client.KeepLog = true

		resp, err := client.Get(fmt.Sprintf("http://localhost:%d", port))
		if err != nil {
			log.Fatalf("error GETing with all options, %s\n\n", client.LogString())
		}
		defer resp.Body.Close()

		log.Printf("Exponential Jitter Backoff :%d %s [request %d, retry %d]\n\n", port, resp.Status, client.SuccessReqNum, client.SuccessRetryNum)
	}

	log.Println("> pester.Get with custom backoff strategy")
	{ // set a custom backoff strategy
		client := pester.New()
		client.Backoff = func(retry int) time.Duration {
			return time.Duration(retry*200) * time.Millisecond
		}
		client.Timeout = 5 * time.Second
		client.KeepLog = true

		resp, err := client.Get(fmt.Sprintf("http://localhost:%d", port))
		if err != nil {
			log.Fatalf("error GETing custom backoff\n\n", client.LogString())
		}
		defer resp.Body.Close()

		log.Printf("Custom backoff :%d %s [request %d, retry %d]\n\n", port, resp.Status, client.SuccessReqNum, client.SuccessRetryNum)
	}

	log.Println("> pester.Post with defaults")
	{ // use the pester.Post drop in replacement
		resp, err := pester.Post(fmt.Sprintf("http://localhost:%d", port), "text/plain", strings.NewReader("data"))
		if err != nil {
			log.Fatalf("error POSTing with defaults - %v\n\n", err)
		}
		defer resp.Body.Close()

		log.Printf("POST :%d %s\n\n", port, resp.Status)
	}

	log.Println("> pester.Post with retries to non-existant url")
	{
		client := pester.New()
		client.MaxRetries = 3
		client.KeepLog = true

		_, err := client.Post("http://localhost:9001", "application/json", strings.NewReader(`{"json":true}`))
		if err == nil {
			log.Printf("expected to error after max retries of 3")
		}

		if len(client.ErrLog) != 3 {
			log.Fatalf("expected 3 error logs, got %d: %v", len(client.ErrLog), client.ErrLog)
		}
		log.Printf("POST: %v\n\n", err)
	}

	log.Println("> pester.Head with defaults")
	{ // use the pester.Head drop in replacement
		resp, err := pester.Head(fmt.Sprintf("http://localhost:%d", port))
		if err != nil {
			log.Fatalf("error HEADing with defaults - %v\n\n", err)
		}
		defer resp.Body.Close()

		log.Printf("HEAD :%d %s\n\n", port, resp.Status)
	}

	log.Println("> pester.PostForm with defaults")
	{ // use the pester.Head drop in replacement
		resp, err := pester.PostForm(fmt.Sprintf("http://localhost:%d", port), url.Values{"param1": []string{"val1a", "val1b"}, "param2": []string{"val2"}})
		if err != nil {
			log.Fatalf("error POSTing a form with defaults - %v\n\n", err)
		}
		defer resp.Body.Close()

		log.Printf("POST (form) :%d %s\n\n", port, resp.Status)
	}

	log.Println("> pester Do with POST")
	{ // use the pester version of http.Client.Do
		req, err := http.NewRequest("POST", fmt.Sprintf("http://localhost:%d", port), strings.NewReader("data"))
		if err != nil {
			log.Fatal("Unable to create a new http request", err)
		}
		resp, err := pester.Do(req)
		if err != nil {
			log.Fatalf("error POSTing with Do() - %v\n\n", err)
		}
		defer resp.Body.Close()

		log.Printf("Do() POST :%d %s\n\n", port, resp.Status)
	}

}

// randoHandler will cause random delays and give random status responses
func randoHandler(w http.ResponseWriter, r *http.Request) {
	delay := rand.Intn(5000)
	var code int
	switch rand.Intn(10) {
	case 0:
		code = 404
	case 1:
		code = 400
	case 2:
		code = 501
	case 3:
		code = 500
	default:
		code = 200
	}

	log.Printf("incoming request on :9000 - will return %d in %d ms", code, delay)

	<-time.Tick(time.Duration(delay) * time.Millisecond)

	w.WriteHeader(code)
	w.Write([]byte(http.StatusText(code)))
}
