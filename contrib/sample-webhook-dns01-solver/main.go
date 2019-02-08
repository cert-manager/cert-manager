package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

// Present updates DNS records of fqdn with value
func Present(fqdn, value string) error {
	log.Printf("updating DNS records for %s with value of %s", fqdn, value)
	return nil
}

// CleanUp cleans up challenge records
func CleanUp(fqdn, value string) error {
	log.Printf("cleaning up DNS records for %s", fqdn)
	return nil
}

func main() {
	http.HandleFunc("/", handler)

	address := "0.0.0.0:3030"
	log.Println("Listening on " + address)

	err := http.ListenAndServe(address, nil)
	if err != nil {
		log.Println(err)
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			log.Println(r)
		}
	}()

	var data, err = ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatal("handler: ", err)
	}

	var hook v1alpha1.WebhookPayload
	err = json.Unmarshal(data, &hook)
	if err != nil {
		log.Println("handler: ", err)
	}

	log.Printf("received webhook request for %s", hook.Identifier)

	switch hook.Operation {
	case v1alpha1.WebhookPresentOperation:
		err = Present(hook.Identifier, hook.Key)
		if err != nil {
			log.Println("error presenting: ", err)
		}
	case v1alpha1.WebhookCleanupOperation:
		err = CleanUp(hook.Identifier, hook.Key)
		if err != nil {
			log.Println("error cleaning up: ", err)
		}
	default:
		log.Printf("unknown operation type: %s", hook.Operation)
	}
}
