/*
Copyright 2019 The Jetstack cert-manager contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"flag"
	"log"
	"time"

	cf "github.com/cloudflare/cloudflare-go"
)

var (
	email            = flag.String("email", "", "Cloudflare email address to use")
	apiKey           = flag.String("api-key", "", "Cloudflare API key to use")
	zoneName         = flag.String("zone-name", "", "Cloudflare DNS zone to clean of old TXT records")
	deleteOlderThan  = flag.Duration("older-than", time.Hour*24*7, "TXT records older than this duration will be deleted")
	deleteWithPrefix = flag.String("with-prefix", "_acme-challenge.", "further filter TXT records to only delete those that begin with this prefix")
	confirm          = flag.Bool("confirm", false, "if false, no records will actually be deleted")
)

func main() {
	flag.Parse()

	cl, err := cf.New(*apiKey, *email)
	if err != nil {
		log.Fatalf("error creating cloudflare client: %v", err)
	}

	zones, err := cl.ListZones(*zoneName)
	if err != nil {
		log.Fatalf("error listing zones: %v", err)
	}
	if len(zones) == 0 {
		log.Fatalf("could not find zone with name %q", *zoneName)
	}
	if len(zones) > 1 {
		log.Fatalf("found multiple zones for name %q", *zoneName)
	}
	zone := zones[0]
	rrs, err := cl.DNSRecords(zone.ID, cf.DNSRecord{
		Type: "TXT",
	})
	if err != nil {
		log.Fatalf("error listing TXT records in zone: %v", err)
	}

	log.Printf("Evaluating %d records", len(rrs))
	deleted := 0
	skipped := 0
	var errs []error
	for _, rr := range rrs {
		if !shouldDelete(rr) {
			log.Printf("Not deleting record %q", rr.Name)
			skipped++
			continue
		}

		if !*confirm {
			log.Printf("Would have deleted record %q", rr.Name)
			deleted++
			continue
		}

		err := cl.DeleteDNSRecord(rr.ZoneID, rr.ID)
		if err != nil {
			log.Printf("Error deleting record: %v", err)
			errs = append(errs, err)
		}

		log.Printf("Deleted record %q", rr.Name)
		deleted++
	}

	if len(errs) > 0 {
		log.Fatalf("Encountered %d errors whilst cleaning up zone", len(errs))
	}

	log.Print()
	log.Printf("Skipped: %d", skipped)
	log.Printf("Deleted: %d", deleted)
	log.Printf("Cleanup complete!")
}

func shouldDelete(rr cf.DNSRecord) bool {
	// be extra safe about only deleting TXT records
	if rr.Type != "TXT" {
		return false
	}
	keepNewerThan := time.Now().Add(-1 * *deleteOlderThan)
	if rr.ModifiedOn.After(keepNewerThan) ||
		rr.CreatedOn.After(keepNewerThan) {
		return false
	}
	if len(rr.Name) < len(*deleteWithPrefix) ||
		rr.Name[0:len(*deleteWithPrefix)] != *deleteWithPrefix {
		return false
	}
	return true
}
