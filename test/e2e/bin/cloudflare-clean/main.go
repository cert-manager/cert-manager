/*
Copyright 2020 The cert-manager Authors.

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
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/cloudflare/cloudflare-go/v5"
	cf "github.com/cloudflare/cloudflare-go/v5"
	"github.com/cloudflare/cloudflare-go/v5/dns"
	"github.com/cloudflare/cloudflare-go/v5/option"
	"github.com/cloudflare/cloudflare-go/v5/zones"

	"github.com/cert-manager/cert-manager/internal/cmd/util"
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
	ctx, exit := util.SetupExitHandler(context.Background(), util.GracefulShutdown)
	defer exit() // This function might call os.Exit, so defer last

	flag.Parse()

	if err := Main(ctx); err != nil {
		log.Print(err)
		util.SetExitCode(err)
	}
}

func Main(ctx context.Context) error {
	cl := cf.NewClient(option.WithAPIKey(*apiKey), option.WithAPIEmail(*email))
	if cl == nil || cl.Zones == nil || cl.DNS == nil {
		return fmt.Errorf("error creating cloudflare client. check permissions related to the client.")
	}

	zs := cl.Zones.ListAutoPaging(ctx, zones.ZoneListParams{
		Name: cloudflare.F(*zoneName),
	})

	zones := make([]zones.Zone, 0)
  for zs.Next() {
		if zs.Err() != nil {
			return fmt.Errorf("error listing zones %v", zs.Err())
		}
    zones = append(zones, zs.Current())
	}

	if len(zones) == 0 {
		return fmt.Errorf("could not find zone with name %q", *zoneName)
	}
	if len(zones) > 1 {
		return fmt.Errorf("found multiple zones for name %q", *zoneName)
	}
	zone := zones[0]
	rrsp := cl.DNS.Records.ListAutoPaging(ctx, dns.RecordListParams{
		ZoneID: cloudflare.F(zone.ID),
		Type: cloudflare.F(dns.RecordListParamsTypeTXT),
	})

	rrs := make([]dns.RecordResponse, 0)
	for rrsp.Next() {
		if rrsp.Err() != nil {
			return fmt.Errorf("unable to fetch records %v", rrsp.Err())
		}

		rrs = append(rrs, rrsp.Current())
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

		_, err := cl.DNS.Records.Delete(ctx, rr.ID, dns.RecordDeleteParams{
			ZoneID: cloudflare.F(zone.ID),
		})
		if err != nil {
			log.Printf("Error deleting record: %v", err)
			errs = append(errs, err)
		}

		log.Printf("Deleted record %q", rr.Name)
		deleted++
	}

	if len(errs) > 0 {
		return fmt.Errorf("encountered %d errors whilst cleaning up zone", len(errs))
	}

	log.Print()
	log.Printf("Skipped: %d", skipped)
	log.Printf("Deleted: %d", deleted)
	log.Printf("Cleanup complete!")

	return nil
}

func shouldDelete(rr dns.RecordResponse) bool {
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
