// +build acceptance

package v3

import (
	"testing"

	"github.com/gophercloud/gophercloud/acceptance/clients"
	"github.com/gophercloud/gophercloud/acceptance/tools"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/regions"
)

func TestRegionsList(t *testing.T) {
	client, err := clients.NewIdentityV3Client()
	if err != nil {
		t.Fatalf("Unable to obtain an identity client: %v", err)
	}

	listOpts := regions.ListOpts{
		ParentRegionID: "RegionOne",
	}

	allPages, err := regions.List(client, listOpts).AllPages()
	if err != nil {
		t.Fatalf("Unable to list regions: %v", err)
	}

	allRegions, err := regions.ExtractRegions(allPages)
	if err != nil {
		t.Fatalf("Unable to extract regions: %v", err)
	}

	for _, region := range allRegions {
		tools.PrintResource(t, region)
	}
}

func TestRegionsGet(t *testing.T) {
	client, err := clients.NewIdentityV3Client()
	if err != nil {
		t.Fatalf("Unable to obtain an identity client: %v", err)
	}

	allPages, err := regions.List(client, nil).AllPages()
	if err != nil {
		t.Fatalf("Unable to list regions: %v", err)
	}

	allRegions, err := regions.ExtractRegions(allPages)
	if err != nil {
		t.Fatalf("Unable to extract regions: %v", err)
	}

	region := allRegions[0]
	p, err := regions.Get(client, region.ID).Extract()
	if err != nil {
		t.Fatalf("Unable to get region: %v", err)
	}

	tools.PrintResource(t, p)
}
