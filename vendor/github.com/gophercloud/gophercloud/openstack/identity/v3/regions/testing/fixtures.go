package testing

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/gophercloud/gophercloud/openstack/identity/v3/regions"
	th "github.com/gophercloud/gophercloud/testhelper"
	"github.com/gophercloud/gophercloud/testhelper/client"
)

// ListOutput provides a single page of Region results.
const ListOutput = `
{
    "links": {
        "next": null,
        "previous": null,
        "self": "http://example.com/identity/v3/regions"
    },
    "regions": [
        {
            "id": "RegionOne-East",
            "description": "East sub-region of RegionOne",
            "links": {
                "self": "http://example.com/identity/v3/regions/RegionOne-East"
            },
            "parent_region_id": "RegionOne"
        },
        {
            "id": "RegionOne-West",
            "description": "West sub-region of RegionOne",
            "links": {
                "self": "https://example.com/identity/v3/regions/RegionOne-West"
            },
            "extra": {
                "email": "westsupport@example.com"
            },
            "parent_region_id": "RegionOne"
        }
    ]
}
`

// GetOutput provides a Get result.
const GetOutput = `
{
    "region": {
        "id": "RegionOne-West",
        "description": "West sub-region of RegionOne",
        "links": {
            "self": "https://example.com/identity/v3/regions/RegionOne-West"
        },
        "name": "support",
        "extra": {
            "email": "westsupport@example.com"
        },
        "parent_region_id": "RegionOne"
    }
}
`

// FirstRegion is the first region in the List request.
var FirstRegion = regions.Region{
	ID: "RegionOne-East",
	Links: map[string]interface{}{
		"self": "http://example.com/identity/v3/regions/RegionOne-East",
	},
	Description:    "East sub-region of RegionOne",
	Extra:          map[string]interface{}{},
	ParentRegionID: "RegionOne",
}

// SecondRegion is the second region in the List request.
var SecondRegion = regions.Region{
	ID: "RegionOne-West",
	Links: map[string]interface{}{
		"self": "https://example.com/identity/v3/regions/RegionOne-West",
	},
	Description: "West sub-region of RegionOne",
	Extra: map[string]interface{}{
		"email": "westsupport@example.com",
	},
	ParentRegionID: "RegionOne",
}

// ExpectedRegionsSlice is the slice of regions expected to be returned from ListOutput.
var ExpectedRegionsSlice = []regions.Region{FirstRegion, SecondRegion}

// HandleListRegionsSuccessfully creates an HTTP handler at `/regions` on the
// test handler mux that responds with a list of two regions.
func HandleListRegionsSuccessfully(t *testing.T) {
	th.Mux.HandleFunc("/regions", func(w http.ResponseWriter, r *http.Request) {
		th.TestMethod(t, r, "GET")
		th.TestHeader(t, r, "Accept", "application/json")
		th.TestHeader(t, r, "X-Auth-Token", client.TokenID)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, ListOutput)
	})
}

// HandleGetRegionSuccessfully creates an HTTP handler at `/regions` on the
// test handler mux that responds with a single region.
func HandleGetRegionSuccessfully(t *testing.T) {
	th.Mux.HandleFunc("/regions/RegionOne-West", func(w http.ResponseWriter, r *http.Request) {
		th.TestMethod(t, r, "GET")
		th.TestHeader(t, r, "Accept", "application/json")
		th.TestHeader(t, r, "X-Auth-Token", client.TokenID)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, GetOutput)
	})
}
