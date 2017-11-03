package testing

import (
	"testing"

	"github.com/gophercloud/gophercloud/openstack/identity/v3/regions"
	"github.com/gophercloud/gophercloud/pagination"
	th "github.com/gophercloud/gophercloud/testhelper"
	"github.com/gophercloud/gophercloud/testhelper/client"
)

func TestListRegions(t *testing.T) {
	th.SetupHTTP()
	defer th.TeardownHTTP()
	HandleListRegionsSuccessfully(t)

	count := 0
	err := regions.List(client.ServiceClient(), nil).EachPage(func(page pagination.Page) (bool, error) {
		count++

		actual, err := regions.ExtractRegions(page)
		th.AssertNoErr(t, err)

		th.CheckDeepEquals(t, ExpectedRegionsSlice, actual)

		return true, nil
	})
	th.AssertNoErr(t, err)
	th.CheckEquals(t, count, 1)
}

func TestListRegionsAllPages(t *testing.T) {
	th.SetupHTTP()
	defer th.TeardownHTTP()
	HandleListRegionsSuccessfully(t)

	allPages, err := regions.List(client.ServiceClient(), nil).AllPages()
	th.AssertNoErr(t, err)
	actual, err := regions.ExtractRegions(allPages)
	th.AssertNoErr(t, err)
	th.CheckDeepEquals(t, ExpectedRegionsSlice, actual)
	th.AssertEquals(t, ExpectedRegionsSlice[1].Extra["email"], "westsupport@example.com")
}

func TestGetRegion(t *testing.T) {
	th.SetupHTTP()
	defer th.TeardownHTTP()
	HandleGetRegionSuccessfully(t)

	actual, err := regions.Get(client.ServiceClient(), "RegionOne-West").Extract()

	th.AssertNoErr(t, err)
	th.CheckDeepEquals(t, SecondRegion, *actual)
}
