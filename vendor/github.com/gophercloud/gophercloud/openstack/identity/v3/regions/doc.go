/*
Package regions manages and retrieves Regions in the OpenStack Identity Service.

Example to List Regions

	listOpts := regions.ListOpts{
		ParentRegionID: "RegionOne",
	}

	allPages, err := regions.List(identityClient, listOpts).AllPages()
	if err != nil {
		panic(err)
	}

	allRegions, err := regions.ExtractRegions(allPages)
	if err != nil {
		panic(err)
	}

	for _, region := range allRegions {
		fmt.Printf("%+v\n", region)
	}
*/
package regions
