package regions

import (
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/pagination"
)

// ListOptsBuilder allows extensions to add additional parameters to
// the List request
type ListOptsBuilder interface {
	ToRegionListQuery() (string, error)
}

// ListOpts provides options to filter the List results.
type ListOpts struct {
	// ParentRegionID filters the response by a parent region ID.
	ParentRegionID string `q:"parent_region_id"`
}

// ToRegionListQuery formats a ListOpts into a query string.
func (opts ListOpts) ToRegionListQuery() (string, error) {
	q, err := gophercloud.BuildQueryString(opts)
	return q.String(), err
}

// List enumerates the Regions to which the current token has access.
func List(client *gophercloud.ServiceClient, opts ListOptsBuilder) pagination.Pager {
	url := listURL(client)
	if opts != nil {
		query, err := opts.ToRegionListQuery()
		if err != nil {
			return pagination.Pager{Err: err}
		}
		url += query
	}
	return pagination.NewPager(client, url, func(r pagination.PageResult) pagination.Page {
		return RegionPage{pagination.LinkedPageBase{PageResult: r}}
	})
}

// Get retrieves details on a single region, by ID.
func Get(client *gophercloud.ServiceClient, id string) (r GetResult) {
	_, r.Err = client.Get(getURL(client, id), &r.Body, nil)
	return
}
