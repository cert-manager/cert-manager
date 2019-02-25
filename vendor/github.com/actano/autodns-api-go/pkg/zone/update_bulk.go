package zone

import (
	"github.com/actano/autodns-api-go/pkg/api"
)

type updateBulkTask struct {
	api.Task
	Zone    zone             `xml:"zone"`
	Adds    []ResourceRecord `xml:"default>rr_add"`
	Removes []ResourceRecord `xml:"default>rr_rem"`
}

type updateBulkRequest struct {
	api.Request
	Task updateBulkTask `xml:"task"`
}

type UpdateBulkResponse struct {
	api.Response
}

func (c *zoneService) newUpdateBulkRequest(zoneName string, adds []ResourceRecord, removes []ResourceRecord) *updateBulkRequest {
	return &updateBulkRequest{
		Request: api.NewRequest(c.client.Auth()),
		Task: updateBulkTask{
			Task: api.NewTask("0202001"),
			Zone: zone{
				Name: zoneName,
			},
			Adds:    adds,
			Removes: removes,
		},
	}
}

func (c *zoneService) UpdateBulk(zoneName string, adds []ResourceRecord, removes []ResourceRecord) error {
	request := c.newUpdateBulkRequest(zoneName, adds, removes)
	response := &UpdateBulkResponse{}

	err := c.client.MakeRequest(request, response)

	if err != nil {
		return err
	}

	return nil
}
