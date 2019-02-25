package zone

import (
	"github.com/actano/autodns-api-go/pkg/api"
)

type zoneTask struct {
	api.Task
	Zone zone `xml:"zone"`
}

type zoneInfoRequest struct {
	api.Request
	Task zoneTask `xml:"task"`
}

type zoneInfoResponse struct {
	api.Response
	ZoneInfo
}

type ZoneInfo struct {
	Records []ResourceRecord `xml:"result>data>zone>rr"`
}

func (c *zoneService) newZoneInfoRequest(zoneName string) *zoneInfoRequest {
	return &zoneInfoRequest{
        Request: api.NewRequest(c.client.Auth()),
		Task: zoneTask{
			Task: api.NewTask("0205"),
			Zone: zone{
				Name: zoneName,
			},
		},
	}
}

func (c *zoneService) GetZoneInfo(zoneName string) (*ZoneInfo, error) {
	request := c.newZoneInfoRequest(zoneName)
	response := &zoneInfoResponse{}

    err := c.client.MakeRequest(request, response)

	if err != nil {
		return nil, err
	}

	return &response.ZoneInfo, nil
}
