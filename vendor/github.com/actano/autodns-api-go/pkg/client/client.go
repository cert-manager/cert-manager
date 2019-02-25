package client

import (
	"bytes"
	"encoding/xml"
	"errors"
	"github.com/actano/autodns-api-go/pkg/api"
	"github.com/actano/autodns-api-go/pkg/zone"
	"io/ioutil"
	"net/http"
)

const (
	DefaultEndpoint = "https://gateway.autodns.com"
)

type AutoDnsClient struct {
	auth     api.Auth
	Endpoint string
	Zone     zone.ZoneService
}

func NewAutoDnsClient(username, password, context string) *AutoDnsClient {
	return NewAutoDnsClientCustomEndpoint(DefaultEndpoint, username, password, context)
}

func NewAutoDnsClientCustomEndpoint(endpoint, username, password, context string) *AutoDnsClient {
	c := &AutoDnsClient{
		auth:     api.NewAuth(username, password, context),
		Endpoint: endpoint,
	}

	c.Zone = zone.NewZoneService(c)

	return c
}

func (c *AutoDnsClient) Auth() api.Auth {
	return c.auth
}

func (c *AutoDnsClient) MakeRequest(request interface{}, response api.ResponseWithStatus) error {
	data, err := xml.Marshal(request)

	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", c.Endpoint, bytes.NewBuffer(data))

	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "text/xml")

	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return err
	}

	err = xml.Unmarshal(body, response)

	if err != nil {
		return err
	}

	if response.GetStatus().Type != "success" {
		return errors.New("request was not successful")
	}

	return nil
}
