package utilization

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

const (
	azureHostname     = "169.254.169.254"
	azureEndpointPath = "/metadata/instance/compute?api-version=2017-03-01"
	azureEndpoint     = "http://" + azureHostname + azureEndpointPath
)

type azure struct {
	Location string `json:"location,omitempty"`
	Name     string `json:"name,omitempty"`
	VMID     string `json:"vmId,omitempty"`
	VMSize   string `json:"vmSize,omitempty"`
}

func gatherAzure(util *Data, client *http.Client) error {
	az, err := getAzure(client)
	if err != nil {
		// Only return the error here if it is unexpected to prevent
		// warning customers who aren't running Azure about a timeout.
		if _, ok := err.(unexpectedAzureErr); ok {
			return err
		}
		return nil
	}
	util.Vendors.Azure = az

	return nil
}

type unexpectedAzureErr struct{ e error }

func (e unexpectedAzureErr) Error() string {
	return fmt.Sprintf("unexpected Azure error: %v", e.e)
}

func getAzure(client *http.Client) (*azure, error) {
	req, err := http.NewRequest("GET", azureEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Metadata", "true")

	response, err := client.Do(req)
	if err != nil {
		// No unexpectedAzureErr here: a timeout isusually going to
		// happen.
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return nil, unexpectedAzureErr{e: fmt.Errorf("response code %d", response.StatusCode)}
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, unexpectedAzureErr{e: err}
	}

	az := &azure{}
	if err := json.Unmarshal(data, az); err != nil {
		return nil, unexpectedAzureErr{e: err}
	}

	if err := az.validate(); err != nil {
		return nil, unexpectedAzureErr{e: err}
	}

	return az, nil
}

func (az *azure) validate() (err error) {
	az.Location, err = normalizeValue(az.Location)
	if err != nil {
		return fmt.Errorf("Invalid location: %v", err)
	}

	az.Name, err = normalizeValue(az.Name)
	if err != nil {
		return fmt.Errorf("Invalid name: %v", err)
	}

	az.VMID, err = normalizeValue(az.VMID)
	if err != nil {
		return fmt.Errorf("Invalid VM ID: %v", err)
	}

	az.VMSize, err = normalizeValue(az.VMSize)
	if err != nil {
		return fmt.Errorf("Invalid VM size: %v", err)
	}

	return
}
