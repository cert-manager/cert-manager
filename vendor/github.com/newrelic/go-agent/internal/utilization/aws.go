package utilization

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

const (
	awsHostname     = "169.254.169.254"
	awsEndpointPath = "/2016-09-02/dynamic/instance-identity/document"
	awsEndpoint     = "http://" + awsHostname + awsEndpointPath
)

type aws struct {
	InstanceID       string `json:"instanceId,omitempty"`
	InstanceType     string `json:"instanceType,omitempty"`
	AvailabilityZone string `json:"availabilityZone,omitempty"`
}

func gatherAWS(util *Data, client *http.Client) error {
	aws, err := getAWS(client)
	if err != nil {
		// Only return the error here if it is unexpected to prevent
		// warning customers who aren't running AWS about a timeout.
		if _, ok := err.(unexpectedAWSErr); ok {
			return err
		}
		return nil
	}
	util.Vendors.AWS = aws

	return nil
}

type unexpectedAWSErr struct{ e error }

func (e unexpectedAWSErr) Error() string {
	return fmt.Sprintf("unexpected AWS error: %v", e.e)
}

func getAWS(client *http.Client) (*aws, error) {
	response, err := client.Get(awsEndpoint)
	if err != nil {
		// No unexpectedAWSErr here: A timeout is usually going to
		// happen.
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return nil, unexpectedAWSErr{e: fmt.Errorf("response code %d", response.StatusCode)}
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, unexpectedAWSErr{e: err}
	}
	a := &aws{}
	if err := json.Unmarshal(data, a); err != nil {
		return nil, unexpectedAWSErr{e: err}
	}

	if err := a.validate(); err != nil {
		return nil, unexpectedAWSErr{e: err}
	}

	return a, nil
}

func (a *aws) validate() (err error) {
	a.InstanceID, err = normalizeValue(a.InstanceID)
	if err != nil {
		return fmt.Errorf("invalid instance ID: %v", err)
	}

	a.InstanceType, err = normalizeValue(a.InstanceType)
	if err != nil {
		return fmt.Errorf("invalid instance type: %v", err)
	}

	a.AvailabilityZone, err = normalizeValue(a.AvailabilityZone)
	if err != nil {
		return fmt.Errorf("invalid availability zone: %v", err)
	}

	return
}
