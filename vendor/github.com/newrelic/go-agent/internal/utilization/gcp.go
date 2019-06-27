package utilization

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	gcpHostname     = "metadata.google.internal"
	gcpEndpointPath = "/computeMetadata/v1/instance/?recursive=true"
	gcpEndpoint     = "http://" + gcpHostname + gcpEndpointPath
)

func gatherGCP(util *Data, client *http.Client) error {
	gcp, err := getGCP(client)
	if err != nil {
		// Only return the error here if it is unexpected to prevent
		// warning customers who aren't running GCP about a timeout.
		if _, ok := err.(unexpectedGCPErr); ok {
			return err
		}
		return nil
	}
	util.Vendors.GCP = gcp

	return nil
}

// numericString is used rather than json.Number because we want the output when
// marshalled to be a string, rather than a number.
type numericString string

func (ns *numericString) MarshalJSON() ([]byte, error) {
	return json.Marshal(ns.String())
}

func (ns *numericString) String() string {
	return string(*ns)
}

func (ns *numericString) UnmarshalJSON(data []byte) error {
	var n int64

	// Try to unmarshal as an integer first.
	if err := json.Unmarshal(data, &n); err == nil {
		*ns = numericString(fmt.Sprintf("%d", n))
		return nil
	}

	// Otherwise, unmarshal as a string, and verify that it's numeric (for our
	// definition of numeric, which is actually integral).
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	for _, r := range s {
		if r < '0' || r > '9' {
			return fmt.Errorf("invalid numeric character: %c", r)
		}
	}

	*ns = numericString(s)
	return nil
}

type gcp struct {
	ID          numericString `json:"id"`
	MachineType string        `json:"machineType,omitempty"`
	Name        string        `json:"name,omitempty"`
	Zone        string        `json:"zone,omitempty"`
}

type unexpectedGCPErr struct{ e error }

func (e unexpectedGCPErr) Error() string {
	return fmt.Sprintf("unexpected GCP error: %v", e.e)
}

func getGCP(client *http.Client) (*gcp, error) {
	// GCP's metadata service requires a Metadata-Flavor header because... hell, I
	// don't know, maybe they really like Guy Fieri?
	req, err := http.NewRequest("GET", gcpEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Metadata-Flavor", "Google")

	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return nil, unexpectedGCPErr{e: fmt.Errorf("response code %d", response.StatusCode)}
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, unexpectedGCPErr{e: err}
	}

	g := &gcp{}
	if err := json.Unmarshal(data, g); err != nil {
		return nil, unexpectedGCPErr{e: err}
	}

	if err := g.validate(); err != nil {
		return nil, unexpectedGCPErr{e: err}
	}

	return g, nil
}

func (g *gcp) validate() (err error) {
	id, err := normalizeValue(g.ID.String())
	if err != nil {
		return fmt.Errorf("Invalid ID: %v", err)
	}
	g.ID = numericString(id)

	mt, err := normalizeValue(g.MachineType)
	if err != nil {
		return fmt.Errorf("Invalid machine type: %v", err)
	}
	g.MachineType = stripGCPPrefix(mt)

	g.Name, err = normalizeValue(g.Name)
	if err != nil {
		return fmt.Errorf("Invalid name: %v", err)
	}

	zone, err := normalizeValue(g.Zone)
	if err != nil {
		return fmt.Errorf("Invalid zone: %v", err)
	}
	g.Zone = stripGCPPrefix(zone)

	return
}

// We're only interested in the last element of slash separated paths for the
// machine type and zone values, so this function handles stripping the parts
// we don't need.
func stripGCPPrefix(s string) string {
	parts := strings.Split(s, "/")
	return parts[len(parts)-1]
}
