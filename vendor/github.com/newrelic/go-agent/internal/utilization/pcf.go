package utilization

import (
	"errors"
	"fmt"
	"net/http"
	"os"
)

type pcf struct {
	InstanceGUID string `json:"cf_instance_guid,omitempty"`
	InstanceIP   string `json:"cf_instance_ip,omitempty"`
	MemoryLimit  string `json:"memory_limit,omitempty"`
}

func gatherPCF(util *Data, _ *http.Client) error {
	pcf, err := getPCF(os.Getenv)
	if err != nil {
		// Only return the error here if it is unexpected to prevent
		// warning customers who aren't running PCF about a timeout.
		if _, ok := err.(unexpectedPCFErr); ok {
			return err
		}
		return nil
	}
	util.Vendors.PCF = pcf

	return nil
}

type unexpectedPCFErr struct{ e error }

func (e unexpectedPCFErr) Error() string {
	return fmt.Sprintf("unexpected PCF error: %v", e.e)
}

var (
	errNoPCFVariables = errors.New("no PCF environment variables present")
)

func getPCF(initializer func(key string) string) (*pcf, error) {
	p := &pcf{}

	p.InstanceGUID = initializer("CF_INSTANCE_GUID")
	p.InstanceIP = initializer("CF_INSTANCE_IP")
	p.MemoryLimit = initializer("MEMORY_LIMIT")

	if "" == p.InstanceGUID && "" == p.InstanceIP && "" == p.MemoryLimit {
		return nil, errNoPCFVariables
	}

	if err := p.validate(); err != nil {
		return nil, unexpectedPCFErr{e: err}
	}

	return p, nil
}

func (pcf *pcf) validate() (err error) {
	pcf.InstanceGUID, err = normalizeValue(pcf.InstanceGUID)
	if err != nil {
		return fmt.Errorf("Invalid instance GUID: %v", err)
	}

	pcf.InstanceIP, err = normalizeValue(pcf.InstanceIP)
	if err != nil {
		return fmt.Errorf("Invalid instance IP: %v", err)
	}

	pcf.MemoryLimit, err = normalizeValue(pcf.MemoryLimit)
	if err != nil {
		return fmt.Errorf("Invalid memory limit: %v", err)
	}

	if pcf.InstanceGUID == "" || pcf.InstanceIP == "" || pcf.MemoryLimit == "" {
		err = errors.New("One or more environment variables are unavailable")
	}

	return
}
