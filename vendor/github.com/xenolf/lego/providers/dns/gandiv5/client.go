package gandiv5

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

const apiKeyHeader = "X-Api-Key"

// types for JSON responses with only a message
type apiResponse struct {
	Message string `json:"message"`
	UUID    string `json:"uuid,omitempty"`
}

// Record TXT record representation
type Record struct {
	RRSetTTL    int      `json:"rrset_ttl"`
	RRSetValues []string `json:"rrset_values"`
	RRSetName   string   `json:"rrset_name,omitempty"`
	RRSetType   string   `json:"rrset_type,omitempty"`
}

func (d *DNSProvider) newRequest(method, resource string, body interface{}) (*http.Request, error) {
	u := fmt.Sprintf("%s/%s", d.config.BaseURL, resource)

	if body == nil {
		req, err := http.NewRequest(method, u, nil)
		if err != nil {
			return nil, err
		}

		return req, nil
	}

	reqBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, u, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	return req, nil
}

func (d *DNSProvider) do(req *http.Request, v interface{}) error {
	if len(d.config.APIKey) > 0 {
		req.Header.Set(apiKeyHeader, d.config.APIKey)
	}

	resp, err := d.config.HTTPClient.Do(req)
	if err != nil {
		return err
	}

	err = checkResponse(resp)
	if err != nil {
		return err
	}

	if v == nil {
		return nil
	}

	raw, err := readBody(resp)
	if err != nil {
		return fmt.Errorf("failed to read body: %v", err)
	}

	if len(raw) > 0 {
		err = json.Unmarshal(raw, v)
		if err != nil {
			return fmt.Errorf("unmarshaling error: %v: %s", err, string(raw))
		}
	}

	return nil
}

func checkResponse(resp *http.Response) error {
	if resp.StatusCode == 404 && resp.Request.Method == http.MethodGet {
		return nil
	}

	if resp.StatusCode >= 400 {
		data, err := readBody(resp)
		if err != nil {
			return fmt.Errorf("%d [%s] request failed: %v", resp.StatusCode, http.StatusText(resp.StatusCode), err)
		}

		message := &apiResponse{}
		err = json.Unmarshal(data, message)
		if err != nil {
			return fmt.Errorf("%d [%s] request failed: %v: %s", resp.StatusCode, http.StatusText(resp.StatusCode), err, data)
		}
		return fmt.Errorf("%d [%s] request failed: %s", resp.StatusCode, http.StatusText(resp.StatusCode), message.Message)
	}

	return nil
}

func readBody(resp *http.Response) ([]byte, error) {
	if resp.Body == nil {
		return nil, fmt.Errorf("response body is nil")
	}

	defer resp.Body.Close()

	rawBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return rawBody, nil
}
