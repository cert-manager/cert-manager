package internal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/newrelic/go-agent/internal/logger"
)

const (
	// ProcotolVersion is the protocol version used to communicate with NR
	// backend.
	ProcotolVersion = 17
	userAgentPrefix = "NewRelic-Go-Agent/"

	// Methods used in collector communication.
	cmdPreconnect   = "preconnect"
	cmdConnect      = "connect"
	cmdMetrics      = "metric_data"
	cmdCustomEvents = "custom_event_data"
	cmdTxnEvents    = "analytic_event_data"
	cmdErrorEvents  = "error_event_data"
	cmdErrorData    = "error_data"
	cmdTxnTraces    = "transaction_sample_data"
	cmdSlowSQLs     = "sql_trace_data"
	cmdSpanEvents   = "span_event_data"
)

// RpmCmd contains fields specific to an individual call made to RPM.
type RpmCmd struct {
	Name              string
	Collector         string
	RunID             string
	Data              []byte
	RequestHeadersMap map[string]string
}

// RpmControls contains fields which will be the same for all calls made
// by the same application.
type RpmControls struct {
	License      string
	Client       *http.Client
	Logger       logger.Logger
	AgentVersion string
}

// RPMResponse contains a NR endpoint response.
//
// Agent Behavior Summary:
//
// on connect/preconnect:
//     410 means shutdown
//     200, 202 mean success (start run)
//     all other response codes and errors mean try after backoff
//
// on harvest:
//     410 means shutdown
//     401, 409 mean restart run
//     408, 429, 500, 503 mean save data for next harvest
//     all other response codes and errors discard the data and continue the current harvest
type RPMResponse struct {
	statusCode int
	body       []byte
	// Err indicates whether or not the call was successful: newRPMResponse
	// should be used to avoid mismatch between statusCode and Err.
	Err                      error
	disconnectSecurityPolicy bool
}

func newRPMResponse(statusCode int) RPMResponse {
	var err error
	if statusCode != 200 && statusCode != 202 {
		err = fmt.Errorf("response code: %d", statusCode)
	}
	return RPMResponse{statusCode: statusCode, Err: err}
}

// IsDisconnect indicates that the agent should disconnect.
func (resp RPMResponse) IsDisconnect() bool {
	return resp.statusCode == 410 || resp.disconnectSecurityPolicy
}

// IsRestartException indicates that the agent should restart.
func (resp RPMResponse) IsRestartException() bool {
	return resp.statusCode == 401 ||
		resp.statusCode == 409
}

// ShouldSaveHarvestData indicates that the agent should save the data and try
// to send it in the next harvest.
func (resp RPMResponse) ShouldSaveHarvestData() bool {
	switch resp.statusCode {
	case 408, 429, 500, 503:
		return true
	default:
		return false
	}
}

func rpmURL(cmd RpmCmd, cs RpmControls) string {
	var u url.URL

	u.Host = cmd.Collector
	u.Path = "agent_listener/invoke_raw_method"
	u.Scheme = "https"

	query := url.Values{}
	query.Set("marshal_format", "json")
	query.Set("protocol_version", strconv.Itoa(ProcotolVersion))
	query.Set("method", cmd.Name)
	query.Set("license_key", cs.License)

	if len(cmd.RunID) > 0 {
		query.Set("run_id", cmd.RunID)
	}

	u.RawQuery = query.Encode()
	return u.String()
}

func collectorRequestInternal(url string, cmd RpmCmd, cs RpmControls) RPMResponse {
	compressed, err := compress(cmd.Data)
	if nil != err {
		return RPMResponse{Err: err}
	}

	req, err := http.NewRequest("POST", url, compressed)
	if nil != err {
		return RPMResponse{Err: err}
	}

	req.Header.Add("Accept-Encoding", "identity, deflate")
	req.Header.Add("Content-Type", "application/octet-stream")
	req.Header.Add("User-Agent", userAgentPrefix+cs.AgentVersion)
	req.Header.Add("Content-Encoding", "gzip")
	for k, v := range cmd.RequestHeadersMap {
		req.Header.Add(k, v)
	}

	resp, err := cs.Client.Do(req)
	if err != nil {
		return RPMResponse{Err: err}
	}

	defer resp.Body.Close()

	r := newRPMResponse(resp.StatusCode)

	// Read the entire response, rather than using resp.Body as input to json.NewDecoder to
	// avoid the issue described here:
	// https://github.com/google/go-github/pull/317
	// https://ahmetalpbalkan.com/blog/golang-json-decoder-pitfalls/
	// Also, collector JSON responses are expected to be quite small.
	body, err := ioutil.ReadAll(resp.Body)
	if nil == r.Err {
		r.Err = err
	}
	r.body = body

	return r
}

// CollectorRequest makes a request to New Relic.
func CollectorRequest(cmd RpmCmd, cs RpmControls) RPMResponse {
	url := rpmURL(cmd, cs)

	if cs.Logger.DebugEnabled() {
		cs.Logger.Debug("rpm request", map[string]interface{}{
			"command": cmd.Name,
			"url":     url,
			"payload": JSONString(cmd.Data),
		})
	}

	resp := collectorRequestInternal(url, cmd, cs)

	if cs.Logger.DebugEnabled() {
		if err := resp.Err; err != nil {
			cs.Logger.Debug("rpm failure", map[string]interface{}{
				"command":  cmd.Name,
				"url":      url,
				"response": string(resp.body), // Body might not be JSON on failure.
				"error":    err.Error(),
			})
		} else {
			cs.Logger.Debug("rpm response", map[string]interface{}{
				"command":  cmd.Name,
				"url":      url,
				"response": JSONString(resp.body),
			})
		}
	}

	return resp
}

const (
	// NEW_RELIC_HOST can be used to override the New Relic endpoint.  This
	// is useful for testing.
	envHost = "NEW_RELIC_HOST"
)

var (
	preconnectHostOverride       = os.Getenv(envHost)
	preconnectHostDefault        = "collector.newrelic.com"
	preconnectRegionLicenseRegex = regexp.MustCompile(`(^.+?)x`)
)

func calculatePreconnectHost(license, overrideHost string) string {
	if "" != overrideHost {
		return overrideHost
	}
	m := preconnectRegionLicenseRegex.FindStringSubmatch(license)
	if len(m) > 1 {
		return "collector." + m[1] + ".nr-data.net"
	}
	return preconnectHostDefault
}

// ConnectJSONCreator allows the creation of the connect payload JSON to be
// deferred until the SecurityPolicies are acquired and vetted.
type ConnectJSONCreator interface {
	CreateConnectJSON(*SecurityPolicies) ([]byte, error)
}

type preconnectRequest struct {
	SecurityPoliciesToken string `json:"security_policies_token,omitempty"`
}

// ConnectEventData is the event_data key in the connect request payload
type ConnectEventData struct {
	HarvestLimits harvestLimits `json:"harvest_limits"`
}

// harvestLimits is used in both the connect request and reply's event_data key
// to specify the max number of events of each type allowable by the agent
type harvestLimits struct {
	TxnEvents    int `json:"analytic_event_data"`
	CustomEvents int `json:"custom_event_data"`
	ErrorEvents  int `json:"error_event_data"`
}

// newHarvestLimits creates a harvestLimits with the currently set max values
// for each event type.
func newHarvestLimits() harvestLimits {
	return harvestLimits{
		TxnEvents:    maxTxnEvents,
		CustomEvents: maxCustomEvents,
		ErrorEvents:  maxErrorEvents,
	}
}

// NewConnectEventData creates a new ConnectEventData with values set for the
// maximums for each event type
func NewConnectEventData() ConnectEventData {
	return ConnectEventData{
		HarvestLimits: newHarvestLimits(),
	}
}

// ConnectAttempt tries to connect an application.
func ConnectAttempt(config ConnectJSONCreator, securityPoliciesToken string, cs RpmControls) (*ConnectReply, RPMResponse) {
	preconnectData, err := json.Marshal([]preconnectRequest{
		{SecurityPoliciesToken: securityPoliciesToken},
	})
	if nil != err {
		return nil, RPMResponse{Err: fmt.Errorf("unable to marshal preconnect data: %v", err)}
	}

	call := RpmCmd{
		Name:      cmdPreconnect,
		Collector: calculatePreconnectHost(cs.License, preconnectHostOverride),
		Data:      preconnectData,
	}

	resp := CollectorRequest(call, cs)
	if nil != resp.Err {
		return nil, resp
	}

	var preconnect struct {
		Preconnect PreconnectReply `json:"return_value"`
	}
	err = json.Unmarshal(resp.body, &preconnect)
	if nil != err {
		// Certain security policy errors must be treated as a disconnect.
		return nil, RPMResponse{
			Err:                      fmt.Errorf("unable to process preconnect reply: %v", err),
			disconnectSecurityPolicy: isDisconnectSecurityPolicyError(err),
		}
	}

	js, err := config.CreateConnectJSON(preconnect.Preconnect.SecurityPolicies.PointerIfPopulated())
	if nil != err {
		return nil, RPMResponse{Err: fmt.Errorf("unable to create connect data: %v", err)}
	}

	call.Collector = preconnect.Preconnect.Collector
	call.Data = js
	call.Name = cmdConnect

	resp = CollectorRequest(call, cs)
	if nil != resp.Err {
		return nil, resp
	}

	reply, err := constructConnectReply(resp.body, preconnect.Preconnect)
	if nil != err {
		return nil, RPMResponse{Err: err}
	}
	return reply, resp
}

func constructConnectReply(body []byte, preconnect PreconnectReply) (*ConnectReply, error) {
	var reply struct {
		Reply *ConnectReply `json:"return_value"`
	}
	reply.Reply = ConnectReplyDefaults()
	err := json.Unmarshal(body, &reply)
	if nil != err {
		return nil, fmt.Errorf("unable to parse connect reply: %v", err)
	}
	// Note:  This should never happen.  It would mean the collector
	// response is malformed.  This exists merely as extra defensiveness.
	if "" == reply.Reply.RunID {
		return nil, errors.New("connect reply missing agent run id")
	}

	reply.Reply.PreconnectReply = preconnect

	reply.Reply.AdaptiveSampler = NewAdaptiveSampler(
		time.Duration(reply.Reply.SamplingTargetPeriodInSeconds)*time.Second,
		reply.Reply.SamplingTarget,
		time.Now())
	reply.Reply.rulesCache = newRulesCache(txnNameCacheLimit)

	if !reply.Reply.EventData.validate() {
		reply.Reply.EventData = harvestDataDefaults()
	}

	return reply.Reply, nil
}
