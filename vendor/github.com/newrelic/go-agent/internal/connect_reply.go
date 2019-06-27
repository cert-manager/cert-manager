package internal

import (
	"encoding/json"
	"strings"
	"time"
)

// AgentRunID identifies the current connection with the collector.
type AgentRunID string

func (id AgentRunID) String() string {
	return string(id)
}

// PreconnectReply contains settings from the preconnect endpoint.
type PreconnectReply struct {
	Collector        string           `json:"redirect_host"`
	SecurityPolicies SecurityPolicies `json:"security_policies"`
}

// ConnectReply contains all of the settings and state send down from the
// collector.  It should not be modified after creation.
type ConnectReply struct {
	RunID             AgentRunID        `json:"agent_run_id"`
	RequestHeadersMap map[string]string `json:"request_headers_map"`

	// Transaction Name Modifiers
	SegmentTerms segmentRules `json:"transaction_segment_terms"`
	TxnNameRules metricRules  `json:"transaction_name_rules"`
	URLRules     metricRules  `json:"url_rules"`
	MetricRules  metricRules  `json:"metric_name_rules"`

	// Cross Process
	EncodingKey     string            `json:"encoding_key"`
	CrossProcessID  string            `json:"cross_process_id"`
	TrustedAccounts trustedAccountSet `json:"trusted_account_ids"`

	// Settings
	KeyTxnApdex            map[string]float64 `json:"web_transactions_apdex"`
	ApdexThresholdSeconds  float64            `json:"apdex_t"`
	CollectAnalyticsEvents bool               `json:"collect_analytics_events"`
	CollectCustomEvents    bool               `json:"collect_custom_events"`
	CollectTraces          bool               `json:"collect_traces"`
	CollectErrors          bool               `json:"collect_errors"`
	CollectErrorEvents     bool               `json:"collect_error_events"`
	CollectSpanEvents      bool               `json:"collect_span_events"`

	// RUM
	AgentLoader string `json:"js_agent_loader"`
	Beacon      string `json:"beacon"`
	BrowserKey  string `json:"browser_key"`
	AppID       string `json:"application_id"`
	ErrorBeacon string `json:"error_beacon"`
	JSAgentFile string `json:"js_agent_file"`

	// PreconnectReply fields are not in the connect reply, this embedding
	// is done to simplify code.
	PreconnectReply `json:"-"`

	Messages []struct {
		Message string `json:"message"`
		Level   string `json:"level"`
	} `json:"messages"`

	AdaptiveSampler AdaptiveSampler

	// BetterCAT/Distributed Tracing
	AccountID                     string `json:"account_id"`
	TrustedAccountKey             string `json:"trusted_account_key"`
	PrimaryAppID                  string `json:"primary_application_id"`
	SamplingTarget                uint64 `json:"sampling_target"`
	SamplingTargetPeriodInSeconds int    `json:"sampling_target_period_in_seconds"`

	// rulesCache caches the results of calling CreateFullTxnName.  It
	// exists here in ConnectReply since it is specific to a set of rules
	// and is shared between transactions.
	rulesCache *rulesCache

	ServerSideConfig struct {
		TransactionTracerEnabled *bool `json:"transaction_tracer.enabled"`
		// TransactionTracerThreshold should contain either a number or
		// "apdex_f" if it is non-nil.
		TransactionTracerThreshold           interface{} `json:"transaction_tracer.transaction_threshold"`
		TransactionTracerStackTraceThreshold *float64    `json:"transaction_tracer.stack_trace_threshold"`
		ErrorCollectorEnabled                *bool       `json:"error_collector.enabled"`
		ErrorCollectorIgnoreStatusCodes      []int       `json:"error_collector.ignore_status_codes"`
		CrossApplicationTracerEnabled        *bool       `json:"cross_application_tracer.enabled"`
	} `json:"agent_config"`

	// Faster Event Harvest
	EventData harvestData `json:"event_data"`
}

type harvestData struct {
	EventReportPeriodMs int           `json:"report_period_ms"`
	HarvestLimits       harvestLimits `json:"harvest_limits"`
}

func (r *ConnectReply) getHarvestData() harvestData {
	if nil != r {
		return r.EventData
	}
	return harvestDataDefaults()
}

func harvestDataDefaults() harvestData {
	return harvestData{
		EventReportPeriodMs: 60 * 1000, // 60 seconds
		HarvestLimits:       newHarvestLimits(),
	}
}

func (h harvestData) eventReportPeriod() time.Duration {
	return time.Duration(h.EventReportPeriodMs) * time.Millisecond
}

func (h harvestData) validate() bool {
	if 0 == h.HarvestLimits.TxnEvents {
		return false
	}
	if 0 == h.HarvestLimits.CustomEvents {
		return false
	}
	if 0 == h.HarvestLimits.ErrorEvents {
		return false
	}
	if 0 == h.EventReportPeriodMs {
		return false
	}
	return true
}

type trustedAccountSet map[int]struct{}

func (t *trustedAccountSet) IsTrusted(account int) bool {
	_, exists := (*t)[account]
	return exists
}

func (t *trustedAccountSet) UnmarshalJSON(data []byte) error {
	accounts := make([]int, 0)
	if err := json.Unmarshal(data, &accounts); err != nil {
		return err
	}

	*t = make(trustedAccountSet)
	for _, account := range accounts {
		(*t)[account] = struct{}{}
	}

	return nil
}

// ConnectReplyDefaults returns a newly allocated ConnectReply with the proper
// default settings.  A pointer to a global is not used to prevent consumers
// from changing the default settings.
func ConnectReplyDefaults() *ConnectReply {
	return &ConnectReply{
		ApdexThresholdSeconds:  0.5,
		CollectAnalyticsEvents: true,
		CollectCustomEvents:    true,
		CollectTraces:          true,
		CollectErrors:          true,
		CollectErrorEvents:     true,
		CollectSpanEvents:      true,
		// No transactions should be sampled before the application is
		// connected.
		AdaptiveSampler: SampleNothing{},

		SamplingTarget:                10,
		SamplingTargetPeriodInSeconds: 60,

		EventData: harvestDataDefaults(),
	}
}

// CalculateApdexThreshold calculates the apdex threshold.
func CalculateApdexThreshold(c *ConnectReply, txnName string) time.Duration {
	if t, ok := c.KeyTxnApdex[txnName]; ok {
		return FloatSecondsToDuration(t)
	}
	return FloatSecondsToDuration(c.ApdexThresholdSeconds)
}

// CreateFullTxnName uses collector rules and the appropriate metric prefix to
// construct the full transaction metric name from the name given by the
// consumer.
func CreateFullTxnName(input string, reply *ConnectReply, isWeb bool) string {
	if name := reply.rulesCache.find(input, isWeb); "" != name {
		return name
	}
	name := constructFullTxnName(input, reply, isWeb)
	if "" != name {
		// Note that we  don't cache situations where the rules say
		// ignore.  It would increase complication (we would need to
		// disambiguate not-found vs ignore).  Also, the ignore code
		// path is probably extremely uncommon.
		reply.rulesCache.set(input, isWeb, name)
	}
	return name
}

func constructFullTxnName(input string, reply *ConnectReply, isWeb bool) string {
	var afterURLRules string
	if "" != input {
		afterURLRules = reply.URLRules.Apply(input)
		if "" == afterURLRules {
			return ""
		}
	}

	prefix := backgroundMetricPrefix
	if isWeb {
		prefix = webMetricPrefix
	}

	var beforeNameRules string
	if strings.HasPrefix(afterURLRules, "/") {
		beforeNameRules = prefix + afterURLRules
	} else {
		beforeNameRules = prefix + "/" + afterURLRules
	}

	afterNameRules := reply.TxnNameRules.Apply(beforeNameRules)
	if "" == afterNameRules {
		return ""
	}

	return reply.SegmentTerms.apply(afterNameRules)
}
