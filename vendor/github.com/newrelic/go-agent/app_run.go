package newrelic

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/newrelic/go-agent/internal"
)

// appRun contains information regarding a single connection session with the
// collector.  It is immutable after creation at application connect.
type appRun struct {
	Reply *internal.ConnectReply

	// AttributeConfig is calculated on every connect since it depends on
	// the security policies.
	AttributeConfig *internal.AttributeConfig
	Config          Config
}

func newAppRun(config Config, reply *internal.ConnectReply) *appRun {
	run := &appRun{
		Reply: reply,
		AttributeConfig: internal.CreateAttributeConfig(internal.AttributeConfigInput{
			Attributes:        convertAttributeDestinationConfig(config.Attributes),
			ErrorCollector:    convertAttributeDestinationConfig(config.ErrorCollector.Attributes),
			TransactionEvents: convertAttributeDestinationConfig(config.TransactionEvents.Attributes),
			TransactionTracer: convertAttributeDestinationConfig(config.TransactionTracer.Attributes),
			BrowserMonitoring: convertAttributeDestinationConfig(config.BrowserMonitoring.Attributes),
			SpanEvents:        convertAttributeDestinationConfig(config.SpanEvents.Attributes),
			TraceSegments:     convertAttributeDestinationConfig(config.TransactionTracer.Segments.Attributes),
		}, reply.SecurityPolicies.AttributesInclude.Enabled()),
		Config: config,
	}

	// Overwrite local settings with any server-side-config settings
	// present. NOTE!  This requires that the Config provided to this
	// function is a value and not a pointer: We do not want to change the
	// input Config with values particular to this connection.

	if v := run.Reply.ServerSideConfig.TransactionTracerEnabled; nil != v {
		run.Config.TransactionTracer.Enabled = *v
	}
	if v := run.Reply.ServerSideConfig.ErrorCollectorEnabled; nil != v {
		run.Config.ErrorCollector.Enabled = *v
	}
	if v := run.Reply.ServerSideConfig.CrossApplicationTracerEnabled; nil != v {
		run.Config.CrossApplicationTracer.Enabled = *v
	}
	if v := run.Reply.ServerSideConfig.TransactionTracerThreshold; nil != v {
		switch val := v.(type) {
		case float64:
			run.Config.TransactionTracer.Threshold.IsApdexFailing = false
			run.Config.TransactionTracer.Threshold.Duration = internal.FloatSecondsToDuration(val)
		case string:
			if val == "apdex_f" {
				run.Config.TransactionTracer.Threshold.IsApdexFailing = true
			}
		}
	}
	if v := run.Reply.ServerSideConfig.TransactionTracerStackTraceThreshold; nil != v {
		run.Config.TransactionTracer.StackTraceThreshold = internal.FloatSecondsToDuration(*v)
	}
	if v := run.Reply.ServerSideConfig.ErrorCollectorIgnoreStatusCodes; nil != v {
		run.Config.ErrorCollector.IgnoreStatusCodes = v
	}

	if !run.Reply.CollectErrorEvents {
		run.Config.ErrorCollector.CaptureEvents = false
	}
	if !run.Reply.CollectAnalyticsEvents {
		run.Config.TransactionEvents.Enabled = false
	}
	if !run.Reply.CollectTraces {
		run.Config.TransactionTracer.Enabled = false
		run.Config.DatastoreTracer.SlowQuery.Enabled = false
	}
	if !run.Reply.CollectSpanEvents {
		run.Config.SpanEvents.Enabled = false
	}

	// Distributed tracing takes priority over cross-app-tracing per:
	// https://source.datanerd.us/agents/agent-specs/blob/master/Distributed-Tracing.md#distributed-trace-payload
	if run.Config.DistributedTracer.Enabled {
		run.Config.CrossApplicationTracer.Enabled = false
	}

	if "" != run.Reply.RunID {
		js, _ := json.Marshal(settings(run.Config))
		run.Config.Logger.Debug("final configuration", map[string]interface{}{
			"config": internal.JSONString(js),
		})
	}

	return run
}

const (
	// https://source.datanerd.us/agents/agent-specs/blob/master/Lambda.md#distributed-tracing
	serverlessDefaultPrimaryAppID = "Unknown"
)

const (
	// https://source.datanerd.us/agents/agent-specs/blob/master/Lambda.md#adaptive-sampling
	serverlessSamplerPeriod = 60 * time.Second
	serverlessSamplerTarget = 10
)

func newServerlessConnectReply(config Config) *internal.ConnectReply {
	reply := internal.ConnectReplyDefaults()

	reply.ApdexThresholdSeconds = config.ServerlessMode.ApdexThreshold.Seconds()

	reply.AccountID = config.ServerlessMode.AccountID
	reply.TrustedAccountKey = config.ServerlessMode.TrustedAccountKey
	reply.PrimaryAppID = config.ServerlessMode.PrimaryAppID

	if "" == reply.TrustedAccountKey {
		// The trust key does not need to be provided by customers whose
		// account ID is the same as the trust key.
		reply.TrustedAccountKey = reply.AccountID
	}

	if "" == reply.PrimaryAppID {
		reply.PrimaryAppID = serverlessDefaultPrimaryAppID
	}

	reply.AdaptiveSampler = internal.NewAdaptiveSampler(serverlessSamplerPeriod,
		serverlessSamplerTarget, time.Now())

	return reply
}

func (run *appRun) responseCodeIsError(code int) bool {
	if code < http.StatusBadRequest { // 400
		return false
	}
	for _, ignoreCode := range run.Config.ErrorCollector.IgnoreStatusCodes {
		if code == ignoreCode {
			return false
		}
	}
	return true
}

func (run *appRun) txnTraceThreshold(apdexThreshold time.Duration) time.Duration {
	if run.Config.TransactionTracer.Threshold.IsApdexFailing {
		return internal.ApdexFailingThreshold(apdexThreshold)
	}
	return run.Config.TransactionTracer.Threshold.Duration
}
