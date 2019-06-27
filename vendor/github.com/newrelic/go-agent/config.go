package newrelic

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Config contains Application and Transaction behavior settings.
// Use NewConfig to create a Config with proper defaults.
type Config struct {
	// AppName is used by New Relic to link data across servers.
	//
	// https://docs.newrelic.com/docs/apm/new-relic-apm/installation-configuration/naming-your-application
	AppName string

	// License is your New Relic license key.
	//
	// https://docs.newrelic.com/docs/accounts/install-new-relic/account-setup/license-key
	License string

	// Logger controls go-agent logging.  For info level logging to stdout:
	//
	//	cfg.Logger = newrelic.NewLogger(os.Stdout)
	//
	// For debug level logging to stdout:
	//
	//	cfg.Logger = newrelic.NewDebugLogger(os.Stdout)
	//
	// See https://github.com/newrelic/go-agent/blob/master/GUIDE.md#logging
	// for more examples and logging integrations.
	Logger Logger

	// Enabled controls whether the agent will communicate with the New Relic
	// servers and spawn goroutines.  Setting this to be false is useful in
	// testing and staging situations.
	Enabled bool

	// Labels are key value pairs used to roll up applications into specific
	// categories.
	//
	// https://docs.newrelic.com/docs/using-new-relic/user-interface-functions/organize-your-data/labels-categories-organize-apps-monitors
	Labels map[string]string

	// HighSecurity guarantees that certain agent settings can not be made
	// more permissive.  This setting must match the corresponding account
	// setting in the New Relic UI.
	//
	// https://docs.newrelic.com/docs/agents/manage-apm-agents/configuration/high-security-mode
	HighSecurity bool

	// SecurityPoliciesToken enables security policies if set to a non-empty
	// string.  Only set this if security policies have been enabled on your
	// account.  This cannot be used in conjunction with HighSecurity.
	//
	// https://docs.newrelic.com/docs/agents/manage-apm-agents/configuration/enable-configurable-security-policies
	SecurityPoliciesToken string

	// CustomInsightsEvents controls the behavior of
	// Application.RecordCustomEvent.
	//
	// https://docs.newrelic.com/docs/insights/new-relic-insights/adding-querying-data/inserting-custom-events-new-relic-apm-agents
	CustomInsightsEvents struct {
		// Enabled controls whether RecordCustomEvent will collect
		// custom analytics events.  High security mode overrides this
		// setting.
		Enabled bool
	}

	// TransactionEvents controls the behavior of transaction analytics
	// events.
	TransactionEvents struct {
		// Enabled controls whether transaction events are captured.
		Enabled bool
		// Attributes controls the attributes included with transaction
		// events.
		Attributes AttributeDestinationConfig
	}

	// ErrorCollector controls the capture of errors.
	ErrorCollector struct {
		// Enabled controls whether errors are captured.  This setting
		// affects both traced errors and error analytics events.
		Enabled bool
		// CaptureEvents controls whether error analytics events are
		// captured.
		CaptureEvents bool
		// IgnoreStatusCodes controls which http response codes are
		// automatically turned into errors.  By default, response codes
		// greater than or equal to 400, with the exception of 404, are
		// turned into errors.
		IgnoreStatusCodes []int
		// Attributes controls the attributes included with errors.
		Attributes AttributeDestinationConfig
	}

	// TransactionTracer controls the capture of transaction traces.
	TransactionTracer struct {
		// Enabled controls whether transaction traces are captured.
		Enabled bool
		// Threshold controls whether a transaction trace will be
		// considered for capture.  Of the traces exceeding the
		// threshold, the slowest trace every minute is captured.
		Threshold struct {
			// If IsApdexFailing is true then the trace threshold is
			// four times the apdex threshold.
			IsApdexFailing bool
			// If IsApdexFailing is false then this field is the
			// threshold, otherwise it is ignored.
			Duration time.Duration
		}
		// SegmentThreshold is the threshold at which segments will be
		// added to the trace.  Lowering this setting may increase
		// overhead.  Decrease this duration if your Transaction Traces are
		// missing segments.
		SegmentThreshold time.Duration
		// StackTraceThreshold is the threshold at which segments will
		// be given a stack trace in the transaction trace.  Lowering
		// this setting will increase overhead.
		StackTraceThreshold time.Duration
		// Attributes controls the attributes included with transaction
		// traces.
		Attributes AttributeDestinationConfig
		// Segments.Attributes controls the attributes included with
		// each trace segment.
		Segments struct {
			Attributes AttributeDestinationConfig
		}
	}

	// BrowserMonitoring contains settings which control the behavior of
	// Transaction.BrowserTimingHeader.
	BrowserMonitoring struct {
		// Enabled controls whether or not the Browser monitoring feature is
		// enabled.
		Enabled bool
		// Attributes controls the attributes included with Browser monitoring.
		// BrowserMonitoring.Attributes.Enabled is false by default, to include
		// attributes in the Browser timing Javascript:
		//
		//	cfg.BrowserMonitoring.Attributes.Enabled = true
		Attributes AttributeDestinationConfig
	}

	// HostDisplayName gives this server a recognizable name in the New
	// Relic UI.  This is an optional setting.
	HostDisplayName string

	// Transport customizes communication with the New Relic servers.  This may
	// be used to configure a proxy.
	Transport http.RoundTripper

	// Utilization controls the detection and gathering of system
	// information.
	Utilization struct {
		// DetectAWS controls whether the Application attempts to detect
		// AWS.
		DetectAWS bool
		// DetectAzure controls whether the Application attempts to detect
		// Azure.
		DetectAzure bool
		// DetectPCF controls whether the Application attempts to detect
		// PCF.
		DetectPCF bool
		// DetectGCP controls whether the Application attempts to detect
		// GCP.
		DetectGCP bool
		// DetectDocker controls whether the Application attempts to
		// detect Docker.
		DetectDocker bool
		// DetectKubernetes controls whether the Application attempts to
		// detect Kubernetes.
		DetectKubernetes bool

		// These settings provide system information when custom values
		// are required.
		LogicalProcessors int
		TotalRAMMIB       int
		BillingHostname   string
	}

	// CrossApplicationTracer controls behaviour relating to cross application
	// tracing (CAT), available since Go Agent v0.11.  The
	// CrossApplicationTracer and the DistributedTracer cannot be
	// simultaneously enabled.
	//
	// https://docs.newrelic.com/docs/apm/transactions/cross-application-traces/introduction-cross-application-traces
	CrossApplicationTracer struct {
		Enabled bool
	}

	// DistributedTracer controls behaviour relating to Distributed Tracing,
	// available since Go Agent v2.1. The DistributedTracer and the
	// CrossApplicationTracer cannot be simultaneously enabled.
	//
	// https://docs.newrelic.com/docs/apm/distributed-tracing/getting-started/introduction-distributed-tracing
	DistributedTracer struct {
		Enabled bool
	}

	// SpanEvents controls behavior relating to Span Events.  Span Events
	// require that DistributedTracer is enabled.
	SpanEvents struct {
		Enabled    bool
		Attributes AttributeDestinationConfig
	}

	// DatastoreTracer controls behavior relating to datastore segments.
	DatastoreTracer struct {
		// InstanceReporting controls whether the host and port are collected
		// for datastore segments.
		InstanceReporting struct {
			Enabled bool
		}
		// DatabaseNameReporting controls whether the database name is
		// collected for datastore segments.
		DatabaseNameReporting struct {
			Enabled bool
		}
		QueryParameters struct {
			Enabled bool
		}
		// SlowQuery controls the capture of slow query traces.  Slow
		// query traces show you instances of your slowest datastore
		// segments.
		SlowQuery struct {
			Enabled   bool
			Threshold time.Duration
		}
	}

	// Attributes controls which attributes are enabled and disabled globally.
	// This setting affects all attribute destinations: Transaction Events,
	// Error Events, Transaction Traces and segments, Traced Errors, Span
	// Events, and Browser timing header.
	Attributes AttributeDestinationConfig

	// RuntimeSampler controls the collection of runtime statistics like
	// CPU/Memory usage, goroutine count, and GC pauses.
	RuntimeSampler struct {
		// Enabled controls whether runtime statistics are captured.
		Enabled bool
	}

	// ServerlessMode contains fields which control behavior when running in
	// AWS Lambda.
	//
	// https://docs.newrelic.com/docs/serverless-function-monitoring/aws-lambda-monitoring/get-started/introduction-new-relic-monitoring-aws-lambda
	ServerlessMode struct {
		// Enabling ServerlessMode will print each transaction's data to
		// stdout.  No agent goroutines will be spawned in serverless mode, and
		// no data will be sent directly to the New Relic backend.
		// nrlambda.NewConfig sets Enabled to true.
		Enabled bool
		// ApdexThreshold sets the Apdex threshold when in ServerlessMode.  The
		// default is 500 milliseconds.  nrlambda.NewConfig populates this
		// field using the NEW_RELIC_APDEX_T environment variable.
		//
		// https://docs.newrelic.com/docs/apm/new-relic-apm/apdex/apdex-measure-user-satisfaction
		ApdexThreshold time.Duration
		// AccountID, TrustedAccountKey, and PrimaryAppID are used for
		// distributed tracing in ServerlessMode.  AccountID and
		// TrustedAccountKey must be populated for distributed tracing to be
		// enabled. nrlambda.NewConfig populates these fields using the
		// NEW_RELIC_ACCOUNT_ID, NEW_RELIC_TRUSTED_ACCOUNT_KEY, and
		// NEW_RELIC_PRIMARY_APPLICATION_ID environment variables.
		AccountID         string
		TrustedAccountKey string
		PrimaryAppID      string
	}
}

// AttributeDestinationConfig controls the attributes sent to each destination.
// For more information, see:
// https://docs.newrelic.com/docs/agents/manage-apm-agents/agent-data/agent-attributes
type AttributeDestinationConfig struct {
	// Enabled controls whether or not this destination will get any
	// attributes at all.  For example, to prevent any attributes from being
	// added to errors, set:
	//
	//	cfg.ErrorCollector.Attributes.Enabled = false
	//
	Enabled bool
	Include []string
	// Exclude allows you to prevent the capture of certain attributes.  For
	// example, to prevent the capture of the request URL attribute
	// "request.uri", set:
	//
	//	cfg.Attributes.Exclude = append(cfg.Attributes.Exclude, newrelic.AttributeRequestURI)
	//
	// The '*' character acts as a wildcard.  For example, to prevent the
	// capture of all request related attributes, set:
	//
	//	cfg.Attributes.Exclude = append(cfg.Attributes.Exclude, "request.*")
	//
	Exclude []string
}

// NewConfig creates a Config populated with default settings and the given
// appname and license.
func NewConfig(appname, license string) Config {
	c := Config{}

	c.AppName = appname
	c.License = license
	c.Enabled = true
	c.Labels = make(map[string]string)
	c.CustomInsightsEvents.Enabled = true
	c.TransactionEvents.Enabled = true
	c.TransactionEvents.Attributes.Enabled = true
	c.HighSecurity = false
	c.ErrorCollector.Enabled = true
	c.ErrorCollector.CaptureEvents = true
	c.ErrorCollector.IgnoreStatusCodes = []int{
		http.StatusNotFound, // 404
	}
	c.ErrorCollector.Attributes.Enabled = true
	c.Utilization.DetectAWS = true
	c.Utilization.DetectAzure = true
	c.Utilization.DetectPCF = true
	c.Utilization.DetectGCP = true
	c.Utilization.DetectDocker = true
	c.Utilization.DetectKubernetes = true
	c.Attributes.Enabled = true
	c.RuntimeSampler.Enabled = true

	c.TransactionTracer.Enabled = true
	c.TransactionTracer.Threshold.IsApdexFailing = true
	c.TransactionTracer.Threshold.Duration = 500 * time.Millisecond
	c.TransactionTracer.SegmentThreshold = 2 * time.Millisecond
	c.TransactionTracer.StackTraceThreshold = 500 * time.Millisecond
	c.TransactionTracer.Attributes.Enabled = true
	c.TransactionTracer.Segments.Attributes.Enabled = true

	c.BrowserMonitoring.Enabled = true
	// browser monitoring attributes are disabled by default
	c.BrowserMonitoring.Attributes.Enabled = false

	c.CrossApplicationTracer.Enabled = true
	c.DistributedTracer.Enabled = false
	c.SpanEvents.Enabled = true
	c.SpanEvents.Attributes.Enabled = true

	c.DatastoreTracer.InstanceReporting.Enabled = true
	c.DatastoreTracer.DatabaseNameReporting.Enabled = true
	c.DatastoreTracer.QueryParameters.Enabled = true
	c.DatastoreTracer.SlowQuery.Enabled = true
	c.DatastoreTracer.SlowQuery.Threshold = 10 * time.Millisecond

	c.ServerlessMode.ApdexThreshold = 500 * time.Millisecond
	c.ServerlessMode.Enabled = false

	return c
}

const (
	licenseLength = 40
	appNameLimit  = 3
)

// The following errors will be returned if your Config fails to validate.
var (
	errLicenseLen                       = fmt.Errorf("license length is not %d", licenseLength)
	errAppNameMissing                   = errors.New("string AppName required")
	errAppNameLimit                     = fmt.Errorf("max of %d rollup application names", appNameLimit)
	errHighSecurityWithSecurityPolicies = errors.New("SecurityPoliciesToken and HighSecurity are incompatible; please ensure HighSecurity is set to false if SecurityPoliciesToken is a non-empty string and a security policy has been set for your account")
)

// Validate checks the config for improper fields.  If the config is invalid,
// newrelic.NewApplication returns an error.
func (c Config) Validate() error {
	if c.Enabled && !c.ServerlessMode.Enabled {
		if len(c.License) != licenseLength {
			return errLicenseLen
		}
	} else {
		// The License may be empty when the agent is not enabled.
		if len(c.License) != licenseLength && len(c.License) != 0 {
			return errLicenseLen
		}
	}
	if "" == c.AppName && c.Enabled && !c.ServerlessMode.Enabled {
		return errAppNameMissing
	}
	if c.HighSecurity && "" != c.SecurityPoliciesToken {
		return errHighSecurityWithSecurityPolicies
	}
	if strings.Count(c.AppName, ";") >= appNameLimit {
		return errAppNameLimit
	}
	return nil
}
