package internal

const (
	apdexRollup = "Apdex"
	apdexPrefix = "Apdex/"

	webRollup        = "WebTransaction"
	backgroundRollup = "OtherTransaction/all"

	// https://source.datanerd.us/agents/agent-specs/blob/master/Total-Time-Async.md
	totalTimeWeb        = "WebTransactionTotalTime"
	totalTimeBackground = "OtherTransactionTotalTime"

	errorsPrefix = "Errors/"

	// "HttpDispatcher" metric is used for the overview graph, and
	// therefore should only be made for web transactions.
	dispatcherMetric = "HttpDispatcher"

	queueMetric = "WebFrontend/QueueTime"

	webMetricPrefix        = "WebTransaction/Go"
	backgroundMetricPrefix = "OtherTransaction/Go"

	instanceReporting = "Instance/Reporting"

	// https://newrelic.atlassian.net/wiki/display/eng/Custom+Events+in+New+Relic+Agents
	customEventsSeen = "Supportability/Events/Customer/Seen"
	customEventsSent = "Supportability/Events/Customer/Sent"

	// https://source.datanerd.us/agents/agent-specs/blob/master/Transaction-Events-PORTED.md
	txnEventsSeen = "Supportability/AnalyticsEvents/TotalEventsSeen"
	txnEventsSent = "Supportability/AnalyticsEvents/TotalEventsSent"

	// https://source.datanerd.us/agents/agent-specs/blob/master/Error-Events.md
	errorEventsSeen = "Supportability/Events/TransactionError/Seen"
	errorEventsSent = "Supportability/Events/TransactionError/Sent"

	// https://source.datanerd.us/agents/agent-specs/blob/master/Span-Events.md
	spanEventsSeen = "Supportability/SpanEvent/TotalEventsSeen"
	spanEventsSent = "Supportability/SpanEvent/TotalEventsSent"

	supportabilityDropped = "Supportability/MetricsDropped"

	// Runtime/System Metrics
	memoryPhysical       = "Memory/Physical"
	heapObjectsAllocated = "Memory/Heap/AllocatedObjects"
	cpuUserUtilization   = "CPU/User/Utilization"
	cpuSystemUtilization = "CPU/System/Utilization"
	cpuUserTime          = "CPU/User Time"
	cpuSystemTime        = "CPU/System Time"
	runGoroutine         = "Go/Runtime/Goroutines"
	gcPauseFraction      = "GC/System/Pause Fraction"
	gcPauses             = "GC/System/Pauses"

	// Distributed Tracing Supportability Metrics
	supportTracingAcceptSuccess          = "Supportability/DistributedTrace/AcceptPayload/Success"
	supportTracingAcceptException        = "Supportability/DistributedTrace/AcceptPayload/Exception"
	supportTracingAcceptParseException   = "Supportability/DistributedTrace/AcceptPayload/ParseException"
	supportTracingCreateBeforeAccept     = "Supportability/DistributedTrace/AcceptPayload/Ignored/CreateBeforeAccept"
	supportTracingIgnoredMultiple        = "Supportability/DistributedTrace/AcceptPayload/Ignored/Multiple"
	supportTracingIgnoredVersion         = "Supportability/DistributedTrace/AcceptPayload/Ignored/MajorVersion"
	supportTracingAcceptUntrustedAccount = "Supportability/DistributedTrace/AcceptPayload/Ignored/UntrustedAccount"
	supportTracingAcceptNull             = "Supportability/DistributedTrace/AcceptPayload/Ignored/Null"
	supportTracingCreatePayloadSuccess   = "Supportability/DistributedTrace/CreatePayload/Success"
	supportTracingCreatePayloadException = "Supportability/DistributedTrace/CreatePayload/Exception"
)

// DistributedTracingSupport is used to track distributed tracing activity for
// supportability.
type DistributedTracingSupport struct {
	AcceptPayloadSuccess            bool // AcceptPayload was called successfully
	AcceptPayloadException          bool // AcceptPayload had a generic exception
	AcceptPayloadParseException     bool // AcceptPayload had a parsing exception
	AcceptPayloadCreateBeforeAccept bool // AcceptPayload was ignored because CreatePayload had already been called
	AcceptPayloadIgnoredMultiple    bool // AcceptPayload was ignored because AcceptPayload had already been called
	AcceptPayloadIgnoredVersion     bool // AcceptPayload was ignored because the payload's major version was greater than the agent's
	AcceptPayloadUntrustedAccount   bool // AcceptPayload was ignored because the payload was untrusted
	AcceptPayloadNullPayload        bool // AcceptPayload was ignored because the payload was nil
	CreatePayloadSuccess            bool // CreatePayload was called successfully
	CreatePayloadException          bool // CreatePayload had a generic exception
}

type rollupMetric struct {
	all      string
	allWeb   string
	allOther string
}

func newRollupMetric(s string) rollupMetric {
	return rollupMetric{
		all:      s + "all",
		allWeb:   s + "allWeb",
		allOther: s + "allOther",
	}
}

func (r rollupMetric) webOrOther(isWeb bool) string {
	if isWeb {
		return r.allWeb
	}
	return r.allOther
}

var (
	errorsRollupMetric = newRollupMetric("Errors/")

	// source.datanerd.us/agents/agent-specs/blob/master/APIs/external_segment.md
	// source.datanerd.us/agents/agent-specs/blob/master/APIs/external_cat.md
	// source.datanerd.us/agents/agent-specs/blob/master/Cross-Application-Tracing-PORTED.md
	externalRollupMetric = newRollupMetric("External/")

	// source.datanerd.us/agents/agent-specs/blob/master/Datastore-Metrics-PORTED.md
	datastoreRollupMetric = newRollupMetric("Datastore/")

	datastoreProductMetricsCache = map[string]rollupMetric{
		"Cassandra":     newRollupMetric("Datastore/Cassandra/"),
		"Derby":         newRollupMetric("Datastore/Derby/"),
		"Elasticsearch": newRollupMetric("Datastore/Elasticsearch/"),
		"Firebird":      newRollupMetric("Datastore/Firebird/"),
		"IBMDB2":        newRollupMetric("Datastore/IBMDB2/"),
		"Informix":      newRollupMetric("Datastore/Informix/"),
		"Memcached":     newRollupMetric("Datastore/Memcached/"),
		"MongoDB":       newRollupMetric("Datastore/MongoDB/"),
		"MySQL":         newRollupMetric("Datastore/MySQL/"),
		"MSSQL":         newRollupMetric("Datastore/MSSQL/"),
		"Oracle":        newRollupMetric("Datastore/Oracle/"),
		"Postgres":      newRollupMetric("Datastore/Postgres/"),
		"Redis":         newRollupMetric("Datastore/Redis/"),
		"Solr":          newRollupMetric("Datastore/Solr/"),
		"SQLite":        newRollupMetric("Datastore/SQLite/"),
		"CouchDB":       newRollupMetric("Datastore/CouchDB/"),
		"Riak":          newRollupMetric("Datastore/Riak/"),
		"VoltDB":        newRollupMetric("Datastore/VoltDB/"),
	}
)

func customSegmentMetric(s string) string {
	return "Custom/" + s
}

// customMetric is used to construct custom metrics from the input given to
// Application.RecordCustomMetric.  Note that the "Custom/" prefix helps prevent
// collision with other agent metrics, but does not eliminate the possibility
// since "Custom/" is also used for segments.
func customMetric(customerInput string) string {
	return "Custom/" + customerInput
}

// DatastoreMetricKey contains the fields by which datastore metrics are
// aggregated.
type DatastoreMetricKey struct {
	Product      string
	Collection   string
	Operation    string
	Host         string
	PortPathOrID string
}

type externalMetricKey struct {
	Host                    string
	ExternalCrossProcessID  string
	ExternalTransactionName string
}

func datastoreScopedMetric(key DatastoreMetricKey) string {
	if "" != key.Collection {
		return datastoreStatementMetric(key)
	}
	return datastoreOperationMetric(key)
}

// Datastore/{datastore}/*
func datastoreProductMetric(key DatastoreMetricKey) rollupMetric {
	d, ok := datastoreProductMetricsCache[key.Product]
	if ok {
		return d
	}
	return newRollupMetric("Datastore/" + key.Product + "/")
}

// Datastore/operation/{datastore}/{operation}
func datastoreOperationMetric(key DatastoreMetricKey) string {
	return "Datastore/operation/" + key.Product +
		"/" + key.Operation
}

// Datastore/statement/{datastore}/{table}/{operation}
func datastoreStatementMetric(key DatastoreMetricKey) string {
	return "Datastore/statement/" + key.Product +
		"/" + key.Collection +
		"/" + key.Operation
}

// Datastore/instance/{datastore}/{host}/{port_path_or_id}
func datastoreInstanceMetric(key DatastoreMetricKey) string {
	return "Datastore/instance/" + key.Product +
		"/" + key.Host +
		"/" + key.PortPathOrID
}

func externalScopedMetric(key externalMetricKey) string {
	if "" != key.ExternalCrossProcessID && "" != key.ExternalTransactionName {
		return externalTransactionMetric(key)
	}
	return externalHostMetric(key)
}

// External/{host}/all
func externalHostMetric(key externalMetricKey) string {
	return "External/" + key.Host + "/all"
}

// ExternalApp/{host}/{external_id}/all
func externalAppMetric(key externalMetricKey) string {
	return "ExternalApp/" + key.Host +
		"/" + key.ExternalCrossProcessID + "/all"
}

// ExternalTransaction/{host}/{external_id}/{external_txnname}
func externalTransactionMetric(key externalMetricKey) string {
	return "ExternalTransaction/" + key.Host +
		"/" + key.ExternalCrossProcessID +
		"/" + key.ExternalTransactionName
}

func callerFields(c payloadCaller) string {
	return "/" + c.Type +
		"/" + c.Account +
		"/" + c.App +
		"/" + c.TransportType +
		"/"
}

// DurationByCaller/{type}/{account}/{app}/{transport}/*
func durationByCallerMetric(c payloadCaller) rollupMetric {
	return newRollupMetric("DurationByCaller" + callerFields(c))
}

// ErrorsByCaller/{type}/{account}/{app}/{transport}/*
func errorsByCallerMetric(c payloadCaller) rollupMetric {
	return newRollupMetric("ErrorsByCaller" + callerFields(c))
}

// TransportDuration/{type}/{account}/{app}/{transport}/*
func transportDurationMetric(c payloadCaller) rollupMetric {
	return newRollupMetric("TransportDuration" + callerFields(c))
}
