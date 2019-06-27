package internal

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/newrelic/go-agent/internal/cat"
	"github.com/newrelic/go-agent/internal/jsonx"
	"github.com/newrelic/go-agent/internal/logger"
	"github.com/newrelic/go-agent/internal/sysinfo"
)

// MarshalJSON limits the number of decimals.
func (p *Priority) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(priorityFormat, *p)), nil
}

// WriteJSON limits the number of decimals.
func (p Priority) WriteJSON(buf *bytes.Buffer) {
	fmt.Fprintf(buf, priorityFormat, p)
}

// TxnEvent represents a transaction.
// https://source.datanerd.us/agents/agent-specs/blob/master/Transaction-Events-PORTED.md
// https://newrelic.atlassian.net/wiki/display/eng/Agent+Support+for+Synthetics%3A+Forced+Transaction+Traces+and+Analytic+Events
type TxnEvent struct {
	FinalName string
	Start     time.Time
	Duration  time.Duration
	TotalTime time.Duration
	Queuing   time.Duration
	Zone      ApdexZone
	Attrs     *Attributes
	DatastoreExternalTotals
	CrossProcess TxnCrossProcess
	BetterCAT    BetterCAT
	HasError     bool
}

// BetterCAT stores the transaction's priority and all fields related
// to a DistributedTracer's Cross-Application Trace.
type BetterCAT struct {
	Enabled  bool
	Priority Priority
	Sampled  bool
	Inbound  *Payload
	ID       string
}

// TraceID returns the trace id.
func (e BetterCAT) TraceID() string {
	if nil != e.Inbound {
		return e.Inbound.TracedID
	}
	return e.ID
}

// TxnData contains the recorded data of a transaction.
type TxnData struct {
	TxnEvent
	IsWeb          bool
	Name           string    // Work in progress name.
	Errors         TxnErrors // Lazily initialized.
	Stop           time.Time
	ApdexThreshold time.Duration

	stamp           segmentStamp
	threadIDCounter uint64

	LazilyCalculateSampled func() bool
	SpanEventsEnabled      bool
	rootSpanID             string
	spanEvents             []*SpanEvent

	customSegments    map[string]*metricData
	datastoreSegments map[DatastoreMetricKey]*metricData
	externalSegments  map[externalMetricKey]*metricData

	TxnTrace

	SlowQueriesEnabled bool
	SlowQueryThreshold time.Duration
	SlowQueries        *slowQueries

	// These better CAT supportability fields are left outside of
	// TxnEvent.BetterCAT to minimize the size of transaction event memory.
	DistributedTracingSupport
}

func (t *TxnData) saveTraceSegment(end segmentEnd, name string, attrs spanAttributeMap, externalGUID string) {
	attrs = t.Attrs.filterSpanAttributes(attrs, destSegment)
	t.TxnTrace.witnessNode(end, name, attrs, externalGUID)
}

// Thread contains a segment stack that is used to track segment parenting time
// within a single goroutine.
type Thread struct {
	threadID uint64
	stack    []segmentFrame
	// start and end are used to track the TotalTime this Thread was active.
	start time.Time
	end   time.Time
}

// RecordActivity indicates that activity happened at this time on this
// goroutine which helps track total time.
func (thread *Thread) RecordActivity(now time.Time) {
	if thread.start.IsZero() || now.Before(thread.start) {
		thread.start = now
	}
	if now.After(thread.end) {
		thread.end = now
	}
}

// TotalTime returns the amount to time that this thread contributes to the
// total time.
func (thread *Thread) TotalTime() time.Duration {
	if thread.start.Before(thread.end) {
		return thread.end.Sub(thread.start)
	}
	return 0
}

// NewThread returns a new Thread to track segments in a new goroutine.
func NewThread(txndata *TxnData) *Thread {
	// Each thread needs a unique ID.
	txndata.threadIDCounter++
	return &Thread{
		threadID: txndata.threadIDCounter,
	}
}

type segmentStamp uint64

type segmentTime struct {
	Stamp segmentStamp
	Time  time.Time
}

// SegmentStartTime is embedded into the top level segments (rather than
// segmentTime) to minimize the structure sizes to minimize allocations.
type SegmentStartTime struct {
	Stamp segmentStamp
	Depth int
}

type stringJSONWriter string

func (s stringJSONWriter) WriteJSON(buf *bytes.Buffer) {
	jsonx.AppendString(buf, string(s))
}

// spanAttributeMap is used for span attributes and segment attributes. The
// value is a jsonWriter to allow for segment query parameters.
type spanAttributeMap map[SpanAttribute]jsonWriter

func (m *spanAttributeMap) addString(key SpanAttribute, val string) {
	if "" != val {
		m.add(key, stringJSONWriter(val))
	}
}

func (m *spanAttributeMap) add(key SpanAttribute, val jsonWriter) {
	if *m == nil {
		*m = make(spanAttributeMap)
	}
	(*m)[key] = val
}

func (m spanAttributeMap) copy() spanAttributeMap {
	if len(m) == 0 {
		return nil
	}
	cpy := make(spanAttributeMap, len(m))
	for k, v := range m {
		cpy[k] = v
	}
	return cpy
}

type segmentFrame struct {
	segmentTime
	children   time.Duration
	spanID     string
	attributes spanAttributeMap
}

type segmentEnd struct {
	start      segmentTime
	stop       segmentTime
	duration   time.Duration
	exclusive  time.Duration
	SpanID     string
	ParentID   string
	threadID   uint64
	attributes spanAttributeMap
}

func (end segmentEnd) spanEvent() *SpanEvent {
	if "" == end.SpanID {
		return nil
	}
	return &SpanEvent{
		GUID:         end.SpanID,
		ParentID:     end.ParentID,
		Timestamp:    end.start.Time,
		Duration:     end.duration,
		Attributes:   end.attributes,
		IsEntrypoint: false,
	}
}

const (
	datastoreProductUnknown   = "Unknown"
	datastoreOperationUnknown = "other"
)

// HasErrors indicates whether the transaction had errors.
func (t *TxnData) HasErrors() bool {
	return len(t.Errors) > 0
}

func (t *TxnData) time(now time.Time) segmentTime {
	// Update the stamp before using it so that a 0 stamp can be special.
	t.stamp++
	return segmentTime{
		Time:  now,
		Stamp: t.stamp,
	}
}

// AddAgentSpanAttribute allows attributes to be added to spans.
func (thread *Thread) AddAgentSpanAttribute(key SpanAttribute, val string) {
	if len(thread.stack) > 0 {
		thread.stack[len(thread.stack)-1].attributes.addString(key, val)
	}
}

// StartSegment begins a segment.
func StartSegment(t *TxnData, thread *Thread, now time.Time) SegmentStartTime {
	tm := t.time(now)
	thread.stack = append(thread.stack, segmentFrame{
		segmentTime: tm,
		children:    0,
	})

	return SegmentStartTime{
		Stamp: tm.Stamp,
		Depth: len(thread.stack) - 1,
	}
}

// NewSpanID returns a random identifier in the format used for spans and
// transactions.
func NewSpanID() string {
	bits := RandUint64()
	return fmt.Sprintf("%016x", bits)
}

func (t *TxnData) getRootSpanID() string {
	if "" == t.rootSpanID {
		t.rootSpanID = NewSpanID()
	}
	return t.rootSpanID
}

// CurrentSpanIdentifier returns the identifier of the span at the top of the
// segment stack.
func (t *TxnData) CurrentSpanIdentifier(thread *Thread) string {
	if 0 == len(thread.stack) {
		return t.getRootSpanID()
	}
	if "" == thread.stack[len(thread.stack)-1].spanID {
		thread.stack[len(thread.stack)-1].spanID = NewSpanID()
	}
	return thread.stack[len(thread.stack)-1].spanID
}

func (t *TxnData) saveSpanEvent(e *SpanEvent) {
	e.Attributes = t.Attrs.filterSpanAttributes(e.Attributes, destSpan)
	if len(t.spanEvents) < maxSpanEvents {
		t.spanEvents = append(t.spanEvents, e)
	}
}

var (
	errMalformedSegment = errors.New("segment identifier malformed: perhaps unsafe code has modified it?")
	errSegmentOrder     = errors.New(`improper segment use: the Transaction must be used ` +
		`in a single goroutine and segments must be ended in "last started first ended" order: ` +
		`see https://github.com/newrelic/go-agent/blob/master/GUIDE.md#segments`)
)

func endSegment(t *TxnData, thread *Thread, start SegmentStartTime, now time.Time) (segmentEnd, error) {
	if 0 == start.Stamp {
		return segmentEnd{}, errMalformedSegment
	}
	if start.Depth >= len(thread.stack) {
		return segmentEnd{}, errSegmentOrder
	}
	if start.Depth < 0 {
		return segmentEnd{}, errMalformedSegment
	}
	frame := thread.stack[start.Depth]
	if start.Stamp != frame.Stamp {
		return segmentEnd{}, errSegmentOrder
	}

	var children time.Duration
	for i := start.Depth; i < len(thread.stack); i++ {
		children += thread.stack[i].children
	}
	s := segmentEnd{
		stop:       t.time(now),
		start:      frame.segmentTime,
		attributes: frame.attributes,
	}
	if s.stop.Time.After(s.start.Time) {
		s.duration = s.stop.Time.Sub(s.start.Time)
	}
	if s.duration > children {
		s.exclusive = s.duration - children
	}

	// Note that we expect (depth == (len(t.stack) - 1)).  However, if
	// (depth < (len(t.stack) - 1)), that's ok: could be a panic popped
	// some stack frames (and the consumer was not using defer).

	if start.Depth > 0 {
		thread.stack[start.Depth-1].children += s.duration
	}

	thread.stack = thread.stack[0:start.Depth]

	if t.SpanEventsEnabled && t.LazilyCalculateSampled() {
		s.SpanID = frame.spanID
		if "" == s.SpanID {
			s.SpanID = NewSpanID()
		}
		// Note that the current span identifier is the parent's
		// identifier because we've already popped the segment that's
		// ending off of the stack.
		s.ParentID = t.CurrentSpanIdentifier(thread)
	}

	s.threadID = thread.threadID

	thread.RecordActivity(s.start.Time)
	thread.RecordActivity(s.stop.Time)

	return s, nil
}

// EndBasicSegment ends a basic segment.
func EndBasicSegment(t *TxnData, thread *Thread, start SegmentStartTime, now time.Time, name string) error {
	end, err := endSegment(t, thread, start, now)
	if nil != err {
		return err
	}
	if nil == t.customSegments {
		t.customSegments = make(map[string]*metricData)
	}
	m := metricDataFromDuration(end.duration, end.exclusive)
	if data, ok := t.customSegments[name]; ok {
		data.aggregate(m)
	} else {
		// Use `new` in place of &m so that m is not
		// automatically moved to the heap.
		cpy := new(metricData)
		*cpy = m
		t.customSegments[name] = cpy
	}

	if t.TxnTrace.considerNode(end) {
		attributes := end.attributes.copy()
		t.saveTraceSegment(end, customSegmentMetric(name), attributes, "")
	}

	if evt := end.spanEvent(); evt != nil {
		evt.Name = customSegmentMetric(name)
		evt.Category = spanCategoryGeneric
		t.saveSpanEvent(evt)
	}

	return nil
}

// EndExternalSegment ends an external segment.
func EndExternalSegment(t *TxnData, thread *Thread, start SegmentStartTime, now time.Time, u *url.URL, method string, resp *http.Response, lg logger.Logger) error {
	end, err := endSegment(t, thread, start, now)
	if nil != err {
		return err
	}

	host := HostFromURL(u)
	if "" == host {
		host = "unknown"
	}

	var appData *cat.AppDataHeader
	if resp != nil {
		hdr := HTTPHeaderToAppData(resp.Header)
		appData, err = t.CrossProcess.ParseAppData(hdr)
		if err != nil {
			if lg.DebugEnabled() {
				lg.Debug("failure to parse cross application response header", map[string]interface{}{
					"err":    err.Error(),
					"header": hdr,
				})
			}
		}
	}

	var crossProcessID string
	var transactionName string
	var transactionGUID string
	if appData != nil {
		crossProcessID = appData.CrossProcessID
		transactionName = appData.TransactionName
		transactionGUID = appData.TransactionGUID
	}

	key := externalMetricKey{
		Host:                    host,
		ExternalCrossProcessID:  crossProcessID,
		ExternalTransactionName: transactionName,
	}
	if nil == t.externalSegments {
		t.externalSegments = make(map[externalMetricKey]*metricData)
	}
	t.externalCallCount++
	t.externalDuration += end.duration
	m := metricDataFromDuration(end.duration, end.exclusive)
	if data, ok := t.externalSegments[key]; ok {
		data.aggregate(m)
	} else {
		// Use `new` in place of &m so that m is not
		// automatically moved to the heap.
		cpy := new(metricData)
		*cpy = m
		t.externalSegments[key] = cpy
	}

	if t.TxnTrace.considerNode(end) {
		attributes := end.attributes.copy()
		attributes.addString(spanAttributeHTTPURL, SafeURL(u))
		t.saveTraceSegment(end, externalScopedMetric(key), attributes, transactionGUID)
	}

	if evt := end.spanEvent(); evt != nil {
		evt.Name = externalHostMetric(key)
		evt.Category = spanCategoryHTTP
		evt.Kind = "client"
		evt.Component = "http"
		evt.Attributes.addString(spanAttributeHTTPURL, SafeURL(u))
		evt.Attributes.addString(spanAttributeHTTPMethod, method)
		t.saveSpanEvent(evt)
	}

	return nil
}

// EndDatastoreParams contains the parameters for EndDatastoreSegment.
type EndDatastoreParams struct {
	TxnData            *TxnData
	Thread             *Thread
	Start              SegmentStartTime
	Now                time.Time
	Product            string
	Collection         string
	Operation          string
	ParameterizedQuery string
	QueryParameters    map[string]interface{}
	Host               string
	PortPathOrID       string
	Database           string
}

const (
	unknownDatastoreHost         = "unknown"
	unknownDatastorePortPathOrID = "unknown"
)

var (
	// ThisHost is the system hostname.
	ThisHost = func() string {
		if h, err := sysinfo.Hostname(); nil == err {
			return h
		}
		return unknownDatastoreHost
	}()
	hostsToReplace = map[string]struct{}{
		"localhost":       {},
		"127.0.0.1":       {},
		"0.0.0.0":         {},
		"0:0:0:0:0:0:0:1": {},
		"::1":             {},
		"0:0:0:0:0:0:0:0": {},
		"::":              {},
	}
)

func (t TxnData) slowQueryWorthy(d time.Duration) bool {
	return t.SlowQueriesEnabled && (d >= t.SlowQueryThreshold)
}

func datastoreSpanAddress(host, portPathOrID string) string {
	if "" != host && "" != portPathOrID {
		return host + ":" + portPathOrID
	}
	if "" != host {
		return host
	}
	return portPathOrID
}

// EndDatastoreSegment ends a datastore segment.
func EndDatastoreSegment(p EndDatastoreParams) error {
	end, err := endSegment(p.TxnData, p.Thread, p.Start, p.Now)
	if nil != err {
		return err
	}
	if p.Operation == "" {
		p.Operation = datastoreOperationUnknown
	}
	if p.Product == "" {
		p.Product = datastoreProductUnknown
	}
	if p.Host == "" && p.PortPathOrID != "" {
		p.Host = unknownDatastoreHost
	}
	if p.PortPathOrID == "" && p.Host != "" {
		p.PortPathOrID = unknownDatastorePortPathOrID
	}
	if _, ok := hostsToReplace[p.Host]; ok {
		p.Host = ThisHost
	}

	// We still want to create a slowQuery if the consumer has not provided
	// a Query string (or it has been removed by LASP) since the stack trace
	// has value.
	if p.ParameterizedQuery == "" {
		collection := p.Collection
		if "" == collection {
			collection = "unknown"
		}
		p.ParameterizedQuery = fmt.Sprintf(`'%s' on '%s' using '%s'`,
			p.Operation, collection, p.Product)
	}

	key := DatastoreMetricKey{
		Product:      p.Product,
		Collection:   p.Collection,
		Operation:    p.Operation,
		Host:         p.Host,
		PortPathOrID: p.PortPathOrID,
	}
	if nil == p.TxnData.datastoreSegments {
		p.TxnData.datastoreSegments = make(map[DatastoreMetricKey]*metricData)
	}
	p.TxnData.datastoreCallCount++
	p.TxnData.datastoreDuration += end.duration
	m := metricDataFromDuration(end.duration, end.exclusive)
	if data, ok := p.TxnData.datastoreSegments[key]; ok {
		data.aggregate(m)
	} else {
		// Use `new` in place of &m so that m is not
		// automatically moved to the heap.
		cpy := new(metricData)
		*cpy = m
		p.TxnData.datastoreSegments[key] = cpy
	}

	scopedMetric := datastoreScopedMetric(key)
	// errors in QueryParameters must not stop the recording of the segment
	queryParams, err := vetQueryParameters(p.QueryParameters)

	if p.TxnData.TxnTrace.considerNode(end) {
		attributes := end.attributes.copy()
		attributes.addString(spanAttributeDBStatement, p.ParameterizedQuery)
		attributes.addString(spanAttributeDBInstance, p.Database)
		attributes.addString(spanAttributePeerAddress, datastoreSpanAddress(p.Host, p.PortPathOrID))
		attributes.addString(spanAttributePeerHostname, p.Host)
		if len(queryParams) > 0 {
			attributes.add(spanAttributeQueryParameters, queryParams)
		}
		p.TxnData.saveTraceSegment(end, scopedMetric, attributes, "")
	}

	if p.TxnData.slowQueryWorthy(end.duration) {
		if nil == p.TxnData.SlowQueries {
			p.TxnData.SlowQueries = newSlowQueries(maxTxnSlowQueries)
		}
		p.TxnData.SlowQueries.observeInstance(slowQueryInstance{
			Duration:           end.duration,
			DatastoreMetric:    scopedMetric,
			ParameterizedQuery: p.ParameterizedQuery,
			QueryParameters:    queryParams,
			Host:               p.Host,
			PortPathOrID:       p.PortPathOrID,
			DatabaseName:       p.Database,
			StackTrace:         GetStackTrace(),
		})
	}

	if evt := end.spanEvent(); evt != nil {
		evt.Name = scopedMetric
		evt.Category = spanCategoryDatastore
		evt.Kind = "client"
		evt.Component = p.Product
		evt.Attributes.addString(spanAttributeDBStatement, p.ParameterizedQuery)
		evt.Attributes.addString(spanAttributeDBInstance, p.Database)
		evt.Attributes.addString(spanAttributePeerAddress, datastoreSpanAddress(p.Host, p.PortPathOrID))
		evt.Attributes.addString(spanAttributePeerHostname, p.Host)
		evt.Attributes.addString(spanAttributeDBCollection, p.Collection)
		p.TxnData.saveSpanEvent(evt)
	}

	return err
}

// MergeBreakdownMetrics creates segment metrics.
func MergeBreakdownMetrics(t *TxnData, metrics *metricTable) {
	scope := t.FinalName
	isWeb := t.IsWeb
	// Custom Segment Metrics
	for key, data := range t.customSegments {
		name := customSegmentMetric(key)
		// Unscoped
		metrics.add(name, "", *data, unforced)
		// Scoped
		metrics.add(name, scope, *data, unforced)
	}

	// External Segment Metrics
	for key, data := range t.externalSegments {
		metrics.add(externalRollupMetric.all, "", *data, forced)
		metrics.add(externalRollupMetric.webOrOther(isWeb), "", *data, forced)

		hostMetric := externalHostMetric(key)
		metrics.add(hostMetric, "", *data, unforced)
		if "" != key.ExternalCrossProcessID && "" != key.ExternalTransactionName {
			txnMetric := externalTransactionMetric(key)

			// Unscoped CAT metrics
			metrics.add(externalAppMetric(key), "", *data, unforced)
			metrics.add(txnMetric, "", *data, unforced)

			// Scoped External Metric
			metrics.add(txnMetric, scope, *data, unforced)
		} else {
			// Scoped External Metric
			metrics.add(hostMetric, scope, *data, unforced)
		}
	}

	// Datastore Segment Metrics
	for key, data := range t.datastoreSegments {
		metrics.add(datastoreRollupMetric.all, "", *data, forced)
		metrics.add(datastoreRollupMetric.webOrOther(isWeb), "", *data, forced)

		product := datastoreProductMetric(key)
		metrics.add(product.all, "", *data, forced)
		metrics.add(product.webOrOther(isWeb), "", *data, forced)

		if key.Host != "" && key.PortPathOrID != "" {
			instance := datastoreInstanceMetric(key)
			metrics.add(instance, "", *data, unforced)
		}

		operation := datastoreOperationMetric(key)
		metrics.add(operation, "", *data, unforced)

		if "" != key.Collection {
			statement := datastoreStatementMetric(key)

			metrics.add(statement, "", *data, unforced)
			metrics.add(statement, scope, *data, unforced)
		} else {
			metrics.add(operation, scope, *data, unforced)
		}
	}
}
