package internal

import (
	"bytes"
	"time"
)

// https://source.datanerd.us/agents/agent-specs/blob/master/Span-Events.md

type spanCategory string

const (
	spanCategoryHTTP      spanCategory = "http"
	spanCategoryDatastore              = "datastore"
	spanCategoryGeneric                = "generic"
)

// SpanEvent represents a span event, necessary to support Distributed Tracing.
type SpanEvent struct {
	TraceID       string
	GUID          string
	ParentID      string
	TransactionID string
	Sampled       bool
	Priority      Priority
	Timestamp     time.Time
	Duration      time.Duration
	Name          string
	Category      spanCategory
	Component     string
	Kind          string
	IsEntrypoint  bool
	Attributes    spanAttributeMap
}

// WriteJSON prepares JSON in the format expected by the collector.
func (e *SpanEvent) WriteJSON(buf *bytes.Buffer) {
	w := jsonFieldsWriter{buf: buf}
	buf.WriteByte('[')
	buf.WriteByte('{')
	w.stringField("type", "Span")
	w.stringField("traceId", e.TraceID)
	w.stringField("guid", e.GUID)
	if "" != e.ParentID {
		w.stringField("parentId", e.ParentID)
	}
	w.stringField("transactionId", e.TransactionID)
	w.boolField("sampled", e.Sampled)
	w.writerField("priority", e.Priority)
	w.intField("timestamp", e.Timestamp.UnixNano()/(1000*1000)) // in milliseconds
	w.floatField("duration", e.Duration.Seconds())
	w.stringField("name", e.Name)
	w.stringField("category", string(e.Category))
	if e.IsEntrypoint {
		w.boolField("nr.entryPoint", true)
	}
	if e.Component != "" {
		w.stringField("component", e.Component)
	}
	if e.Kind != "" {
		w.stringField("span.kind", e.Kind)
	}
	buf.WriteByte('}')
	buf.WriteByte(',')
	buf.WriteByte('{')
	// user attributes section is unused
	buf.WriteByte('}')
	buf.WriteByte(',')
	buf.WriteByte('{')

	w = jsonFieldsWriter{buf: buf}
	for key, val := range e.Attributes {
		w.writerField(key.String(), val)
	}

	buf.WriteByte('}')
	buf.WriteByte(']')
}

// MarshalJSON is used for testing.
func (e *SpanEvent) MarshalJSON() ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, 256))

	e.WriteJSON(buf)

	return buf.Bytes(), nil
}

type spanEvents struct {
	events *analyticsEvents
}

func newSpanEvents(max int) *spanEvents {
	return &spanEvents{
		events: newAnalyticsEvents(max),
	}
}

func (events *spanEvents) addEvent(e *SpanEvent, cat *BetterCAT) {
	e.TraceID = cat.TraceID()
	e.TransactionID = cat.ID
	e.Sampled = cat.Sampled
	e.Priority = cat.Priority
	events.addEventPopulated(e)
}

func (events *spanEvents) addEventPopulated(e *SpanEvent) {
	events.events.addEvent(analyticsEvent{priority: e.Priority, jsonWriter: e})
}

// MergeFromTransaction merges the span events from a transaction into the
// harvest's span events.  This should only be called if the transaction was
// sampled and span events are enabled.
func (events *spanEvents) MergeFromTransaction(txndata *TxnData) {
	root := &SpanEvent{
		GUID:         txndata.getRootSpanID(),
		Timestamp:    txndata.Start,
		Duration:     txndata.Duration,
		Name:         txndata.FinalName,
		Category:     spanCategoryGeneric,
		IsEntrypoint: true,
	}
	if nil != txndata.BetterCAT.Inbound {
		root.ParentID = txndata.BetterCAT.Inbound.ID
	}
	events.addEvent(root, &txndata.BetterCAT)

	for _, evt := range txndata.spanEvents {
		events.addEvent(evt, &txndata.BetterCAT)
	}
}

func (events *spanEvents) MergeIntoHarvest(h *Harvest) {
	h.SpanEvents.events.mergeFailed(events.events)
}

func (events *spanEvents) Data(agentRunID string, harvestStart time.Time) ([]byte, error) {
	return events.events.CollectorJSON(agentRunID)
}

func (events *spanEvents) numSeen() float64  { return events.events.NumSeen() }
func (events *spanEvents) numSaved() float64 { return events.events.NumSaved() }

func (events *spanEvents) EndpointMethod() string {
	return cmdSpanEvents
}
