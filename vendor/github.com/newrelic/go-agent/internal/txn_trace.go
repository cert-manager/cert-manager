package internal

import (
	"bytes"
	"container/heap"
	"sort"
	"time"

	"github.com/newrelic/go-agent/internal/jsonx"
)

// See https://source.datanerd.us/agents/agent-specs/blob/master/Transaction-Trace-LEGACY.md

type traceNodeHeap []traceNode

type traceNodeParams struct {
	attributes              map[SpanAttribute]jsonWriter
	StackTrace              StackTrace
	TransactionGUID         string
	exclusiveDurationMillis *float64
}

type traceNode struct {
	start    segmentTime
	stop     segmentTime
	threadID uint64
	duration time.Duration
	traceNodeParams
	name string
}

func (h traceNodeHeap) Len() int           { return len(h) }
func (h traceNodeHeap) Less(i, j int) bool { return h[i].duration < h[j].duration }
func (h traceNodeHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

// Push and Pop are unused: only heap.Init and heap.Fix are used.
func (h traceNodeHeap) Push(x interface{}) {}
func (h traceNodeHeap) Pop() interface{}   { return nil }

// TxnTrace contains the work in progress transaction trace.
type TxnTrace struct {
	Enabled             bool
	SegmentThreshold    time.Duration
	StackTraceThreshold time.Duration
	nodes               traceNodeHeap
	maxNodes            int
}

// getMaxNodes allows the maximum number of nodes to be overwritten for unit
// tests.
func (trace *TxnTrace) getMaxNodes() int {
	if 0 != trace.maxNodes {
		return trace.maxNodes
	}
	return maxTxnTraceNodes
}

// considerNode exists to prevent unnecessary calls to witnessNode: constructing
// the metric name and params map requires allocations.
func (trace *TxnTrace) considerNode(end segmentEnd) bool {
	return trace.Enabled && (end.duration >= trace.SegmentThreshold)
}

func (trace *TxnTrace) witnessNode(end segmentEnd, name string, attrs spanAttributeMap, externalGUID string) {
	node := traceNode{
		start:    end.start,
		stop:     end.stop,
		duration: end.duration,
		threadID: end.threadID,
		name:     name,
	}
	node.attributes = attrs
	node.TransactionGUID = externalGUID
	if !trace.considerNode(end) {
		return
	}
	if trace.nodes == nil {
		trace.nodes = make(traceNodeHeap, 0, startingTxnTraceNodes)
	}
	if end.exclusive >= trace.StackTraceThreshold {
		node.StackTrace = GetStackTrace()
	}
	if max := trace.getMaxNodes(); len(trace.nodes) < max {
		trace.nodes = append(trace.nodes, node)
		if len(trace.nodes) == max {
			heap.Init(trace.nodes)
		}
		return
	}

	if node.duration <= trace.nodes[0].duration {
		return
	}
	trace.nodes[0] = node
	heap.Fix(trace.nodes, 0)
}

// HarvestTrace contains a finished transaction trace ready for serialization to
// the collector.
type HarvestTrace struct {
	TxnEvent
	Trace TxnTrace
}

type nodeDetails struct {
	name          string
	relativeStart time.Duration
	relativeStop  time.Duration
	traceNodeParams
}

func printNodeStart(buf *bytes.Buffer, n nodeDetails) {
	// time.Seconds() is intentionally not used here.  Millisecond
	// precision is enough.
	relativeStartMillis := n.relativeStart.Nanoseconds() / (1000 * 1000)
	relativeStopMillis := n.relativeStop.Nanoseconds() / (1000 * 1000)

	buf.WriteByte('[')
	jsonx.AppendInt(buf, relativeStartMillis)
	buf.WriteByte(',')
	jsonx.AppendInt(buf, relativeStopMillis)
	buf.WriteByte(',')
	jsonx.AppendString(buf, n.name)
	buf.WriteByte(',')

	w := jsonFieldsWriter{buf: buf}
	buf.WriteByte('{')
	if nil != n.StackTrace {
		w.writerField("backtrace", n.StackTrace)
	}
	if nil != n.exclusiveDurationMillis {
		w.floatField("exclusive_duration_millis", *n.exclusiveDurationMillis)
	}
	if "" != n.TransactionGUID {
		w.stringField("transaction_guid", n.TransactionGUID)
	}
	for k, v := range n.attributes {
		w.writerField(k.String(), v)
	}
	buf.WriteByte('}')

	buf.WriteByte(',')
	buf.WriteByte('[')
}

func printChildren(buf *bytes.Buffer, traceStart time.Time, nodes sortedTraceNodes, next int, stop *segmentStamp, threadID uint64) int {
	firstChild := true
	for {
		if next >= len(nodes) {
			// No more children to print.
			break
		}
		if nodes[next].threadID != threadID {
			// The next node is not of the same thread.  Due to the
			// node sorting, all nodes of the same thread should be
			// together.
			break
		}
		if stop != nil && nodes[next].start.Stamp >= *stop {
			// Make sure this node is a child of the parent that is
			// being printed.
			break
		}
		if firstChild {
			firstChild = false
		} else {
			buf.WriteByte(',')
		}
		printNodeStart(buf, nodeDetails{
			name:            nodes[next].name,
			relativeStart:   nodes[next].start.Time.Sub(traceStart),
			relativeStop:    nodes[next].stop.Time.Sub(traceStart),
			traceNodeParams: nodes[next].traceNodeParams,
		})
		next = printChildren(buf, traceStart, nodes, next+1, &nodes[next].stop.Stamp, threadID)
		buf.WriteString("]]")

	}
	return next
}

type sortedTraceNodes []*traceNode

func (s sortedTraceNodes) Len() int { return len(s) }
func (s sortedTraceNodes) Less(i, j int) bool {
	// threadID is the first sort key and start.Stamp is the second key.
	if s[i].threadID == s[j].threadID {
		return s[i].start.Stamp < s[j].start.Stamp
	}
	return s[i].threadID < s[j].threadID
}
func (s sortedTraceNodes) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// MarshalJSON is used for testing.
//
// TODO: Eliminate this entirely by using harvestTraces.Data().
func (trace *HarvestTrace) MarshalJSON() ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, 100+100*trace.Trace.nodes.Len()))

	trace.writeJSON(buf)

	return buf.Bytes(), nil
}

func (trace *HarvestTrace) writeJSON(buf *bytes.Buffer) {
	nodes := make(sortedTraceNodes, len(trace.Trace.nodes))
	for i := 0; i < len(nodes); i++ {
		nodes[i] = &trace.Trace.nodes[i]
	}
	sort.Sort(nodes)

	buf.WriteByte('[') // begin trace

	jsonx.AppendInt(buf, trace.Start.UnixNano()/1000)
	buf.WriteByte(',')
	jsonx.AppendFloat(buf, trace.Duration.Seconds()*1000.0)
	buf.WriteByte(',')
	jsonx.AppendString(buf, trace.FinalName)
	buf.WriteByte(',')
	if uri, _ := trace.Attrs.GetAgentValue(attributeRequestURI, destTxnTrace); "" != uri {
		jsonx.AppendString(buf, uri)
	} else {
		buf.WriteString("null")
	}
	buf.WriteByte(',')

	buf.WriteByte('[') // begin trace data

	// If the trace string pool is used, insert another array here.

	jsonx.AppendFloat(buf, 0.0) // unused timestamp
	buf.WriteByte(',')          //
	buf.WriteString("{}")       // unused: formerly request parameters
	buf.WriteByte(',')          //
	buf.WriteString("{}")       // unused: formerly custom parameters
	buf.WriteByte(',')          //

	printNodeStart(buf, nodeDetails{ // begin outer root
		name:          "ROOT",
		relativeStart: 0,
		relativeStop:  trace.Duration,
	})

	// exclusive_duration_millis field is added to fix the transaction trace
	// summary tab.  If exclusive_duration_millis is not provided, the UIs
	// will calculate exclusive time, which doesn't work for this root node
	// since all async goroutines are children of this root.
	exclusiveDurationMillis := trace.Duration.Seconds() * 1000.0
	details := nodeDetails{ // begin inner root
		name:          trace.FinalName,
		relativeStart: 0,
		relativeStop:  trace.Duration,
	}
	details.exclusiveDurationMillis = &exclusiveDurationMillis
	printNodeStart(buf, details)

	for next := 0; next < len(nodes); {
		if next > 0 {
			buf.WriteByte(',')
		}
		// We put each thread's nodes into the root node instead of the
		// node that spawned the thread. This approach is simple and
		// works when the segment which spawned a thread has been pruned
		// from the trace.  Each call to printChildren prints one
		// thread.
		next = printChildren(buf, trace.Start, nodes, next, nil, nodes[next].threadID)
	}

	buf.WriteString("]]") // end outer root
	buf.WriteString("]]") // end inner root

	buf.WriteByte(',')
	buf.WriteByte('{')
	buf.WriteString(`"agentAttributes":`)
	agentAttributesJSON(trace.Attrs, buf, destTxnTrace)
	buf.WriteByte(',')
	buf.WriteString(`"userAttributes":`)
	userAttributesJSON(trace.Attrs, buf, destTxnTrace, nil)
	buf.WriteByte(',')
	buf.WriteString(`"intrinsics":`)
	intrinsicsJSON(&trace.TxnEvent, buf)
	buf.WriteByte('}')

	// If the trace string pool is used, end another array here.

	buf.WriteByte(']') // end trace data

	buf.WriteByte(',')
	if trace.CrossProcess.Used() && trace.CrossProcess.GUID != "" {
		jsonx.AppendString(buf, trace.CrossProcess.GUID)
	} else {
		buf.WriteString(`""`)
	}
	buf.WriteByte(',')       //
	buf.WriteString(`null`)  // reserved for future use
	buf.WriteByte(',')       //
	buf.WriteString(`false`) // ForcePersist is not yet supported
	buf.WriteByte(',')       //
	buf.WriteString(`null`)  // X-Ray sessions not supported
	buf.WriteByte(',')       //

	// Synthetics are supported:
	if trace.CrossProcess.IsSynthetics() {
		jsonx.AppendString(buf, trace.CrossProcess.Synthetics.ResourceID)
	} else {
		buf.WriteString(`""`)
	}

	buf.WriteByte(']') // end trace
}

type txnTraceHeap []*HarvestTrace

func (h *txnTraceHeap) isEmpty() bool {
	return 0 == len(*h)
}

func newTxnTraceHeap(max int) *txnTraceHeap {
	h := make(txnTraceHeap, 0, max)
	heap.Init(&h)
	return &h
}

// Implement sort.Interface.
func (h txnTraceHeap) Len() int           { return len(h) }
func (h txnTraceHeap) Less(i, j int) bool { return h[i].Duration < h[j].Duration }
func (h txnTraceHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

// Implement heap.Interface.
func (h *txnTraceHeap) Push(x interface{}) { *h = append(*h, x.(*HarvestTrace)) }

func (h *txnTraceHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

func (h *txnTraceHeap) isKeeper(t *HarvestTrace) bool {
	if len(*h) < cap(*h) {
		return true
	}
	return t.Duration >= (*h)[0].Duration
}

func (h *txnTraceHeap) addTxnTrace(t *HarvestTrace) {
	if len(*h) < cap(*h) {
		heap.Push(h, t)
		return
	}

	if t.Duration <= (*h)[0].Duration {
		return
	}
	heap.Pop(h)
	heap.Push(h, t)
}

type harvestTraces struct {
	regular    *txnTraceHeap
	synthetics *txnTraceHeap
}

func newHarvestTraces() *harvestTraces {
	return &harvestTraces{
		regular:    newTxnTraceHeap(maxRegularTraces),
		synthetics: newTxnTraceHeap(maxSyntheticsTraces),
	}
}

func (traces *harvestTraces) Len() int {
	return traces.regular.Len() + traces.synthetics.Len()
}

func (traces *harvestTraces) Witness(trace HarvestTrace) {
	traceHeap := traces.regular
	if trace.CrossProcess.IsSynthetics() {
		traceHeap = traces.synthetics
	}

	if traceHeap.isKeeper(&trace) {
		cpy := new(HarvestTrace)
		*cpy = trace
		traceHeap.addTxnTrace(cpy)
	}
}

func (traces *harvestTraces) Data(agentRunID string, harvestStart time.Time) ([]byte, error) {
	if traces.Len() == 0 {
		return nil, nil
	}

	// This estimate is used to guess the size of the buffer.  No worries if
	// the estimate is small since the buffer will be lengthened as
	// necessary.  This is just about minimizing reallocations.
	estimate := 512
	for _, t := range *traces.regular {
		estimate += 100 * t.Trace.nodes.Len()
	}
	for _, t := range *traces.synthetics {
		estimate += 100 * t.Trace.nodes.Len()
	}

	buf := bytes.NewBuffer(make([]byte, 0, estimate))
	buf.WriteByte('[')
	jsonx.AppendString(buf, agentRunID)
	buf.WriteByte(',')
	buf.WriteByte('[')

	// use a function to add traces to the buffer to avoid duplicating comma
	// logic in both loops
	firstTrace := true
	addTrace := func(trace *HarvestTrace) {
		if firstTrace {
			firstTrace = false
		} else {
			buf.WriteByte(',')
		}
		trace.writeJSON(buf)
	}

	for _, trace := range *traces.regular {
		addTrace(trace)
	}
	for _, trace := range *traces.synthetics {
		addTrace(trace)
	}
	buf.WriteByte(']')
	buf.WriteByte(']')

	return buf.Bytes(), nil
}

func (traces *harvestTraces) slice() []*HarvestTrace {
	out := make([]*HarvestTrace, 0, traces.Len())
	out = append(out, (*traces.regular)...)
	out = append(out, (*traces.synthetics)...)

	return out
}

func (traces *harvestTraces) MergeIntoHarvest(h *Harvest) {}

func (traces *harvestTraces) EndpointMethod() string {
	return cmdTxnTraces
}
