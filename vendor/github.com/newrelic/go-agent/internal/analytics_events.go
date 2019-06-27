package internal

import (
	"bytes"
	"container/heap"

	"github.com/newrelic/go-agent/internal/jsonx"
)

type analyticsEvent struct {
	priority Priority
	jsonWriter
}

type analyticsEventHeap []analyticsEvent

type analyticsEvents struct {
	numSeen        int
	events         analyticsEventHeap
	failedHarvests int
}

func (events *analyticsEvents) NumSeen() float64  { return float64(events.numSeen) }
func (events *analyticsEvents) NumSaved() float64 { return float64(len(events.events)) }

func (h analyticsEventHeap) Len() int           { return len(h) }
func (h analyticsEventHeap) Less(i, j int) bool { return h[i].priority.isLowerPriority(h[j].priority) }
func (h analyticsEventHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

// Push and Pop are unused: only heap.Init and heap.Fix are used.
func (h analyticsEventHeap) Push(x interface{}) {}
func (h analyticsEventHeap) Pop() interface{}   { return nil }

func newAnalyticsEvents(max int) *analyticsEvents {
	return &analyticsEvents{
		numSeen:        0,
		events:         make(analyticsEventHeap, 0, max),
		failedHarvests: 0,
	}
}

func (events *analyticsEvents) addEvent(e analyticsEvent) {
	events.numSeen++

	if len(events.events) < cap(events.events) {
		events.events = append(events.events, e)
		if len(events.events) == cap(events.events) {
			// Delay heap initialization so that we can have
			// deterministic ordering for integration tests (the max
			// is not being reached).
			heap.Init(events.events)
		}
		return
	}

	if e.priority.isLowerPriority((events.events)[0].priority) {
		return
	}

	events.events[0] = e
	heap.Fix(events.events, 0)
}

func (events *analyticsEvents) mergeFailed(other *analyticsEvents) {
	fails := other.failedHarvests + 1
	if fails >= failedEventsAttemptsLimit {
		return
	}
	events.failedHarvests = fails
	events.Merge(other)
}

func (events *analyticsEvents) Merge(other *analyticsEvents) {
	allSeen := events.numSeen + other.numSeen

	for _, e := range other.events {
		events.addEvent(e)
	}
	events.numSeen = allSeen
}

func (events *analyticsEvents) CollectorJSON(agentRunID string) ([]byte, error) {
	if 0 == events.numSeen {
		return nil, nil
	}

	estimate := 256 * len(events.events)
	buf := bytes.NewBuffer(make([]byte, 0, estimate))

	buf.WriteByte('[')
	jsonx.AppendString(buf, agentRunID)
	buf.WriteByte(',')
	buf.WriteByte('{')
	buf.WriteString(`"reservoir_size":`)
	jsonx.AppendUint(buf, uint64(cap(events.events)))
	buf.WriteByte(',')
	buf.WriteString(`"events_seen":`)
	jsonx.AppendUint(buf, uint64(events.numSeen))
	buf.WriteByte('}')
	buf.WriteByte(',')
	buf.WriteByte('[')
	for i, e := range events.events {
		if i > 0 {
			buf.WriteByte(',')
		}
		e.WriteJSON(buf)
	}
	buf.WriteByte(']')
	buf.WriteByte(']')

	return buf.Bytes(), nil

}

// split splits the events into two.  NOTE! The two event pools are not valid
// priority queues, and should only be used to create JSON, not for adding any
// events.
func (events *analyticsEvents) split() (*analyticsEvents, *analyticsEvents) {
	// numSeen is conserved: e1.numSeen + e2.numSeen == events.numSeen.
	e1 := &analyticsEvents{
		numSeen:        len(events.events) / 2,
		events:         make([]analyticsEvent, len(events.events)/2),
		failedHarvests: events.failedHarvests,
	}
	e2 := &analyticsEvents{
		numSeen:        events.numSeen - e1.numSeen,
		events:         make([]analyticsEvent, len(events.events)-len(e1.events)),
		failedHarvests: events.failedHarvests,
	}
	// Note that slicing is not used to ensure that length == capacity for
	// e1.events and e2.events.
	copy(e1.events, events.events)
	copy(e2.events, events.events[len(events.events)/2:])

	return e1, e2
}
