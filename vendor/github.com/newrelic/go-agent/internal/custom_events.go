package internal

import (
	"time"
)

type customEvents struct {
	events *analyticsEvents
}

func newCustomEvents(max int) *customEvents {
	return &customEvents{
		events: newAnalyticsEvents(max),
	}
}

func (cs *customEvents) Add(e *CustomEvent) {
	// For the Go Agent, customEvents are added to the application, not the transaction.
	// As a result, customEvents do not inherit their priority from the transaction, though
	// they are still sampled according to priority sampling.
	priority := NewPriority()
	cs.events.addEvent(analyticsEvent{priority, e})
}

func (cs *customEvents) MergeIntoHarvest(h *Harvest) {
	h.CustomEvents.events.mergeFailed(cs.events)
}

func (cs *customEvents) Data(agentRunID string, harvestStart time.Time) ([]byte, error) {
	return cs.events.CollectorJSON(agentRunID)
}

func (cs *customEvents) numSeen() float64  { return cs.events.NumSeen() }
func (cs *customEvents) numSaved() float64 { return cs.events.NumSaved() }

func (cs *customEvents) EndpointMethod() string {
	return cmdCustomEvents
}
