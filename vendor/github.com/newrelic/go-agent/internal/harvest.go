package internal

import (
	"strings"
	"sync"
	"time"
)

// Harvestable is something that can be merged into a Harvest.
type Harvestable interface {
	MergeIntoHarvest(h *Harvest)
}

type harvestTimer struct {
	lastHarvest time.Time
	period      time.Duration
}

func newHarvestTimer(now time.Time, period time.Duration) harvestTimer {
	return harvestTimer{
		lastHarvest: now,
		period:      period,
	}
}

func (timer *harvestTimer) ready(now time.Time) bool {
	deadline := timer.lastHarvest.Add(timer.period)
	if now.After(deadline) {
		timer.lastHarvest = deadline
		return true
	}
	return false
}

// Harvest contains collected data.
type Harvest struct {
	configurableHarvestTimer harvestTimer
	fixedHarvestTimer        harvestTimer

	// fixedHarvest and configurableHarvest are non-nil in the main Harvest
	// used in app.process(), but may be nil in the Harvest returned by
	// Harvest.Ready().
	*fixedHarvest
	*configurableHarvest
}

type fixedHarvest struct {
	Metrics     *metricTable
	ErrorTraces harvestErrors
	TxnTraces   *harvestTraces
	SlowSQLs    *slowQueries
	SpanEvents  *spanEvents
}

type configurableHarvest struct {
	CustomEvents *customEvents
	TxnEvents    *txnEvents
	ErrorEvents  *errorEvents
}

const (
	// txnEventPayloadlimit is the maximum number of events that should be
	// sent up in one post.
	txnEventPayloadlimit = 5000
)

// Ready returns a new Harvest which contains the data types ready for harvest,
// or nil if no data is ready for harvest.
func (h *Harvest) Ready(now time.Time, reply *ConnectReply) *Harvest {
	ready := &Harvest{}

	if h.configurableHarvestTimer.ready(now) {
		h.Metrics.addCount(customEventsSeen, h.CustomEvents.numSeen(), forced)
		h.Metrics.addCount(customEventsSent, h.CustomEvents.numSaved(), forced)

		h.Metrics.addCount(txnEventsSeen, h.TxnEvents.numSeen(), forced)
		h.Metrics.addCount(txnEventsSent, h.TxnEvents.numSaved(), forced)

		h.Metrics.addCount(errorEventsSeen, h.ErrorEvents.numSeen(), forced)
		h.Metrics.addCount(errorEventsSent, h.ErrorEvents.numSaved(), forced)

		ready.configurableHarvest = h.configurableHarvest
		h.configurableHarvest = newConfigurableHarvest(now, reply)
	}

	// NOTE!  This must happen after the configurable harvest conditional to
	// ensure that the metrics contain the event supportability metrics.
	if h.fixedHarvestTimer.ready(now) {
		h.Metrics.addCount(spanEventsSeen, h.SpanEvents.numSeen(), forced)
		h.Metrics.addCount(spanEventsSent, h.SpanEvents.numSaved(), forced)

		ready.fixedHarvest = h.fixedHarvest
		h.fixedHarvest = newFixedHarvest(now)
	}

	if nil == ready.fixedHarvest && nil == ready.configurableHarvest {
		return nil
	}
	return ready
}

func (h *configurableHarvest) payloads(splitLargeTxnEvents bool) []PayloadCreator {
	if nil == h {
		return nil
	}
	ps := []PayloadCreator{
		h.CustomEvents,
		h.ErrorEvents,
	}
	if splitLargeTxnEvents {
		ps = append(ps, h.TxnEvents.payloads(txnEventPayloadlimit)...)
	} else {
		ps = append(ps, h.TxnEvents)
	}
	return ps
}

func (h *fixedHarvest) payloads() []PayloadCreator {
	if nil == h {
		return nil
	}
	return []PayloadCreator{
		h.Metrics,
		h.ErrorTraces,
		h.TxnTraces,
		h.SlowSQLs,
		h.SpanEvents,
	}
}

// Payloads returns a map from expected collector method name to data type.
func (h *Harvest) Payloads(splitLargeTxnEvents bool) []PayloadCreator {
	if nil == h {
		return nil
	}
	var ps []PayloadCreator
	ps = append(ps, h.configurableHarvest.payloads(splitLargeTxnEvents)...)
	ps = append(ps, h.fixedHarvest.payloads()...)
	return ps
}

func newFixedHarvest(now time.Time) *fixedHarvest {
	return &fixedHarvest{
		Metrics:     newMetricTable(maxMetrics, now),
		ErrorTraces: newHarvestErrors(maxHarvestErrors),
		TxnTraces:   newHarvestTraces(),
		SlowSQLs:    newSlowQueries(maxHarvestSlowSQLs),
		SpanEvents:  newSpanEvents(maxSpanEvents),
	}
}

func newConfigurableHarvest(now time.Time, reply *ConnectReply) *configurableHarvest {
	harvestData := reply.getHarvestData()
	return &configurableHarvest{
		CustomEvents: newCustomEvents(harvestData.HarvestLimits.CustomEvents),
		TxnEvents:    newTxnEvents(harvestData.HarvestLimits.TxnEvents),
		ErrorEvents:  newErrorEvents(harvestData.HarvestLimits.ErrorEvents),
	}
}

// NewHarvest returns a new Harvest.
func NewHarvest(now time.Time, reply *ConnectReply) *Harvest {
	harvestData := reply.getHarvestData()
	return &Harvest{
		configurableHarvestTimer: newHarvestTimer(now, harvestData.eventReportPeriod()),
		fixedHarvestTimer:        newHarvestTimer(now, fixedHarvestPeriod),

		configurableHarvest: newConfigurableHarvest(now, reply),
		fixedHarvest:        newFixedHarvest(now),
	}
}

var (
	trackMutex   sync.Mutex
	trackMetrics []string
)

// TrackUsage helps track which integration packages are used.
func TrackUsage(s ...string) {
	trackMutex.Lock()
	defer trackMutex.Unlock()

	m := "Supportability/" + strings.Join(s, "/")
	trackMetrics = append(trackMetrics, m)
}

func createTrackUsageMetrics(metrics *metricTable) {
	trackMutex.Lock()
	defer trackMutex.Unlock()

	for _, m := range trackMetrics {
		metrics.addSingleCount(m, forced)
	}
}

// CreateFinalMetrics creates extra metrics at harvest time.
func (h *fixedHarvest) CreateFinalMetrics(rules metricRules) {
	if nil == h {
		return
	}

	h.Metrics.addSingleCount(instanceReporting, forced)

	createTrackUsageMetrics(h.Metrics)

	h.Metrics = h.Metrics.ApplyRules(rules)
}

// PayloadCreator is a data type in the harvest.
type PayloadCreator interface {
	// In the event of a rpm request failure (hopefully simply an
	// intermittent collector issue) the payload may be merged into the next
	// time period's harvest.
	Harvestable
	// Data prepares JSON in the format expected by the collector endpoint.
	// This method should return (nil, nil) if the payload is empty and no
	// rpm request is necessary.
	Data(agentRunID string, harvestStart time.Time) ([]byte, error)
	// EndpointMethod is used for the "method" query parameter when posting
	// the data.
	EndpointMethod() string
}

func supportMetric(metrics *metricTable, b bool, metricName string) {
	if b {
		metrics.addSingleCount(metricName, forced)
	}
}

// CreateTxnMetrics creates metrics for a transaction.
func CreateTxnMetrics(args *TxnData, metrics *metricTable) {
	withoutFirstSegment := removeFirstSegment(args.FinalName)

	// Duration Metrics
	var durationRollup string
	var totalTimeRollup string
	if args.IsWeb {
		durationRollup = webRollup
		totalTimeRollup = totalTimeWeb
		metrics.addDuration(dispatcherMetric, "", args.Duration, 0, forced)
	} else {
		durationRollup = backgroundRollup
		totalTimeRollup = totalTimeBackground
	}

	metrics.addDuration(args.FinalName, "", args.Duration, 0, forced)
	metrics.addDuration(durationRollup, "", args.Duration, 0, forced)

	metrics.addDuration(totalTimeRollup, "", args.TotalTime, args.TotalTime, forced)
	metrics.addDuration(totalTimeRollup+"/"+withoutFirstSegment, "", args.TotalTime, args.TotalTime, unforced)

	// Better CAT Metrics
	if cat := args.BetterCAT; cat.Enabled {
		caller := callerUnknown
		if nil != cat.Inbound {
			caller = cat.Inbound.payloadCaller
		}
		m := durationByCallerMetric(caller)
		metrics.addDuration(m.all, "", args.Duration, args.Duration, unforced)
		metrics.addDuration(m.webOrOther(args.IsWeb), "", args.Duration, args.Duration, unforced)

		// Transport Duration Metric
		if nil != cat.Inbound {
			d := cat.Inbound.TransportDuration
			m = transportDurationMetric(caller)
			metrics.addDuration(m.all, "", d, d, unforced)
			metrics.addDuration(m.webOrOther(args.IsWeb), "", d, d, unforced)
		}

		// CAT Error Metrics
		if args.HasErrors() {
			m = errorsByCallerMetric(caller)
			metrics.addSingleCount(m.all, unforced)
			metrics.addSingleCount(m.webOrOther(args.IsWeb), unforced)
		}

		supportMetric(metrics, args.AcceptPayloadSuccess, supportTracingAcceptSuccess)
		supportMetric(metrics, args.AcceptPayloadException, supportTracingAcceptException)
		supportMetric(metrics, args.AcceptPayloadParseException, supportTracingAcceptParseException)
		supportMetric(metrics, args.AcceptPayloadCreateBeforeAccept, supportTracingCreateBeforeAccept)
		supportMetric(metrics, args.AcceptPayloadIgnoredMultiple, supportTracingIgnoredMultiple)
		supportMetric(metrics, args.AcceptPayloadIgnoredVersion, supportTracingIgnoredVersion)
		supportMetric(metrics, args.AcceptPayloadUntrustedAccount, supportTracingAcceptUntrustedAccount)
		supportMetric(metrics, args.AcceptPayloadNullPayload, supportTracingAcceptNull)
		supportMetric(metrics, args.CreatePayloadSuccess, supportTracingCreatePayloadSuccess)
		supportMetric(metrics, args.CreatePayloadException, supportTracingCreatePayloadException)
	}

	// Apdex Metrics
	if args.Zone != ApdexNone {
		metrics.addApdex(apdexRollup, "", args.ApdexThreshold, args.Zone, forced)

		mname := apdexPrefix + withoutFirstSegment
		metrics.addApdex(mname, "", args.ApdexThreshold, args.Zone, unforced)
	}

	// Error Metrics
	if args.HasErrors() {
		metrics.addSingleCount(errorsRollupMetric.all, forced)
		metrics.addSingleCount(errorsRollupMetric.webOrOther(args.IsWeb), forced)
		metrics.addSingleCount(errorsPrefix+args.FinalName, forced)
	}

	// Queueing Metrics
	if args.Queuing > 0 {
		metrics.addDuration(queueMetric, "", args.Queuing, args.Queuing, forced)
	}
}
