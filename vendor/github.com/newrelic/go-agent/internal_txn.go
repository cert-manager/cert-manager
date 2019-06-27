package newrelic

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/newrelic/go-agent/internal"
)

type txnInput struct {
	// This ResponseWriter should only be accessed using txn.getWriter()
	writer   http.ResponseWriter
	app      Application
	Consumer dataConsumer
	*appRun
}

type txn struct {
	txnInput
	// This mutex is required since the consumer may call the public API
	// interface functions from different routines.
	sync.Mutex
	// finished indicates whether or not End() has been called.  After
	// finished has been set to true, no recording should occur.
	finished           bool
	numPayloadsCreated uint32
	sampledCalculated  bool

	ignore bool

	// wroteHeader prevents capturing multiple response code errors if the
	// user erroneously calls WriteHeader multiple times.
	wroteHeader bool

	internal.TxnData

	mainThread   internal.Thread
	asyncThreads []*internal.Thread
}

type thread struct {
	*txn
	// thread does not have locking because it should only be accessed while
	// the txn is locked.
	thread *internal.Thread
}

func (txn *txn) markStart(now time.Time) {
	txn.Start = now
	// The mainThread is considered active now.
	txn.mainThread.RecordActivity(now)

}

func (txn *txn) markEnd(now time.Time, thread *internal.Thread) {
	txn.Stop = now
	// The thread on which End() was called is considered active now.
	thread.RecordActivity(now)
	txn.Duration = txn.Stop.Sub(txn.Start)

	// TotalTime is the sum of "active time" across all threads.  A thread
	// was active when it started the transaction, stopped the transaction,
	// started a segment, or stopped a segment.
	txn.TotalTime = txn.mainThread.TotalTime()
	for _, thd := range txn.asyncThreads {
		txn.TotalTime += thd.TotalTime()
	}
	// Ensure that TotalTime is at least as large as Duration so that the
	// graphs look sensible.  This can happen under the following situation:
	// goroutine1: txn.start----|segment1|
	// goroutine2:                                   |segment2|----txn.end
	if txn.Duration > txn.TotalTime {
		txn.TotalTime = txn.Duration
	}
}

func newTxn(input txnInput, name string) *thread {
	txn := &txn{
		txnInput: input,
	}
	txn.markStart(time.Now())

	txn.Name = name
	txn.Attrs = internal.NewAttributes(input.AttributeConfig)

	if input.Config.DistributedTracer.Enabled {
		txn.BetterCAT.Enabled = true
		txn.BetterCAT.Priority = internal.NewPriority()
		txn.BetterCAT.ID = internal.NewSpanID()
		txn.SpanEventsEnabled = txn.Config.SpanEvents.Enabled
		txn.LazilyCalculateSampled = txn.lazilyCalculateSampled
	}

	txn.Attrs.Agent.Add(internal.AttributeHostDisplayName, txn.Config.HostDisplayName, nil)
	txn.TxnTrace.Enabled = txn.Config.TransactionTracer.Enabled
	txn.TxnTrace.SegmentThreshold = txn.Config.TransactionTracer.SegmentThreshold
	txn.StackTraceThreshold = txn.Config.TransactionTracer.StackTraceThreshold
	txn.SlowQueriesEnabled = txn.Config.DatastoreTracer.SlowQuery.Enabled
	txn.SlowQueryThreshold = txn.Config.DatastoreTracer.SlowQuery.Threshold

	// Synthetics support is tied up with a transaction's Old CAT field,
	// CrossProcess. To support Synthetics with either BetterCAT or Old CAT,
	// Initialize the CrossProcess field of the transaction, passing in
	// the top-level configuration.
	doOldCAT := txn.Config.CrossApplicationTracer.Enabled
	noGUID := txn.Config.DistributedTracer.Enabled
	txn.CrossProcess.Init(doOldCAT, noGUID, input.Reply)

	return &thread{
		txn:    txn,
		thread: &txn.mainThread,
	}
}

// lazilyCalculateSampled calculates and returns whether or not the transaction
// should be sampled.  Sampled is not computed at the beginning of the
// transaction because we want to calculate Sampled only for transactions that
// do not accept an inbound payload.
func (txn *txn) lazilyCalculateSampled() bool {
	if !txn.BetterCAT.Enabled {
		return false
	}
	if txn.sampledCalculated {
		return txn.BetterCAT.Sampled
	}
	txn.BetterCAT.Sampled = txn.Reply.AdaptiveSampler.ComputeSampled(txn.BetterCAT.Priority.Float32(), time.Now())
	if txn.BetterCAT.Sampled {
		txn.BetterCAT.Priority += 1.0
	}
	txn.sampledCalculated = true
	return txn.BetterCAT.Sampled
}

type requestWrap struct{ request *http.Request }

func (r requestWrap) Header() http.Header { return r.request.Header }
func (r requestWrap) URL() *url.URL       { return r.request.URL }
func (r requestWrap) Method() string      { return r.request.Method }

func (r requestWrap) Transport() TransportType {
	if strings.HasPrefix(r.request.Proto, "HTTP") {
		if r.request.TLS != nil {
			return TransportHTTPS
		}
		return TransportHTTP
	}
	return TransportUnknown

}

func (txn *txn) SetWebRequest(r WebRequest) error {
	txn.Lock()
	defer txn.Unlock()

	if txn.finished {
		return errAlreadyEnded
	}

	// Any call to SetWebRequest should indicate a web transaction.
	txn.IsWeb = true

	if nil == r {
		return nil
	}
	h := r.Header()
	if nil != h {
		txn.Queuing = internal.QueueDuration(h, txn.Start)

		if p := h.Get(DistributedTracePayloadHeader); p != "" {
			txn.acceptDistributedTracePayloadLocked(r.Transport(), p)
		}

		txn.CrossProcess.InboundHTTPRequest(h)
	}

	internal.RequestAgentAttributes(txn.Attrs, r.Method(), h, r.URL())

	return nil
}

func (thd *thread) SetWebResponse(w http.ResponseWriter) Transaction {
	txn := thd.txn
	txn.Lock()
	defer txn.Unlock()

	// Replace the ResponseWriter even if the transaction has ended so that
	// consumers calling ResponseWriter methods on the transactions see that
	// data flowing through as expected.
	txn.writer = w

	return upgradeTxn(&thread{
		thread: thd.thread,
		txn:    txn,
	})
}

func (txn *txn) freezeName() {
	if txn.ignore || ("" != txn.FinalName) {
		return
	}

	txn.FinalName = internal.CreateFullTxnName(txn.Name, txn.Reply, txn.IsWeb)
	if "" == txn.FinalName {
		txn.ignore = true
	}
}

func (txn *txn) getsApdex() bool {
	return txn.IsWeb
}

func (txn *txn) shouldSaveTrace() bool {
	if !txn.Config.TransactionTracer.Enabled {
		return false
	}
	if txn.CrossProcess.IsSynthetics() {
		return true
	}
	return txn.Duration >= txn.txnTraceThreshold(txn.ApdexThreshold)
}

func (txn *txn) MergeIntoHarvest(h *internal.Harvest) {

	var priority internal.Priority
	if txn.BetterCAT.Enabled {
		priority = txn.BetterCAT.Priority
	} else {
		priority = internal.NewPriority()
	}

	internal.CreateTxnMetrics(&txn.TxnData, h.Metrics)
	internal.MergeBreakdownMetrics(&txn.TxnData, h.Metrics)

	if txn.Config.TransactionEvents.Enabled {
		// Allocate a new TxnEvent to prevent a reference to the large transaction.
		alloc := new(internal.TxnEvent)
		*alloc = txn.TxnData.TxnEvent
		h.TxnEvents.AddTxnEvent(alloc, priority)
	}

	if txn.Reply.CollectErrors {
		internal.MergeTxnErrors(&h.ErrorTraces, txn.Errors, txn.TxnEvent)
	}

	if txn.Config.ErrorCollector.CaptureEvents {
		for _, e := range txn.Errors {
			errEvent := &internal.ErrorEvent{
				ErrorData: *e,
				TxnEvent:  txn.TxnEvent,
			}
			// Since the stack trace is not used in error events, remove the reference
			// to minimize memory.
			errEvent.Stack = nil
			h.ErrorEvents.Add(errEvent, priority)
		}
	}

	if txn.shouldSaveTrace() {
		h.TxnTraces.Witness(internal.HarvestTrace{
			TxnEvent: txn.TxnEvent,
			Trace:    txn.TxnTrace,
		})
	}

	if nil != txn.SlowQueries {
		h.SlowSQLs.Merge(txn.SlowQueries, txn.TxnEvent)
	}

	if txn.BetterCAT.Sampled && txn.SpanEventsEnabled {
		h.SpanEvents.MergeFromTransaction(&txn.TxnData)
	}
}

func headersJustWritten(txn *txn, code int, hdr http.Header) {
	txn.Lock()
	defer txn.Unlock()

	if txn.finished {
		return
	}
	if txn.wroteHeader {
		return
	}
	txn.wroteHeader = true

	internal.ResponseHeaderAttributes(txn.Attrs, hdr)
	internal.ResponseCodeAttribute(txn.Attrs, code)

	if txn.appRun.responseCodeIsError(code) {
		e := internal.TxnErrorFromResponseCode(time.Now(), code)
		e.Stack = internal.GetStackTrace()
		txn.noticeErrorInternal(e)
	}
}

func (txn *txn) responseHeader(hdr http.Header) http.Header {
	txn.Lock()
	defer txn.Unlock()

	if txn.finished {
		return nil
	}
	if txn.wroteHeader {
		return nil
	}
	if !txn.CrossProcess.Enabled {
		return nil
	}
	if !txn.CrossProcess.IsInbound() {
		return nil
	}
	txn.freezeName()
	contentLength := internal.GetContentLengthFromHeader(hdr)

	appData, err := txn.CrossProcess.CreateAppData(txn.FinalName, txn.Queuing, time.Since(txn.Start), contentLength)
	if err != nil {
		txn.Config.Logger.Debug("error generating outbound response header", map[string]interface{}{
			"error": err,
		})
		return nil
	}
	return internal.AppDataToHTTPHeader(appData)
}

func addCrossProcessHeaders(txn *txn, hdr http.Header) {
	// responseHeader() checks the wroteHeader field and returns a nil map if the
	// header has been written, so we don't need a check here.
	if nil != hdr {
		for key, values := range txn.responseHeader(hdr) {
			for _, value := range values {
				hdr.Add(key, value)
			}
		}
	}
}

// getWriter is used to access the transaction's ResponseWriter. The
// ResponseWriter is mutex protected since it may be changed with
// txn.SetWebResponse, and we want changes to be visible across goroutines.  The
// ResponseWriter is accessed using this getWriter() function rather than directly
// in mutex protected methods since we do NOT want the transaction to be locked
// while calling the ResponseWriter's methods.
func (txn *txn) getWriter() http.ResponseWriter {
	txn.Lock()
	rw := txn.writer
	txn.Unlock()
	return rw
}

func nilSafeHeader(rw http.ResponseWriter) http.Header {
	if nil == rw {
		return nil
	}
	return rw.Header()
}

func (txn *txn) Header() http.Header {
	return nilSafeHeader(txn.getWriter())
}

func (txn *txn) Write(b []byte) (n int, err error) {
	rw := txn.getWriter()
	hdr := nilSafeHeader(rw)

	// This is safe to call unconditionally, even if Write() is called multiple
	// times; see also the commentary in addCrossProcessHeaders().
	addCrossProcessHeaders(txn, hdr)

	if rw != nil {
		n, err = rw.Write(b)
	}

	headersJustWritten(txn, http.StatusOK, hdr)

	return
}

func (txn *txn) WriteHeader(code int) {
	rw := txn.getWriter()
	hdr := nilSafeHeader(rw)

	addCrossProcessHeaders(txn, hdr)

	if nil != rw {
		rw.WriteHeader(code)
	}

	headersJustWritten(txn, code, hdr)
}

const (
	lambdaMetadataVersion = 2
)

func (txn *txn) serverlessDataJSON() ([]byte, error) {
	harvest := internal.NewHarvest(txn.Start, nil)
	txn.MergeIntoHarvest(harvest)
	payloads := harvest.Payloads(false)
	harvestPayloads := make(map[string]json.RawMessage, len(payloads))
	for _, p := range payloads {
		agentRunID := ""
		cmd := p.EndpointMethod()
		data, err := p.Data(agentRunID, txn.Stop)
		if err != nil {
			txn.Config.Logger.Error("error creating payload json", map[string]interface{}{
				"command": cmd,
				"error":   err.Error(),
			})
			continue
		}
		if nil == data {
			continue
		}
		// NOTE!  This code relies on the fact that each payload is
		// using a different endpoint method.  Sometimes the transaction
		// events payload might be split, but since there is only one
		// transaction event per serverless transaction, that's not an
		// issue.  Likewise, if we ever split normal transaction events
		// apart from synthetics events, the transaction will either be
		// normal or synthetic, so that won't be an issue.  Log an error
		// if this happens for future defensiveness.
		if _, ok := harvestPayloads[cmd]; ok {
			txn.Config.Logger.Error("data with duplicate command name lost", map[string]interface{}{
				"command": cmd,
			})
		}
		harvestPayloads[cmd] = json.RawMessage(data)
	}

	return json.Marshal(harvestPayloads)
}

func (txn *txn) serverlessJSON(executionEnv string) ([]byte, error) {
	data, err := txn.serverlessDataJSON()
	if nil != err {
		return nil, err
	}

	var dataBuf bytes.Buffer
	gz := gzip.NewWriter(&dataBuf)
	gz.Write(data)
	gz.Flush()
	gz.Close()

	arn, _ := txn.Attrs.GetAgentValue(internal.AttributeAWSLambdaARN, internal.DestAll)
	return json.Marshal([]interface{}{
		lambdaMetadataVersion,
		"NR_LAMBDA_MONITORING",
		struct {
			MetadataVersion      int    `json:"metadata_version"`
			ARN                  string `json:"arn,omitempty"`
			ProtocolVersion      int    `json:"protocol_version"`
			ExecutionEnvironment string `json:"execution_environment,omitempty"`
			AgentVersion         string `json:"agent_version"`
			AgentLanguage        string `json:"agent_language"`
		}{
			MetadataVersion:      lambdaMetadataVersion,
			ProtocolVersion:      internal.ProcotolVersion,
			AgentVersion:         Version,
			ExecutionEnvironment: executionEnv,
			ARN:                  arn,
			AgentLanguage:        agentLanguage,
		},
		base64.StdEncoding.EncodeToString(dataBuf.Bytes()),
	})
}

var (
	_ serverlessTransaction = &txn{}
)

type serverlessTransaction interface {
	// serverlessJSON creates the Lambda JSON that will be printed to stdout
	// by serverlessDump.  It is exposed through this interface to
	// facilitate testing.
	serverlessJSON(executionEnv string) ([]byte, error)
	// serverlessDump writes the Lambda JSON to stdout.
	serverlessDump()
}

func (txn *txn) serverlessDump() {
	js, err := txn.serverlessJSON(os.Getenv("AWS_EXECUTION_ENV"))
	if err != nil {
		txn.Config.Logger.Error("error creating serverless json", map[string]interface{}{
			"error": err.Error(),
		})
	} else {
		fmt.Println(string(js))
	}
}

func (thd *thread) End() error {
	txn := thd.txn
	txn.Lock()
	defer txn.Unlock()

	if txn.finished {
		return errAlreadyEnded
	}

	txn.finished = true

	r := recover()
	if nil != r {
		e := internal.TxnErrorFromPanic(time.Now(), r)
		e.Stack = internal.GetStackTrace()
		txn.noticeErrorInternal(e)
	}

	txn.markEnd(time.Now(), thd.thread)
	txn.freezeName()
	// Make a sampling decision if there have been no segments or outbound
	// payloads.
	txn.lazilyCalculateSampled()

	// Finalise the CAT state.
	if err := txn.CrossProcess.Finalise(txn.Name, txn.Config.AppName); err != nil {
		txn.Config.Logger.Debug("error finalising the cross process state", map[string]interface{}{
			"error": err,
		})
	}

	// Assign apdexThreshold regardless of whether or not the transaction
	// gets apdex since it may be used to calculate the trace threshold.
	txn.ApdexThreshold = internal.CalculateApdexThreshold(txn.Reply, txn.FinalName)

	if txn.getsApdex() {
		if txn.HasErrors() {
			txn.Zone = internal.ApdexFailing
		} else {
			txn.Zone = internal.CalculateApdexZone(txn.ApdexThreshold, txn.Duration)
		}
	} else {
		txn.Zone = internal.ApdexNone
	}

	if txn.Config.Logger.DebugEnabled() {
		txn.Config.Logger.Debug("transaction ended", map[string]interface{}{
			"name":          txn.FinalName,
			"duration_ms":   txn.Duration.Seconds() * 1000.0,
			"ignored":       txn.ignore,
			"app_connected": "" != txn.Reply.RunID,
		})
	}

	if !txn.ignore {
		txn.Consumer.Consume(txn.Reply.RunID, txn)
	}

	// Note that if a consumer uses `panic(nil)`, the panic will not
	// propagate.
	if nil != r {
		panic(r)
	}

	return nil
}

func (txn *txn) AddAttribute(name string, value interface{}) error {
	txn.Lock()
	defer txn.Unlock()

	if txn.Config.HighSecurity {
		return errHighSecurityEnabled
	}

	if !txn.Reply.SecurityPolicies.CustomParameters.Enabled() {
		return errSecurityPolicy
	}

	if txn.finished {
		return errAlreadyEnded
	}

	return internal.AddUserAttribute(txn.Attrs, name, value, internal.DestAll)
}

var (
	errorsDisabled        = errors.New("errors disabled")
	errNilError           = errors.New("nil error")
	errAlreadyEnded       = errors.New("transaction has already ended")
	errSecurityPolicy     = errors.New("disabled by security policy")
	errTransactionIgnored = errors.New("transaction has been ignored")
	errBrowserDisabled    = errors.New("browser disabled by local configuration")
)

const (
	highSecurityErrorMsg   = "message removed by high security setting"
	securityPolicyErrorMsg = "message removed by security policy"
)

func (txn *txn) noticeErrorInternal(err internal.ErrorData) error {
	if !txn.Config.ErrorCollector.Enabled {
		return errorsDisabled
	}

	if nil == txn.Errors {
		txn.Errors = internal.NewTxnErrors(internal.MaxTxnErrors)
	}

	if txn.Config.HighSecurity {
		err.Msg = highSecurityErrorMsg
	}

	if !txn.Reply.SecurityPolicies.AllowRawExceptionMessages.Enabled() {
		err.Msg = securityPolicyErrorMsg
	}

	txn.Errors.Add(err)
	txn.TxnData.TxnEvent.HasError = true //mark transaction as having an error
	return nil
}

var (
	errTooManyErrorAttributes = fmt.Errorf("too many extra attributes: limit is %d",
		internal.AttributeErrorLimit)
)

func (txn *txn) NoticeError(err error) error {
	txn.Lock()
	defer txn.Unlock()

	if txn.finished {
		return errAlreadyEnded
	}

	if nil == err {
		return errNilError
	}

	e := internal.ErrorData{
		When: time.Now(),
		Msg:  err.Error(),
	}
	if ec, ok := err.(ErrorClasser); ok {
		e.Klass = ec.ErrorClass()
	}
	if "" == e.Klass {
		e.Klass = reflect.TypeOf(err).String()
	}
	if st, ok := err.(StackTracer); ok {
		e.Stack = st.StackTrace()
		// Note that if the provided stack trace is excessive in length,
		// it will be truncated during JSON creation.
	}
	if nil == e.Stack {
		e.Stack = internal.GetStackTrace()
	}

	if ea, ok := err.(ErrorAttributer); ok && !txn.Config.HighSecurity && txn.Reply.SecurityPolicies.CustomParameters.Enabled() {
		unvetted := ea.ErrorAttributes()
		if len(unvetted) > internal.AttributeErrorLimit {
			return errTooManyErrorAttributes
		}

		e.ExtraAttributes = make(map[string]interface{})
		for key, val := range unvetted {
			val, errr := internal.ValidateUserAttribute(key, val)
			if nil != errr {
				return errr
			}
			e.ExtraAttributes[key] = val
		}
	}

	return txn.noticeErrorInternal(e)
}

func (txn *txn) SetName(name string) error {
	txn.Lock()
	defer txn.Unlock()

	if txn.finished {
		return errAlreadyEnded
	}

	txn.Name = name
	return nil
}

func (txn *txn) Ignore() error {
	txn.Lock()
	defer txn.Unlock()

	if txn.finished {
		return errAlreadyEnded
	}
	txn.ignore = true
	return nil
}

func (thd *thread) StartSegmentNow() SegmentStartTime {
	var s internal.SegmentStartTime
	txn := thd.txn
	txn.Lock()
	if !txn.finished {
		s = internal.StartSegment(&txn.TxnData, thd.thread, time.Now())
	}
	txn.Unlock()
	return SegmentStartTime{
		segment: segment{
			start:  s,
			thread: thd,
		},
	}
}

const (
	// Browser fields are encoded using the first digits of the license
	// key.
	browserEncodingKeyLimit = 13
)

func browserEncodingKey(licenseKey string) []byte {
	key := []byte(licenseKey)
	if len(key) > browserEncodingKeyLimit {
		key = key[0:browserEncodingKeyLimit]
	}
	return key
}

func (txn *txn) BrowserTimingHeader() (*BrowserTimingHeader, error) {
	txn.Lock()
	defer txn.Unlock()

	if !txn.Config.BrowserMonitoring.Enabled {
		return nil, errBrowserDisabled
	}

	if txn.Reply.AgentLoader == "" {
		// If the loader is empty, either browser has been disabled
		// by the server or the application is not yet connected.
		return nil, nil
	}

	if txn.finished {
		return nil, errAlreadyEnded
	}

	txn.freezeName()

	// Freezing the name might cause the transaction to be ignored, so check
	// this after txn.freezeName().
	if txn.ignore {
		return nil, errTransactionIgnored
	}

	encodingKey := browserEncodingKey(txn.Config.License)

	attrs, err := internal.Obfuscate(internal.BrowserAttributes(txn.Attrs), encodingKey)
	if err != nil {
		return nil, fmt.Errorf("error getting browser attributes: %v", err)
	}

	name, err := internal.Obfuscate([]byte(txn.FinalName), encodingKey)
	if err != nil {
		return nil, fmt.Errorf("error obfuscating name: %v", err)
	}

	return &BrowserTimingHeader{
		agentLoader: txn.Reply.AgentLoader,
		info: browserInfo{
			Beacon:                txn.Reply.Beacon,
			LicenseKey:            txn.Reply.BrowserKey,
			ApplicationID:         txn.Reply.AppID,
			TransactionName:       name,
			QueueTimeMillis:       txn.Queuing.Nanoseconds() / (1000 * 1000),
			ApplicationTimeMillis: time.Now().Sub(txn.Start).Nanoseconds() / (1000 * 1000),
			ObfuscatedAttributes:  attrs,
			ErrorBeacon:           txn.Reply.ErrorBeacon,
			Agent:                 txn.Reply.JSAgentFile,
		},
	}, nil
}

func createThread(txn *txn) *internal.Thread {
	newThread := internal.NewThread(&txn.TxnData)
	txn.asyncThreads = append(txn.asyncThreads, newThread)
	return newThread
}

func (thd *thread) NewGoroutine() Transaction {
	txn := thd.txn
	txn.Lock()
	defer txn.Unlock()

	if txn.finished {
		// If the transaction has finished, return the same thread.
		return upgradeTxn(thd)
	}
	return upgradeTxn(&thread{
		thread: createThread(txn),
		txn:    txn,
	})
}

type segment struct {
	start  internal.SegmentStartTime
	thread *thread
}

func endSegment(s *Segment) error {
	if nil == s {
		return nil
	}
	thd := s.StartTime.thread
	if nil == thd {
		return nil
	}
	txn := thd.txn
	var err error
	txn.Lock()
	if txn.finished {
		err = errAlreadyEnded
	} else {
		err = internal.EndBasicSegment(&txn.TxnData, thd.thread, s.StartTime.start, time.Now(), s.Name)
	}
	txn.Unlock()
	return err
}

func endDatastore(s *DatastoreSegment) error {
	if nil == s {
		return nil
	}
	thd := s.StartTime.thread
	if nil == thd {
		return nil
	}
	txn := thd.txn
	txn.Lock()
	defer txn.Unlock()

	if txn.finished {
		return errAlreadyEnded
	}
	if txn.Config.HighSecurity {
		s.QueryParameters = nil
	}
	if !txn.Config.DatastoreTracer.QueryParameters.Enabled {
		s.QueryParameters = nil
	}
	if txn.Reply.SecurityPolicies.RecordSQL.IsSet() {
		s.QueryParameters = nil
		if !txn.Reply.SecurityPolicies.RecordSQL.Enabled() {
			s.ParameterizedQuery = ""
		}
	}
	if !txn.Config.DatastoreTracer.DatabaseNameReporting.Enabled {
		s.DatabaseName = ""
	}
	if !txn.Config.DatastoreTracer.InstanceReporting.Enabled {
		s.Host = ""
		s.PortPathOrID = ""
	}
	return internal.EndDatastoreSegment(internal.EndDatastoreParams{
		TxnData:            &txn.TxnData,
		Thread:             thd.thread,
		Start:              s.StartTime.start,
		Now:                time.Now(),
		Product:            string(s.Product),
		Collection:         s.Collection,
		Operation:          s.Operation,
		ParameterizedQuery: s.ParameterizedQuery,
		QueryParameters:    s.QueryParameters,
		Host:               s.Host,
		PortPathOrID:       s.PortPathOrID,
		Database:           s.DatabaseName,
	})
}

func externalSegmentMethod(s *ExternalSegment) string {
	r := s.Request

	// Is this a client request?
	if nil != s.Response && nil != s.Response.Request {
		r = s.Response.Request

		// Golang's http package states that when a client's
		// Request has an empty string for Method, the
		// method is GET.
		if "" == r.Method {
			return "GET"
		}
	}
	if nil == r {
		return ""
	}
	return r.Method
}

func externalSegmentURL(s *ExternalSegment) (*url.URL, error) {
	if "" != s.URL {
		return url.Parse(s.URL)
	}
	r := s.Request
	if nil != s.Response && nil != s.Response.Request {
		r = s.Response.Request
	}
	if r != nil {
		return r.URL, nil
	}
	return nil, nil
}

func endExternal(s *ExternalSegment) error {
	if nil == s {
		return nil
	}
	thd := s.StartTime.thread
	if nil == thd {
		return nil
	}
	txn := thd.txn
	txn.Lock()
	defer txn.Unlock()

	if txn.finished {
		return errAlreadyEnded
	}
	m := externalSegmentMethod(s)
	u, err := externalSegmentURL(s)
	if nil != err {
		return err
	}
	return internal.EndExternalSegment(&txn.TxnData, thd.thread, s.StartTime.start, time.Now(), u, m, s.Response, txn.Config.Logger)
}

// oldCATOutboundHeaders generates the Old CAT and Synthetics headers, depending
// on whether Old CAT is enabled or any Synthetics functionality has been
// triggered in the agent.
func oldCATOutboundHeaders(txn *txn) http.Header {
	txn.Lock()
	defer txn.Unlock()

	if txn.finished {
		return http.Header{}
	}

	metadata, err := txn.CrossProcess.CreateCrossProcessMetadata(txn.Name, txn.Config.AppName)
	if err != nil {
		txn.Config.Logger.Debug("error generating outbound headers", map[string]interface{}{
			"error": err,
		})

		// It's possible for CreateCrossProcessMetadata() to error and still have a
		// Synthetics header, so we'll still fall through to returning headers
		// based on whatever metadata was returned.
	}

	return internal.MetadataToHTTPHeader(metadata)
}

func outboundHeaders(s *ExternalSegment) http.Header {
	thd := s.StartTime.thread

	if nil == thd {
		return http.Header{}
	}
	txn := thd.txn
	hdr := oldCATOutboundHeaders(txn)

	// hdr may be empty, or it may contain headers.  If DistributedTracer
	// is enabled, add more to the existing hdr
	if p := thd.CreateDistributedTracePayload().HTTPSafe(); "" != p {
		hdr.Add(DistributedTracePayloadHeader, p)
		return hdr
	}

	return hdr
}

const (
	maxSampledDistributedPayloads = 35
)

type shimPayload struct{}

func (s shimPayload) Text() string     { return "" }
func (s shimPayload) HTTPSafe() string { return "" }

func (thd *thread) CreateDistributedTracePayload() (payload DistributedTracePayload) {
	payload = shimPayload{}

	txn := thd.txn
	txn.Lock()
	defer txn.Unlock()

	if !txn.BetterCAT.Enabled {
		return
	}

	if txn.finished {
		txn.CreatePayloadException = true
		return
	}

	if "" == txn.Reply.AccountID || "" == txn.Reply.TrustedAccountKey {
		// We can't create a payload:  The application is not yet
		// connected or serverless distributed tracing configuration was
		// not provided.
		return
	}

	txn.numPayloadsCreated++

	var p internal.Payload
	p.Type = internal.CallerType
	p.Account = txn.Reply.AccountID

	p.App = txn.Reply.PrimaryAppID
	p.TracedID = txn.BetterCAT.TraceID()
	p.Priority = txn.BetterCAT.Priority
	p.Timestamp.Set(time.Now())
	p.TransactionID = txn.BetterCAT.ID // Set the transaction ID to the transaction guid.

	if txn.Reply.AccountID != txn.Reply.TrustedAccountKey {
		p.TrustedAccountKey = txn.Reply.TrustedAccountKey
	}

	sampled := txn.lazilyCalculateSampled()
	if sampled && txn.SpanEventsEnabled {
		p.ID = txn.CurrentSpanIdentifier(thd.thread)
	}

	// limit the number of outbound sampled=true payloads to prevent too
	// many downstream sampled events.
	p.SetSampled(false)
	if txn.numPayloadsCreated < maxSampledDistributedPayloads {
		p.SetSampled(sampled)
	}

	txn.CreatePayloadSuccess = true

	payload = p
	return
}

var (
	errOutboundPayloadCreated   = errors.New("outbound payload already created")
	errAlreadyAccepted          = errors.New("AcceptDistributedTracePayload has already been called")
	errInboundPayloadDTDisabled = errors.New("DistributedTracer must be enabled to accept an inbound payload")
	errTrustedAccountKey        = errors.New("trusted account key missing or does not match")
)

func (txn *txn) AcceptDistributedTracePayload(t TransportType, p interface{}) error {
	txn.Lock()
	defer txn.Unlock()

	return txn.acceptDistributedTracePayloadLocked(t, p)
}

func (txn *txn) acceptDistributedTracePayloadLocked(t TransportType, p interface{}) error {

	if !txn.BetterCAT.Enabled {
		return errInboundPayloadDTDisabled
	}

	if txn.finished {
		txn.AcceptPayloadException = true
		return errAlreadyEnded
	}

	if txn.numPayloadsCreated > 0 {
		txn.AcceptPayloadCreateBeforeAccept = true
		return errOutboundPayloadCreated
	}

	if txn.BetterCAT.Inbound != nil {
		txn.AcceptPayloadIgnoredMultiple = true
		return errAlreadyAccepted
	}

	if nil == p {
		txn.AcceptPayloadNullPayload = true
		return nil
	}

	if "" == txn.Reply.AccountID || "" == txn.Reply.TrustedAccountKey {
		// We can't accept a payload:  The application is not yet
		// connected or serverless distributed tracing configuration was
		// not provided.
		return nil
	}

	payload, err := internal.AcceptPayload(p)
	if nil != err {
		if _, ok := err.(internal.ErrPayloadParse); ok {
			txn.AcceptPayloadParseException = true
		} else if _, ok := err.(internal.ErrUnsupportedPayloadVersion); ok {
			txn.AcceptPayloadIgnoredVersion = true
		} else if _, ok := err.(internal.ErrPayloadMissingField); ok {
			txn.AcceptPayloadParseException = true
		} else {
			txn.AcceptPayloadException = true
		}
		return err
	}

	if nil == payload {
		return nil
	}

	// now that we have a parsed and alloc'd payload,
	// let's make  sure it has the correct fields
	if err := payload.IsValid(); nil != err {
		txn.AcceptPayloadParseException = true
		return err
	}

	// and let's also do our trustedKey check
	receivedTrustKey := payload.TrustedAccountKey
	if "" == receivedTrustKey {
		receivedTrustKey = payload.Account
	}
	if receivedTrustKey != txn.Reply.TrustedAccountKey {
		txn.AcceptPayloadUntrustedAccount = true
		return errTrustedAccountKey
	}

	if 0 != payload.Priority {
		txn.BetterCAT.Priority = payload.Priority
	}

	// a nul payload.Sampled means the a field wasn't provided
	if nil != payload.Sampled {
		txn.BetterCAT.Sampled = *payload.Sampled
		txn.sampledCalculated = true
	}

	txn.BetterCAT.Inbound = payload

	// TransportType's name field is not mutable outside of its package
	// so the only check needed is if the caller is using an empty TransportType
	txn.BetterCAT.Inbound.TransportType = t.name
	if t.name == "" {
		txn.BetterCAT.Inbound.TransportType = TransportUnknown.name
		txn.Config.Logger.Debug("Invalid transport type, defaulting to Unknown", map[string]interface{}{})
	}

	if tm := payload.Timestamp.Time(); txn.Start.After(tm) {
		txn.BetterCAT.Inbound.TransportDuration = txn.Start.Sub(tm)
	}

	txn.AcceptPayloadSuccess = true

	return nil
}

func (txn *txn) Application() Application {
	return txn.app
}

func (thd *thread) AddAgentSpanAttribute(key internal.SpanAttribute, val string) {
	thd.thread.AddAgentSpanAttribute(key, val)
}

var (
	// Ensure that txn implements AddAgentAttributer to avoid breaking
	// integration package type assertions.
	_ internal.AddAgentAttributer = &txn{}
)

func (txn *txn) AddAgentAttribute(id internal.AgentAttributeID, stringVal string, otherVal interface{}) {
	txn.Lock()
	defer txn.Unlock()

	if txn.finished {
		return
	}
	txn.Attrs.Agent.Add(id, stringVal, otherVal)
}
