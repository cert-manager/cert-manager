package internal

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// AgentAttributeID uniquely identifies each agent attribute.
type AgentAttributeID int

// New agent attributes must be added in the following places:
// * Constants here.
// * Top level attributes.go file.
// * agentAttributeInfo
const (
	AttributeHostDisplayName AgentAttributeID = iota
	attributeRequestMethod
	attributeRequestAcceptHeader
	attributeRequestContentType
	attributeRequestContentLength
	attributeRequestHeadersHost
	attributeRequestHeadersUserAgent
	attributeRequestHeadersReferer
	attributeRequestURI
	attributeResponseHeadersContentType
	attributeResponseHeadersContentLength
	attributeResponseCode
	AttributeAWSRequestID
	AttributeAWSLambdaARN
	AttributeAWSLambdaColdStart
	AttributeAWSLambdaEventSourceARN
)

// SpanAttribute is an attribute put in span events.
type SpanAttribute string

// AddAgentSpanAttributer should be implemented by the Transaction.
type AddAgentSpanAttributer interface {
	AddAgentSpanAttribute(key SpanAttribute, val string)
}

// AddAgentSpanAttribute allows instrumentation packages to add span attributes.
func AddAgentSpanAttribute(txn interface{}, key SpanAttribute, val string) {
	if aa, ok := txn.(AddAgentSpanAttributer); ok {
		aa.AddAgentSpanAttribute(key, val)
	}
}

// These span event string constants must match the contents of the top level
// attributes.go file.
const (
	spanAttributeDBStatement  SpanAttribute = "db.statement"
	spanAttributeDBInstance   SpanAttribute = "db.instance"
	spanAttributeDBCollection SpanAttribute = "db.collection"
	spanAttributePeerAddress  SpanAttribute = "peer.address"
	spanAttributePeerHostname SpanAttribute = "peer.hostname"
	spanAttributeHTTPURL      SpanAttribute = "http.url"
	spanAttributeHTTPMethod   SpanAttribute = "http.method"
	// query parameters only appear in segments, not span events, but is
	// listed as span attributes to simplify code.
	spanAttributeQueryParameters SpanAttribute = "query_parameters"
	// These span attributes are added by aws sdk instrumentation.
	// https://source.datanerd.us/agents/agent-specs/blob/master/implementation_guides/aws-sdk.md#span-and-segment-attributes
	SpanAttributeAWSOperation SpanAttribute = "aws.operation"
	SpanAttributeAWSRequestID SpanAttribute = "aws.requestId"
	SpanAttributeAWSRegion    SpanAttribute = "aws.region"
)

func (sa SpanAttribute) String() string { return string(sa) }

var (
	usualDests         = DestAll &^ destBrowser
	tracesDests        = destTxnTrace | destError
	agentAttributeInfo = map[AgentAttributeID]struct {
		name         string
		defaultDests destinationSet
	}{
		AttributeHostDisplayName:              {name: "host.displayName", defaultDests: usualDests},
		attributeRequestMethod:                {name: "request.method", defaultDests: usualDests},
		attributeRequestAcceptHeader:          {name: "request.headers.accept", defaultDests: usualDests},
		attributeRequestContentType:           {name: "request.headers.contentType", defaultDests: usualDests},
		attributeRequestContentLength:         {name: "request.headers.contentLength", defaultDests: usualDests},
		attributeRequestHeadersHost:           {name: "request.headers.host", defaultDests: usualDests},
		attributeRequestHeadersUserAgent:      {name: "request.headers.User-Agent", defaultDests: tracesDests},
		attributeRequestHeadersReferer:        {name: "request.headers.referer", defaultDests: tracesDests},
		attributeRequestURI:                   {name: "request.uri", defaultDests: usualDests},
		attributeResponseHeadersContentType:   {name: "response.headers.contentType", defaultDests: usualDests},
		attributeResponseHeadersContentLength: {name: "response.headers.contentLength", defaultDests: usualDests},
		attributeResponseCode:                 {name: "httpResponseCode", defaultDests: usualDests},
		AttributeAWSRequestID:                 {name: "aws.requestId", defaultDests: usualDests},
		AttributeAWSLambdaARN:                 {name: "aws.lambda.arn", defaultDests: usualDests},
		AttributeAWSLambdaColdStart:           {name: "aws.lambda.coldStart", defaultDests: usualDests},
		AttributeAWSLambdaEventSourceARN:      {name: "aws.lambda.eventSource.arn", defaultDests: usualDests},
	}
	spanAttributes = []SpanAttribute{
		spanAttributeDBStatement,
		spanAttributeDBInstance,
		spanAttributeDBCollection,
		spanAttributePeerAddress,
		spanAttributePeerHostname,
		spanAttributeHTTPURL,
		spanAttributeHTTPMethod,
		spanAttributeQueryParameters,
		SpanAttributeAWSOperation,
		SpanAttributeAWSRequestID,
		SpanAttributeAWSRegion,
	}
)

func (id AgentAttributeID) name() string { return agentAttributeInfo[id].name }

// https://source.datanerd.us/agents/agent-specs/blob/master/Agent-Attributes-PORTED.md

// AttributeDestinationConfig matches newrelic.AttributeDestinationConfig to
// avoid circular dependency issues.
type AttributeDestinationConfig struct {
	Enabled bool
	Include []string
	Exclude []string
}

type destinationSet int

const (
	destTxnEvent destinationSet = 1 << iota
	destError
	destTxnTrace
	destBrowser
	destSpan
	destSegment
)

const (
	destNone destinationSet = 0
	// DestAll contains all destinations.
	DestAll destinationSet = destTxnEvent | destTxnTrace | destError | destBrowser | destSpan | destSegment
)

const (
	attributeWildcardSuffix = '*'
)

type attributeModifier struct {
	match string // This will not contain a trailing '*'.
	includeExclude
}

type byMatch []*attributeModifier

func (m byMatch) Len() int           { return len(m) }
func (m byMatch) Swap(i, j int)      { m[i], m[j] = m[j], m[i] }
func (m byMatch) Less(i, j int) bool { return m[i].match < m[j].match }

// AttributeConfig is created at connect and shared between all transactions.
type AttributeConfig struct {
	disabledDestinations destinationSet
	exactMatchModifiers  map[string]*attributeModifier
	// Once attributeConfig is constructed, wildcardModifiers is sorted in
	// lexicographical order.  Modifiers appearing later have precedence
	// over modifiers appearing earlier.
	wildcardModifiers []*attributeModifier
	agentDests        map[AgentAttributeID]destinationSet
	spanDests         map[SpanAttribute]destinationSet
}

type includeExclude struct {
	include destinationSet
	exclude destinationSet
}

func modifierApply(m *attributeModifier, d destinationSet) destinationSet {
	// Include before exclude, since exclude has priority.
	d |= m.include
	d &^= m.exclude
	return d
}

func applyAttributeConfig(c *AttributeConfig, key string, d destinationSet) destinationSet {
	// Important: The wildcard modifiers must be applied before the exact
	// match modifiers, and the slice must be iterated in a forward
	// direction.
	for _, m := range c.wildcardModifiers {
		if strings.HasPrefix(key, m.match) {
			d = modifierApply(m, d)
		}
	}

	if m, ok := c.exactMatchModifiers[key]; ok {
		d = modifierApply(m, d)
	}

	d &^= c.disabledDestinations

	return d
}

func addModifier(c *AttributeConfig, match string, d includeExclude) {
	if "" == match {
		return
	}
	exactMatch := true
	if attributeWildcardSuffix == match[len(match)-1] {
		exactMatch = false
		match = match[0 : len(match)-1]
	}
	mod := &attributeModifier{
		match:          match,
		includeExclude: d,
	}

	if exactMatch {
		if m, ok := c.exactMatchModifiers[mod.match]; ok {
			m.include |= mod.include
			m.exclude |= mod.exclude
		} else {
			c.exactMatchModifiers[mod.match] = mod
		}
	} else {
		for _, m := range c.wildcardModifiers {
			// Important: Duplicate entries for the same match
			// string would not work because exclude needs
			// precedence over include.
			if m.match == mod.match {
				m.include |= mod.include
				m.exclude |= mod.exclude
				return
			}
		}
		c.wildcardModifiers = append(c.wildcardModifiers, mod)
	}
}

func processDest(c *AttributeConfig, includeEnabled bool, dc *AttributeDestinationConfig, d destinationSet) {
	if !dc.Enabled {
		c.disabledDestinations |= d
	}
	if includeEnabled {
		for _, match := range dc.Include {
			addModifier(c, match, includeExclude{include: d})
		}
	}
	for _, match := range dc.Exclude {
		addModifier(c, match, includeExclude{exclude: d})
	}
}

// AttributeConfigInput is used as the input to CreateAttributeConfig:  it
// transforms newrelic.Config settings into an AttributeConfig.
type AttributeConfigInput struct {
	Attributes        AttributeDestinationConfig
	ErrorCollector    AttributeDestinationConfig
	TransactionEvents AttributeDestinationConfig
	BrowserMonitoring AttributeDestinationConfig
	TransactionTracer AttributeDestinationConfig
	SpanEvents        AttributeDestinationConfig
	TraceSegments     AttributeDestinationConfig
}

var (
	sampleAttributeConfigInput = AttributeConfigInput{
		Attributes:        AttributeDestinationConfig{Enabled: true},
		ErrorCollector:    AttributeDestinationConfig{Enabled: true},
		TransactionEvents: AttributeDestinationConfig{Enabled: true},
		TransactionTracer: AttributeDestinationConfig{Enabled: true},
		BrowserMonitoring: AttributeDestinationConfig{Enabled: true},
		SpanEvents:        AttributeDestinationConfig{Enabled: true},
		TraceSegments:     AttributeDestinationConfig{Enabled: true},
	}
)

// CreateAttributeConfig creates a new AttributeConfig.
func CreateAttributeConfig(input AttributeConfigInput, includeEnabled bool) *AttributeConfig {
	c := &AttributeConfig{
		exactMatchModifiers: make(map[string]*attributeModifier),
		wildcardModifiers:   make([]*attributeModifier, 0, 64),
	}

	processDest(c, includeEnabled, &input.Attributes, DestAll)
	processDest(c, includeEnabled, &input.ErrorCollector, destError)
	processDest(c, includeEnabled, &input.TransactionEvents, destTxnEvent)
	processDest(c, includeEnabled, &input.TransactionTracer, destTxnTrace)
	processDest(c, includeEnabled, &input.BrowserMonitoring, destBrowser)
	processDest(c, includeEnabled, &input.SpanEvents, destSpan)
	processDest(c, includeEnabled, &input.TraceSegments, destSegment)

	sort.Sort(byMatch(c.wildcardModifiers))

	c.agentDests = make(map[AgentAttributeID]destinationSet)
	for id, info := range agentAttributeInfo {
		c.agentDests[id] = applyAttributeConfig(c, info.name, info.defaultDests)
	}
	c.spanDests = make(map[SpanAttribute]destinationSet, len(spanAttributes))
	for _, id := range spanAttributes {
		c.spanDests[id] = applyAttributeConfig(c, id.String(), destSpan|destSegment)
	}

	return c
}

type userAttribute struct {
	value interface{}
	dests destinationSet
}

type agentAttributeValue struct {
	stringVal string
	otherVal  interface{}
}

type agentAttributes map[AgentAttributeID]agentAttributeValue

func (a *Attributes) filterSpanAttributes(s map[SpanAttribute]jsonWriter, d destinationSet) map[SpanAttribute]jsonWriter {
	if nil != a {
		for key := range s {
			if a.config.spanDests[key]&d == 0 {
				delete(s, key)
			}
		}
	}
	return s
}

// GetAgentValue is used to access agent attributes.  This function returns ("",
// nil) if the attribute doesn't exist or it doesn't match the destinations
// provided.
func (a *Attributes) GetAgentValue(id AgentAttributeID, d destinationSet) (string, interface{}) {
	if nil == a || 0 == a.config.agentDests[id]&d {
		return "", nil
	}
	v, _ := a.Agent[id]
	return v.stringVal, v.otherVal
}

// AddAgentAttributer allows instrumentation to add agent attributes without
// exposing a Transaction method.
type AddAgentAttributer interface {
	AddAgentAttribute(id AgentAttributeID, stringVal string, otherVal interface{})
}

// Add is used to add agent attributes.  Only one of stringVal and
// otherVal should be populated.  Since most agent attribute values are strings,
// stringVal exists to avoid allocations.
func (attr agentAttributes) Add(id AgentAttributeID, stringVal string, otherVal interface{}) {
	if "" != stringVal || otherVal != nil {
		attr[id] = agentAttributeValue{
			stringVal: truncateStringValueIfLong(stringVal),
			otherVal:  otherVal,
		}
	}
}

// Attributes are key value pairs attached to the various collected data types.
type Attributes struct {
	config *AttributeConfig
	user   map[string]userAttribute
	Agent  agentAttributes
}

// NewAttributes creates a new Attributes.
func NewAttributes(config *AttributeConfig) *Attributes {
	return &Attributes{
		config: config,
		Agent:  make(agentAttributes),
	}
}

// ErrInvalidAttributeType is returned when the value is not valid.
type ErrInvalidAttributeType struct {
	key string
	val interface{}
}

func (e ErrInvalidAttributeType) Error() string {
	return fmt.Sprintf("attribute '%s' value of type %T is invalid", e.key, e.val)
}

type invalidAttributeKeyErr struct{ key string }

func (e invalidAttributeKeyErr) Error() string {
	return fmt.Sprintf("attribute key '%.32s...' exceeds length limit %d",
		e.key, attributeKeyLengthLimit)
}

type userAttributeLimitErr struct{ key string }

func (e userAttributeLimitErr) Error() string {
	return fmt.Sprintf("attribute '%s' discarded: limit of %d reached", e.key,
		attributeUserLimit)
}

func truncateStringValueIfLong(val string) string {
	if len(val) > attributeValueLengthLimit {
		return StringLengthByteLimit(val, attributeValueLengthLimit)
	}
	return val
}

// ValidateUserAttribute validates a user attribute.
func ValidateUserAttribute(key string, val interface{}) (interface{}, error) {
	if str, ok := val.(string); ok {
		val = interface{}(truncateStringValueIfLong(str))
	}

	switch val.(type) {
	case string, bool,
		uint8, uint16, uint32, uint64, int8, int16, int32, int64,
		float32, float64, uint, int, uintptr:
	default:
		return nil, ErrInvalidAttributeType{
			key: key,
			val: val,
		}
	}

	// Attributes whose keys are excessively long are dropped rather than
	// truncated to avoid worrying about the application of configuration to
	// truncated values or performing the truncation after configuration.
	if len(key) > attributeKeyLengthLimit {
		return nil, invalidAttributeKeyErr{key: key}
	}
	return val, nil
}

// AddUserAttribute adds a user attribute.
func AddUserAttribute(a *Attributes, key string, val interface{}, d destinationSet) error {
	val, err := ValidateUserAttribute(key, val)
	if nil != err {
		return err
	}
	dests := applyAttributeConfig(a.config, key, d)
	if destNone == dests {
		return nil
	}
	if nil == a.user {
		a.user = make(map[string]userAttribute)
	}

	if _, exists := a.user[key]; !exists && len(a.user) >= attributeUserLimit {
		return userAttributeLimitErr{key}
	}

	// Note: Duplicates are overridden: last attribute in wins.
	a.user[key] = userAttribute{
		value: val,
		dests: dests,
	}
	return nil
}

func writeAttributeValueJSON(w *jsonFieldsWriter, key string, val interface{}) {
	switch v := val.(type) {
	case string:
		w.stringField(key, v)
	case bool:
		if v {
			w.rawField(key, `true`)
		} else {
			w.rawField(key, `false`)
		}
	case uint8:
		w.intField(key, int64(v))
	case uint16:
		w.intField(key, int64(v))
	case uint32:
		w.intField(key, int64(v))
	case uint64:
		w.intField(key, int64(v))
	case uint:
		w.intField(key, int64(v))
	case uintptr:
		w.intField(key, int64(v))
	case int8:
		w.intField(key, int64(v))
	case int16:
		w.intField(key, int64(v))
	case int32:
		w.intField(key, int64(v))
	case int64:
		w.intField(key, v)
	case int:
		w.intField(key, int64(v))
	case float32:
		w.floatField(key, float64(v))
	case float64:
		w.floatField(key, v)
	default:
		w.stringField(key, fmt.Sprintf("%T", v))
	}
}

func agentAttributesJSON(a *Attributes, buf *bytes.Buffer, d destinationSet) {
	if nil == a {
		buf.WriteString("{}")
		return
	}
	w := jsonFieldsWriter{buf: buf}
	buf.WriteByte('{')
	for id, val := range a.Agent {
		if 0 != a.config.agentDests[id]&d {
			if val.stringVal != "" {
				w.stringField(id.name(), val.stringVal)
			} else {
				writeAttributeValueJSON(&w, id.name(), val.otherVal)
			}
		}
	}
	buf.WriteByte('}')

}

func userAttributesJSON(a *Attributes, buf *bytes.Buffer, d destinationSet, extraAttributes map[string]interface{}) {
	buf.WriteByte('{')
	if nil != a {
		w := jsonFieldsWriter{buf: buf}
		for key, val := range extraAttributes {
			outputDest := applyAttributeConfig(a.config, key, d)
			if 0 != outputDest&d {
				writeAttributeValueJSON(&w, key, val)
			}
		}
		for name, atr := range a.user {
			if 0 != atr.dests&d {
				if _, found := extraAttributes[name]; found {
					continue
				}
				writeAttributeValueJSON(&w, name, atr.value)
			}
		}
	}
	buf.WriteByte('}')
}

// userAttributesStringJSON is only used for testing.
func userAttributesStringJSON(a *Attributes, d destinationSet, extraAttributes map[string]interface{}) string {
	estimate := len(a.user) * 128
	buf := bytes.NewBuffer(make([]byte, 0, estimate))
	userAttributesJSON(a, buf, d, extraAttributes)
	return buf.String()
}

// RequestAgentAttributes gathers agent attributes out of the request.
func RequestAgentAttributes(a *Attributes, method string, h http.Header, u *url.URL) {
	a.Agent.Add(attributeRequestMethod, method, nil)

	if nil != u {
		a.Agent.Add(attributeRequestURI, SafeURL(u), nil)
	}

	if nil == h {
		return
	}
	a.Agent.Add(attributeRequestAcceptHeader, h.Get("Accept"), nil)
	a.Agent.Add(attributeRequestContentType, h.Get("Content-Type"), nil)
	a.Agent.Add(attributeRequestHeadersHost, h.Get("Host"), nil)
	a.Agent.Add(attributeRequestHeadersUserAgent, h.Get("User-Agent"), nil)
	a.Agent.Add(attributeRequestHeadersReferer, SafeURLFromString(h.Get("Referer")), nil)

	if l := GetContentLengthFromHeader(h); l >= 0 {
		a.Agent.Add(attributeRequestContentLength, "", l)
	}
}

// ResponseHeaderAttributes gather agent attributes from the response headers.
func ResponseHeaderAttributes(a *Attributes, h http.Header) {
	if nil == h {
		return
	}
	a.Agent.Add(attributeResponseHeadersContentType, h.Get("Content-Type"), nil)

	if l := GetContentLengthFromHeader(h); l >= 0 {
		a.Agent.Add(attributeResponseHeadersContentLength, "", l)
	}
}

var (
	// statusCodeLookup avoids a strconv.Itoa call.
	statusCodeLookup = map[int]string{
		100: "100", 101: "101",
		200: "200", 201: "201", 202: "202", 203: "203", 204: "204", 205: "205", 206: "206",
		300: "300", 301: "301", 302: "302", 303: "303", 304: "304", 305: "305", 307: "307",
		400: "400", 401: "401", 402: "402", 403: "403", 404: "404", 405: "405", 406: "406",
		407: "407", 408: "408", 409: "409", 410: "410", 411: "411", 412: "412", 413: "413",
		414: "414", 415: "415", 416: "416", 417: "417", 418: "418", 428: "428", 429: "429",
		431: "431", 451: "451",
		500: "500", 501: "501", 502: "502", 503: "503", 504: "504", 505: "505", 511: "511",
	}
)

// ResponseCodeAttribute sets the response code agent attribute.
func ResponseCodeAttribute(a *Attributes, code int) {
	rc := statusCodeLookup[code]
	if rc == "" {
		rc = strconv.Itoa(code)
	}
	a.Agent.Add(attributeResponseCode, rc, nil)
}
