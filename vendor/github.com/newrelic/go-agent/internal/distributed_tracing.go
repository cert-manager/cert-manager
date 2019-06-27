package internal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

type distTraceVersion [2]int

func (v distTraceVersion) major() int { return v[0] }
func (v distTraceVersion) minor() int { return v[1] }

const (
	// CallerType is the Type field's value for outbound payloads.
	CallerType = "App"
)

var (
	currentDistTraceVersion = distTraceVersion([2]int{0 /* Major */, 1 /* Minor */})
	callerUnknown           = payloadCaller{Type: "Unknown", App: "Unknown", Account: "Unknown", TransportType: "Unknown"}
)

// timestampMillis allows raw payloads to use exact times, and marshalled
// payloads to use times in millis.
type timestampMillis time.Time

func (tm *timestampMillis) UnmarshalJSON(data []byte) error {
	var millis uint64
	if err := json.Unmarshal(data, &millis); nil != err {
		return err
	}
	*tm = timestampMillis(timeFromUnixMilliseconds(millis))
	return nil
}

func (tm timestampMillis) MarshalJSON() ([]byte, error) {
	return json.Marshal(TimeToUnixMilliseconds(tm.Time()))
}

func (tm timestampMillis) Time() time.Time  { return time.Time(tm) }
func (tm *timestampMillis) Set(t time.Time) { *tm = timestampMillis(t) }

// Payload is the distributed tracing payload.
type Payload struct {
	payloadCaller
	TransactionID     string          `json:"tx,omitempty"`
	ID                string          `json:"id,omitempty"`
	TracedID          string          `json:"tr"`
	Priority          Priority        `json:"pr"`
	Sampled           *bool           `json:"sa"`
	Timestamp         timestampMillis `json:"ti"`
	TransportDuration time.Duration   `json:"-"`
}

type payloadCaller struct {
	TransportType     string `json:"-"`
	Type              string `json:"ty"`
	App               string `json:"ap"`
	Account           string `json:"ac"`
	TrustedAccountKey string `json:"tk,omitempty"`
}

// IsValid validates the payload data by looking for missing fields.
// Returns an error if there's a problem, nil if everything's fine
func (p Payload) IsValid() error {

	// If a payload is missing both `guid` and `transactionId` is received,
	// a ParseException supportability metric should be generated.
	if "" == p.TransactionID && "" == p.ID {
		return ErrPayloadMissingField{message: "missing both guid/id and TransactionId/tx"}
	}

	if "" == p.Type {
		return ErrPayloadMissingField{message: "missing Type/ty"}
	}

	if "" == p.Account {
		return ErrPayloadMissingField{message: "missing Account/ac"}
	}

	if "" == p.App {
		return ErrPayloadMissingField{message: "missing App/ap"}
	}

	if "" == p.TracedID {
		return ErrPayloadMissingField{message: "missing TracedID/tr"}
	}

	if p.Timestamp.Time().IsZero() || 0 == p.Timestamp.Time().Unix() {
		return ErrPayloadMissingField{message: "missing Timestamp/ti"}
	}

	return nil
}

func (p Payload) text(v distTraceVersion) []byte {
	js, _ := json.Marshal(struct {
		Version distTraceVersion `json:"v"`
		Data    Payload          `json:"d"`
	}{
		Version: v,
		Data:    p,
	})
	return js
}

// Text implements newrelic.DistributedTracePayload.
func (p Payload) Text() string {
	t := p.text(currentDistTraceVersion)
	return string(t)
}

// HTTPSafe implements newrelic.DistributedTracePayload.
func (p Payload) HTTPSafe() string {
	t := p.text(currentDistTraceVersion)
	return base64.StdEncoding.EncodeToString(t)
}

// SetSampled lets us set a value for our *bool,
// which we can't do directly since a pointer
// needs something to point at.
func (p *Payload) SetSampled(sampled bool) {
	p.Sampled = &sampled
}

// ErrPayloadParse indicates that the payload was malformed.
type ErrPayloadParse struct{ err error }

func (e ErrPayloadParse) Error() string {
	return fmt.Sprintf("unable to parse inbound payload: %s", e.err.Error())
}

// ErrPayloadMissingField indicates there's a required field that's missing
type ErrPayloadMissingField struct{ message string }

func (e ErrPayloadMissingField) Error() string {
	return fmt.Sprintf("payload is missing required fields: %s", e.message)
}

// ErrUnsupportedPayloadVersion indicates that the major version number is
// unknown.
type ErrUnsupportedPayloadVersion struct{ version int }

func (e ErrUnsupportedPayloadVersion) Error() string {
	return fmt.Sprintf("unsupported major version number %d", e.version)
}

// AcceptPayload parses the inbound distributed tracing payload.
func AcceptPayload(p interface{}) (*Payload, error) {
	var payload Payload
	if byteSlice, ok := p.([]byte); ok {
		p = string(byteSlice)
	}
	switch v := p.(type) {
	case string:
		if "" == v {
			return nil, nil
		}
		var decoded []byte
		if '{' == v[0] {
			decoded = []byte(v)
		} else {
			var err error
			decoded, err = base64.StdEncoding.DecodeString(v)
			if nil != err {
				return nil, ErrPayloadParse{err: err}
			}
		}
		envelope := struct {
			Version distTraceVersion `json:"v"`
			Data    json.RawMessage  `json:"d"`
		}{}
		if err := json.Unmarshal(decoded, &envelope); nil != err {
			return nil, ErrPayloadParse{err: err}
		}

		if 0 == envelope.Version.major() && 0 == envelope.Version.minor() {
			return nil, ErrPayloadMissingField{message: "missing v"}
		}

		if envelope.Version.major() > currentDistTraceVersion.major() {
			return nil, ErrUnsupportedPayloadVersion{
				version: envelope.Version.major(),
			}
		}
		if err := json.Unmarshal(envelope.Data, &payload); nil != err {
			return nil, ErrPayloadParse{err: err}
		}
	case Payload:
		payload = v
	default:
		// Could be a shim payload (if the app is not yet connected).
		return nil, nil
	}
	// Ensure that we don't have a reference to the input payload: we don't
	// want to change it, it could be used multiple times.
	alloc := new(Payload)
	*alloc = payload

	return alloc, nil
}
