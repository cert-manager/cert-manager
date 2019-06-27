package newrelic

import (
	"net/http"
)

// SegmentStartTime is created by Transaction.StartSegmentNow and marks the
// beginning of a segment.  A segment with a zero-valued SegmentStartTime may
// safely be ended.
type SegmentStartTime struct{ segment }

// Segment is used to instrument functions, methods, and blocks of code.  The
// easiest way use Segment is the StartSegment function.
type Segment struct {
	StartTime SegmentStartTime
	Name      string
}

// DatastoreSegment is used to instrument calls to databases and object stores.
type DatastoreSegment struct {
	// StartTime should be assigned using StartSegmentNow before each datastore
	// call is made.
	StartTime SegmentStartTime

	// Product, Collection, and Operation are highly recommended as they are
	// used for aggregate metrics:
	//
	// Product is the datastore type.  See the constants in
	// https://github.com/newrelic/go-agent/blob/master/datastore.go.  Product
	// is one of the fields primarily responsible for the grouping of Datastore
	// metrics.
	Product DatastoreProduct
	// Collection is the table or group being operated upon in the datastore,
	// e.g. "users_table".  This becomes the db.collection attribute on Span
	// events and Transaction Trace segments.  Collection is one of the fields
	// primarily responsible for the grouping of Datastore metrics.
	Collection string
	// Operation is the relevant action, e.g. "SELECT" or "GET".  Operation is
	// one of the fields primarily responsible for the grouping of Datastore
	// metrics.
	Operation string

	// The following fields are used for extra metrics and added to instance
	// data:
	//
	// ParameterizedQuery may be set to the query being performed.  It must
	// not contain any raw parameters, only placeholders.
	ParameterizedQuery string
	// QueryParameters may be used to provide query parameters.  Care should
	// be taken to only provide parameters which are not sensitive.
	// QueryParameters are ignored in high security mode. The keys must contain
	// fewer than than 255 bytes.  The values must be numbers, strings, or
	// booleans.
	QueryParameters map[string]interface{}
	// Host is the name of the server hosting the datastore.
	Host string
	// PortPathOrID can represent either the port, path, or id of the
	// datastore being connected to.
	PortPathOrID string
	// DatabaseName is name of database instance where the current query is
	// being executed.  This becomes the db.instance attribute on Span events
	// and Transaction Trace segments.
	DatabaseName string
}

// ExternalSegment instruments external calls.  StartExternalSegment is the
// recommended way to create ExternalSegments.
type ExternalSegment struct {
	StartTime SegmentStartTime
	Request   *http.Request
	Response  *http.Response

	// URL is an optional field which can be populated in lieu of Request if
	// you don't have an http.Request.  Either URL or Request must be
	// populated.  If both are populated then Request information takes
	// priority.  URL is parsed using url.Parse so it must include the
	// protocol scheme (eg. "http://").
	URL string
}

// End finishes the segment.
func (s *Segment) End() error { return endSegment(s) }

// End finishes the datastore segment.
func (s *DatastoreSegment) End() error { return endDatastore(s) }

// End finishes the external segment.
func (s *ExternalSegment) End() error { return endExternal(s) }

// OutboundHeaders returns the headers that should be attached to the external
// request.
func (s *ExternalSegment) OutboundHeaders() http.Header {
	return outboundHeaders(s)
}

// StartSegmentNow starts timing a segment.  This function is recommended over
// Transaction.StartSegmentNow() because it is nil safe.
func StartSegmentNow(txn Transaction) SegmentStartTime {
	if nil != txn {
		return txn.StartSegmentNow()
	}
	return SegmentStartTime{}
}

// StartSegment makes it easy to instrument segments.  To time a function, do
// the following:
//
//	func timeMe(txn newrelic.Transaction) {
//		defer newrelic.StartSegment(txn, "timeMe").End()
//		// ... function code here ...
//	}
//
// To time a block of code, do the following:
//
//	segment := StartSegment(txn, "myBlock")
//	// ... code you want to time here ...
//	segment.End()
//
func StartSegment(txn Transaction, name string) *Segment {
	return &Segment{
		StartTime: StartSegmentNow(txn),
		Name:      name,
	}
}

// StartExternalSegment starts the instrumentation of an external call and adds
// distributed tracing headers to the request.  If the Transaction parameter is
// nil then StartExternalSegment will look for a Transaction in the request's
// context using FromContext.
//
// Using the same http.Client for all of your external requests?  Check out
// NewRoundTripper: You may not need to use StartExternalSegment at all!
//
func StartExternalSegment(txn Transaction, request *http.Request) *ExternalSegment {
	if nil == txn {
		txn = transactionFromRequestContext(request)
	}
	s := &ExternalSegment{
		StartTime: StartSegmentNow(txn),
		Request:   request,
	}

	if request != nil && request.Header != nil {
		for key, values := range s.OutboundHeaders() {
			for _, value := range values {
				request.Header.Add(key, value)
			}
		}
	}

	return s
}
