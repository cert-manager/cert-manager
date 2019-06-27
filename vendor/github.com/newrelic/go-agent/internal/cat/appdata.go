package cat

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/newrelic/go-agent/internal/jsonx"
)

// AppDataHeader represents a decoded AppData header.
type AppDataHeader struct {
	CrossProcessID        string
	TransactionName       string
	QueueTimeInSeconds    float64
	ResponseTimeInSeconds float64
	ContentLength         int64
	TransactionGUID       string
}

var (
	errInvalidAppDataJSON                  = errors.New("invalid transaction data JSON")
	errInvalidAppDataCrossProcessID        = errors.New("cross process ID is not a string")
	errInvalidAppDataTransactionName       = errors.New("transaction name is not a string")
	errInvalidAppDataQueueTimeInSeconds    = errors.New("queue time is not a float64")
	errInvalidAppDataResponseTimeInSeconds = errors.New("response time is not a float64")
	errInvalidAppDataContentLength         = errors.New("content length is not a float64")
	errInvalidAppDataTransactionGUID       = errors.New("transaction GUID is not a string")
)

// MarshalJSON marshalls an AppDataHeader as raw JSON.
func (appData *AppDataHeader) MarshalJSON() ([]byte, error) {
	buf := bytes.NewBufferString("[")

	jsonx.AppendString(buf, appData.CrossProcessID)

	buf.WriteString(",")
	jsonx.AppendString(buf, appData.TransactionName)

	buf.WriteString(",")
	jsonx.AppendFloat(buf, appData.QueueTimeInSeconds)

	buf.WriteString(",")
	jsonx.AppendFloat(buf, appData.ResponseTimeInSeconds)

	buf.WriteString(",")
	jsonx.AppendInt(buf, appData.ContentLength)

	buf.WriteString(",")
	jsonx.AppendString(buf, appData.TransactionGUID)

	// The mysterious unused field. We don't need to round trip this, so we'll
	// just hardcode it to false.
	buf.WriteString(",false]")
	return buf.Bytes(), nil
}

// UnmarshalJSON unmarshalls an AppDataHeader from raw JSON.
func (appData *AppDataHeader) UnmarshalJSON(data []byte) error {
	var ok bool
	var v interface{}

	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	arr, ok := v.([]interface{})
	if !ok {
		return errInvalidAppDataJSON
	}
	if len(arr) < 7 {
		return errUnexpectedArraySize{
			label:    "unexpected number of application data elements",
			expected: 7,
			actual:   len(arr),
		}
	}

	if appData.CrossProcessID, ok = arr[0].(string); !ok {
		return errInvalidAppDataCrossProcessID
	}

	if appData.TransactionName, ok = arr[1].(string); !ok {
		return errInvalidAppDataTransactionName
	}

	if appData.QueueTimeInSeconds, ok = arr[2].(float64); !ok {
		return errInvalidAppDataQueueTimeInSeconds
	}

	if appData.ResponseTimeInSeconds, ok = arr[3].(float64); !ok {
		return errInvalidAppDataResponseTimeInSeconds
	}

	cl, ok := arr[4].(float64)
	if !ok {
		return errInvalidAppDataContentLength
	}
	// Content length is specced as int32, but not all agents are consistent on
	// this in practice. Let's handle it as int64 to maximise compatibility.
	appData.ContentLength = int64(cl)

	if appData.TransactionGUID, ok = arr[5].(string); !ok {
		return errInvalidAppDataTransactionGUID
	}

	// As above, we don't bother decoding the unused field here. It just has to
	// be present (which was checked earlier with the length check).

	return nil
}
