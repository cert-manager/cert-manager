package cat

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/newrelic/go-agent/internal/jsonx"
)

// TxnDataHeader represents a decoded TxnData header.
type TxnDataHeader struct {
	GUID     string
	TripID   string
	PathHash string
}

var (
	errInvalidTxnDataJSON     = errors.New("invalid transaction data JSON")
	errInvalidTxnDataGUID     = errors.New("GUID is not a string")
	errInvalidTxnDataTripID   = errors.New("trip ID is not a string or null")
	errInvalidTxnDataPathHash = errors.New("path hash is not a string or null")
)

// MarshalJSON marshalls a TxnDataHeader as raw JSON.
func (txnData *TxnDataHeader) MarshalJSON() ([]byte, error) {
	// Note that, although there are two and four element versions of this header
	// in the wild, we will only ever generate the four element version.

	buf := bytes.NewBufferString("[")

	jsonx.AppendString(buf, txnData.GUID)

	// Write the unused second field.
	buf.WriteString(",false,")
	jsonx.AppendString(buf, txnData.TripID)

	buf.WriteString(",")
	jsonx.AppendString(buf, txnData.PathHash)

	buf.WriteString("]")

	return buf.Bytes(), nil
}

// UnmarshalJSON unmarshalls a TxnDataHeader from raw JSON.
func (txnData *TxnDataHeader) UnmarshalJSON(data []byte) error {
	var ok bool
	var v interface{}

	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	arr, ok := v.([]interface{})
	if !ok {
		return errInvalidTxnDataJSON
	}
	if len(arr) < 2 {
		return errUnexpectedArraySize{
			label:    "unexpected number of transaction data elements",
			expected: 2,
			actual:   len(arr),
		}
	}

	if txnData.GUID, ok = arr[0].(string); !ok {
		return errInvalidTxnDataGUID
	}

	// Ignore the unused second field.

	// Set up defaults for the optional values.
	txnData.TripID = ""
	txnData.PathHash = ""

	if len(arr) >= 3 {
		// Per the cross agent tests, an explicit null is valid here.
		if nil != arr[2] {
			if txnData.TripID, ok = arr[2].(string); !ok {
				return errInvalidTxnDataTripID
			}
		}

		if len(arr) >= 4 {
			// Per the cross agent tests, an explicit null is also valid here.
			if nil != arr[3] {
				if txnData.PathHash, ok = arr[3].(string); !ok {
					return errInvalidTxnDataPathHash
				}
			}
		}
	}

	return nil
}
