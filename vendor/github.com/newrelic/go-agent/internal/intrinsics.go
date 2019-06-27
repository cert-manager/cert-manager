package internal

import (
	"bytes"
)

func addOptionalStringField(w *jsonFieldsWriter, key, value string) {
	if value != "" {
		w.stringField(key, value)
	}
}

func intrinsicsJSON(e *TxnEvent, buf *bytes.Buffer) {
	w := jsonFieldsWriter{buf: buf}

	buf.WriteByte('{')

	w.floatField("totalTime", e.TotalTime.Seconds())

	if e.BetterCAT.Enabled {
		w.stringField("guid", e.BetterCAT.ID)
		w.stringField("traceId", e.BetterCAT.TraceID())
		w.writerField("priority", e.BetterCAT.Priority)
		w.boolField("sampled", e.BetterCAT.Sampled)
	}

	if e.CrossProcess.Used() {
		addOptionalStringField(&w, "client_cross_process_id", e.CrossProcess.ClientID)
		addOptionalStringField(&w, "trip_id", e.CrossProcess.TripID)
		addOptionalStringField(&w, "path_hash", e.CrossProcess.PathHash)
		addOptionalStringField(&w, "referring_transaction_guid", e.CrossProcess.ReferringTxnGUID)
	}

	if e.CrossProcess.IsSynthetics() {
		addOptionalStringField(&w, "synthetics_resource_id", e.CrossProcess.Synthetics.ResourceID)
		addOptionalStringField(&w, "synthetics_job_id", e.CrossProcess.Synthetics.JobID)
		addOptionalStringField(&w, "synthetics_monitor_id", e.CrossProcess.Synthetics.MonitorID)
	}

	buf.WriteByte('}')
}
