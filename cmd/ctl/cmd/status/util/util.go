/*
Copyright 2020 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package util

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/duration"
	"k8s.io/kubectl/pkg/describe"
	"k8s.io/kubectl/pkg/util/event"
)

// This file contains functions that are copied from "k8s.io/kubectl/pkg/describe".
// DescribeEvents was slightly modified. The other functions are copied over.
// The purpose of this is to be able to reuse the PrefixWriter interface defined in the describe package,
// and because we need to indent certain lines differently than the original function.

// DescribeEvents writes a formatted string of the Events in el with PrefixWriter.
// The intended use is for w to be created with a *tabWriter.Writer underneath, and the caller
// of DescribeEvents would need to call Flush() on that *tabWriter.Writer to actually print the output.
func DescribeEvents(el *corev1.EventList, w describe.PrefixWriter, baseLevel int) {
	if el == nil || len(el.Items) == 0 {
		w.Write(baseLevel, "Events:\t<none>\n")
		w.Flush()
		return
	}
	w.Flush()
	sort.Sort(event.SortableEvents(el.Items))
	w.Write(baseLevel, "Events:\n")
	w.Write(baseLevel+1, "Type\tReason\tAge\tFrom\tMessage\n")
	w.Write(baseLevel+1, "----\t------\t----\t----\t-------\n")
	for _, e := range el.Items {
		var interval string
		if e.Count > 1 {
			interval = fmt.Sprintf("%s (x%d over %s)", translateTimestampSince(e.LastTimestamp), e.Count, translateTimestampSince(e.FirstTimestamp))
		} else {
			interval = translateTimestampSince(e.FirstTimestamp)
		}
		w.Write(baseLevel+1, "%v\t%v\t%s\t%v\t%v\n",
			e.Type,
			e.Reason,
			interval,
			formatEventSource(e.Source),
			strings.TrimSpace(e.Message),
		)
	}
	w.Flush()
}

// NewTabWriter returns a *tabwriter.Writer with fixed parameters to be used in the status command
func NewTabWriter(writer io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(writer, 0, 8, 2, ' ', 0)
}

// formatEventSource formats EventSource as a comma separated string excluding Host when empty
func formatEventSource(es corev1.EventSource) string {
	EventSourceString := []string{es.Component}
	if len(es.Host) > 0 {
		EventSourceString = append(EventSourceString, es.Host)
	}
	return strings.Join(EventSourceString, ", ")
}

// translateTimestampSince returns the elapsed time since timestamp in
// human-readable approximation.
func translateTimestampSince(timestamp metav1.Time) string {
	if timestamp.IsZero() {
		return "<unknown>"
	}

	return duration.HumanDuration(time.Since(timestamp.Time))
}
