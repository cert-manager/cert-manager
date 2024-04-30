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

package test

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// FakeRecorder is used as a fake during tests. It is thread safe. It is usable
// when created manually and not by NewFakeRecorder, however all events may be
// thrown away in this case.
type FakeRecorder struct {
	Events []string
}

func (f *FakeRecorder) Event(object runtime.Object, eventtype, reason, message string) {
	f.Events = append(f.Events, fmt.Sprintf("%s %s %s", eventtype, reason, message))
}

func (f *FakeRecorder) Eventf(object runtime.Object, eventtype, reason, messageFmt string, args ...interface{}) {
	f.Events = append(f.Events, fmt.Sprintf(eventtype+" "+reason+" "+messageFmt, args...))
}

func (f *FakeRecorder) PastEventf(object runtime.Object, timestamp metav1.Time, eventtype, reason, messageFmt string, args ...interface{}) {
}

func (f *FakeRecorder) AnnotatedEventf(object runtime.Object, annotations map[string]string, eventtype, reason, messageFmt string, args ...interface{}) {
	f.Eventf(object, eventtype, reason, messageFmt, args...)
}
