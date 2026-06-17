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
	"time"

	"k8s.io/apimachinery/pkg/types"

	"github.com/cert-manager/cert-manager/pkg/scheduler"
)

var _ scheduler.ScheduledWorkQueue[types.NamespacedName] = &FakeScheduler{}

// FakeScheduler allows stubbing the methods of scheduler.ScheduledWorkQueue in tests.
type FakeScheduler struct {
	AddFunc    func(types.NamespacedName, time.Duration)
	ForgetFunc func(types.NamespacedName)
}

func (f *FakeScheduler) Add(obj types.NamespacedName, duration time.Duration) {
	f.AddFunc(obj, duration)
}

func (f *FakeScheduler) Forget(obj types.NamespacedName) {
	f.ForgetFunc(obj)
}
