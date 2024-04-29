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

package log

import (
	"fmt"
	"sync"
	"time"

	"github.com/onsi/ginkgo/v2"
	"k8s.io/apimachinery/pkg/util/wait"
)

var Writer = ginkgo.GinkgoWriter

func nowStamp() string {
	return time.Now().Format(time.StampMilli)
}

func logf(level string, format string, args ...interface{}) {
	fmt.Fprintf(Writer, nowStamp()+": "+level+": "+format+"\n", args...)
}

func Logf(format string, args ...interface{}) {
	logf("INFO", format, args...)
}

// LogBackoff gives you a logger with an exponential backoff. If the
// returned 'logf' func is called too often, the logf calls get ignored
// until the backoff expires.
//
// The reason we use this backoff mechanism is that we have many "waiting
// loops" that poll every 0.5 seconds. We don't want to use a higher
// polling interval since it would slow the test.
//
// The first log line is immediately printed, and the last message is
// always printed even if the backoff isn't done. That's because the first
// and last messages are often helpful to understand how things went.
func LogBackoff() (logf func(format string, args ...interface{}), done func()) {
	backoff := wait.Backoff{
		Duration: 5 * time.Second,
		Factor:   1.2,
		Steps:    10,
		Cap:      1 * time.Minute,
	}

	start := time.Now()
	var msg string
	done = func() {
		Logf(msg + fmt.Sprintf(" (took %v)", time.Since(start).Truncate(time.Second)))
	}

	once := sync.Once{}
	step := time.Now()
	return func(format string, args ...interface{}) {
		msg = fmt.Sprintf(format, args...)
		once.Do(func() {
			Logf(msg)
		})

		if time.Since(step) < backoff.Duration {
			return
		}

		step = time.Now()
		_ = backoff.Step()
		Logf(msg)
	}, done
}
