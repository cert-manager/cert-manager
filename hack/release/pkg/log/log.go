/*
Copyright 2019 The Jetstack cert-manager contributors.

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
	goflag "flag"
	"os"

	"github.com/spf13/pflag"
	"k8s.io/klog"
	"k8s.io/klog/klogr"
)

const (
	LogLevelDebug = 3
	LogLevelTrace = 4
)

var (
	Log = klogr.New()

	// Output is a reference to the systems Stderr, for printing multi-line
	// strings such as log output
	Output = os.Stderr
)

func InitLogs(fs *pflag.FlagSet) {
	// add klog flags to flagset
	gofs := &goflag.FlagSet{}
	klog.InitFlags(gofs)
	fs.AddGoFlagSet(gofs)

	// hide klog flags and set some ourselves
	fs.Set("skip_headers", "true")
	fs.MarkHidden("log_dir")
	fs.MarkHidden("log_file")
	fs.MarkHidden("logtostderr")
	fs.MarkHidden("alsologtostderr")
	fs.MarkHidden("skip_headers")
	fs.MarkHidden("stderrthreshold")
	fs.MarkHidden("vmodule")
	fs.MarkHidden("log_backtrace_at")
}
