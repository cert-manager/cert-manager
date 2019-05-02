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
	fs.MarkHidden("v")
	fs.MarkHidden("skip_headers")
	fs.MarkHidden("stderrthreshold")
	fs.MarkHidden("vmodule")
	fs.MarkHidden("log_backtrace_at")
}
