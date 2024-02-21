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

package logs

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/go-logr/logr"
	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/component-base/logs"
	logsapi "k8s.io/component-base/logs/api/v1"
	_ "k8s.io/component-base/logs/json/register"
	"k8s.io/klog/v2"

	"github.com/cert-manager/cert-manager/pkg/api"
)

var (
	Log = klog.TODO().WithName("cert-manager")
)

const (
	// Following analog to https://github.com/kubernetes/community/blob/master/contributors/devel/sig-instrumentation/logging.md

	ErrorLevel        = 0
	WarnLevel         = 1
	InfoLevel         = 2
	ExtendedInfoLevel = 3
	DebugLevel        = 4
	TraceLevel        = 5
)

// GlogWriter serves as a bridge between the standard log package and the glog package.
type GlogWriter struct{}

// Write implements the io.Writer interface.
func (writer GlogWriter) Write(data []byte) (n int, err error) {
	klog.Info(string(data))
	return len(data), nil
}

// InitLogs initializes logs the way we want for kubernetes.
func InitLogs() {
	logs.InitLogs()

	log.SetOutput(GlogWriter{})
	log.SetFlags(0)
}

func AddFlagsNonDeprecated(opts *logsapi.LoggingConfiguration, fs *pflag.FlagSet) {
	var allFlags pflag.FlagSet
	logsapi.AddFlags(opts, &allFlags)

	allFlags.VisitAll(func(f *pflag.Flag) {
		switch f.Name {
		case "logging-format", "log-flush-frequency", "v", "vmodule":
			fs.AddFlag(f)
		}
	})
}

func AddFlags(opts *logsapi.LoggingConfiguration, fs *pflag.FlagSet) {
	var allFlags flag.FlagSet
	klog.InitFlags(&allFlags)

	allFlags.VisitAll(func(f *flag.Flag) {
		switch f.Name {
		case "add_dir_header", "alsologtostderr", "log_backtrace_at", "log_dir", "log_file", "log_file_max_size",
			"logtostderr", "one_output", "skip_headers", "skip_log_headers", "stderrthreshold":
			pf := pflag.PFlagFromGoFlag(f)
			pf.Deprecated = "this flag may be removed in the future"
			pf.Hidden = true
			fs.AddFlag(pf)
		}
	})

	AddFlagsNonDeprecated(opts, fs)
}

func ValidateAndApply(opts *logsapi.LoggingConfiguration) error {
	return logsapi.ValidateAndApply(opts, nil)
}

func ValidateAndApplyAsField(opts *logsapi.LoggingConfiguration, fldPath *field.Path) error {
	return logsapi.ValidateAndApplyAsField(opts, nil, fldPath)
}

// FlushLogs flushes logs immediately.
func FlushLogs() {
	logs.FlushLogs()
}

const (
	ResourceNameKey      = "resource_name"
	ResourceNamespaceKey = "resource_namespace"
	ResourceKindKey      = "resource_kind"
	ResourceVersionKey   = "resource_version"

	RelatedResourceNameKey      = "related_resource_name"
	RelatedResourceNamespaceKey = "related_resource_namespace"
	RelatedResourceKindKey      = "related_resource_kind"
	RelatedResourceVersionKey   = "related_resource_version"
)

func WithResource(l logr.Logger, obj metav1.Object) logr.Logger {
	var gvk schema.GroupVersionKind

	if runtimeObj, ok := obj.(runtime.Object); ok {
		gvks, _, _ := api.Scheme.ObjectKinds(runtimeObj)
		if len(gvks) > 0 {
			gvk = gvks[0]
		}
	}

	return l.WithValues(
		ResourceNameKey, obj.GetName(),
		ResourceNamespaceKey, obj.GetNamespace(),
		ResourceKindKey, gvk.Kind,
		ResourceVersionKey, gvk.Version,
	)
}

func WithRelatedResource(l logr.Logger, obj metav1.Object) logr.Logger {
	var gvk schema.GroupVersionKind

	if runtimeObj, ok := obj.(runtime.Object); ok {
		gvks, _, _ := api.Scheme.ObjectKinds(runtimeObj)
		if len(gvks) > 0 {
			gvk = gvks[0]
		}
	}

	return l.WithValues(
		RelatedResourceNameKey, obj.GetName(),
		RelatedResourceNamespaceKey, obj.GetNamespace(),
		RelatedResourceKindKey, gvk.Kind,
		RelatedResourceVersionKey, gvk.Version,
	)
}

func WithRelatedResourceName(l logr.Logger, name, namespace, kind string) logr.Logger {
	return l.WithValues(
		RelatedResourceNameKey, name,
		RelatedResourceNamespaceKey, namespace,
		RelatedResourceKindKey, kind,
	)
}

func FromContext(ctx context.Context, names ...string) logr.Logger {
	l, err := logr.FromContext(ctx)
	if err != nil {
		l = Log
	}
	for _, n := range names {
		l = l.WithName(n)
	}
	return l
}

func NewContext(ctx context.Context, l logr.Logger, names ...string) context.Context {
	for _, n := range names {
		l = l.WithName(n)
	}
	return logr.NewContext(ctx, l)
}

func V(level int) klog.Verbose {
	return klog.V(klog.Level(level))
}

// LogWithFormat is a wrapper for logger that adds Infof method to log messages
// with the given format and arguments.
//
// Used as a patch to the controller eventBroadcaster for sending non-string objects.
type LogWithFormat struct {
	logr.Logger
}

func WithInfof(l logr.Logger) *LogWithFormat {
	return &LogWithFormat{l}
}

// Infof logs message with the given format and arguments.
func (l *LogWithFormat) Infof(format string, a ...interface{}) {
	l.Info(fmt.Sprintf(format, a...))
}
