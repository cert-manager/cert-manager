/*
Copyright 2020 The Jetstack cert-manager contributors.

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

	"k8s.io/kubectl/pkg/describe"
)

// This file defines implementation of the PrefixWriter interface defined in "k8s.io/kubectl/pkg/describe"
// This implementation is based on the one in the describe package, with a slight modification of having a baseLevel
// on top of which any other indentations are added.
// The purpose is be able to reuse functions in the describe package where the Level of the output is fixed,
// e.g. DescribeEvents() only prints out at Level 0.

// prefixWriter implements describe.PrefixWriter
type prefixWriter struct {
	out       io.Writer
	baseLevel int
}

var _ describe.PrefixWriter = &prefixWriter{}

// NewPrefixWriter creates a new PrefixWriter.
func NewPrefixWriter(out io.Writer) *prefixWriter {
	return &prefixWriter{out: out, baseLevel: 0}
}

func (pw *prefixWriter) Write(level int, format string, a ...interface{}) {
	level += pw.baseLevel
	levelSpace := "  "
	prefix := ""
	for i := 0; i < level; i++ {
		prefix += levelSpace
	}
	fmt.Fprintf(pw.out, prefix+format, a...)
}

func (pw *prefixWriter) WriteLine(a ...interface{}) {
	fmt.Fprintln(pw.out, a...)
}

func (pw *prefixWriter) Flush() {
	if f, ok := pw.out.(flusher); ok {
		f.Flush()
	}
}

func (pw *prefixWriter) SetBaseLevel(level int) {
	pw.baseLevel = level
}

type flusher interface {
	Flush()
}
