package listers

import (
	"bufio"
	"bytes"
	"runtime"
	"strings"
	"testing"
)

// Returns the caller's function name with the full package import path.
func curFuncName() (fnName string) {
	pc, _, _, _ := runtime.Caller(1)
	return runtime.FuncForPC(pc).Name()
}

// failWithStack does the same as assert.Fail except it gives you the
// ability to give your own stack frames. The purpose of this function is
// just to help the developer who wants to know where a Testify assertion
// failed.
//
// We use that whenever we want to do an assertion that happens in a
// t.Cleanup function, since the t.Cleanup happens outside of the user's
// test file which means the stack frames are totally off.
func failWithStack(t *testing.T, stackFrames []string, msg string) {
	// The following is a vendored version of Testify's assert.Fail.
	type labeledContent struct{ Label, Content string }
	content := []labeledContent{
		{Label: "Error Trace", Content: strings.Join(stackFrames, "\n")},
		{Label: "Error", Content: msg},
		{Label: "Test", Content: t.Name()},
	}

	// Helper that re-wrap and indent the "content" fields of the above
	// content array.
	indentMessageLines := func(message string, longestLabelLen int) string {
		buf := new(bytes.Buffer)
		for i, scanner := 0, bufio.NewScanner(strings.NewReader(message)); scanner.Scan(); i++ {
			if i != 0 {
				buf.WriteString("\n\t" + strings.Repeat(" ", longestLabelLen+1) + "\t")
			}
			buf.WriteString(scanner.Text())
		}
		return buf.String()
	}

	longestLabelLen := 0
	for _, v := range content {
		if len(v.Label) > longestLabelLen {
			longestLabelLen = len(v.Label)
		}
	}

	// Turn the above content slice into a nicely formatted string that
	// wraps and properly indented.
	var output string
	for _, v := range content {
		output += "\t" + v.Label + ":" + strings.Repeat(" ", longestLabelLen-len(v.Label)) + "\t" + indentMessageLines(v.Content, longestLabelLen) + "\n"
	}

	t.Errorf("\n%s", ""+output)
}
