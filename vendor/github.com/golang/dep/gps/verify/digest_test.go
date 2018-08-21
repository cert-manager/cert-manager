// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package verify

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// crossBuffer is a test io.Reader that emits a few canned responses.
type crossBuffer struct {
	readCount  int
	iterations []string
}

func (cb *crossBuffer) Read(buf []byte) (int, error) {
	if cb.readCount == len(cb.iterations) {
		return 0, io.EOF
	}
	cb.readCount++
	return copy(buf, cb.iterations[cb.readCount-1]), nil
}

func streamThruLineEndingReader(t *testing.T, iterations []string) []byte {
	dst := new(bytes.Buffer)
	n, err := io.Copy(dst, newLineEndingReader(&crossBuffer{iterations: iterations}))
	if got, want := err, error(nil); got != want {
		t.Errorf("(GOT): %v; (WNT): %v", got, want)
	}
	if got, want := n, int64(dst.Len()); got != want {
		t.Errorf("(GOT): %v; (WNT): %v", got, want)
	}
	return dst.Bytes()
}

func TestLineEndingReader(t *testing.T) {
	testCases := []struct {
		input  []string
		output string
	}{
		{[]string{"\r"}, "\r"},
		{[]string{"\r\n"}, "\n"},
		{[]string{"now is the time\r\n"}, "now is the time\n"},
		{[]string{"now is the time\r\n(trailing data)"}, "now is the time\n(trailing data)"},
		{[]string{"now is the time\n"}, "now is the time\n"},
		{[]string{"now is the time\r"}, "now is the time\r"},     // trailing CR ought to convey
		{[]string{"\rnow is the time"}, "\rnow is the time"},     // CR not followed by LF ought to convey
		{[]string{"\rnow is the time\r"}, "\rnow is the time\r"}, // CR not followed by LF ought to convey

		// no line splits
		{[]string{"first", "second", "third"}, "firstsecondthird"},

		// 1->2 and 2->3 both break across a CRLF
		{[]string{"first\r", "\nsecond\r", "\nthird"}, "first\nsecond\nthird"},

		// 1->2 breaks across CRLF and 2->3 does not
		{[]string{"first\r", "\nsecond", "third"}, "first\nsecondthird"},

		// 1->2 breaks across CRLF and 2 ends in CR but 3 does not begin LF
		{[]string{"first\r", "\nsecond\r", "third"}, "first\nsecond\rthird"},

		// 1 ends in CR but 2 does not begin LF, and 2->3 breaks across CRLF
		{[]string{"first\r", "second\r", "\nthird"}, "first\rsecond\nthird"},

		// 1 ends in CR but 2 does not begin LF, and 2->3 does not break across CRLF
		{[]string{"first\r", "second\r", "\nthird"}, "first\rsecond\nthird"},

		// 1->2 and 2->3 both break across a CRLF, but 3->4 does not
		{[]string{"first\r", "\nsecond\r", "\nthird\r", "fourth"}, "first\nsecond\nthird\rfourth"},
		{[]string{"first\r", "\nsecond\r", "\nthird\n", "fourth"}, "first\nsecond\nthird\nfourth"},

		{[]string{"this is the result\r\nfrom the first read\r", "\nthis is the result\r\nfrom the second read\r"},
			"this is the result\nfrom the first read\nthis is the result\nfrom the second read\r"},
		{[]string{"now is the time\r\nfor all good engineers\r\nto improve their test coverage!\r\n"},
			"now is the time\nfor all good engineers\nto improve their test coverage!\n"},
		{[]string{"now is the time\r\nfor all good engineers\r", "\nto improve their test coverage!\r\n"},
			"now is the time\nfor all good engineers\nto improve their test coverage!\n"},
	}

	for _, testCase := range testCases {
		got := streamThruLineEndingReader(t, testCase.input)
		if want := []byte(testCase.output); !bytes.Equal(got, want) {
			t.Errorf("Input: %#v; (GOT): %#q; (WNT): %#q", testCase.input, got, want)
		}
	}
}

////////////////////////////////////////

func getTestdataVerifyRoot(t *testing.T) string {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(filepath.Dir(cwd), "_testdata/digest")
}

func TestDigestFromDirectoryBailsUnlessDirectory(t *testing.T) {
	prefix := getTestdataVerifyRoot(t)
	relativePathname := "launchpad.net/match"
	_, err := DigestFromDirectory(filepath.Join(prefix, relativePathname))
	if got, want := err, error(nil); got != want {
		t.Errorf("\n(GOT): %v; (WNT): %v", got, want)
	}
}

func TestDigestFromDirectory(t *testing.T) {
	relativePathname := "launchpad.net/match"
	want := []byte{0x7e, 0x10, 0x6, 0x2f, 0x8, 0x3, 0x3c, 0x76, 0xae, 0xbc, 0xa4, 0xc9, 0xec, 0x73, 0x67, 0x15, 0x70, 0x2b, 0x0, 0x89, 0x27, 0xbb, 0x61, 0x9d, 0xc7, 0xc3, 0x39, 0x46, 0x3, 0x91, 0xb7, 0x3b}

	// NOTE: Create the hash using both an absolute and a relative pathname to
	// ensure hash ignores prefix.

	t.Run("AbsolutePrefix", func(t *testing.T) {
		prefix := getTestdataVerifyRoot(t)
		got, err := DigestFromDirectory(filepath.Join(prefix, relativePathname))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Digest, want) {
			t.Errorf("\n(GOT):\n\t%#v\n(WNT):\n\t%#v", got, want)
		}
	})

	t.Run("RelativePrefix", func(t *testing.T) {
		prefix := "../_testdata/digest"
		got, err := DigestFromDirectory(filepath.Join(prefix, relativePathname))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Digest, want) {
			t.Errorf("\n(GOT):\n\t%#v\n(WNT):\n\t%#v", got, want)
		}
	})
}

func TestVerifyDepTree(t *testing.T) {
	vendorRoot := getTestdataVerifyRoot(t)

	wantSums := map[string][]byte{
		"github.com/alice/match":       {0x7e, 0x10, 0x6, 0x2f, 0x8, 0x3, 0x3c, 0x76, 0xae, 0xbc, 0xa4, 0xc9, 0xec, 0x73, 0x67, 0x15, 0x70, 0x2b, 0x0, 0x89, 0x27, 0xbb, 0x61, 0x9d, 0xc7, 0xc3, 0x39, 0x46, 0x3, 0x91, 0xb7, 0x3b},
		"github.com/alice/mismatch":    []byte("some non-matching digest"),
		"github.com/bob/emptyDigest":   nil, // empty hash result
		"github.com/bob/match":         {0x7e, 0x10, 0x6, 0x2f, 0x8, 0x3, 0x3c, 0x76, 0xae, 0xbc, 0xa4, 0xc9, 0xec, 0x73, 0x67, 0x15, 0x70, 0x2b, 0x0, 0x89, 0x27, 0xbb, 0x61, 0x9d, 0xc7, 0xc3, 0x39, 0x46, 0x3, 0x91, 0xb7, 0x3b},
		"github.com/charlie/notInTree": nil, // not in tree result ought to superseede empty digest result
		// matching result at seldom found directory level
		"launchpad.net/match": {0x7e, 0x10, 0x6, 0x2f, 0x8, 0x3, 0x3c, 0x76, 0xae, 0xbc, 0xa4, 0xc9, 0xec, 0x73, 0x67, 0x15, 0x70, 0x2b, 0x0, 0x89, 0x27, 0xbb, 0x61, 0x9d, 0xc7, 0xc3, 0x39, 0x46, 0x3, 0x91, 0xb7, 0x3b},
	}

	checkStatus := func(t *testing.T, status map[string]VendorStatus, key string, want VendorStatus) {
		t.Helper()
		got, ok := status[key]
		if !ok {
			t.Errorf("Want key: %q", key)
			return
		}
		if got != want {
			t.Errorf("Key: %q; (GOT): %v; (WNT): %v", key, got, want)
		}
	}

	t.Run("normal", func(t *testing.T) {
		t.Parallel()
		wantDigests := make(map[string]VersionedDigest)
		for k, v := range wantSums {
			wantDigests[k] = VersionedDigest{
				HashVersion: HashVersion,
				Digest:      v,
			}
		}

		status, err := CheckDepTree(vendorRoot, wantDigests)
		if err != nil {
			t.Fatal(err)
		}

		if got, want := len(status), 7; got != want {
			t.Errorf("Unexpected result count from VerifyDepTree:\n\t(GOT): %v\n\t(WNT): %v", got, want)
		}

		checkStatus(t, status, "github.com/alice/match", NoMismatch)
		checkStatus(t, status, "github.com/alice/mismatch", DigestMismatchInLock)
		checkStatus(t, status, "github.com/alice/notInLock", NotInLock)
		checkStatus(t, status, "github.com/bob/match", NoMismatch)
		checkStatus(t, status, "github.com/bob/emptyDigest", EmptyDigestInLock)
		checkStatus(t, status, "github.com/charlie/notInTree", NotInTree)
		checkStatus(t, status, "launchpad.net/match", NoMismatch)

		if t.Failed() {
			for k, want := range wantSums {
				got, err := DigestFromDirectory(filepath.Join(vendorRoot, k))
				if err != nil {
					t.Error(err)
				}
				if !bytes.Equal(got.Digest, want) {
					t.Errorf("Digest mismatch for %q\n(GOT):\n\t%#v\n(WNT):\n\t%#v", k, got, want)
				}
			}
		}

	})

	t.Run("hashv-mismatch", func(t *testing.T) {
		t.Parallel()
		wantDigests := make(map[string]VersionedDigest)
		for k, v := range wantSums {
			wantDigests[k] = VersionedDigest{
				HashVersion: HashVersion + 1,
				Digest:      v,
			}
		}

		status, err := CheckDepTree(vendorRoot, wantDigests)
		if err != nil {
			t.Fatal(err)
		}

		if got, want := len(status), 7; got != want {
			t.Errorf("Unexpected result count from VerifyDepTree:\n\t(GOT): %v\n\t(WNT): %v", got, want)
		}

		checkStatus(t, status, "github.com/alice/match", HashVersionMismatch)
		checkStatus(t, status, "github.com/alice/mismatch", HashVersionMismatch)
		checkStatus(t, status, "github.com/alice/notInLock", NotInLock)
		checkStatus(t, status, "github.com/bob/match", HashVersionMismatch)
		checkStatus(t, status, "github.com/bob/emptyDigest", HashVersionMismatch)
		checkStatus(t, status, "github.com/charlie/notInTree", NotInTree)
		checkStatus(t, status, "launchpad.net/match", HashVersionMismatch)
	})
}

func BenchmarkDigestFromDirectory(b *testing.B) {
	b.Skip("Eliding benchmark of user's Go source directory")

	prefix := filepath.Join(os.Getenv("GOPATH"), "src")

	for i := 0; i < b.N; i++ {
		_, err := DigestFromDirectory(prefix)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyDepTree(b *testing.B) {
	b.Skip("Eliding benchmark of user's Go source directory")

	prefix := filepath.Join(os.Getenv("GOPATH"), "src")

	for i := 0; i < b.N; i++ {
		_, err := CheckDepTree(prefix, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}
