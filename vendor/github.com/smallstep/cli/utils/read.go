package utils

import (
	"bufio"
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"unicode"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/ui"
)

// In command line utilities, it is a de facto standard that a hyphen "-"
// indicates STDIN as a file to be read.
const stdinFilename = "-"

// stdin points to os.Stdin.
var stdin = os.Stdin

// FileExists is a wrapper on os.Stat that returns false if os.Stat returns an
// error, it returns true otherwise. This method does not care if os.Stat
// returns any other kind of errors.
func FileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// ReadAll returns a slice of bytes with the content of the given reader.
func ReadAll(r io.Reader) ([]byte, error) {
	b, err := ioutil.ReadAll(r)
	return b, errors.Wrap(err, "error reading data")
}

// ReadString reads one line from the given io.Reader.
func ReadString(r io.Reader) (string, error) {
	br := bufio.NewReader(r)
	str, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", errors.Wrap(err, "error reading string")
	}
	return strings.TrimSpace(str), nil
}

// ReadPasswordFromFile reads and returns the password from the given filename.
// The contents of the file will be trimmed at the right.
func ReadPasswordFromFile(filename string) ([]byte, error) {
	password, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errs.FileError(err, filename)
	}
	password = bytes.TrimRightFunc(password, unicode.IsSpace)
	return password, nil
}

// ReadStringPasswordFromFile reads and returns the password from the given filename.
// The contents of the file will be trimmed at the right.
func ReadStringPasswordFromFile(filename string) (string, error) {
	b, err := ReadPasswordFromFile(filename)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ReadInput from stdin if something is detected or ask the user for an input
// using the given prompt.
func ReadInput(prompt string) ([]byte, error) {
	st, err := stdin.Stat()
	if err != nil {
		return nil, errors.Wrap(err, "error reading data")
	}

	if st.Size() == 0 && st.Mode()&os.ModeNamedPipe == 0 {
		return ui.PromptPassword(prompt)
	}

	return ReadAll(stdin)
}

// ReadFile returns the contents of the file identified by name. It reads from
// STDIN if name is a hyphen ("-").
func ReadFile(name string) (b []byte, err error) {
	if name == stdinFilename {
		name = "/dev/stdin"
		b, err = ioutil.ReadAll(stdin)
	} else {
		b, err = ioutil.ReadFile(name)
	}
	if err != nil {
		return nil, errs.FileError(err, name)
	}
	return b, nil
}
