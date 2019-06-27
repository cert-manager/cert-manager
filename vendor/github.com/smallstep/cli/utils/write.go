package utils

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/ui"
)

var (
	// ErrFileExists is the error returned if a file exists.
	ErrFileExists = errors.New("file exists")

	// ErrIsDir is the error returned if the file is a directory.
	ErrIsDir = errors.New("file is a directory")
)

// WriteFile wraps ioutil.WriteFile with a prompt to overwrite a file if
// the file exists. It returns ErrFileExists if the user picks to not overwrite
// the file. If force is set to true, the prompt will not be presented and the
// file if exists will be overwritten.
func WriteFile(filename string, data []byte, perm os.FileMode) error {
	if command.IsForce() {
		return ioutil.WriteFile(filename, data, perm)
	}

	st, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return ioutil.WriteFile(filename, data, perm)
		}
		return errors.Wrapf(err, "error reading information for %s", filename)
	}

	if st.IsDir() {
		return ErrIsDir
	}

	str, err := ui.Prompt(fmt.Sprintf("Would you like to overwrite %s [y/n]", filename), ui.WithValidateYesNo())
	if err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(str)) {
	case "y", "yes":
	case "n", "no":
		return ErrFileExists
	}

	return ioutil.WriteFile(filename, data, perm)
}
