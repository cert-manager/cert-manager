package config

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"path"
	"runtime"
	"time"
)

// version and buildTime are filled in during build by the Makefile
var (
	name      = "Smallstep CLI"
	buildTime = "N/A"
	commit    = "N/A"
)

// StepPathEnv defines the name of the environment variable that can overwrite
// the default configuration path.
const StepPathEnv = "STEPPATH"

// stepPath will be populated in init() with the proper STEPPATH.
var stepPath string

// StepPath returns the path for the step configuration directory, this is
// defined by the environment variable STEPPATH or if this is not set it will
// default to '$HOME/.step'.
func StepPath() string {
	return stepPath
}

func init() {
	l := log.New(os.Stderr, "", 0)

	// Get step path from environment or user's home directory
	stepPath = os.Getenv(StepPathEnv)
	if stepPath == "" {
		usr, err := user.Current()
		if err == nil && usr.HomeDir != "" {
			stepPath = path.Join(usr.HomeDir, ".step")
		} else if home := os.Getenv("HOME"); home != "" {
			stepPath = path.Join(home, ".step")
		} else {
			l.Fatalf("Error obtaining home directory, please define environment variable %s.", StepPathEnv)
		}
	}

	// Check for presence or attempt to create it if necessary.
	//
	// Some environments (e.g. third party docker images) might fail creating
	// the directory, so this should not panic if it can't.
	if fi, err := os.Stat(stepPath); err != nil {
		os.MkdirAll(stepPath, 0700)
	} else if !fi.IsDir() {
		l.Fatalf("File '%s' is not a directory.", stepPath)
	}
	// cleanup
	stepPath = path.Clean(stepPath)
}

// Set updates the Version and ReleaseDate
func Set(n, v, t string) {
	name = n
	buildTime = t
	commit = v
}

// Version returns the current version of the binary
func Version() string {
	out := commit
	if commit == "N/A" {
		out = "0000000-dev"
	}

	return fmt.Sprintf("%s/%s (%s/%s)",
		name, out, runtime.GOOS, runtime.GOARCH)
}

// ReleaseDate returns the time of when the binary was built
func ReleaseDate() string {
	out := buildTime
	if buildTime == "N/A" {
		out = time.Now().UTC().Format("2006-01-02 15:04 MST")
	}

	return out
}
