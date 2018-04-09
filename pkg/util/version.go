package util

import "fmt"

var (
	AppGitState  = ""
	AppGitCommit = ""
	AppVersion   = "canary"
)

func version() string {
	v := AppVersion
	if AppGitCommit != "" {
		v += "-" + AppGitCommit
	}
	if AppGitState != "" {
		v += fmt.Sprintf(" (%v)", AppGitState)
	}
	return v
}
