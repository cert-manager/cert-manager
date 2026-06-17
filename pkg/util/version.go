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

package util

import (
	"fmt"
	"runtime"
)

type Version struct {
	GitVersion   string `json:"gitVersion"`
	GitCommit    string `json:"gitCommit"`
	GitTreeState string `json:"gitTreeState"`
	GoVersion    string `json:"goVersion"`
	Compiler     string `json:"compiler"`
	Platform     string `json:"platform"`
}

// This variable block holds information used to build up the version string
var (
	AppGitState  = ""
	AppGitCommit = ""
	AppVersion   = "canary"
)

func VersionInfo() Version {
	return Version{
		GitVersion:   AppVersion,
		GitCommit:    AppGitCommit,
		GitTreeState: AppGitState,
		GoVersion:    runtime.Version(),
		Compiler:     runtime.Compiler,
		Platform:     fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

func version() string {
	v := AppVersion
	if AppVersion == "canary" && AppGitCommit != "" {
		v += "-" + AppGitCommit
	}
	if AppGitState != "" {
		v += fmt.Sprintf(" (%v)", AppGitState)
	}
	return v
}
