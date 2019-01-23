/*
 * Copyright 2018 Venafi, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package vcert

import (
	"fmt"
)

//ProjectName contains the friendly name of the vcert utiltity
const ProjectName string = "Venafi Certificate Utility"

var (
	versionString         string
	versionBuildTimeStamp string
)

//GetFormattedVersionString gets a friendly printable string to represent the version
func GetFormattedVersionString() string {
	if versionBuildTimeStamp != "" {
		versionBuildTimeStamp = fmt.Sprintf("\tBuild Timestamp: %s\n", versionBuildTimeStamp)
	}
	return fmt.Sprintf("%s\n\tVersion: %s\n%s", ProjectName, GetVersionString(), versionBuildTimeStamp)
}

//GetVersionString gets a simple version string
func GetVersionString() string {
	if versionString == "" {
		versionString = "3.18.3.1"
	}
	return versionString
}
