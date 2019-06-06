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
/*
VCert is a Go library, SDK, and command line utility designed to simplify key generation and enrollment of machine identities (also known as SSL/TLS certificates and keys) that comply with enterprise security policy by using the Venafi Platform or Venafi Cloud.
*/
package vcert

import (
	"fmt"
)

//projectName contains the friendly name of the vcert utiltity
const projectName string = "Venafi Certificate Utility"

var (
	versionBuildTimeStamp string
	versionString         string
)

//GetFormattedVersionString gets a friendly printable string to represent the version
func GetFormattedVersionString() string {
	if versionBuildTimeStamp != "" {
		versionBuildTimeStamp = fmt.Sprintf("\tBuild Timestamp: %s\n", versionBuildTimeStamp)
	}
	if versionString == "" {
		versionString = "Unknown"
	}
	return fmt.Sprintf("%s\n\tVersion: %s\n%s", projectName, versionString, versionBuildTimeStamp)
}
