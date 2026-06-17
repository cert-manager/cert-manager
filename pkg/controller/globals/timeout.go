/*
Copyright 2022 The cert-manager Authors.

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

package globals

import "time"

const (
	// DefaultControllerContextTimeout is the default maximum amount of time which a single synchronize action in some controllers
	// may take before the sync will be cancelled by a context timeout.
	// This timeout might not be respected on all controllers thanks to backwards compatibility concerns, but it's a goal to have
	// all issuers have some default timeout which represents a default upper bound on the time they're permitted to take.
	DefaultControllerContextTimeout = 2 * time.Minute
)
