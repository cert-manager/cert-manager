#!/usr/bin/env bash

# Copyright 2022 The cert-manager Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


set -eu -o pipefail

# This script was used to update kind images, but Kind specifically discourages that
# saying that:
# > NOTE: You must use the @sha256 digest to guarantee an image built for this release,
# > until such a time as we switch to a different tagging scheme.
# > Even then we will highly encourage digest pinning for security and reproducibility reasons.
echo "latest-kind-images deprecated for cert-manager 1.13; see comments in $@"
exit 1
