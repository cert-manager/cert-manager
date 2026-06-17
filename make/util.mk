# Copyright 2023 The cert-manager Authors.
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

# Utility helper function to "get every go file in all except binary / make dirs"
# The first argument $(1) defines the commands which the find output are piped into
# Note that the "-not \( ... -prune \)" syntax is important here, if a little trickier to
# understand. It causes find to prune entire search branches and not search inside the path.
# If we used "-not -path X" instead, find would _still look inside X_.
define get-sources
$(shell find . -not \( -path "./$(bin_dir)/*" -prune \) -not \( -path "./bin/*" -prune \) -not \( -path "./make/*" -prune \) -name "*.go" | $(1))
endef

.PHONY: print-bindir
print-bindir:
	@echo $(bin_dir)

.PHONY: print-sources
print-sources:
	@echo $(SOURCES)

.PHONY: print-source-dirs
print-source-dirs:
	@echo $(SOURCE_DIRS)
