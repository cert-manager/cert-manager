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

VERSION_INFO := $(shell ./hack/build/version.sh version .)

GIT_VERSION := $(patsubst GIT_VERSION=%,%,$(filter GIT_VERSION=%,$(VERSION_INFO)))
GIT_COMMIT := $(patsubst GIT_COMMIT=%,%,$(filter GIT_COMMIT=%,$(VERSION_INFO)))
IS_TAGGED_RELEASE := $(patsubst GIT_IS_TAGGED_RELEASE=%,%,$(filter GIT_IS_TAGGED_RELEASE=%,$(VERSION_INFO)))
IS_PRERELEASE := $(patsubst GIT_IS_PRERELEASE=%,%,$(filter GIT_IS_PRERELEASE=%,$(VERSION_INFO)))
IMAGE_NAME_SHORT := $(patsubst IMAGE_NAME_SHORT=%,%,$(filter IMAGE_NAME_SHORT=%,$(VERSION_INFO)))
IMAGE_NAME_LONG := $(patsubst IMAGE_NAME_LONG=%,%,$(filter IMAGE_NAME_LONG=%,$(VERSION_INFO)))
RELEASE_VERSION := $(IMAGE_NAME_LONG)

.PHONY: gitver
gitver:
	@echo "Release version:   \"$(RELEASE_VERSION)\""
	@echo "Is tagged release: \"$(IS_TAGGED_RELEASE)\""
	@echo "Is prerelease:     \"$(IS_PRERELEASE)\""
	@echo "Git commit hash:   \"$(GIT_COMMIT)\""

.PHONY: last-published-release
last-published-release:
	@./hack/build/version.sh last-published-release https://github.com/cert-manager/cert-manager.git

# Lists all remote tags on the upstream, which gives tags in format:
# "<commit> ref/tags/<tag>". Strips commit + tag prefix, filters out tags for v1+,
# and manually removes v1.2.0-alpha.1, since that version's manifest contains
# duplicate CRD resources (2 CRDs with the same name) which causes problems
# with the versionchecker test.
#
# This file has a version suffix so we can force all checkouts to pick up the new
# version in response to a change in how we generate it. Users will get warning messages
# printing explaining the latest version available in their checkout when they run tests,
# but sometimes we'll want to force a new version.
$(BINDIR)/scratch/git/upstream-tags.1.txt: | $(BINDIR)/scratch/git
	./hack/build/version.sh list-published-releases https://github.com/cert-manager/cert-manager.git > $@

# This target is preserved entirely to make it clear that the file has been renamed, so
# that anyone who has scripts which reference the file will know to update
$(BINDIR)/scratch/git/upstream-tags.txt: $(BINDIR)/scratch/git/upstream-tags.1.txt
	$(warning '$@' has been replaced by '$<'. Update your scripts to use the '$<' name instead.)
	cp $< $@

# The file "release-version" gets updated whenever git describe --tags changes.
# This is used by the $(BINDIR)/containers/*.tar.gz targets to make sure that the
# containers, which use the output of "git describe --tags" as their tag, get
# rebuilt whenever you check out a different commit. If we didn't do this, the
# Helm chart $(BINDIR)/cert-manager-*.tgz would refer to an image tag that doesn't
# exist in $(BINDIR)/containers/*.tar.gz.
#
# We use FORCE instead of .PHONY because this is a real file that can be used as
# a prerequisite. If we were to use .PHONY, then the file's timestamp would not
# be used to check whether targets should be rebuilt, and they would get
# constantly rebuilt.
$(BINDIR)/release-version: FORCE | $(BINDIR)
	@test "$(RELEASE_VERSION)" == "$(shell cat $@ 2>/dev/null)" || echo $(RELEASE_VERSION) > $@

$(BINDIR)/scratch/git:
	@mkdir -p $@
