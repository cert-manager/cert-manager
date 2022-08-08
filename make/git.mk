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

# Open question: how do we decide when to refresh this target?
$(BINDIR)/scratch/git/upstream-tags.txt: | $(BINDIR)/scratch/git
	./hack/build/version.sh list-published-releases https://github.com/cert-manager/cert-manager.git > $@

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
