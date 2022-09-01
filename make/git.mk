RELEASE_VERSION := $(shell git describe --tags --match='v*' --abbrev=14)

GITCOMMIT := $(shell git rev-parse HEAD)

IS_TAGGED_RELEASE := $(shell git describe --exact-match HEAD >/dev/null 2>&1 && echo "true" || echo "false")

IS_PRERELEASE := $(shell echo $(RELEASE_VERSION) | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$$' - && echo "false" || echo "true")

.PHONY: gitver
gitver:
	@echo "Release version:   \"$(RELEASE_VERSION)\""
	@echo "Is tagged release: \"$(IS_TAGGED_RELEASE)\""
	@echo "Is prerelease:     \"$(IS_PRERELEASE)\""
	@echo "Git commit hash:   \"$(GITCOMMIT)\""

.PHONY: release-version
release-version:
	@echo "$(RELEASE_VERSION)"

# Lists all remote tags on the upstream, which gives tags in format:
# "<commit> ref/tags/<tag>". Strips commit + tag prefix, filters out tags for v1+,
# and manually removes v1.2.0-alpha.1, since that version's manifest contains
# duplicate CRD resources (2 CRDs with the same name) which in turn can cause problems
# with the versionchecker test.
# Open question: how do we decide when to refresh this target?
$(BINDIR)/scratch/git/upstream-tags.txt: | $(BINDIR)/scratch/git
	git ls-remote --tags --refs https://github.com/cert-manager/cert-manager.git | \
		awk '{print $$2;}' | \
		sed 's/refs\/tags\///' | \
		sed -n '/v1.0.0/,$$p' | \
		grep -v "v1.2.0-alpha.1" > $@

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
