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

# Lists all remote tags on the upstream, which gives tags in format:
# "<commit> ref/tags/<tag>". Strips commit + tag prefix, filters out tags for v1+,
# and manually removes v1.2.0-alpha.1, since that version's manifest contains
# duplicate CRD resources (2 CRDs with the same name) which in turn can cause problems
# with the versionchecker test.
# Open question: how do we decide when to refresh this target?
bin/scratch/git/upstream-tags.txt: | bin/scratch/git
	git ls-remote --tags --refs https://github.com/cert-manager/cert-manager.git | \
		awk '{print $$2;}' | \
		sed 's/refs\/tags\///' | \
		sed -n '/v1.0.0/,$$p' | \
		grep -v "v1.2.0-alpha.1" > $@

bin/release-version: | bin
	@test "$(RELEASE_VERSION)" == "$$(cat "$@" 2>/dev/null)" || echo $(RELEASE_VERSION) > $@

bin/scratch/git:
	@mkdir -p $@
