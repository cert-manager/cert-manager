RELEASE_VERSION := $(shell git describe --tags)

GITCOMMIT := $(shell git rev-parse HEAD)

IS_TAGGED_RELEASE := $(shell git describe --exact-match HEAD >/dev/null 2>&1 && echo "true" || echo "false")

IS_PRERELEASE := $(shell echo $(RELEASE_VERSION) | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$$' - && echo "false" || echo "true")

.PHONY: gitver
gitver:
	@echo "Release version:   \"$(RELEASE_VERSION)\""
	@echo "Is tagged release: \"$(IS_TAGGED_RELEASE)\""
	@echo "Is prerelease:     \"$(IS_PRERELEASE)\""
	@echo "Git commit hash:   \"$(GITCOMMIT)\""
