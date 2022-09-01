# Utility helper function to "get every go file in all except binary / make dirs"
# The first argument $(1) defines the commands which the find output are piped into
# Note that the "-not \( ... -prune \)" syntax is important here, if a little trickier to
# understand. It causes find to prune entire search branches and not search inside the path.
# If we used "-not -path X" instead, find would _still look inside X_.
define get-sources
$(shell find . -not \( -path "./$(BINDIR)/*" -prune \) -not \( -path "./bin/*" -prune \) -not \( -path "./make/*" -prune \) -name "*.go" | $(1))
endef

.PHONY: print-bindir
print-bindir:
	@echo $(BINDIR)

.PHONY: print-sources
print-sources:
	@echo $(SOURCES)

.PHONY: print-source-dirs
print-source-dirs:
	@echo $(call get-sources,cut -d'/' -f2 | sort | uniq | tr '\n' ' ')
