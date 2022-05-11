# Inspired from
# https://github.com/Mischback/django-calingen/blob/3f0e6db6/Makefile
# and https://gist.github.com/klmr/575726c7e05d8780505a

# fancy colors
cyan := "$$(tput setaf 6)"
green := "$$(tput setaf 2)"
red := "$$(tput setaf 1)"
yel := "$$(tput setaf 3)"
gray := "$$(tput setaf 8)"
grayb := "$$(printf "\033[1m"; tput setaf 8)"
end := "$$(tput sgr0)"
TARGET_STYLED_HELP_NAME = "$(cyan)TARGET$(end)"
ARGUMENTS_HELP_NAME = "$(green)ARGUMENT$(end)=$(red)VALUE$(end)"

# This mountrous sed is compatible with both GNU sed and BSD sed (for macOS).
# That's why "-E", "|", "+", "\s", "?", and "\t" aren't used. See the details
# about BSD sed vs. GNU sed: https://riptutorial.com/sed/topic/9436

target_regex := [a-zA-Z0-9%_\/%-][a-zA-Z0-9%_\/%-]*
variable_regex := [^:= ][^:= ]*
variable_assignment_regex := [ ]*:*[+:!\?]*= *
value_regex := .*
category_annotation_regex := @category *
category_regex := [^<][^<]*

# We first parse and markup with these ad-hoc tags, and then we turn the markup
# into a colorful output.
target_tag_start := <target-definition>
target_tag_end := </target-definition>
target_variable_tag_start := <target-variable>
target_variable_tag_end := </target-variable>
variable_tag_start := <variable>
variable_tag_end := </variable>
global_variable_tag_start := <global-variable>
global_variable_tag_end := </global-variable>
value_tag_start := <value>
value_tag_end := </value>
prerequisites_tag_start := <prerequisites>
prerequisites_tag_end := </prerequisites>
doc_tag_start := <doc>
doc_tag_indented_start := <doc-indent>
doc_tag_indented_end := </doc-indent>
doc_tag_end := </doc>
category_tag_start := <category-other>
category_tag_end := </category-other>
default_category_tag_start := <category-default>
default_category_tag_end := </category-default>

DEFAULT_CATEGORY = General

.PHONY: help
help:
	@echo "Usage: make [$(TARGET_STYLED_HELP_NAME) [$(TARGET_STYLED_HELP_NAME) ...]] [$(ARGUMENTS_HELP_NAME) [$(ARGUMENTS_HELP_NAME) ...]]"
	@cat ${MAKEFILE_LIST} \
	| tr '\t' '    ' \
	| sed -n -e "/^## / { \
		h; \
		s/.*/##/; \
		:doc" \
		-e "H; \
		n; \
		s|^##   *\(.*\)|$(doc_tag_start)$(doc_tag_indented_start)\1$(doc_tag_indented_end)$(doc_tag_end)|; \
		s|^## *\(.*\)|$(doc_tag_start)\1$(doc_tag_end)|; \
		t doc" \
		-e "s| *#[^#].*||; " \
		-e "s|^\(define *\)\($(variable_regex)\)$(variable_assignment_regex)\($(value_regex)\)|$(global_variable_tag_start)\2$(global_variable_tag_end)$(value_tag_start)\3$(value_tag_end)|;" \
		-e "s|^\($(variable_regex)\)$(variable_assignment_regex)\($(value_regex)\)|$(global_variable_tag_start)\1$(global_variable_tag_end)$(value_tag_start)\2$(value_tag_end)|;" \
		-e "s|^\($(target_regex)\) *: *\(\($(variable_regex)\)$(variable_assignment_regex)\($(value_regex)\)\)|$(target_variable_tag_start)\1$(target_variable_tag_end)$(variable_tag_start)\3$(variable_tag_end)$(value_tag_start)\4$(value_tag_end)|;" \
		-e "s|^\($(target_regex)\) *: *\($(target_regex)\( *$(target_regex)\)*\) *\(\| *\( *$(target_regex)\)*\)|$(target_tag_start)\1$(target_tag_end)$(prerequisites_tag_start)\2$(prerequisites_tag_end)|;" \
		-e "s|^\($(target_regex)\) *: *\($(target_regex)\( *$(target_regex)\)*\)|$(target_tag_start)\1$(target_tag_end)$(prerequisites_tag_start)\2$(prerequisites_tag_end)|;" \
		-e "s|^\($(target_regex)\) *: *\(\| *\( *$(target_regex)\)*\)|$(target_tag_start)\1$(target_tag_end)|;" \
		-e "s|^\($(target_regex)\) *: *|$(target_tag_start)\1$(target_tag_end)|;" \
		-e " \
		G; \
		s|## *\(.*\) *##|$(doc_tag_start)\1$(doc_tag_end)|; \
		s|\\n||g;" \
		-e "/$(category_annotation_regex)/!s|.*|$(default_category_tag_start)$(DEFAULT_CATEGORY)$(default_category_tag_end)&|" \
		-e "s|^\(.*\)$(doc_tag_start)$(category_annotation_regex)\($(category_regex)\)$(doc_tag_end)|$(category_tag_start)\2$(category_tag_end)\1|" \
		-e "p; \
	}" \
	| sort  \
	| sed -n \
		-e "s|$(default_category_tag_start)|$(category_tag_start)|" \
		-e "s|$(default_category_tag_end)|$(category_tag_end)|" \
		-e "{G; s|\($(category_tag_start)$(category_regex)$(category_tag_end)\)\(.*\)\n\1|\2|; s|\n.*||; H; }" \
		-e "s|$(category_tag_start)||" \
		-e "s|$(category_tag_end)|:\n|" \
		-e "s|$(target_variable_tag_start)|$(target_tag_start)|" \
		-e "s|$(target_variable_tag_end)|$(target_tag_end)|" \
		-e "s|$(target_tag_start)|    $(cyan)|" \
		-e "s|$(target_tag_end)|$(end) |" \
		-e "s|$(prerequisites_tag_start).*$(prerequisites_tag_end)||" \
		-e "s|$(variable_tag_start)|$(green)|g" \
		-e "s|$(variable_tag_end)|$(end)|" \
		-e "s|$(global_variable_tag_start)|    $(green)|g" \
		-e "s|$(global_variable_tag_end)|$(end)|" \
		-e "s|$(value_tag_start)| (default: $(red)|" \
		-e "s|$(value_tag_end)|$(end))|" \
		-e "s|$(doc_tag_indented_start)|$(grayb)|g" \
		-e "s|$(doc_tag_indented_end)|$(end)|g" \
		-e "s|$(doc_tag_start)|\n        |g" \
		-e "s|$(doc_tag_end)||g" \
		-e "p"
