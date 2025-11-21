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


# see https://stackoverflow.com/a/53408233
sed_inplace := sed -i''
ifeq ($(HOST_OS),darwin)
	sed_inplace := sed -i ''
endif


.PHONY: update-third-party
## Update the code in the `third_party/` directory.
##
## @category Development
update-third-party: | $(NEEDS_KLONE)
	@pushd third_party && $(KLONE) sync
	@echo acme: Removing autocert
	@rm -rf third_party/forked/acme/autocert
	@echo acme: Updating import statements
	@find third_party/forked/acme -iname '*.go' \
  | xargs $(sed_inplace) -e 's%golang\.org/x/crypto/acme%github.com/cert-manager/cert-manager/third_party/forked/acme%g'
	@echo acme: Updating the package version in the user-agent string
	@$(sed_inplace) -e 's%golang\.org/x/crypto%github.com/cert-manager/cert-manager%' third_party/forked/acme/http.go
	@pushd third_party/forked/acme && curl -fsSL \
		-O https://raw.githubusercontent.com/golang/crypto/refs/heads/master/LICENSE \
		-O https://raw.githubusercontent.com/golang/crypto/refs/heads/master/PATENTS
