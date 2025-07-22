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

ifndef bin_dir
$(error bin_dir is not set)
endif

ifndef kind_cluster_name
$(error kind_cluster_name is not set)
endif

ifndef kind_cluster_config
$(error kind_cluster_config is not set)
endif

##########################################

kind_kubeconfig := $(bin_dir)/scratch/kube.config
absolute_kubeconfig := $(CURDIR)/$(kind_kubeconfig)

$(bin_dir)/scratch/cluster-check: FORCE | $(NEEDS_KIND) $(bin_dir)/scratch
	@if ! $(KIND) get clusters -q | grep -q "^$(kind_cluster_name)\$$"; then \
		echo "❌  cluster $(kind_cluster_name) not found. Starting ..."; \
		echo "trigger" > $@; \
	else \
		echo "✅  existing cluster $(kind_cluster_name) found"; \
	fi
	$(eval export KUBECONFIG=$(absolute_kubeconfig))

kind_post_create_hook ?= 
$(kind_kubeconfig): $(kind_cluster_config) $(bin_dir)/scratch/cluster-check | images-preload $(bin_dir)/scratch $(NEEDS_KIND) $(NEEDS_KUBECTL) $(NEEDS_CTR)
	@[ -f "$(bin_dir)/scratch/cluster-check" ] && ( \
		$(KIND) delete cluster --name $(kind_cluster_name); \
		$(CTR) load -i $(docker.io/kindest/node.TAR); \
		$(KIND) create cluster \
			--image $(docker.io/kindest/node.FULL) \
			--name $(kind_cluster_name) \
			--config "$<"; \
		$(CTR) exec $(kind_cluster_name)-control-plane find /mounted_images/ -name "*.tar" -exec echo {} \; -exec ctr --namespace=k8s.io images import --all-platforms --no-unpack --digests {} \; ; \
		$(MAKE) --no-print-directory noop $(kind_post_create_hook); \
		$(KUBECTL) config use-context kind-$(kind_cluster_name); \
	) || true

	$(KIND) get kubeconfig --name $(kind_cluster_name) > $@

.PHONY: kind-cluster
kind-cluster: $(kind_kubeconfig)

.PHONY: kind-cluster-load
## Create Kind cluster and wait for nodes to be ready
## Load the kubeconfig into the default location so that
## it can be easily queried by kubectl. This target is
## meant to be used directly, NOT as a dependency.
## Use `kind-cluster` as a dependency instead.
## @category [shared] Kind cluster
kind-cluster-load: kind-cluster | $(NEEDS_KUBECTL)
	mkdir -p ~/.kube
	KUBECONFIG=~/.kube/config:$(kind_kubeconfig) $(KUBECTL) config view --flatten > ~/.kube/config
	$(KUBECTL) config use-context kind-$(kind_cluster_name)

.PHONY: kind-cluster-clean
## Delete the Kind cluster
## @category [shared] Kind cluster
kind-cluster-clean: $(NEEDS_KIND)
	$(KIND) delete cluster --name $(kind_cluster_name)
	rm -rf $(kind_kubeconfig)
	$(MAKE) --no-print-directory noop $(kind_post_create_hook)

.PHONY: kind-logs
## Get the Kind cluster
## @category [shared] Kind cluster
kind-logs: | kind-cluster $(NEEDS_KIND) $(ARTIFACTS)
	rm -rf $(ARTIFACTS)/e2e-logs
	mkdir -p $(ARTIFACTS)/e2e-logs
	$(KIND) export logs $(ARTIFACTS)/e2e-logs --name=$(kind_cluster_name)
