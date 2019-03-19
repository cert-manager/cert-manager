#!/bin/bash

# Copyright 2019 The Jetstack cert-manager contributors.
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

# This script will provision a development environment using kind on your local
# machine.
# The end result should be an environment that can pass e2e tests.

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
source "${SCRIPT_ROOT}/lib/lib.sh"

echo "+++ Creating cluster using kind"
"${SCRIPT_ROOT}/lib/cluster_create.sh"

echo "+++ Building cert-manager images from source and exporting them to the development cluster"
"${SCRIPT_ROOT}/lib/build_images.sh"

echo ""
echo ""
echo "Your development environment is now ready."
echo
echo "A single node Kubernetes cluster has been provisioned in a Docker container"
echo "on your machine."
echo ""
echo "You should now configure your shell to use the KUBECONFIG file that has"
echo "been generated in order to access this cluster:"
echo ""
echo "  export KUBECONFIG=\$HOME/.kube/kind-config-${KIND_CLUSTER_NAME}"
echo ""
echo ""
echo "A freshly built copy of the cert-manager images have also been exported to"
echo "the docker daemon in this single node Kubernetes cluster."
echo ""
echo "You can build and export a fresh copy of these images with:"
echo ""
echo "  ./hack/ci/lib/build_images.sh"
echo ""
echo ""
echo "You should now be able to run end-to-end tests using:"
echo ""
echo "  make e2e_test"
echo ""
echo ""
echo "We have \*\*not\*\* automatically deployed cert-manager into this cluster."
echo "To deploy cert-manager into this cluster, run:"
echo ""
echo "  bazel run //hack/bin:helm -- install \\"
echo "      --name cert-manager \\"
echo "      --namespace cert-manager \\"
echo "      --values ./test/fixtures/cert-manager-values.yaml \\"
echo "      ./contrib/charts/cert-manager"
echo ""
echo ""
echo "Each time you make a change and run build_images.sh, you will need to manually"
echo "delete the cert-manager pod that is deployed in the cert-manager namespace."
echo ""
echo "Thanks for contributing!"
echo ""
echo ""