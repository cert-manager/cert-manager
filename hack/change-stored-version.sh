#!/usr/bin/env bash
# Copyright 2020 The Jetstack cert-manager contributors.
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

set -o errexit
set -o nounset
set -o pipefail

REPO_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/../" > /dev/null && pwd )"

git reset --hard

echo moving k8s v1 to corev1
find cmd pkg test -type f -name '*.go' | \
    fgrep -v --file "${REPO_ROOT}/hack/change-stored-version.ignorepatterns.txt" | \
    xargs -r fgrep --files-with-matches 'v1 "k8s.io/api/core/v1"' | \
    xargs -r sed -E -i \
          -e 's|(\W)v1 "k8s\.io/api/core/v1"|\1corev1 "k8s.io/api/core/v1"|g' \
          -e 's/(\W)v1\./\1corev1./g' || echo none

echo CM updating versioned clientsets
find cmd pkg test -type f -name '*.go' | \
    fgrep -v --file "${REPO_ROOT}/hack/change-stored-version.ignorepatterns.txt" | \
    xargs -r fgrep --files-with-matches CertmanagerV1alpha2 | \
    xargs -r sed -i \
          -e 's/v1alpha2/v1/g' \
          -e 's/CertmanagerV1alpha2/CertmanagerV1/g' || echo none

echo CM updating versioned listers
find cmd pkg test -type f -name '*.go' | \
    fgrep -v --file "${REPO_ROOT}/hack/change-stored-version.ignorepatterns.txt" | \
    xargs -r fgrep --files-with-matches '"github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha2"' | \
    xargs -r sed -i \
          -e 's/v1alpha2/v1/g' || echo none

echo CM updating versioned informers
find cmd pkg test -type f -name '*.go' | \
    fgrep -v --file "${REPO_ROOT}/hack/change-stored-version.ignorepatterns.txt" | \
    xargs -r fgrep --files-with-matches '.V1alpha2()' | \
    xargs -r sed -i \
          -e 's/v1alpha2/v1/g' \
          -e 's/\.V1alpha2()/.V1()/g' || echo none

echo CM updating remaining certmanager.v1alpha2 references
find cmd pkg test -type f -name '*.go' | \
    fgrep -v --file "${REPO_ROOT}/hack/change-stored-version.ignorepatterns.txt" | \
    xargs -r fgrep --files-without-match '"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"' | \
    xargs -r fgrep --files-with-matches '"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"' | \
    xargs -r sed -i \
          -e 's/v1alpha2/v1/g' || echo none

echo ACME updating versioned clientsets
find cmd pkg test -type f -name '*.go' | \
    fgrep -v --file "${REPO_ROOT}/hack/change-stored-version.ignorepatterns.txt" | \
    xargs -r fgrep --files-with-matches AcmeV1alpha2 | \
    xargs -r sed -i \
          -e 's/v1alpha2/v1/g' \
          -e 's/AcmeV1alpha2/AcmeV1/g' || echo none

echo ACME updating versioned listers
find cmd pkg test -type f -name '*.go' | \
    fgrep -v --file "${REPO_ROOT}/hack/change-stored-version.ignorepatterns.txt" | \
    xargs -r fgrep --files-with-matches '"github.com/jetstack/cert-manager/pkg/client/listers/acme/v1alpha2"' | \
    xargs -r sed -i \
          -e 's/v1alpha2/v1/g' || echo none

echo ACME updating remaining acme
find cmd pkg test -type f -name '*.go' | \
    fgrep -v --file "${REPO_ROOT}/hack/change-stored-version.ignorepatterns.txt" | \
    xargs -r fgrep --files-with-matches '"github.com/jetstack/cert-manager/pkg/apis/acme/v1alpha2"' | \
    xargs -r sed -i \
          -e 's/v1alpha2/v1/g' || echo none found

echo Updating field names

sed -i -E \
    -e 's/URISANs(\W)/URIs\1/g' \
    -e 's/EmailSANs(\W)/EmailAddresses\1/g' \
    pkg/util/pki/csr.go \
    test/unit/gen/certificate.go \
    pkg/controller/certificates/util.go \
    test/e2e/framework/helper/certificates.go \
    test/e2e/suite/conformance/certificates/suite.go


sed -i \
    -e 's/pec.Organization/pec.Subject.Organizations/g' \
    pkg/util/pki/csr.go \
    test/unit/gen/certificate.go \
    pkg/controller/certificates/util.go

sed -i -E \
    -e 's/(\W)CSRPEM/\1Request/g' \
    pkg/util/pki/csr.go \
    pkg/controller/certificates/util.go \
    cmd/ctl/pkg/create/certificaterequest/certificaterequest.go \
    test/unit/gen/certificaterequest.go \
    pkg/controller/certificaterequests/vault/vault.go \
    pkg/controller/certificaterequests/venafi/venafi.go \
    pkg/controller/certificaterequests/acme/acme.go \
    pkg/controller/certificates/requestmanager/requestmanager_controller.go \
    pkg/controller/certificates/trigger/policies/policies_test.go \
    pkg/controller/certificates/internal/test/test.go \
    pkg/controller/certificates/requestmanager/requestmanager_controller_test.go \
    pkg/controller/certificates/issuing/issuing_controller.go \
    pkg/controller/certificates/requestmanager/util_test.go \
    test/e2e/framework/helper/certificaterequests.go \
    test/e2e/util/util.go

sed -i -E \
    -e 's/(\W)CSR(\W)?/\1Request\2/g' \
    pkg/controller/certificaterequests/acme/acme.go \
    test/unit/gen/order.go \
    pkg/controller/acmeorders/sync.go

sed -i \
    -e 's/pec\.KeyAlgorithm/pec.PrivateKey.Algorithm/g' \
    -e 's/pec\.KeySize/pec.PrivateKey.Size/g' \
    -e 's/pec\.KeyEncoding/pec.PrivateKey.Encoding/g' \
    pkg/util/pki/csr.go \
    pkg/util/pki/generate.go \
    pkg/controller/certificates/util.go \
    test/unit/gen/certificate.go \
    cmd/ctl/pkg/create/certificaterequest/certificaterequest.go \
    pkg/controller/certificates/internal/test/test.go \
    pkg/controller/certificates/issuing/issuing_controller.go \
    pkg/controller/certificates/requestmanager/util_test.go \
    pkg/controller/certificates/issuing/temporary.go \
    pkg/util/pki/parse_test.go \
    test/e2e/framework/helper/certificates.go \
    test/e2e/suite/issuers/selfsigned/certificate.go \
    test/e2e/suite/issuers/ca/certificate.go


sed -i -E \
    -e 's/(v1|cmapi)\.KeyEncoding/\1.PrivateKeyEncoding/g' \
    -e 's/(v1|cmapi)\.KeyAlgorithm/\1.PrivateKeyAlgorithm/g' \
    pkg/util/pki/generate.go \
    pkg/util/pki/generate_test.go \
    pkg/util/pki/parse_test.go \
    pkg/util/pki/csr.go \
    pkg/util/pki/csr_test.go \
    test/unit/gen/certificate.go \
    pkg/controller/certificates/util_test.go \
    pkg/controller/certificates/internal/secretsmanager/keystore_test.go \
    test/e2e/framework/helper/certificates.go \
    test/e2e/framework/helper/certificaterequests.go

sed -i \
    -e 's/\AuthzURL/AuthorizationURL/g' \
    pkg/controller/acmechallenges/sync.go \
    pkg/controller/acmeorders/util.go

${REPO_ROOT}/hack/update-gofmt.sh
patch -p1 < ${REPO_ROOT}/hack/change-stored-version.patch

echo "CHANGES:"
git status | tee changes.txt | wc -l
tail changes.txt
echo "ERRORS:"
if ! go vet ./cmd/... ./pkg/... ./test/...  >errors.txt 2>&1; then
    tail errors.txt
    wc -l < errors.txt
fi
date
