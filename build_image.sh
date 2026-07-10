#!/bin/bash
# -
#   ========================LICENSE_START=================================
#   Copyright (C) 2024: Deutsche Telekom
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#   SPDX-License-Identifier: Apache-2.0
#   ========================LICENSE_END===================================


export IMAGE_NAME="nexus3.onap.org:10003/onap/policy-opa-pdp"
VERSION_FILE="version"
GO_VERSION="1.23.3"
INSTALL_DIR="/usr/local"
GO_URL="https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"


# Check for the version file
# If it exists, load the version from that file
# If not found, then use the current version as 1.1.0 for docker images
if [ -f "$VERSION_FILE" ]; then
    VERSION=`cat version|xargs echo`;
else
    VERSION=1.0.0-SNAPSHOT;
fi


function  _build_docker_and_push_image {
    # Fail the job on any build/tag/push error instead of exiting green.
    set -euo pipefail

    # UTC minute-precision timestamp, matching the ONAP fabric8
    # maven.build.timestamp.format 'yyyyMMdd'T'HHmm' used by the Java repos.
    local timestamp
    timestamp=$(date -u +%Y%m%dT%H%M)

    local snapshot_tag="${IMAGE_NAME}:${VERSION}"
    local unique_tag="${IMAGE_NAME}:${VERSION}-${timestamp}"

    docker build -f Dockerfile -t policy-opa-pdp:${VERSION} .

    # Publish three tags: floating 'latest', the mutable version-tracking
    # SNAPSHOT tag, and a unique immutable per-build tag that can be pinned.
    docker tag policy-opa-pdp:${VERSION} ${IMAGE_NAME}:latest
    docker tag policy-opa-pdp:${VERSION} ${snapshot_tag}
    docker tag policy-opa-pdp:${VERSION} ${unique_tag}

    echo "Start push ${IMAGE_NAME}:latest"
    docker push ${IMAGE_NAME}:latest
    echo "Start push ${snapshot_tag}"
    docker push ${snapshot_tag}
    echo "Start push ${unique_tag}"
    docker push ${unique_tag}
}

function _install_golang_latest {

     echo "Downloading Go ${GO_VERSION}..."
     curl -fsSL ${GO_URL} -o go.tar.gz
     echo "Extracting Go ${GO_VERSION}..."
     sudo rm -rf ${INSTALL_DIR}/go
     sudo tar -C ${INSTALL_DIR} -xzf go.tar.gz
     echo "Adding Go to PATH..."
     echo "export PATH=${INSTALL_DIR}/go/bin:$PATH" >> ~/.profile
     echo "Reloading PATH for verification..."
     export PATH=${INSTALL_DIR}/go/bin:$PATH; ${INSTALL_DIR}/go/bin/go version
     echo "Go ${GO_VERSION} installed successfully. Run 'source ~/.profile' to update PATH."

}


if [ $1 == "build" ] ; then
   _build_docker_and_push_image
else
   _install_golang_latest
fi
