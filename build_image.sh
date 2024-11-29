#!/bin/bash
# -
#   ========================LICENSE_START=================================
#   Copyright (C) 2024: Deutsche Telecom
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
#   ========================LICENSE_END===================================
#

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
    VERSION=1.0.0;
fi


function  _build_docker_and_push_image {
    local tag_name=${IMAGE_NAME}:${VERSION}

    docker build -f  Dockerfile  -t policy-opa-pdp:${VERSION} .
    echo "Start push {$tag_name}"
    docker tag policy-opa-pdp:${VERSION} ${IMAGE_NAME}:latest
    docker push ${IMAGE_NAME}:latest
    docker tag ${IMAGE_NAME}:latest ${tag_name}
    docker push ${tag_name}
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
