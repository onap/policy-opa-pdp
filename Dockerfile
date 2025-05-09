# -
#   ========================LICENSE_START=================================
#   Copyright (C) 2024-2025: Deutsche Telekom
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
#
FROM curlimages/curl:7.78.0 AS build

# Get OPA
RUN curl --proto "=https" -Lo /tmp/opa https://github.com/open-policy-agent/opa/releases/download/v0.69.0/opa_linux_amd64

FROM golang:1.23 AS compile

RUN mkdir /app

COPY go.mod go.sum /app/

# Copy individual files and directories
COPY Dockerfile /go/
COPY api /go/api
COPY cfg /go/cfg
COPY cmd /go/cmd
COPY consts /go/consts
COPY go.mod /go/
COPY go.sum /go/
COPY pkg /go/pkg
COPY sonar-project.properties /go/
COPY version /go/
COPY version.properties /go/

RUN mkdir -p /app/cfg /app/consts /app/api /app/cmd /app/pkg /app/bundles
COPY cfg /app/cfg
COPY consts /app/consts
COPY api /app/api
COPY cmd /app/cmd
COPY pkg /app/pkg


WORKDIR /app

# Build the binary
RUN GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /app/opa-pdp /app/cmd/opa-pdp/opa-pdp.go

FROM ubuntu:24.04

RUN apt-get update && apt-get --no-install-recommends install -y netcat-openbsd curl && rm -rf /var/lib/apt/lists/*\
    && mkdir -p /app /opt/policies /opt/data /var/logs \
    && chown -R ubuntu:ubuntu /app /opt/policies /opt/data /var/logs

COPY --from=compile /app /app
# Copy our opa executable from build stage
COPY --from=build /tmp/opa /app/opa

RUN chown 1000:1000 /app/opa-pdp && chown 1000:1000 /app/opa && chown 1000:1000 /app/bundles\
    && chmod u+x /app/opa-pdp && chmod u+x /app/opa && chmod u+x /app/bundles


# Switch to the non-root user and 1000 is for ubuntu
USER 1000:1000

WORKDIR /app
EXPOSE 8282

# Command to run OPA with the policies
CMD ["/app/opa-pdp"]
