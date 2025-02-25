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
RUN curl -Lo /tmp/opa https://github.com/open-policy-agent/opa/releases/download/v0.69.0/opa_linux_amd64

FROM golang:1.23 AS compile

RUN mkdir /app

COPY go.mod go.sum /app/

COPY . .

RUN mkdir -p /app/cfg /app/consts /app/api /app/cmd /app/pkg /app/bundles
COPY cfg /app/cfg
COPY consts /app/consts
COPY api /app/api
COPY cmd /app/cmd
COPY pkg /app/pkg


WORKDIR /app

# Build the binary
RUN GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /app/opa-pdp /app/cmd/opa-pdp/opa-pdp.go

FROM ubuntu

RUN apt-get update && apt-get install -y netcat-openbsd curl && rm -rf /var/lib/apt/lists/*\
    && mkdir -p /app /opt/policies /opt/data /var/logs \
    && chown -R ubuntu:ubuntu /app /opt/policies /opt/data /var/logs

COPY --from=compile /app /app
# Copy our opa executable from build stage
COPY --from=build /tmp/opa /app/opa

RUN chmod +x /app/opa-pdp && chmod 755 /app/opa


# Switch to the non-root user and 1000 is for ubuntu
USER 1000:1000

WORKDIR /app
EXPOSE 8282

# Command to run OPA with the policies
CMD ["/app/opa-pdp"]

