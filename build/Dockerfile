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
#

FROM curlimages/curl:7.78.0 AS build

# Get OPA
RUN curl -Lo /tmp/opa https://github.com/open-policy-agent/opa/releases/download/v0.69.0/opa_linux_amd64

FROM golang:1.23 AS compile

RUN mkdir /app

COPY ../go.mod ../go.sum /app/

COPY . .

RUN mkdir /app/cfg
ADD ../cfg /app/cfg

RUN mkdir /app/consts
ADD ../consts /app/consts

RUN mkdir /app/api
ADD ../api /app/api

RUN mkdir /app/cmd
ADD ../cmd /app/cmd

RUN mkdir /app/pkg
ADD ../pkg /app/pkg

RUN mkdir /app/bundles

WORKDIR /app

# Build the binary
RUN GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /app/opa-pdp /app/cmd/opa-pdp/opa-pdp.go
#COPY config.json /app/config.json
#RUN chmod 644 /app/config.json

FROM ubuntu

RUN apt-get update && apt-get install -y netcat-openbsd && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y curl

# Copy our static executable from compile stage
RUN mkdir /app
COPY --from=compile /app /app
RUN chmod +x /app/opa-pdp

# Copy our opa executable from build stage
COPY --from=build /tmp/opa /app/opa
RUN chmod 755 /app/opa

WORKDIR /app
EXPOSE 8282

# Command to run OPA with the policies
CMD ["/app/opa-pdp"]

