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

FROM curlimages/curl:7.78.0 AS opa

ARG OPA_VERSION=v0.69.0
RUN curl --proto "=https" --tlsv1.2 -fsSLo /tmp/opa \
        https://github.com/open-policy-agent/opa/releases/download/${OPA_VERSION}/opa_linux_amd64

FROM golang:1.23-bookworm AS compile

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY api ./api
COPY cfg ./cfg
COPY cmd ./cmd
COPY consts ./consts
COPY pkg ./pkg

RUN GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /rootfs/app/opa-pdp ./cmd/opa-pdp/opa-pdp.go

COPY --from=opa /tmp/opa /rootfs/app/opa
RUN chmod 0755 /rootfs/app/opa /rootfs/app/opa-pdp \
    && mkdir -p /rootfs/app/bundles /rootfs/app/config \
                /rootfs/opt/policies /rootfs/opt/data /rootfs/var/logs \
    && chown -R 1000:1000 /rootfs/app /rootfs/opt /rootfs/var

FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=compile --chown=1000:1000 /rootfs /

USER 1000:1000
WORKDIR /app
EXPOSE 8282

CMD ["/app/opa-pdp"]
