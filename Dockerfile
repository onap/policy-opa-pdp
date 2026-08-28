# -
#   ========================LICENSE_START=================================
#   Copyright (C) 2024-2026: Deutsche Telekom
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

RUN chmod 0755 /rootfs/app/opa-pdp \
    && mkdir -p /rootfs/app/config \
                /rootfs/opt/policies /rootfs/opt/data /rootfs/var/logs \
    && chown -R 1000:1000 /rootfs/app /rootfs/opt /rootfs/var

FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=compile --chown=1000:1000 /rootfs /

USER 1000:1000
WORKDIR /app
EXPOSE 8282

# The runtime image is distroless (no shell/curl), so the health probe is the
# binary itself: `opa-pdp -healthcheck` does an authenticated GET on the local
# /healthcheck endpoint and exits non-zero when unhealthy. Kubernetes uses its
# own tcpSocket probe and ignores this directive.
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD ["/app/opa-pdp", "-healthcheck"]

CMD ["/app/opa-pdp"]
