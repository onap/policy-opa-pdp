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

