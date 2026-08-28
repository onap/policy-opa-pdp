# Running docker  policy-opa-pdp

## Building Docker Image.
docker build -t opa-pdp:1.0.0 .


## Generating models with openapi.yaml

1. oapi-codegen -package=oapicodegen  -generate "models" openapi.yaml > models.go


## Creating New Policy

1. Create a tosca policy file that has policy.rego and data.json encoded contents.

2. Ensure data key should have node as prefix. For example refer to test/test_resources/blacklist/policy_blacklist.yaml.

3. OPA emphasizes that each policy should have a unique policy-name/policy-id,

   example:
   Not Allowed: 
   1. If a policy named onap.org.cell is deployed, then deploying a policy named onap.org.cell.consistency is disallowed because it shares the same hierarchical structure.

   2. If a policy named onap.org.cell is deployed, then deploying a policy named onap.org is disallowed because it is parent directory.

   Allowed: If a policy named onap.org.cell is deployed, then deploying a policy named onap.org.consistency is permitted, as it does not share the same hierarchy.


4. Policy key should start (prefixed) with policy-id. For ex refer to test/test_resources/blacklist/policy_blacklist.yaml.

5. Create a deploy.json file to deploy through pap. Refer to file under test/test_resources/blacklist/deploy_blacklist.json.

## Deploy Policy Using Docker Compose

1. Ensure you have docker and docker-compose installed

2. Check out the policy/docker repo from the ONAP gerrit or from github: https://github.com/onap/policy-docker

3. Latest Docker image created can be updated in compose.yml inside policy/docker repo.

4. Start opa-pdp containers by running the start-compose.sh script

5. Command to start opa-pdp container ./start-compose.sh opa-pdp

6. Check the logs. docker logs -f policy-opa-pdp


## Testing Decision Api

To get opa Decision for the deployed policies please refer to  test/README.md for the API details.


## Distributed Tracing

OPA-PDP can emit OpenTelemetry traces over OTLP. Tracing is off by default and is
enabled with `ALLOW_TRACING=true`. Everything else is configured through the
standard OpenTelemetry environment variables, which the SDK reads itself:

| Variable | Default | Purpose |
|----------|---------|---------|
| `ALLOW_TRACING` | `false` | Enables the OTLP exporter. When false, a no-op tracer is installed. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:4318` (http), `http://localhost:4317` (grpc) | Collector endpoint. |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` | Transport; `http/protobuf` or `grpc`. `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` overrides it. |
| `OTEL_SERVICE_NAME` | `policy-opa-pdp` | Service name reported on every span. |
| `OTEL_TRACES_SAMPLER` | `parentbased_always_on` | Sampler; `OTEL_TRACES_SAMPLER_ARG` sets its argument. |

What is instrumented:

- **HTTP** — a server span per request on `/policy/pdpo/v1/decision`, `/data`,
  `/statistics`, `/generateast` and `/opa/listpolicies`. The `X-ONAP-RequestID`
  header, when present, is recorded as the `onap.request.id` span attribute.
  `/healthcheck`, `/readiness` and `/metrics` are deliberately not instrumented:
  kubelet probes and Prometheus scrapes would otherwise dominate every trace view.
- **Kafka** — the W3C `traceparent` of an inbound PAP message is continued in a
  consumer span, and injected into the outbound `PDP_STATUS` and data-patch
  messages. A deployment therefore appears as one trace spanning PAP and every PDP
  that acted on it.

Heartbeats answer a timer rather than a request, so each one starts its own trace.

The `policy/docker` compose harness does not yet set these variables, so tracing
has to be enabled explicitly to exercise it locally.
