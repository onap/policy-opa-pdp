// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2026: Deutsche Telekom
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//   SPDX-License-Identifier: Apache-2.0
//   ========================LICENSE_END===================================

// Package tracing wires OpenTelemetry distributed tracing for the policy-opa-pdp
// service. It owns the process-global tracer provider and text-map propagator.
//
// Only ALLOW_TRACING is read from this package; endpoint, protocol, service name
// and sampling are left to the OpenTelemetry SDK, which reads the standard
// OTEL_* environment variables itself. That keeps the configuration surface
// identical to the Java policy components, which are configured the same way in
// the policy/docker compose harness.
package tracing

import (
	"context"
	"fmt"
	"os"
	"policy-opa-pdp/cfg"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	// Must track the semconv version the SDK's own resource.Default() uses;
	// resource.Merge rejects a mismatched schema URL.
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

const (
	// defaultServiceName is used when OTEL_SERVICE_NAME is not set.
	defaultServiceName = "policy-opa-pdp"

	// tracerName identifies this instrumentation scope in emitted spans.
	tracerName = "policy-opa-pdp"

	protocolEnv       = "OTEL_EXPORTER_OTLP_PROTOCOL"
	tracesProtocolEnv = "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"
	serviceNameEnv    = "OTEL_SERVICE_NAME"

	protocolGRPC = "grpc"
	protocolHTTP = "http/protobuf"
)

// Tracer returns the tracer for this service's instrumentation scope. It is safe
// to call before Init: the OpenTelemetry default is a no-op provider.
func Tracer() trace.Tracer {
	return otel.Tracer(tracerName)
}

// Init installs the global propagator and tracer provider and returns a shutdown
// function that flushes pending spans.
//
// When ALLOW_TRACING is false a no-op provider is installed and the returned
// shutdown is a no-op, so callers never need to branch on whether tracing is
// enabled.
func Init(ctx context.Context) (func(context.Context) error, error) {
	// The propagator is installed even when tracing is disabled. Extracting a
	// traceparent then yields a context that feeds the no-op tracer, which keeps
	// the enabled and disabled code paths identical instead of guarding every
	// extract/inject call site.
	//
	// TraceContext (W3C) is required rather than B3: policy-common's message-bus
	// reads and writes the literal "traceparent" header, so W3C is what actually
	// interoperates with PAP.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	if !cfg.AllowTracing {
		otel.SetTracerProvider(noop.NewTracerProvider())
		return func(context.Context) error { return nil }, nil
	}

	exporter, err := newExporter(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating OTLP trace exporter: %w", err)
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(semconv.SchemaURL, semconv.ServiceName(serviceName())),
	)
	if err != nil {
		return nil, fmt.Errorf("building trace resource: %w", err)
	}

	// No sampler is passed: NewTracerProvider already honours OTEL_TRACES_SAMPLER
	// and OTEL_TRACES_SAMPLER_ARG, so configuring one here would override the
	// operator's environment rather than complement it.
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(provider)

	return provider.Shutdown, nil
}

// newExporter selects the OTLP transport from the environment. The exporters read
// endpoint, headers and TLS settings from the standard OTEL_EXPORTER_OTLP_* vars
// themselves, so only the protocol needs deciding here.
func newExporter(ctx context.Context) (sdktrace.SpanExporter, error) {
	protocol := os.Getenv(tracesProtocolEnv)
	if protocol == "" {
		protocol = os.Getenv(protocolEnv)
	}

	switch protocol {
	case protocolGRPC:
		return otlptracegrpc.New(ctx)
	case "", protocolHTTP:
		return otlptracehttp.New(ctx)
	default:
		return nil, fmt.Errorf("unsupported OTLP protocol %q, expected %q or %q",
			protocol, protocolGRPC, protocolHTTP)
	}
}

func serviceName() string {
	if name := os.Getenv(serviceNameEnv); name != "" {
		return name
	}
	return defaultServiceName
}
