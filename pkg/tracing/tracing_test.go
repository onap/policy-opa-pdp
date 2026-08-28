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

package tracing

import (
	"context"
	"policy-opa-pdp/cfg"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// restoreGlobals snapshots the process-global tracer provider, propagator and
// cfg.AllowTracing, restoring them when the test ends.
//
// This is mandatory rather than tidy: the tracer provider is process-global state
// in the same class as the OPA singleton and pdpstate.State, so leaking it out of
// a test is exactly the cross-package interference that `go test -p 1` exists to
// prevent.
func restoreGlobals(t *testing.T) {
	t.Helper()
	provider := otel.GetTracerProvider()
	propagator := otel.GetTextMapPropagator()
	allowTracing := cfg.AllowTracing
	t.Cleanup(func() {
		otel.SetTracerProvider(provider)
		otel.SetTextMapPropagator(propagator)
		cfg.AllowTracing = allowTracing
	})
}

func TestInit_Disabled_InstallsNoopProvider(t *testing.T) {
	restoreGlobals(t)
	cfg.AllowTracing = false

	shutdown, err := Init(context.Background())
	require.NoError(t, err)
	require.NotNil(t, shutdown)
	assert.NoError(t, shutdown(context.Background()))

	_, span := Tracer().Start(context.Background(), "decision")
	defer span.End()
	assert.False(t, span.SpanContext().IsValid(),
		"disabled tracing must not produce a recording span")
}

// The propagator is installed regardless of ALLOW_TRACING, so that extract and
// inject call sites need no enabled/disabled branch.
func TestInit_Disabled_StillInstallsPropagator(t *testing.T) {
	restoreGlobals(t)
	cfg.AllowTracing = false

	_, err := Init(context.Background())
	require.NoError(t, err)

	assert.Contains(t, otel.GetTextMapPropagator().Fields(), "traceparent")
}

func TestInit_Enabled_UnsupportedProtocolIsRejected(t *testing.T) {
	restoreGlobals(t)
	cfg.AllowTracing = true
	t.Setenv(protocolEnv, "thrift")

	shutdown, err := Init(context.Background())
	require.Error(t, err)
	assert.Nil(t, shutdown)
	assert.Contains(t, err.Error(), "unsupported OTLP protocol")
}

func TestInit_Enabled_HTTPProtocolIsAccepted(t *testing.T) {
	restoreGlobals(t)
	cfg.AllowTracing = true
	t.Setenv(protocolEnv, protocolHTTP)
	// A bogus endpoint is fine: the OTLP HTTP exporter connects lazily, so Init
	// must succeed without a collector being reachable.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")

	shutdown, err := Init(context.Background())
	require.NoError(t, err)
	require.NotNil(t, shutdown)

	_, span := Tracer().Start(context.Background(), "decision")
	assert.True(t, span.SpanContext().IsValid(),
		"enabled tracing must produce a valid span context")
	span.End()

	assert.NoError(t, shutdown(context.Background()))
}

func TestInit_Enabled_GRPCProtocolIsAccepted(t *testing.T) {
	restoreGlobals(t)
	cfg.AllowTracing = true
	t.Setenv(protocolEnv, protocolGRPC)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4317")

	shutdown, err := Init(context.Background())
	require.NoError(t, err)
	require.NotNil(t, shutdown)
	assert.NoError(t, shutdown(context.Background()))
}

// OTEL_EXPORTER_OTLP_TRACES_PROTOCOL is the signal-specific variable and must win
// over the generic one; the compose harness sets both.
func TestNewExporter_TracesProtocolOverridesGeneric(t *testing.T) {
	t.Setenv(protocolEnv, "thrift")
	t.Setenv(tracesProtocolEnv, protocolHTTP)

	exporter, err := newExporter(context.Background())
	require.NoError(t, err)
	require.NotNil(t, exporter)
	assert.NoError(t, exporter.Shutdown(context.Background()))
}

func TestServiceName(t *testing.T) {
	t.Run("defaults when unset", func(t *testing.T) {
		t.Setenv(serviceNameEnv, "")
		assert.Equal(t, defaultServiceName, serviceName())
	})

	t.Run("honours OTEL_SERVICE_NAME", func(t *testing.T) {
		t.Setenv(serviceNameEnv, "opa-pdp-canary")
		assert.Equal(t, "opa-pdp-canary", serviceName())
	})
}

func TestTracer_UsableBeforeInit(t *testing.T) {
	restoreGlobals(t)
	// No Init call: the OpenTelemetry default provider must keep Tracer() safe.
	_, span := Tracer().Start(context.Background(), "early")
	assert.NotPanics(t, func() { span.End() })
}

// newRecordingProvider installs a span recorder as the global provider and returns
// it, restoring the previous provider on cleanup.
func newRecordingProvider(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() { otel.SetTracerProvider(previous) })
	return recorder
}
