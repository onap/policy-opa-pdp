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

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
)

// A well-formed W3C traceparent, as PAP's KafkaTelemetry producer interceptor
// would emit it.
const (
	papTraceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	papTraceID     = "0af7651916cd43dd8448eb211c80319c"
	papSpanID      = "b7ad6b7169203331"
)

func TestKafkaHeaderCarrier_SetGetKeys(t *testing.T) {
	var headers []kafka.Header
	carrier := KafkaHeaderCarrier{Headers: &headers}

	carrier.Set("traceparent", papTraceparent)

	assert.Equal(t, papTraceparent, carrier.Get("traceparent"))
	assert.Equal(t, []string{"traceparent"}, carrier.Keys())
	assert.Empty(t, carrier.Get("absent"))
}

func TestKafkaHeaderCarrier_SetReplacesRatherThanAppends(t *testing.T) {
	var headers []kafka.Header
	carrier := KafkaHeaderCarrier{Headers: &headers}

	carrier.Set("traceparent", "first")
	carrier.Set("traceparent", "second")

	require.Len(t, headers, 1, "a stale traceparent must not be left behind")
	assert.Equal(t, "second", carrier.Get("traceparent"))
}

// Kafka allows duplicate keys and the Java consumer reads lastHeader, so Get must
// agree and return the last occurrence.
func TestKafkaHeaderCarrier_GetReturnsLastOccurrence(t *testing.T) {
	headers := []kafka.Header{
		{Key: "traceparent", Value: []byte("older")},
		{Key: "traceparent", Value: []byte("newer")},
	}
	carrier := KafkaHeaderCarrier{Headers: &headers}

	assert.Equal(t, "newer", carrier.Get("traceparent"))
}

// A nil Headers pointer must degrade quietly rather than panic; the carrier is
// constructed from message fields that are not guaranteed to be populated.
func TestKafkaHeaderCarrier_NilHeadersIsSafe(t *testing.T) {
	carrier := KafkaHeaderCarrier{}

	assert.Empty(t, carrier.Get("traceparent"))
	assert.Nil(t, carrier.Keys())
	assert.NotPanics(t, func() { carrier.Set("traceparent", papTraceparent) })
}

func TestExtractFromKafka_ContinuesRemoteTrace(t *testing.T) {
	restoreGlobals(t)
	cfg.AllowTracing = false
	_, err := Init(context.Background())
	require.NoError(t, err)

	headers := []kafka.Header{{Key: "traceparent", Value: []byte(papTraceparent)}}

	spanContext := trace.SpanContextFromContext(
		ExtractFromKafka(context.Background(), headers))

	require.True(t, spanContext.IsValid())
	assert.Equal(t, papTraceID, spanContext.TraceID().String())
	assert.Equal(t, papSpanID, spanContext.SpanID().String())
	assert.True(t, spanContext.IsRemote())
}

func TestExtractFromKafka_MalformedHeaderYieldsNoParent(t *testing.T) {
	restoreGlobals(t)
	cfg.AllowTracing = false
	_, err := Init(context.Background())
	require.NoError(t, err)

	headers := []kafka.Header{{Key: "traceparent", Value: []byte("garbage")}}

	spanContext := trace.SpanContextFromContext(
		ExtractFromKafka(context.Background(), headers))

	assert.False(t, spanContext.IsValid(),
		"a malformed traceparent must fall back to a root span, not fail")
}

func TestExtractFromKafka_NoHeadersYieldsNoParent(t *testing.T) {
	restoreGlobals(t)
	cfg.AllowTracing = false
	_, err := Init(context.Background())
	require.NoError(t, err)

	spanContext := trace.SpanContextFromContext(
		ExtractFromKafka(context.Background(), nil))

	assert.False(t, spanContext.IsValid())
}

func TestInjectIntoKafka_WritesTraceparent(t *testing.T) {
	restoreGlobals(t)
	cfg.AllowTracing = false
	_, err := Init(context.Background())
	require.NoError(t, err)
	recorder := newRecordingProvider(t)

	ctx, span := Tracer().Start(context.Background(), "outbound")
	var headers []kafka.Header
	InjectIntoKafka(ctx, &headers)
	span.End()

	require.Len(t, recorder.Ended(), 1)
	carrier := KafkaHeaderCarrier{Headers: &headers}
	assert.Contains(t, carrier.Get("traceparent"),
		recorder.Ended()[0].SpanContext().TraceID().String())
}

// With tracing off the span context is invalid, and the propagator must emit
// nothing rather than an all-zero traceparent that would corrupt PAP's trace.
func TestInjectIntoKafka_DisabledWritesNothing(t *testing.T) {
	restoreGlobals(t)
	cfg.AllowTracing = false
	_, err := Init(context.Background())
	require.NoError(t, err)

	ctx, span := Tracer().Start(context.Background(), "outbound")
	defer span.End()

	var headers []kafka.Header
	InjectIntoKafka(ctx, &headers)

	assert.Empty(t, headers)
}

// Round-trip: what we inject, the extractor must recover — this is the contract
// that keeps a multi-replica patch broadcast inside one trace.
func TestInjectExtract_RoundTrip(t *testing.T) {
	restoreGlobals(t)
	cfg.AllowTracing = false
	_, err := Init(context.Background())
	require.NoError(t, err)
	newRecordingProvider(t)

	ctx, span := Tracer().Start(context.Background(), "outbound")
	defer span.End()

	var headers []kafka.Header
	InjectIntoKafka(ctx, &headers)

	extracted := trace.SpanContextFromContext(
		ExtractFromKafka(context.Background(), headers))

	assert.Equal(t, span.SpanContext().TraceID(), extracted.TraceID())
	assert.Equal(t, span.SpanContext().SpanID(), extracted.SpanID())
}
