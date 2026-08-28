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

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

// KafkaHeaderCarrier adapts confluent-kafka-go message headers to the
// OpenTelemetry TextMapCarrier interface, so trace context can ride along on
// PAP <-> PDP Kafka messages.
//
// Headers is a pointer because Set has to be able to append to a slice owned by
// the caller (a *kafka.Message being built for Produce).
type KafkaHeaderCarrier struct {
	Headers *[]kafka.Header
}

// compile-time check that the carrier satisfies the propagator contract.
var _ propagation.TextMapCarrier = KafkaHeaderCarrier{}

// Get returns the last value for key, or "" when absent.
//
// Kafka permits repeated header keys. The last occurrence wins here to match the
// Java side (policy-common BusConsumer uses Headers.lastHeader), so both ends
// agree on which traceparent is authoritative when a message carries several.
func (c KafkaHeaderCarrier) Get(key string) string {
	if c.Headers == nil {
		return ""
	}
	for i := len(*c.Headers) - 1; i >= 0; i-- {
		if (*c.Headers)[i].Key == key {
			return string((*c.Headers)[i].Value)
		}
	}
	return ""
}

// Set replaces the value for key, appending only when key is absent. Replacing
// rather than appending matters because a stale traceparent left behind on a
// reused message would be picked up as authoritative by Get and by the Java
// consumer.
func (c KafkaHeaderCarrier) Set(key, value string) {
	if c.Headers == nil {
		return
	}
	for i := range *c.Headers {
		if (*c.Headers)[i].Key == key {
			(*c.Headers)[i].Value = []byte(value)
			return
		}
	}
	*c.Headers = append(*c.Headers, kafka.Header{Key: key, Value: []byte(value)})
}

// Keys lists the header keys present in the carrier.
func (c KafkaHeaderCarrier) Keys() []string {
	if c.Headers == nil {
		return nil
	}
	keys := make([]string, 0, len(*c.Headers))
	for _, header := range *c.Headers {
		keys = append(keys, header.Key)
	}
	return keys
}

// ExtractFromKafka returns ctx enriched with any trace context carried by the
// inbound message headers. A missing or malformed traceparent simply leaves ctx
// without a remote parent, so the caller starts a root span instead of failing.
func ExtractFromKafka(ctx context.Context, headers []kafka.Header) context.Context {
	return otel.GetTextMapPropagator().Extract(ctx, KafkaHeaderCarrier{Headers: &headers})
}

// InjectIntoKafka writes the trace context from ctx into the outbound message
// headers. With tracing disabled the span context is invalid and the propagator
// writes nothing, so no all-zero traceparent is emitted.
func InjectIntoKafka(ctx context.Context, headers *[]kafka.Header) {
	otel.GetTextMapPropagator().Inject(ctx, KafkaHeaderCarrier{Headers: headers})
}
