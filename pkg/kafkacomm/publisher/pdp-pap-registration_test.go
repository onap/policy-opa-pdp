// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2024-2025: Deutsche Telekom
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
//

package publisher

import (
	"context"
	"errors"
	"fmt"
	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"policy-opa-pdp/pkg/model"
	"testing"
	"time"
)

type MockPdpStatusSender struct {
	mock.Mock
}

func (m *MockPdpStatusSender) SendPdpStatus(ctx context.Context, pdpStatus model.PdpStatus) error {
	return m.Called(ctx, pdpStatus).Error(0)

}

// New

type MockKafkaProducer struct {
	mock.Mock
}

func (m *MockKafkaProducer) Produce(message *kafka.Message, evenchan chan kafka.Event) error {
	args := m.Called(message)
	return args.Error(0)
}

func (m *MockKafkaProducer) Close() {
	m.Called()
}

func (m *MockKafkaProducer) Flush(timeout int) int {
	m.Called(timeout)
	return 0
}

// Test the SendPdpStatus method
func TestSendPdpStatus_Success(t *testing.T) {
	// Create the mock producer
	mockProducer := new(MockKafkaProducer)

	// Mock the Produce method to simulate success
	mockProducer.On("Produce", mock.Anything).Return(nil)
	//t.Fatalf("Inside Sender checking for producer , but got: %v", mockProducer)

	// Create the RealPdpStatusSender with the mocked producer
	sender := RealPdpStatusSender{
		Producer: mockProducer,
	}

	// Prepare a mock PdpStatus
	pdpStatus := model.PdpStatus{
		RequestID:   uuid.New().String(),
		TimestampMs: fmt.Sprintf("%d", time.Now().UnixMilli()),
		State:       model.Active, // Use the correct enum value for State
	}
	// Call the SendPdpStatus method
	err := sender.SendPdpStatus(context.Background(), pdpStatus)
	if err != nil {
		t.Fatalf("Expected no error, but got: %v", err)
	}

	// Assert expectations on the mock
	mockProducer.AssertExpectations(t)
}

func TestSendPdpStatus_Failure(t *testing.T) {
	// Create a mock Kafka producer
	mockProducer := new(MockKafkaProducer)

	// Configure the mock to simulate an error when Produce is called
	mockProducer.On("Produce", mock.Anything).Return(errors.New("mock produce error"))

	// Create a RealPdpStatusSender with the mock producer
	sender := RealPdpStatusSender{
		Producer: mockProducer,
	}

	// Create a mock PdpStatus object
	pdpStatus := model.PdpStatus{}

	// Call the method under test
	err := sender.SendPdpStatus(context.Background(), pdpStatus)
	// t.Fatalf("Expected an error, but got: %v", err)

	// Assert that an error was returned
	if err == nil {
		t.Fatalf("Expected an error, but got nil")
	}

	// Assert that the error message is correct
	expectedError := "mock produce error"
	if err.Error() != expectedError {
		t.Errorf("Expected error: %v, but got: %v", expectedError, err)
	}

	// Verify that the Produce method was called exactly once
	mockProducer.AssertExpectations(t)
}

// capturingProducer keeps the produced message so a test can inspect its headers.
type capturingProducer struct {
	produced *kafka.Message
}

func (p *capturingProducer) Produce(message *kafka.Message, eventChan chan kafka.Event) error {
	p.produced = message
	return nil
}

func (p *capturingProducer) Close() {}

func (p *capturingProducer) Flush(timeout int) int { return 0 }

func headerValue(headers []kafka.Header, key string) string {
	for _, header := range headers {
		if header.Key == key {
			return string(header.Value)
		}
	}
	return ""
}

func TestSendPdpStatus_InjectsTraceparent(t *testing.T) {
	previousPropagator := otel.GetTextMapPropagator()
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() { otel.SetTextMapPropagator(previousPropagator) })

	traceID, err := trace.TraceIDFromHex("0af7651916cd43dd8448eb211c80319c")
	require.NoError(t, err)
	spanID, err := trace.SpanIDFromHex("b7ad6b7169203331")
	require.NoError(t, err)
	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	}))

	producer := &capturingProducer{}
	sender := RealPdpStatusSender{Producer: producer}

	require.NoError(t, sender.SendPdpStatus(ctx, model.PdpStatus{}))
	require.NotNil(t, producer.produced)
	assert.Equal(t, "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
		headerValue(producer.produced.Headers, "traceparent"))
}

func TestSendPdpStatus_NoTracing_NoHeader(t *testing.T) {
	previousPropagator := otel.GetTextMapPropagator()
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() { otel.SetTextMapPropagator(previousPropagator) })

	producer := &capturingProducer{}
	sender := RealPdpStatusSender{Producer: producer}

	require.NoError(t, sender.SendPdpStatus(context.Background(), model.PdpStatus{}))
	require.NotNil(t, producer.produced)
	assert.Empty(t, producer.produced.Headers)
}
