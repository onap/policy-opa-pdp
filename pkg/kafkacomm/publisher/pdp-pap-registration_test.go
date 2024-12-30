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
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"time"
	"github.com/google/uuid"
	"policy-opa-pdp/pkg/kafkacomm/publisher/mocks"
	"github.com/confluentinc/confluent-kafka-go/kafka"
	"policy-opa-pdp/pkg/model"
	"testing"
)

type MockPdpStatusSender struct {
	mock.Mock
}

func (m *MockPdpStatusSender) SendPdpStatus(pdpStatus model.PdpStatus) error {
	return m.Called(pdpStatus).Error(0)

}

func TestSendPdpPapRegistration_Success(t *testing.T) {
	mockSender := new(mocks.PdpStatusSender)

	mockSender.On("SendPdpStatus", mock.AnythingOfType("model.PdpStatus")).Return(nil)

	err := SendPdpPapRegistration(mockSender)
	assert.NoError(t, err)
	mockSender.AssertCalled(t, "SendPdpStatus", mock.AnythingOfType("model.PdpStatus"))
}

func TestSendPdpPapRegistration_Failure(t *testing.T) {
	mockSender := new(mocks.PdpStatusSender)

	mockSender.On("SendPdpStatus", mock.AnythingOfType("model.PdpStatus")).Return(errors.New("failed To Send"))

	err := SendPdpPapRegistration(mockSender)
	assert.Error(t, err, "Expected an error for failure")
	assert.EqualError(t, err, "failed To Send", "Error messages should match")
	mockSender.AssertCalled(t, "SendPdpStatus", mock.AnythingOfType("model.PdpStatus"))
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
	err := sender.SendPdpStatus(pdpStatus)
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
	err := sender.SendPdpStatus(pdpStatus)
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

