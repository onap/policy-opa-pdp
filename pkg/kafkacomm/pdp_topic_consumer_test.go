// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2024: Deutsche Telecom
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
//   ========================LICENSE_END===================================
//

package kafkacomm

import (
	"errors"
	"policy-opa-pdp/pkg/kafkacomm/mocks"
	"testing"

	"github.com/confluentinc/confluent-kafka-go/kafka"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNewKafkaConsumer(t *testing.T) {
	// Assuming configuration is correctly loaded from cfg package
	// You can mock or override cfg values here if needed

	consumer, err := NewKafkaConsumer()
	assert.NoError(t, err, "Expected no error when creating Kafka consumer")
	assert.NotNil(t, consumer, "Expected a non-nil KafkaConsumer")

	// Clean up
	if consumer != nil {
		consumer.Close()
	}
}

func TestReadKafkaMessages_Success(t *testing.T) {
	// Create a new mock for ConsumerInterface
	mockConsumer := new(mocks.KafkaConsumerInterface)

	// Create a KafkaConsumer with the mock
	kc := &KafkaConsumer{Consumer: mockConsumer}

	// Define the expected message
	expectedMsg := &kafka.Message{Value: []byte("test message")}

	// Set up the mock to return the expected message
	mockConsumer.On("ReadMessage", mock.Anything).Return(expectedMsg, nil)

	// Test ReadKafkaMessages
	msg, err := ReadKafkaMessages(kc)
	assert.NoError(t, err, "Expected no error when reading message")
	assert.Equal(t, expectedMsg.Value, msg, "Expected message content to match")

	// Assert expectations
	mockConsumer.AssertExpectations(t)
}

func TestReadKafkaMessages_Error(t *testing.T) {
	mockConsumer := new(mocks.KafkaConsumerInterface)

	kc := &KafkaConsumer{Consumer: mockConsumer}

	// Set up the mock to return an error
	expectedErr := errors.New("read error")
	mockConsumer.On("ReadMessage", mock.Anything).Return(nil, expectedErr)

	msg, err := ReadKafkaMessages(kc)
	assert.Error(t, err, "Expected an error when reading message")
	assert.Nil(t, msg, "Expected message to be nil on error")

	mockConsumer.AssertExpectations(t)
}

func TestKafkaConsumer_Close(t *testing.T) {
	mockConsumer := new(mocks.KafkaConsumerInterface)

	kc := &KafkaConsumer{Consumer: mockConsumer}

	// Set up the mock for Close
	mockConsumer.On("Close").Return(nil)

	// Test Close method
	kc.Close()

	// Verify that Close was called
	mockConsumer.AssertExpectations(t)
}

func TestKafkaConsumer_Unsubscribe(t *testing.T) {
	mockConsumer := new(mocks.KafkaConsumerInterface)

	kc := &KafkaConsumer{Consumer: mockConsumer}

	// Set up the mock for Unsubscribe
	mockConsumer.On("Unsubscribe").Return(nil)

	// Test Unsubscribe method
	err := kc.Unsubscribe()
	assert.NoError(t, err)

	// Verify that Unsubscribe was called
	mockConsumer.AssertExpectations(t)
}

func TestKafkaConsumer_Unsubscribe_Error(t *testing.T) {
	mockConsumer := new(mocks.KafkaConsumerInterface)
	mockError := errors.New("Unsubscribe error")
	kc := &KafkaConsumer{Consumer: mockConsumer}

	// Set up the mock for Unsubscribe
	mockConsumer.On("Unsubscribe").Return(mockError)

	// Test Unsubscribe method
	err := kc.Unsubscribe()
	assert.Error(t, err)
	assert.Equal(t, mockError, err)

	// Verify that Unsubscribe was called
	mockConsumer.AssertExpectations(t)
}
